package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
)

type td128Table struct {
	name, fault string
	rows        map[string][]byte
	trace       *[]string
	iterErr     error
	iterations  int
}

func (m *td128Table) record(op string)  { *m.trace = append(*m.trace, m.name+"."+op) }
func (m *td128Table) KeySize() uint32   { return 40 }
func (m *td128Table) ValueSize() uint32 { return 1 }
func (m *td128Table) Update(k, v interface{}, flags ebpf.MapUpdateFlags) error {
	m.record("update")
	key := string(k.([]byte))
	if flags != ebpf.UpdateNoExist {
		return fmt.Errorf("unexpected flags: %v", flags)
	}
	if _, exists := m.rows[key]; exists {
		return ebpf.ErrKeyExist
	}
	m.rows[key] = append([]byte(nil), v.([]byte)...)
	switch m.fault {
	case "tamper":
		m.rows[key][0] = 2
	case "extra":
		m.rows[string(make([]byte, 40))] = []byte{1}
	case "verify-iterate":
		m.iterErr = errors.New("injected verification iteration")
	}
	return nil
}
func (m *td128Table) Lookup(k, out interface{}) error {
	m.record("lookup")
	v, ok := m.rows[string(k.([]byte))]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	copy(out.(*[1]byte)[:], v)
	return nil
}
func (m *td128Table) Delete(k interface{}) error {
	m.record("delete")
	delete(m.rows, string(k.([]byte)))
	return nil
}

type td128Iterator struct {
	table *td128Table
	keys  []string
	n     int
}

func (m *td128Table) Iterate() whitelistIterator {
	m.record("iterate")
	m.iterations++
	if m.fault == "empty-extra" && m.iterations == 2 {
		// An empty batch writes nothing; the stray row appears between clear and verification.
		m.rows[string(make([]byte, 40))] = []byte{1}
	}
	keys := make([]string, 0, len(m.rows))
	for k := range m.rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return &td128Iterator{table: m, keys: keys}
}
func (it *td128Iterator) Next(k, v interface{}) bool {
	if it.n == len(it.keys) {
		return false
	}
	key := it.keys[it.n]
	*k.(*[]byte) = []byte(key)
	*v.(*[]byte) = append([]byte(nil), it.table.rows[key]...)
	it.n++
	return true
}
func (it *td128Iterator) Err() error { return it.table.iterErr }

type td128Selector struct {
	configPublishMap
	trace *[]string
}

func (m td128Selector) Update(k, v interface{}, flags ebpf.MapUpdateFlags) error {
	if err := m.configPublishMap.Update(k, v, flags); err != nil {
		return err
	}
	*m.trace = append(*m.trace, "flip")
	return nil
}

type td128Rig struct {
	h           *Handlers
	old, shadow *td128Table
	trace       []string
	fail        string
	flips       *cut53ConfigFault
	entries     int
}

func td128Fixture(t *testing.T) *td128Rig {
	t.Helper()
	h, flips, selector := cut53PublishFixture("")
	r := &td128Rig{h: h, flips: flips, entries: 1}
	makeTable := func(name string) *td128Table {
		return &td128Table{name: name, rows: map[string][]byte{string(make([]byte, 40)): {1}}, trace: &r.trace}
	}
	r.old, r.shadow = makeTable("old"), makeTable("shadow")
	h.whitelist, h.whitelistB = new(ebpf.Map), new(ebpf.Map)
	saved := whitelistMapIO
	whitelistMapIO = func(m *ebpf.Map) whitelistTable {
		switch m {
		case h.whitelist:
			return r.old
		case h.whitelistB:
			return r.shadow
		default:
			return saved(m)
		}
	}
	t.Cleanup(func() { whitelistMapIO = saved })
	h.configPublishFixture.selector = td128Selector{selector, &r.trace}
	h.quiescer = cut5ReceiptFunc(func() error {
		for _, lock := range []interface {
			TryLock() bool
			Unlock()
		}{&h.syncMu, &h.publishMu, &h.wlMu} {
			if lock.TryLock() {
				lock.Unlock()
				t.Fatal("receipt without all publication locks")
			}
		}
		phase := "R0"
		if flips.flips > 0 {
			phase = "R5c"
			if len(h.wlEntries) != r.entries || h.activeWLSlot != 1 {
				t.Fatal("R5c before memory commit")
			}
		}
		r.trace = append(r.trace, phase)
		if r.fail == phase {
			return errors.New("injected receipt failure")
		}
		return nil
	})
	return r
}

const td128Body = `{"entries":[{"id":"w","src_ip":"192.0.2.1"}]}`

func (r *td128Rig) call(body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/v1/sync/whitelist", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	r.h.SyncWhitelistHandler(c)
	return w
}

func TestTD128ReceiptOrder(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "confirmed"}[confirmed], func(t *testing.T) {
			r := td128Fixture(t)
			r.h.quiescenceConfirmed = confirmed
			w := r.call(td128Body)
			want := "shadow.iterate,shadow.delete,shadow.update,shadow.lookup,shadow.iterate,flip,R5c,old.iterate,old.delete"
			if !confirmed {
				want = "R0," + want
			}
			if w.Code != 200 || strings.Join(r.trace, ",") != want || !r.h.quiescenceConfirmed || len(r.old.rows) != 0 {
				t.Fatalf("status=%d trace=%v confirmed=%v old=%d want=%s", w.Code, r.trace, r.h.quiescenceConfirmed, len(r.old.rows), want)
			}
		})
	}
}

func TestTD128ReceiptFailure(t *testing.T) {
	for _, phase := range []string{"R0", "R5c"} {
		t.Run(phase, func(t *testing.T) {
			r := td128Fixture(t)
			r.fail = phase
			w := r.call(td128Body)
			wantStatus, wantTrace := 500, "R0,R0,R0"
			if phase == "R5c" {
				wantStatus = 200
				wantTrace = "R0,shadow.iterate,shadow.delete,shadow.update,shadow.lookup,shadow.iterate,flip,R5c,R5c,R5c"
			}
			if w.Code != wantStatus || strings.Join(r.trace, ",") != wantTrace || r.h.quiescenceConfirmed || len(r.old.rows) != 1 {
				t.Fatalf("status=%d trace=%v confirmed=%v old=%d", w.Code, r.trace, r.h.quiescenceConfirmed, len(r.old.rows))
			}
			var body map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if phase == "R0" && (body["code"] != "quiescence_failed" || len(r.flips.trace) != 0) {
				t.Fatalf("R0 response=%s config_io=%v", w.Body.String(), r.flips.trace)
			}
			if phase == "R5c" && (body["total"] != float64(1) || body["failed"] != float64(0) || !r.h.whitelistSynced.Load()) {
				t.Fatalf("R5c success response=%s", w.Body.String())
			}
		})
	}
}

func TestTD128ValidationBeforeReceipt(t *testing.T) {
	r := td128Fixture(t)
	w := r.call(`{"entries":[{"id":"","src_ip":"192.0.2.1"}]}`)
	if w.Code != 400 || len(r.trace) != 0 || !strings.Contains(w.Body.String(), "empty ID rejected") {
		t.Fatalf("status=%d trace=%v body=%s", w.Code, r.trace, w.Body.String())
	}
}

func TestTD128Verification(t *testing.T) {
	for _, fault := range []string{"tamper", "extra", "verify-iterate"} {
		t.Run(fault, func(t *testing.T) {
			r := td128Fixture(t)
			r.shadow.fault = fault
			w := r.call(td128Body)
			if w.Code != 500 || r.flips.flips != 0 || r.h.activeWLSlot != 0 || len(r.old.rows) != 1 || !strings.Contains(w.Body.String(), "shadow whitelist verification") {
				t.Fatalf("status=%d flips=%d trace=%v body=%s", w.Code, r.flips.flips, r.trace, w.Body.String())
			}
		})
	}
}

func TestTD128EmptyBatchVerification(t *testing.T) {
	for _, fault := range []string{"", "empty-extra"} {
		t.Run(map[string]string{"": "empty", "empty-extra": "empty-extra"}[fault], func(t *testing.T) {
			r := td128Fixture(t)
			r.entries = 0
			r.shadow.fault = fault
			w := r.call(`{"entries":[]}`)
			if fault == "" {
				if w.Code != 200 || r.flips.flips != 1 || len(r.shadow.rows) != 0 || len(r.old.rows) != 0 {
					t.Fatalf("status=%d flips=%d shadow=%d old=%d body=%s", w.Code, r.flips.flips, len(r.shadow.rows), len(r.old.rows), w.Body.String())
				}
				return
			}
			var body map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != 500 || body["code"] != nil || r.flips.flips != 0 || r.h.activeWLSlot != 0 || len(r.old.rows) != 1 ||
				!strings.Contains(w.Body.String(), "shadow whitelist verification count: got 1 want 0") {
				t.Fatalf("status=%d flips=%d trace=%v body=%s", w.Code, r.flips.flips, r.trace, w.Body.String())
			}
		})
	}
}

func TestTD128ClearIteration(t *testing.T) {
	for _, where := range []string{"direct", "shadow", "old"} {
		t.Run(where, func(t *testing.T) {
			r := td128Fixture(t)
			injected := errors.New("injected traversal")
			r.shadow.iterErr = injected
			if where == "direct" {
				err := clearMap(r.h.shadowWhitelist())
				if !errors.Is(err, injected) || err.Error() != "clearMap: iterate: injected traversal" || len(r.shadow.rows) != 1 || strings.Join(r.trace, ",") != "shadow.iterate" {
					t.Fatalf("err=%v trace=%v rows=%d", err, r.trace, len(r.shadow.rows))
				}
				return
			}
			wantStatus, wantFlips, wantTrace := 500, 0, "R0,shadow.iterate"
			if where == "old" {
				r.shadow.iterErr, r.old.iterErr = nil, injected
				wantStatus, wantFlips = 200, 1
				wantTrace = "R0,shadow.iterate,shadow.delete,shadow.update,shadow.lookup,shadow.iterate,flip,R5c,old.iterate"
			}
			w := r.call(td128Body)
			if w.Code != wantStatus || r.flips.flips != wantFlips || strings.Join(r.trace, ",") != wantTrace || len(r.old.rows) != 1 {
				t.Fatalf("status=%d flips=%d trace=%v old=%d", w.Code, r.flips.flips, r.trace, len(r.old.rows))
			}
			if where == "shadow" && !strings.Contains(w.Body.String(), "failed to clear shadow whitelist: clearMap: iterate:") {
				t.Fatalf("body=%s", w.Body.String())
			}
		})
	}
}
