package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

type cut55Map struct {
	cursors                            map[*ebpf.MapBatchCursor]int
	rows                               map[string][]byte
	keySize, valueSize                 uint32
	enumerateErr, deleteErr, updateErr error
	writes, deletes                    int
}

func cut55Bytes(v interface{}) []byte {
	if b, ok := v.([]byte); ok {
		return append([]byte(nil), b...)
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
		panic(err)
	}
	return b.Bytes()
}
func (m *cut55Map) KeySize() uint32    { return m.keySize }
func (m *cut55Map) ValueSize() uint32  { return m.valueSize }
func (m *cut55Map) MaxEntries() uint32 { return 1024 }
func (m *cut55Map) NextKey(cursor, out interface{}) error {
	if m.enumerateErr != nil {
		return m.enumerateErr
	}
	keys := sortedMirrorKeys(m.rows)
	i := 0
	if cursor != nil {
		k := string(cut55Bytes(cursor))
		i = sort.SearchStrings(keys, k)
		if i < len(keys) && keys[i] == k {
			i++
		}
	}
	if i == len(keys) {
		return ebpf.ErrKeyNotExist
	}
	*(out.(*[]byte)) = []byte(keys[i])
	return nil
}
func (m *cut55Map) Lookup(key, out interface{}) error {
	v, ok := m.rows[string(cut55Bytes(key))]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	if b, ok := out.(*[]byte); ok {
		*b = append([]byte(nil), v...)
		return nil
	}
	return binary.Read(bytes.NewReader(v), binary.LittleEndian, out)
}
func (m *cut55Map) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	k := string(cut55Bytes(key))
	_, exists := m.rows[k]
	if flags == ebpf.UpdateNoExist && exists {
		return ebpf.ErrKeyExist
	}
	if flags == ebpf.UpdateExist && !exists {
		return ebpf.ErrKeyNotExist
	}
	m.rows[k] = cut55Bytes(value)
	m.writes++
	return nil
}
func (m *cut55Map) Delete(key interface{}) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	k := string(cut55Bytes(key))
	if _, ok := m.rows[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.rows, k)
	m.deletes++
	return nil
}

func (m *cut55Map) BatchLookup(c *ebpf.MapBatchCursor, k, v interface{}, _ *ebpf.BatchOptions) (int, error) {
	if m.enumerateErr != nil {
		return 0, m.enumerateErr
	}
	if m.cursors == nil {
		m.cursors = make(map[*ebpf.MapBatchCursor]int)
	}
	keys := sortedMirrorKeys(m.rows)
	kb, vb := reflect.ValueOf(k), reflect.ValueOf(v)
	start := m.cursors[c]
	n := min(kb.Len(), len(keys)-start)
	for i, key := range keys[start : start+n] {
		copy(atomicBatchBytes(kb, i), key)
		copy(atomicBatchBytes(vb, i), m.rows[key])
	}
	m.cursors[c] = start + n
	if start+n == len(keys) {
		delete(m.cursors, c)
		return n, ebpf.ErrKeyNotExist
	}
	return n, nil
}
func (m *cut55Map) BatchUpdate(k, v interface{}, o *ebpf.BatchOptions) (int, error) {
	kb, vb := reflect.ValueOf(k), reflect.ValueOf(v)
	flags := ebpf.UpdateAny
	if o != nil {
		flags = ebpf.MapUpdateFlags(o.ElemFlags)
	}
	for i := 0; i < kb.Len(); i++ {
		if err := m.Update(atomicBatchBytes(kb, i), atomicBatchBytes(vb, i), flags); err != nil {
			return i, err
		}
	}
	return kb.Len(), nil
}
func (m *cut55Map) BatchDelete(k interface{}, _ *ebpf.BatchOptions) (int, error) {
	kb := reflect.ValueOf(k)
	for i := 0; i < kb.Len(); i++ {
		if err := m.Delete(atomicBatchBytes(kb, i)); err != nil {
			return i, err
		}
	}
	return kb.Len(), nil
}

type cut55Trie struct {
	rows                map[string]uint32
	keySize             uint32
	failPut, failDelete bool
}

func (m *cut55Trie) Put(k, v interface{}) error {
	if m.failPut {
		return errors.New("trie publish")
	}
	m.rows[string(cut55Bytes(k))] = v.(uint32)
	return nil
}
func (m *cut55Trie) Delete(k interface{}) error {
	if m.failDelete {
		return errors.New("trie delete")
	}
	delete(m.rows, string(cut55Bytes(k)))
	return nil
}
func (m *cut55Trie) MaxEntries() uint32 { return 1024 }
func (m *cut55Trie) KeySize() uint32 {
	if m.keySize == 0 {
		return 8
	}
	return m.keySize
}
func (m *cut55Trie) NextKey(cursor, out interface{}) error {
	keys := sortedMirrorKeys(m.rows)
	for _, key := range keys {
		if cursor == nil || key > string(cut55Bytes(cursor)) {
			*out.(*[]byte) = []byte(key)
			return nil
		}
	}
	return ebpf.ErrKeyNotExist
}
func (m *cut55Trie) Lookup(key, out interface{}) error {
	value, ok := m.rows[string(cut55Bytes(key))]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*out.(*uint32) = value
	return nil
}

type cut55Fixture struct {
	h        *Handlers
	tables   [2][4]*cut55Map
	configs  [2]*cut55Map
	selector *cut55Map
	tries    [4]*cut55Trie
	triesB   [4]*cut55Trie
	receipts int
}

func cut55Memory(t *testing.T) *cut55Fixture {
	t.Helper()
	f := &cut55Fixture{}
	for i := range f.tries {
		size := uint32(8)
		if i >= 2 {
			size = 20
		}
		f.tries[i] = &cut55Trie{rows: make(map[string]uint32), keySize: size}
		f.triesB[i] = &cut55Trie{rows: make(map[string]uint32), keySize: size}
	}
	h := &Handlers{rules: make(map[string]StoredRule), cidrRules: make(map[string]StoredCIDRRule), ruleKeyIndex: make(map[RuleKey]ruleIDSet), cidrRuleKeyIndex: make(map[CIDRRuleKey]ruleIDSet), logicalOwners: make(map[uint32]string)}
	h.cidrMgr = cidr.NewManager(f.tries[0], f.tries[1], f.tries[2], f.tries[3], f.triesB[0], f.triesB[1], f.triesB[2], f.triesB[3])
	f.h = h
	for slot := range f.tables {
		for kind := range f.tables[slot] {
			k, v := uint32(40), uint32(32)
			if kind%2 == 1 {
				k = 16
			}
			if kind >= 2 {
				v = 844
			}
			f.tables[slot][kind] = &cut55Map{rows: make(map[string][]byte), keySize: k, valueSize: v}
		}
	}
	for slot := range f.configs {
		f.configs[slot] = &cut55Map{rows: make(map[string][]byte), keySize: 4, valueSize: 8}
		for i := uint32(0); i < ConfigMapEntries; i++ {
			f.configs[slot].rows[string(cut55Bytes(i))] = make([]byte, 8)
		}
	}
	f.selector = &cut55Map{rows: map[string][]byte{string(cut55Bytes(uint32(0))): make([]byte, 8)}, keySize: 4, valueSize: 8}
	h.mirrorTableFixture = func(slot, kind int) ruleMirrorMap { return f.tables[slot][kind] }
	h.quiescer = cut5ReceiptFunc(func() error { f.receipts++; return nil })
	f.bindConfig()
	h.commitStageTestHook = func(stage string) {
		if stage == "c-7" {
			f.bindConfig()
		}
	}
	return f
}
func (f *cut55Fixture) bindConfig() {
	f.h.configPublishFixture = &configPublishTableSet{f.configs[1-f.h.activeSlot], f.configs[f.h.activeSlot], f.selector}
}
func cut55Rule(id string, logical uint32, ip string) Rule {
	return Rule{ID: id, LogicalID: logical, SrcIP: ip, Protocol: "tcp", Action: "drop"}
}
func cut55Group(t *testing.T, h *Handlers, key Rule, rules ...Rule) CommitGroup {
	t.Helper()
	g, err := h.classifyRuleKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	return CommitGroup{Key: b, Rules: rules}
}
func cut55Commit(t *testing.T, h *Handlers, groups ...CommitGroup) CommitResult {
	t.Helper()
	result, err := h.DoCommitRules(groups)
	if err != nil {
		t.Fatalf("commit: %+v", err)
	}
	return result
}
func cut55Snapshot(f *cut55Fixture, slot int) string {
	rows := [4]map[string]string{}
	for kind, table := range f.tables[slot] {
		rows[kind] = make(map[string]string)
		for key, value := range table.rows {
			rows[kind][fmt.Sprintf("%x", key)] = fmt.Sprintf("%x", value)
		}
	}
	b, err := json.Marshal(rows)
	if err != nil {
		panic(err)
	}
	return string(b)
}
func cut55Mirror(t *testing.T, f *cut55Fixture) {
	t.Helper()
	for kind := range f.tables[0] {
		if !reflect.DeepEqual(f.tables[0][kind].rows, f.tables[1][kind].rows) {
			t.Fatalf("G2 table %d differs", kind)
		}
	}
}
func cut55HTTP(t *testing.T, h *Handlers, groups []CommitGroup) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/commit", h.CommitRules)
	b, _ := json.Marshal(map[string]interface{}{"groups": groups})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/commit", bytes.NewReader(b)))
	return w
}

func TestCut55Contracts(t *testing.T) {
	f := cut55Memory(t)
	r := cut55Rule("a", 1, "192.0.2.1")
	ttl := "64"
	r.TTL = &ttl
	g := cut55Group(t, f.h, r, r)
	w := cut55HTTP(t, f.h, []CommitGroup{g})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cut53P3Golden(t, "commit_committed_p8", "created", w)
	if f.receipts != 2 {
		t.Fatalf("R0+Rc receipts=%d want=2", f.receipts)
	}
	cut55Mirror(t, f)
	before := f.receipts
	slot := f.h.activeRuleSlot.Load()
	w = cut55HTTP(t, f.h, []CommitGroup{g})
	cut53P3Golden(t, "commit_unchanged_p8", "replay", w)
	if strings.Contains(w.Body.String(), "receipt") || f.receipts != before || f.h.activeRuleSlot.Load() != slot {
		t.Fatal("H6 replay flipped or took a receipt")
	}
	// Same bytes and logical ID, only a different rule ID: identity delta.
	replacement := r
	replacement.ID = "b"
	result := cut55Commit(t, f.h, cut55Group(t, f.h, r, replacement))
	if result.Code != "committed" || result.Groups[0].Result != "replaced" {
		t.Fatal("H6 identity-only change was not committed")
	}
	if _, ok := f.h.rules["a"]; ok {
		t.Fatal("old identity survived")
	}
	if _, ok := f.h.rules["b"]; !ok {
		t.Fatal("new identity missing")
	}
	if f.receipts != before+1 {
		t.Fatalf("confirmed commit must reuse Rc for reclamation, got %d", f.receipts-before)
	}
	cut55Mirror(t, f)
	// Undeclared U is unchanged through moves, narrowing, and pure/condition transitions.
	u := cut55Rule("u", 7, "198.51.100.7")
	cut55Commit(t, f.h, cut55Group(t, f.h, u, u))
	uk, _ := f.h.ruleToKey(u)
	urow := append([]byte(nil), f.tables[int(f.h.activeRuleSlot.Load())][0].rows[string(ruleKeyToBytes(uk))]...)
	moved := replacement
	moved.SrcIP = "203.0.113.1"
	moved.TTL = nil
	result = cut55Commit(t, f.h, cut55Group(t, f.h, r), cut55Group(t, f.h, moved, moved))
	if result.Groups[0].Result != "deleted" || result.Groups[1].Result != "created" {
		t.Fatal(result)
	}
	if !bytes.Equal(urow, f.tables[int(f.h.activeRuleSlot.Load())][0].rows[string(ruleKeyToBytes(uk))]) {
		t.Fatal("H3 undeclared row changed")
	}
	cut55Mirror(t, f)
	moved.TTL = &ttl
	cut55Commit(t, f.h, cut55Group(t, f.h, moved, moved))
	cut55Mirror(t, f)
	t.Log("CUT55_CONTRACT h1=1 h2=1 h3=1 h4=1 h5=1 h6=1 identity_only=1 replay_receipts=0 transitions=4")
}

func TestCut55Rejects(t *testing.T) {
	for _, name := range []string{"key", "empty_id", "zero_id", "key_mismatch", "duplicate_key", "duplicate_id", "duplicate_logical_id", "group_undeclared", "content_different", "cidr_overlap", "condition_capacity", "dead", "anomaly"} {
		t.Run(name, func(t *testing.T) {
			f := cut55Memory(t)
			r := cut55Rule("a", 1, "192.0.2.1")
			cut55Commit(t, f.h, cut55Group(t, f.h, r, r))
			groups := []CommitGroup{cut55Group(t, f.h, r, r)}
			code := mutationInvalid
			switch name {
			case "key":
				groups[0].Key = []byte(`{"kind":"exact","src_ip":"192.0.2.1","protocol":"TCP","src_port":0,"dst_port":0}`)
			case "empty_id":
				groups[0].Rules[0].ID = ""
			case "zero_id":
				groups[0].Rules[0].LogicalID = 0
			case "key_mismatch":
				groups[0].Rules[0].SrcIP = "192.0.2.2"
			case "duplicate_key":
				groups = append(groups, groups[0])
			case "duplicate_id":
				groups[0].Rules = append(groups[0].Rules, r)
				code = "duplicate_id"
			case "duplicate_logical_id":
				b := cut55Rule("b", 1, "192.0.2.2")
				groups = []CommitGroup{cut55Group(t, f.h, b, b)}
				code = name
			case "group_undeclared":
				b := r
				b.SrcIP = "192.0.2.2"
				groups = []CommitGroup{cut55Group(t, f.h, b, b)}
				code = name
			case "content_different":
				groups[0].Rules[0].LogicalID = 2
				code = name
			case "cidr_overlap":
				c := Rule{ID: "c", LogicalID: 3, SrcCIDR: "198.51.100.0/24", Protocol: "tcp", Action: "drop"}
				cut55Commit(t, f.h, cut55Group(t, f.h, c, c))
				n := c
				n.ID = "n"
				n.LogicalID = 4
				n.SrcCIDR = "198.51.100.0/25"
				groups = []CommitGroup{cut55Group(t, f.h, c), cut55Group(t, f.h, n, n)}
				code = name
			case "condition_capacity":
				groups[0].Rules = nil
				for i := 0; i < 5; i++ {
					n := r
					n.ID = fmt.Sprint("n", i)
					n.LogicalID = uint32(20 + i)
					v := fmt.Sprint(60 + i)
					n.TTL = &v
					groups[0].Rules = append(groups[0].Rules, n)
				}
				code = name
			case "dead":
				v := "nonfirst"
				groups[0].Rules[0].Fragment = &v
				groups[0].Rules[0].TcpFlags = "SYN"
			case "anomaly":
				groups[0].Rules[0].MatchAnomaly = 128
			}
			before := cut55Snapshot(f, 0) + cut55Snapshot(f, 1)
			receipts := f.receipts
			slot := f.h.activeRuleSlot.Load()
			w := cut55HTTP(t, f.h, groups)
			var body map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["code"] != code {
				t.Fatalf("code=%v want=%s body=%s", body["code"], code, w.Body)
			}
			if w.Code != 400 && w.Code != 409 {
				t.Fatal(w.Code)
			}
			if before != cut55Snapshot(f, 0)+cut55Snapshot(f, 1) || receipts != f.receipts || slot != f.h.activeRuleSlot.Load() {
				t.Fatal("4xx changed maps, selector, or receipts")
			}
			if len(body["groups"].([]interface{})) == 0 {
				t.Fatal("4xx lacks indexed group errors")
			}
			if name == "key" {
				cut53P3Golden(t, "commit_validation_p8", "noncanonical_key", w)
			}
			if name == "condition_capacity" && !strings.Contains(w.Body.String(), "rule_ids") {
				t.Fatal("typed capacity error lost occupying rule IDs")
			}
			t.Logf("CUT55_REJECT case=%s code=%s zero_write=1", name, code)
		})
	}
}

func TestCut55DeferredAndFailures(t *testing.T) {
	for _, stage := range []string{"R0", "c-3", "c-4", "c-5", "c-6", "c-7", "Rc", "c-9"} {
		t.Run(stage, func(t *testing.T) {
			f := cut55Memory(t)
			r := Rule{ID: "c", LogicalID: 1, SrcCIDR: "192.0.2.0/24", Protocol: "tcp", Action: "drop"}
			cut55Commit(t, f.h, cut55Group(t, f.h, r, r))
			r.Action = "rate_limit"
			r.RateLimit = 100
			oldSlot := int(f.h.activeRuleSlot.Load())
			before := cut55Snapshot(f, oldSlot)
			f.h.commitFaultTestHook = func(s string) error {
				if s == stage {
					return errors.New("injected " + stage)
				}
				return nil
			}
			if stage == "R0" {
				f.h.quiescenceConfirmed = false
				f.h.quiescer = cut5ReceiptFunc(func() error { return errors.New("R0 injected") })
			}
			if stage == "Rc" {
				f.h.quiescer = cut5ReceiptFunc(func() error { return errors.New("Rc injected") })
			}
			w := cut55HTTP(t, f.h, []CommitGroup{cut55Group(t, f.h, r, r)})
			if stage == "Rc" || stage == "c-9" {
				if w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				if stage == "Rc" {
					cut53P3Golden(t, "commit_deferred_p8", "receipt_failed", w)
					if cut55Snapshot(f, oldSlot) != before {
						t.Fatal("Rc failure touched old side")
					}
				}
				if len(f.h.mirrorDebt[mirrorCIDR]) == 0 {
					t.Fatal("old-side debt missing")
				}
				f.h.quiescer = cut5ReceiptFunc(func() error { f.receipts++; return nil })
				f.h.commitFaultTestHook = nil
				u := cut55Rule("u", 7, "198.51.100.7")
				cut55Commit(t, f.h, cut55Group(t, f.h, u, u))
				cut55Mirror(t, f)
			} else {
				if w.Code != 500 {
					t.Fatal(w.Body.String())
				}
				if int(f.h.activeRuleSlot.Load()) != oldSlot || cut55Snapshot(f, oldSlot) != before {
					t.Fatal("preflip failure changed active generation")
				}
				if stage == "c-5" {
					cut53P3Golden(t, "commit_failed_p8", "shadow_config", w)
				}
			}
			t.Logf("CUT55_FAILURE stage=%s reached=1 status=%d", stage, w.Code)
		})
	}
}

func TestCut55MirrorPrimitive(t *testing.T) {
	for _, phase := range []string{"enumerate", "delete", "write"} {
		t.Run(phase, func(t *testing.T) {
			active := &cut55Map{rows: map[string][]byte{"a": {1}}, keySize: 1, valueSize: 1}
			shadow := &cut55Map{rows: map[string][]byte{"z": {2}}, keySize: 1, valueSize: 1}
			fault := errors.New(phase)
			switch phase {
			case "enumerate":
				active.enumerateErr = fault
			case "delete":
				shadow.deleteErr = fault
			case "write":
				shadow.updateErr = fault
			}
			if _, err := alignRuleTable(active, shadow); err == nil || !errors.Is(err, fault) {
				t.Fatalf("strict %s error was swallowed: %v", phase, err)
			}
			if phase == "enumerate" {
				if err := active.Update([]byte("b"), []byte{3}, ebpf.UpdateAny); err != nil {
					t.Fatal("iteration-only fixture also broke writes")
				}
			}
			active.enumerateErr, shadow.deleteErr, shadow.updateErr = nil, nil, nil
			if _, err := alignRuleTable(active, shadow); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(active.rows, shadow.rows) {
				t.Fatal("alignment not byte equal")
			}
			t.Logf("CUT55_MIRROR_PHASE phase=%s isolated=1 recovery=1", phase)
		})
	}
	f := cut55Memory(t)
	if f.h.mirrorReady {
		t.Fatal("literal fixture must start alignment pending")
	}
	f.tables[1][0].rows[string(make([]byte, 40))] = make([]byte, 32)
	r := cut55Rule("r", 1, "192.0.2.1")
	cut55Commit(t, f.h, cut55Group(t, f.h, r, r))
	cut55Mirror(t, f)
	if f.h.mirrorAlignments != 1 {
		t.Fatal("literal fixture did not take whole alignment")
	}
	t.Log("CUT55_LITERAL_PENDING fixtures=1 alignment=1")
}

func TestCut55TableCapacity(t *testing.T) {
	for kind := 0; kind < 4; kind++ {
		t.Run(mirrorNames[kind], func(t *testing.T) {
			f := cut55Memory(t)
			f.h.commitTableCapacity[kind] = 1
			var groups []CommitGroup
			for i := 0; i < 2; i++ {
				r := cut55Rule(fmt.Sprint("r", i), uint32(i+1), fmt.Sprintf("192.0.2.%d", i+1))
				if kind%2 == 1 {
					r.SrcIP = ""
					r.SrcCIDR = fmt.Sprintf("10.55.%d.0/24", i)
				}
				if kind >= 2 {
					v := "64"
					r.TTL = &v
				}
				groups = append(groups, cut55Group(t, f.h, r, r))
			}
			_, err := f.h.DoCommitRules(groups)
			if err == nil || err.Code != "table_full" || err.Groups[0].Table != mirrorNames[kind] {
				t.Fatalf("capacity error=%+v", err)
			}
			if f.receipts != 0 {
				t.Fatal("table full paid receipt")
			}
			t.Logf("CUT55_TABLE_FULL table=%s excess=1", mirrorNames[kind])
		})
	}

}

func TestCut55DirtyAndDebt(t *testing.T) {
	for _, debt := range []string{"dirty", "whole", "old"} {
		t.Run(debt, func(t *testing.T) {
			f := cut55Memory(t)
			r := cut55Rule("u", 17, "192.0.2.1")
			cut55Commit(t, f.h, cut55Group(t, f.h, r, r))
			if !f.h.mirrorReady {
				t.Fatal("dirty witness masked by initial whole alignment")
			}
			slot := int(f.h.activeRuleSlot.Load())
			key, _ := f.h.ruleToKey(r)
			wireKey := string(ruleKeyToBytes(key))
			switch debt {
			case "dirty":
				f.tables[slot][0].rows[wireKey][4] = 7
				f.h.markMirrorDirty(0, []byte(wireKey))
			case "whole":
				delete(f.tables[1-slot][0].rows, wireKey)
				f.h.mirrorReady = false
			case "old":
				f.h.quiescer = cut5ReceiptFunc(func() error { return errors.New("Rc") })
				r.RateLimit = 7
				result := cut55Commit(t, f.h, cut55Group(t, f.h, r, r))
				if result.Receipt != "deferred" {
					t.Fatal(result)
				}
				f.h.quiescer = cut5ReceiptFunc(func() error { f.receipts++; return nil })
			}
			reached := false
			bind := f.h.commitStageTestHook
			f.h.commitStageTestHook = func(stage string) {
				bind(stage)
				if stage == "c-3" {
					reached = true
					cut55Mirror(t, f)
				}
			}
			n := cut55Rule("n", 18, "203.0.113.18")
			cut55Commit(t, f.h, cut55Group(t, f.h, n, n))
			if !reached {
				t.Fatal("catch-up stage not reached")
			}
			cut55Mirror(t, f)
			t.Logf("CUT55_DEBT kind=%s caught_up_before_delta=1", debt)
		})
	}
}

func TestCut55LogicalAdmissionReceiptFailure(t *testing.T) {
	f := cut55Memory(t)
	r := cut55Rule("r", 17, "192.0.2.1")
	cut55Commit(t, f.h, cut55Group(t, f.h, r, r))
	f.h.logicalStateCapacity = 1
	f.h.pendingLogicalIDs = map[uint32]bool{19: true}
	f.h.quiescer = cut5ReceiptFunc(func() error { return errors.New("payment receipt") })
	before := cut55Snapshot(f, 0) + cut55Snapshot(f, 1)
	n := cut55Rule("n", 18, "203.0.113.18")
	_, err := f.h.DoCommitRules([]CommitGroup{cut55Group(t, f.h, n, n)})
	if err == nil || err.Code != "table_full" || !f.h.pendingLogicalIDs[19] {
		t.Fatal("M5b receipt failure lost debt or admitted", err)
	}
	if before != cut55Snapshot(f, 0)+cut55Snapshot(f, 1) {
		t.Fatal("M5b rejection wrote business maps")
	}
	t.Log("CUT55_FAILURE_ROW9A receipt_failure=1 debt_retained=1 business_writes=0")
}

func TestCut55FailureRow9BRegression(t *testing.T) {
	TestCut53PublishEveryFailure(t)
	t.Log("CUT55_FAILURE_ROW9B existing_copy_failure_matrix=1 regression=1")
}
func TestCut55FailureRow9CRegression(t *testing.T) {
	TestCut53StartupFaultMatrix(t)
	TestCut53StartupReceiptCreationFailure(t)
	t.Log("CUT55_FAILURE_ROW9C startup_failure_matrix=1 creation_failure=1 regression=1")
}
