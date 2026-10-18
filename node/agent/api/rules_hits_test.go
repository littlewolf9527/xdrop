package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
)

func nsHitsFixture(n int) (*Handlers, *time.Time, *int) {
	now, calls, offset := time.Unix(100, 0), 0, 0
	h := &Handlers{logicalOwners: map[uint32]string{}}
	for i := 1; i <= n; i++ {
		h.logicalOwners[uint32(i)] = fmt.Sprintf("rule-%d", i)
	}
	h.hits.wall = func() time.Time { return now }
	h.hits.clock = func() (uint64, error) { return 1000, nil }
	h.hits.values = make([]LogicalRuleCounters, 2)
	h.hits.lookup = func(_ *ebpf.MapBatchCursor, keys []uint32, values []uint64) (int, error) {
		calls++
		count := min(n-offset, len(keys))
		for i := 0; i < count; i++ {
			id := uint32(offset + i + 1)
			keys[i] = id
			values[i] = 200
		}
		offset += count
		if offset == n {
			offset = 0
			return count, ebpf.ErrKeyNotExist
		}
		return count, nil
	}
	h.hits.read = func(id uint32, values []LogicalRuleCounters) error {
		values[0] = LogicalRuleCounters{2, uint64(id), 180, 90 * uint64(id), 100}
		values[1] = LogicalRuleCounters{3, uint64(id), 270, 90 * uint64(id), 200}
		return nil
	}
	h.hits.bucket.clock = func() time.Time { return now }
	return h, &now, &calls
}

func nsHitsRead(t *testing.T, h *Handlers, since uint64) HitsResponse {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", fmt.Sprintf("/rules/hits?since_ns=%d", since), nil)
	h.Hits(c)
	if w.Code != 200 {
		t.Fatalf("NS_CELL class=behavior name=HTTP status=%d body=%s pass=false", w.Code, w.Body.String())
	}
	var r HitsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNSHits(t *testing.T) {
	h, now, calls := nsHitsFixture(3)
	h.logicalOwners[4] = "never-hit"
	h.lastRuleDropCount = map[string]uint64{"sentinel": 771}
	h.lastRuleStatsTime = map[string]int64{"sentinel": 882}
	h.lastStats, h.lastStatsTime = [6]uint64{11, 22, 33, 44, 55, 66}, 993
	baseline := func() []byte {
		b, _ := json.Marshal([]any{h.lastRuleDropCount, h.lastRuleStatsTime, h.lastStats, h.lastStatsTime})
		return b
	}
	before := baseline()
	for _, path := range []string{"cold", "hot"} {
		t.Run(path, func(t *testing.T) {
			r := nsHitsRead(t, h, 150)
			t.Logf("NS_CELL class=behavior name=window path=%s rows=%d returned=%d truncated=%t pass=%t", path, r.Scanned, len(r.Hits), r.Truncated, r.Scanned == 3 && len(r.Hits) == 3 && !r.Truncated)
			if r.Truncated || r.Scanned != 3 || r.NowNS != 1000 || len(r.Hits) != 3 {
				t.Fatal(r)
			}
			for _, v := range r.Hits {
				if v.LastHitNS != 200 || v.MatchCount != 5 || v.MatchBytes != 450 || v.DropBytes != v.DropCount*90 || v.RuleID != h.logicalOwners[v.LogicalID] {
					t.Fatal(v)
				}
			}
			empty := nsHitsRead(t, h, 201)
			t.Logf("NS_CELL class=behavior name=empty_complete path=%s returned=%d truncated=%t pass=%t", path, len(empty.Hits), empty.Truncated, !empty.Truncated && len(empty.Hits) == 0)
			if empty.Truncated || len(empty.Hits) != 0 {
				t.Fatal(empty)
			}
			same := reflect.DeepEqual(r, nsHitsRead(t, h, 150))
			t.Logf("NS_CELL class=behavior name=no_traffic path=%s equal=%t pass=%t", path, same, same)
			if !same {
				t.Fatal("no-traffic counters changed")
			}
			if !bytes.Equal(before, baseline()) {
				t.Fatal("shared rate baseline modified")
			}
			t.Logf("NS_CELL class=behavior name=baseline path=%s unchanged=%t pass=%t", path, bytes.Equal(before, baseline()), bytes.Equal(before, baseline()))
		})
	}
	t.Logf("NS_CELL class=behavior name=cache calls=%d pass=%t", *calls, *calls == 1)
	if *calls != 1 {
		t.Fatal("cache rescanned", *calls)
	}
	delete(h.logicalOwners, 2)
	retired := 0
	for _, r := range nsHitsRead(t, h, 0).Hits {
		if r.LogicalID == 2 {
			retired++
		}
	}
	t.Logf("NS_CELL class=behavior name=retired leaked=%d pass=%t", retired, retired == 0)
	if retired != 0 {
		t.Fatal("retired owner leaked")
	}
	*now = now.Add(2 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.hitsJSON(0); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	t.Logf("NS_CELL class=behavior name=single_flight callers=50 calls=%d pass=%t", *calls, *calls == 2)
	if *calls != 2 {
		t.Fatal("single-flight", *calls)
	}
}

func TestNSHitsReclaimedReuse(t *testing.T) {
	for _, mode := range []string{"deleted", "missing", "rebuilt-owner", "atomic-sync", "orphan"} {
		t.Run(mode, func(t *testing.T) {
			h, now, calls := nsHitsFixture(2)
			h.logicalOwners[1] = "old-rule"
			h.logicalReclaimSeq = 7
			first := nsHitsRead(t, h, 0)
			if len(first.Hits) != 2 || first.Hits[1].RuleID != "old-rule" {
				t.Fatal(first)
			}
			counts, rates := cut54StateMaps()
			if mode != "missing" && mode != "atomic-sync" {
				counts.keys[1] = true
			}
			rates.keys[1] = mode != "missing"
			h.quiescer = cut53Receipt(func() error { return nil })
			reclaimed := mode != "rebuilt-owner"
			func() {
				h.syncMu.Lock()
				defer h.syncMu.Unlock()
				h.publishMu.Lock()
				defer h.publishMu.Unlock()
				h.rulesMu.Lock()
				if mode == "atomic-sync" || mode == "orphan" {
					if mode == "orphan" {
						h.forgetLogicalIDLocked("old-rule", 1)
					}
					next := map[string]StoredRule{"rule-2": {LogicalID: 2}}
					h.replaceLogicalOwnersLocked(next, nil)
					h.rulesMu.Unlock()
					if h.pendingLogicalIDs[1] != (mode == "atomic-sync") {
						t.Fatal("pending/orphan fixture", h.pendingLogicalIDs)
					}
					if err := h.awaitQuiescence(); err != nil {
						t.Fatal(err)
					}
					deleted, err := reconcileLogicalKeysDeleted(cut54OrphanKeys{counts}, map[uint32]bool{2: true})
					wantDeleted := 0 // Missing authority row isolates the pending-drain branch.
					if mode == "orphan" {
						wantDeleted = 1
					}
					if err != nil || len(deleted) != wantDeleted || counts.keys[1] {
						t.Fatal("reconciliation fixture", deleted, err, counts.keys)
					}
					h.finishLogicalReconcileLocked(deleted, err)
					h.rulesMu.Lock()
					next["new-rule"] = StoredRule{LogicalID: 1}
					h.replaceLogicalOwnersLocked(next, nil)
					h.rulesMu.Unlock()
					return
				}
				defer h.rulesMu.Unlock()
				h.retireLogicalIDLocked("old-rule", 1)
				if !reclaimed {
					h.rememberLogicalIDLocked("old-rule", 1)
				}
				if err := h.payPendingLogicalWithMapsLocked(counts, rates); err != nil {
					t.Fatal(err)
				}
				if reclaimed {
					h.rememberLogicalIDLocked("new-rule", 1)
				}
			}()
			wantSeq, wantStamp, wantRows := uint64(7), uint64(0), 2
			if reclaimed {
				wantSeq, wantStamp, wantRows = 8, 8, 1
			}
			read := h.hits.read
			h.hits.read = func(id uint32, values []LogicalRuleCounters) error {
				if reclaimed && id == 1 {
					return ebpf.ErrKeyNotExist
				}
				return read(id, values)
			}
			got := nsHitsRead(t, h, 0)
			pass := len(got.Hits) == wantRows && !got.Truncated && *calls == 1 && got.Hits[0] == first.Hits[0]
			if !reclaimed {
				pass = pass && reflect.DeepEqual(got, first) && counts.deletes+rates.deletes == 0
			}
			t.Logf("NS_CELL class=behavior name=reclaimed_reuse mode=%s seq=%d stamp=%d scan_calls=%d returned=%d pass=%t", mode, h.logicalReclaimSeq, h.logicalReclaimedAt[1], *calls, len(got.Hits), pass)
			if !pass {
				t.Fatalf("cached owner reuse: %+v", got)
			}
			if h.logicalReclaimSeq != wantSeq || h.logicalReclaimedAt[1] != wantStamp || h.pendingLogicalIDs[1] {
				t.Fatal("reclamation receipt", h.logicalReclaimSeq, h.logicalReclaimedAt, h.pendingLogicalIDs)
			}
			h.hits.read = read
			*now = now.Add(2 * time.Second)
			fresh := nsHitsRead(t, h, 0)
			if len(fresh.Hits) != 2 || fresh.Hits[1].RuleID != h.logicalOwners[1] || *calls != 2 {
				t.Fatal("new scan did not restore the current owner", fresh, *calls)
			}
		})
	}
}

func TestNSHitsTruncationAndErrors(t *testing.T) {
	h, _, _ := nsHitsFixture(10003)
	r := nsHitsRead(t, h, 0)
	t.Logf("NS_CELL class=behavior name=truncate rows=%d returned=%d truncated=%t pass=%t", r.Scanned, len(r.Hits), r.Truncated, r.Scanned == 10003 && len(r.Hits) == 10000 && r.Truncated)
	if !r.Truncated || len(r.Hits) != 10000 || r.Scanned != 10003 {
		t.Fatal(r.Truncated, len(r.Hits), r.Scanned)
	}
	for _, path := range []string{"cold", "hot"} {
		if path == "hot" {
			r = nsHitsRead(t, h, 0)
		}
		wrong := 0
		for i, v := range r.Hits {
			if v.LogicalID != uint32(10003-i) {
				wrong++
			}
		}
		pass := wrong == 0 && r.Truncated && len(r.Hits) == 10000
		t.Logf("NS_CELL class=behavior name=retained_IDs path=%s wrong=%d returned=%d pass=%t", path, wrong, len(r.Hits), pass)
		if !pass {
			t.Fatal("wrong retained ID set", wrong)
		}
	}
	previous, err := h.hitsJSON(0)
	if err != nil {
		t.Fatal(err)
	}
	frozen := bytes.Clone(previous)
	for id := uint32(1); id <= 3; id++ {
		delete(h.logicalOwners, id)
	}
	r = nsHitsRead(t, h, 0)
	pass := len(r.Hits) == 10000 && r.Truncated && bytes.Equal(previous, frozen)
	t.Logf("NS_CELL class=behavior name=retired_boundary returned=%d truncated=%t old_bytes_immutable=%t pass=%t", len(r.Hits), r.Truncated, bytes.Equal(previous, frozen), pass)
	if !pass {
		t.Fatal("cached encoding after owner reclamation")
	}
	t.Run("occupancy-empty-window", func(t *testing.T) {
		h, _, _ := nsHitsFixture(8192)
		for _, path := range []string{"cold", "hot"} {
			r := nsHitsRead(t, h, 201)
			pass := r.Scanned == 8192 && len(r.Hits) == 0 && r.Truncated
			t.Logf("NS_CELL class=behavior name=empty_occupancy path=%s rows=%d returned=%d truncated=%t pass=%t", path, r.Scanned, len(r.Hits), r.Truncated, pass)
			if !pass {
				t.Fatal(r)
			}
		}
	})
	for _, err := range []error{syscall.ENOSPC, syscall.EIO} {
		t.Run(err.Error(), func(t *testing.T) {
			h, _, _ := nsHitsFixture(1)
			h.hits.lookup = func(*ebpf.MapBatchCursor, []uint32, []uint64) (int, error) { return 0, err }
			_, e := h.hitsJSON(0)
			t.Logf("NS_CELL class=behavior name=batch_error error=%q matched=%t pass=%t", err, errors.Is(e, err), errors.Is(e, err))
			if !errors.Is(e, err) {
				t.Fatal("batch error hidden", e)
			}
		})
	}
	var output bytes.Buffer
	old := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(old)
	h, now, _ := nsHitsFixture(1)
	nsHitsRead(t, h, 0)
	nsHitsRead(t, h, 0)
	*now = now.Add(2 * time.Second)
	nsHitsRead(t, h, 0)
	n := strings.Count(output.String(), "hits_scan rows=1 ")
	t.Logf("NS_CELL class=behavior name=scan_execution calls=3 logs=%d pass=%t", n, n == 2)
	if n != 2 {
		t.Fatal("independent scan execution", output.String())
	}
}

func TestNSHitsHTTP(t *testing.T) {
	for _, query := range []string{"", "?since_ns=-1", "?since_ns=18446744073709551616", "?since_ns=0"} {
		h, _, _ := nsHitsFixture(0)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/rules/hits"+query, nil)
		h.Hits(c)
		want := 400
		if query == "?since_ns=0" {
			want = 200
		}
		t.Logf("NS_CELL class=behavior name=HTTP_query query=%q status=%d want=%d pass=%t", query, w.Code, want, w.Code == want && (want != 200 || strings.Contains(w.Body.String(), `"hits":[]`)))
		if w.Code != want {
			t.Fatal(query, w.Code, w.Body.String())
		}
		if want == 200 && !strings.Contains(w.Body.String(), `"hits":[]`) {
			t.Fatal(w.Body.String())
		}
	}
}

func TestNSHitsAuthority(t *testing.T) {
	h, _, _ := nsHitsFixture(4)
	read := h.hits.read
	h.hits.read = func(id uint32, v []LogicalRuleCounters) error {
		if id == 1 {
			return ebpf.ErrKeyNotExist
		}
		if err := read(id, v); err != nil {
			return err
		}
		if id == 2 {
			v[0].LastHitNS, v[1].LastHitNS = 40, 50
		}
		if id == 3 {
			v[0].LastHitNS, v[1].LastHitNS = 100, 100
		}
		return nil
	}
	for _, since := range []uint64{150, 75} {
		r := nsHitsRead(t, h, since)
		want := 1
		if since == 75 {
			want = 2
		}
		pass := len(r.Hits) == want && r.Scanned == 4
		for _, hit := range r.Hits {
			pass = pass && hit.LogicalID >= 3
		}
		t.Logf("NS_CELL class=behavior name=authority_narrow_wide since=%d returned=%d pass=%t", since, len(r.Hits), pass)
		if !pass {
			t.Fatal(r)
		}
	}
	for _, e := range []error{syscall.ENOSPC, syscall.EIO} {
		h, _, _ := nsHitsFixture(1)
		h.hits.read = func(uint32, []LogicalRuleCounters) error { return e }
		if _, err := h.hitsJSON(0); !errors.Is(err, e) {
			t.Fatal("single lookup error hidden", err)
		}
	}
}

func TestNSHitsRateLimit(t *testing.T) {
	for _, rate := range []int{20, 5} {
		h, now, calls := nsHitsFixture(1)
		h.SetHits(nil, rate)
		reads := 0
		read := h.hits.read
		h.hits.read = func(id uint32, v []LogicalRuleCounters) error { reads++; return read(id, v) }
		request := func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/rules/hits?since_ns=0", nil)
			h.Hits(c)
			return w
		}
		for i := 0; i < rate; i++ {
			if w := request(); w.Code != 200 {
				t.Fatal(i, w.Code)
			}
		}
		*calls, reads = 0, 0
		w := request()
		pass := w.Code == 429 && w.Header().Get("Retry-After") == "1" && w.Body.String() == `{"error":"rate_limited"}` && *calls == 0 && reads == 0
		t.Logf("NS_CELL class=behavior name=rate_limit rate=%d status=%d batch_reads=%d counter_reads=%d pass=%t", rate, w.Code, *calls, reads, pass)
		if !pass {
			t.Fatal(w.Code, w.Body.String())
		}
		*now = now.Add(time.Second / time.Duration(rate))
		if w := request(); w.Code != 200 {
			t.Fatal("no refill", w.Code)
		}
		if w := request(); w.Code != 429 {
			t.Fatal("excess refill", w.Code)
		}
	}
}
