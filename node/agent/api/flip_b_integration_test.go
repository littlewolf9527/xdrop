//go:build linux && integration

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// MB-6/7/8: commit seeds both K copies; no mutated atomic runs before the witness.
func TestFlipBReceiptDeltaELF(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		name := "known"
		if unknown {
			name = "unknown"
		}
		t.Run(name, func(t *testing.T) {
			h, _, _, coll := flipFixture(t)
			var ws []*dingTrie
			h.cidrMgr, ws = cut53WrapTries(coll)
			old, next := prefixABRule(1), prefixABRule(2)
			if result := cut55Commit(t, h, cut55Group(t, h, old, old)); result.Receipt != "confirmed" {
				t.Fatal("K seed receipt")
			}
			for slot := 0; slot < 2; slot++ {
				if !reflect.ValueOf(h.cidrMgr).Elem().FieldByName("known").Index(slot).Bool() {
					t.Fatal("K seed missing")
				}
				if unknown {
					h.cidrMgr.Invalidate(slot)
				}
			}
			active := int(h.activeRuleSlot.Load())
			oldBytes := b7Snapshot(t, ws[4*active].table)
			puts, deletes := ws[4*active].puts, ws[4*active].deletes
			restore := flipBReceipt(t, h, func() error {
				t.Log("MB_GUARD id=MB-7 R5c_entry=1 selector_flipped=1")
				if !reflect.DeepEqual(oldBytes, b7Snapshot(t, ws[4*active].table)) || ws[4*active].puts != puts || ws[4*active].deletes != deletes {
					t.Error("MB-7 old trie changed before R5c")
				}
				return nil
			})
			result, err := h.DoAtomicSync([]Rule{next})
			restore()
			if err != nil || result.Added != 1 || !h.quiescenceConfirmed {
				t.Fatal("receipt/delta execution guard", result, err)
			}
			t.Logf("MB_GUARD id=MB-6 R5c_success=1 delta_nonzero=1 old_rows=%d", len(oldBytes))
			t.Logf("MB_GUARD id=MB-8 known=%v old_P=1 new_Q=1", !unknown)
			for slot := 0; slot < 2; slot++ {
				prefixABAssert(t, h, coll, slot)
			}
		})
	}
}

// MB-9: old-side orphan rows exist independently of the logical indexes, in all four tables.
func TestFlipBOldOrphansELF(t *testing.T) {
	h, _, _, _ := flipFixture(t)
	old := cut55Rule("old", 1, "192.0.2.1")
	cut55Commit(t, h, cut55Group(t, h, old, old))
	active := int(h.activeRuleSlot.Load())
	for kind := 0; kind < 4; kind++ {
		m := h.mirrorTable(active, kind)
		key := make([]byte, m.KeySize())
		copy(key, []byte{0x20, 1, 0x0d, 0xb8})
		value := make([]byte, m.ValueSize())
		value[0] = 1
		if err := m.Update(key, value, 0); err != nil {
			t.Fatal(err)
		}
	}
	a := cut55Rule("a", 2, "192.0.2.2")
	a.TTL = cut4BString("64")
	c := Rule{ID: "c", LogicalID: 3, SrcCIDR: "198.51.100.0/24", Action: "drop", TTL: cut4BString("64")}
	result, err := h.DoAtomicSync([]Rule{a, c})
	if err != nil || result.Added != 2 || !h.quiescenceConfirmed {
		t.Fatal("old-orphan receipt guard", result, err)
	}
	t.Log("MB_GUARD id=MB-9 old_orphans=4 R5c_success=1")
	cut55KernelMirror(t, h)
	if !h.mirrorReady || !h.ruleRowCountsKnown || h.ruleRowCounts != [4]int{1, 1, 1, 1} || h.mirrorFailures != 0 {
		t.Fatal("Step 6 physical counts/readiness differ")
	}
}

// PLAN §五-2: twenty real HTTP reads overlap one full-load atomic; target misses are recorded.
func TestFlipBStatsConcurrentELF(t *testing.T) {
	defer flipQuiet()()
	h, r, _, coll := flipFixture(t)
	server := httptest.NewServer(r)
	defer server.Close()
	body, err := json.Marshal(map[string]any{"rules": flipScaleRules(50000, "F", false)})
	if err != nil {
		t.Fatal(err)
	}
	atomicClient, statsClient := *server.Client(), *server.Client()
	atomicClient.Timeout = 120 * time.Minute
	statsClient.Timeout = 10 * time.Second
	started := make(chan struct{})
	atomicStageTestHook = func(stage string, owner *Handlers) {
		if stage == "1" && owner == h {
			close(started)
		}
	}
	defer func() { atomicStageTestHook = nil }()
	type reading struct {
		start, end time.Time
		status     int
		err        error
	}
	finished := make(chan reading, 1)
	go func() {
		x := reading{start: time.Now()}
		response, e := atomicClient.Post(server.URL+"/api/v1/sync/atomic", "application/json", bytes.NewReader(body))
		x.err = e
		if e == nil {
			x.status = response.StatusCode
			var result struct{ Added, Failed int }
			x.err = json.NewDecoder(response.Body).Decode(&result)
			response.Body.Close()
			if result.Added != 500000 || result.Failed != 0 {
				x.err = fmt.Errorf("invalid full-load atomic counts: %+v", result)
			}
		}
		x.end = time.Now()
		finished <- x
	}()
	select {
	case <-started:
	case x := <-finished:
		t.Fatal("atomic ended before overlap window", x)
	case <-time.After(2 * time.Minute):
		t.Fatal("atomic start timeout")
	}
	samples := make(chan reading, 20)
	for i := 0; i < 20; i++ {
		go func() {
			x := reading{start: time.Now()}
			response, e := statsClient.Get(server.URL + "/api/v1/stats")
			x.err = e
			if e == nil {
				x.status = response.StatusCode
				_, x.err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
			x.end = time.Now()
			samples <- x
		}()
	}
	var reads []reading
	for i := 0; i < 20; i++ {
		reads = append(reads, <-samples)
	}
	operation := <-finished
	if operation.err != nil || operation.status != 200 {
		t.Fatal("full-load atomic failed", operation.status, operation.err)
	}
	t.Logf("STATS_ATOMIC start_ns=%d end_ns=%d", operation.start.UnixNano(), operation.end.UnixNano())
	overlap := 0
	maxMS := 0.0
	for i, x := range reads {
		ms := float64(x.end.Sub(x.start)) / float64(time.Millisecond)
		maxMS = max(maxMS, ms)
		if x.start.Before(operation.end) && x.end.After(operation.start) {
			overlap++
		}
		t.Logf("STATS_SAMPLE request=%d start_ns=%d end_ns=%d http=%d ms=%.3f", i, x.start.UnixNano(), x.end.UnixNano(), x.status, ms)
		if x.err != nil || x.status != 200 {
			t.Errorf("stats request invalid: status=%d error=%v", x.status, x.err)
		}
	}
	if overlap < 20 {
		t.Errorf("stats overlap=%d want>=20", overlap)
	}
	slot := flipSelector(t, coll)
	if len(flipKeys(t, coll.Maps[[]string{"blacklist", "blacklist_b"}[slot]])) != 400000 || len(flipKeys(t, coll.Maps[[]string{"cidr_blacklist", "cidr_blist_b"}[slot]])) != 100000 {
		t.Fatal("full-load actual rule count guard")
	}
	for _, m := range flipTries(coll, slot) {
		if len(flipKeys(t, m)) != 50000 {
			t.Fatal("full-load actual prefix count guard")
		}
	}
	t.Logf("STATS_TARGET requests=%d overlap=%d max_ms=%.3f limit_ms=200 met=%d", len(reads), overlap, maxMS, flipBool(maxMS <= 200))
}
