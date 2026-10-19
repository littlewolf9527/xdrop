package api

import (
	"fmt"
	"maps"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// Exercise the real ledger transitions with only the in-memory state maps.
func hcB06Reclaim(t *testing.T, h *Handlers, first, last uint32, newOwner string) {
	t.Helper()
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	h.publishMu.Lock()
	defer h.publishMu.Unlock()
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	counts, rates := cut54StateMaps()
	for id := first; id <= last; id++ {
		owner, exists := h.logicalOwners[id]
		if !exists {
			owner = fmt.Sprintf("retired-%d", id)
			h.rememberLogicalIDLocked(owner, id)
		}
		counts.keys[id], rates.keys[id] = true, true
		h.retireLogicalIDLocked(owner, id)
	}
	if err := h.payPendingLogicalWithMapsLocked(counts, rates); err != nil {
		t.Fatal(err)
	}
	if len(counts.keys) != 0 || len(rates.keys) != 0 || len(h.pendingLogicalIDs) != 0 {
		t.Fatal("ledger fixture did not reclaim every retired ID")
	}
	if newOwner != "" {
		h.rememberLogicalIDLocked(newOwner, first)
	}
}

func TestHCB06G6ReclaimShrink(t *testing.T) {
	h, now, calls := nsHitsFixture(0)
	h.quiescer = cut53Receipt(func() error { return nil })
	nsHitsRead(t, h, 0)
	t.Run("initial_64", func(t *testing.T) {
		hcB06Reclaim(t, h, 1, 64, "")
		if len(h.logicalReclaimedAt) != 64 || h.logicalReclaimSeq != 64 {
			t.Errorf("reclaims=%d seq=%d want=64/64", len(h.logicalReclaimedAt), h.logicalReclaimSeq)
		}
	})
	t.Run("refresh_clears_64", func(t *testing.T) {
		*now = now.Add(3 * time.Second)
		nsHitsRead(t, h, 0)
		if len(h.logicalReclaimedAt) != 0 || h.logicalReclaimSeq != 64 || *calls != 2 {
			t.Errorf("reclaims=%d seq=%d scans=%d want=0/64/2", len(h.logicalReclaimedAt), h.logicalReclaimSeq, *calls)
		}
	})
	t.Run("cached_keeps_one", func(t *testing.T) {
		hcB06Reclaim(t, h, 65, 65, "")
		nsHitsRead(t, h, 0)
		if len(h.logicalReclaimedAt) != 1 || h.logicalReclaimedAt[65] != 65 || *calls != 2 {
			t.Errorf("reclaims=%v scans=%d want only ID 65, stamp 65, scans 2", h.logicalReclaimedAt, *calls)
		}
	})
	t.Run("next_refresh_clears_one", func(t *testing.T) {
		*now = now.Add(3 * time.Second)
		nsHitsRead(t, h, 0)
		if len(h.logicalReclaimedAt) != 0 || h.logicalReclaimSeq != 65 || *calls != 3 {
			t.Errorf("reclaims=%d seq=%d scans=%d want=0/65/3", len(h.logicalReclaimedAt), h.logicalReclaimSeq, *calls)
		}
	})
}

func TestHCB06G7ReclaimDuringScan(t *testing.T) {
	h, now, _ := nsHitsFixture(1)
	h.logicalOwners[1] = "old-rule"
	h.quiescer = cut53Receipt(func() error { return nil })
	lookup, reclaimed := h.hits.lookup, false
	h.hits.lookup = func(cursor *ebpf.MapBatchCursor, keys []uint32, values []uint64) (int, error) {
		if !reclaimed {
			reclaimed = true
			hcB06Reclaim(t, h, 1, 1, "new-rule")
		}
		return lookup(cursor, keys, values)
	}
	t.Run("scan_skips_reused_id", func(t *testing.T) {
		r := nsHitsRead(t, h, 0)
		if !reclaimed || len(r.Hits) != 0 || h.logicalReclaimedAt[1] == 0 || h.logicalReclaimedAt[1] <= h.hits.reclaimSeq {
			t.Errorf("scan returned reused ID or lost reclaim: reply=%+v stamp=%d S=%d", r, h.logicalReclaimedAt[1], h.hits.reclaimSeq)
		}
	})
	t.Run("next_snapshot_uses_new_owner", func(t *testing.T) {
		*now = now.Add(3 * time.Second)
		r := nsHitsRead(t, h, 0)
		if len(r.Hits) != 1 || r.Hits[0].LogicalID != 1 || r.Hits[0].RuleID != "new-rule" || len(h.logicalReclaimedAt) != 0 {
			t.Errorf("new snapshot=%+v reclaims=%v", r, h.logicalReclaimedAt)
		}
	})
}

func hcB06SeedPPS(h *Handlers, ids ...string) {
	h.rulePPSMu.Lock()
	defer h.rulePPSMu.Unlock()
	h.lastRuleDropCount = map[string]uint64{"sentinel": 900}
	h.lastRuleStatsTime = map[string]int64{"sentinel": 901}
	for i, id := range ids {
		h.lastRuleDropCount[id] = uint64(100 + i)
		h.lastRuleStatsTime[id] = int64(200 + i)
	}
}

func hcB06PPS(t *testing.T, h *Handlers, counts map[string]uint64, times map[string]int64, ids ...string) {
	t.Helper()
	h.rulePPSMu.Lock()
	defer h.rulePPSMu.Unlock()
	wantCounts, wantTimes := make(map[string]uint64), make(map[string]int64)
	for _, id := range ids {
		wantCounts[id], wantTimes[id] = counts[id], times[id]
	}
	gotCounts, gotTimes := make([]string, 0, len(h.lastRuleDropCount)), make([]string, 0, len(h.lastRuleStatsTime))
	for id := range h.lastRuleDropCount {
		gotCounts = append(gotCounts, id)
	}
	for id := range h.lastRuleStatsTime {
		gotTimes = append(gotTimes, id)
	}
	sort.Strings(ids)
	sort.Strings(gotCounts)
	sort.Strings(gotTimes)
	if len(h.lastRuleDropCount) != len(ids) || len(h.lastRuleStatsTime) != len(ids) || !reflect.DeepEqual(gotCounts, ids) || !reflect.DeepEqual(gotTimes, ids) {
		t.Errorf("PPS keys counts=%v times=%v want=%v", gotCounts, gotTimes, ids)
	}
	if !reflect.DeepEqual(h.lastRuleDropCount, wantCounts) || !reflect.DeepEqual(h.lastRuleStatsTime, wantTimes) {
		t.Errorf("PPS values counts=%v times=%v want=%v/%v", h.lastRuleDropCount, h.lastRuleStatsTime, wantCounts, wantTimes)
	}
}

func TestHCB06G8CommitPPS(t *testing.T) {
	for _, mode := range []string{"delete_exact", "delete_cidr", "replace_id", "move_exact", "move_to_cidr", "move_to_exact", "replace_content", "replay", "selector_failure", "deferred_exact", "deferred_cidr"} {
		t.Run(mode, func(t *testing.T) {
			f := cut55Memory(t)
			a, b := cut53Pure(false, "a", 1), cut53Pure(false, "b", 2)
			ttlA, ttlB := "64", "65"
			a.TTL, b.TTL = &ttlA, &ttlB
			if mode == "delete_cidr" || mode == "deferred_cidr" || mode == "move_to_exact" {
				a.SrcIP, b.SrcIP = "", ""
				a.SrcCIDR, b.SrcCIDR = "192.0.2.0/24", "192.0.2.0/24"
			}
			members := []Rule{a, b}
			moving := mode == "move_exact" || mode == "move_to_cidr" || mode == "move_to_exact"
			if moving {
				a.ID = "m"
				members = []Rule{a}
			} else if mode == "replace_id" || mode == "replace_content" {
				members = []Rule{a}
			}
			cut55Commit(t, f.h, cut55Group(t, f.h, a, members...))
			groups := []CommitGroup{cut55Group(t, f.h, a, b)}
			seed, want := []string{"a", "b"}, []string{"b", "sentinel"}
			switch mode {
			case "delete_cidr", "deferred_cidr":
				groups = []CommitGroup{cut55Group(t, f.h, a)}
				want = []string{"sentinel"}
			case "replace_id":
				c := a
				c.ID = "c"
				groups = []CommitGroup{cut55Group(t, f.h, a, c)}
				seed, want = []string{"a", "c"}, []string{"c", "sentinel"}
			case "move_exact", "move_to_cidr", "move_to_exact":
				moved := a
				moved.SrcIP, moved.SrcCIDR = "203.0.113.9", ""
				if mode == "move_to_cidr" {
					moved.SrcIP, moved.SrcCIDR = "", "203.0.113.0/24"
				}
				groups = []CommitGroup{cut55Group(t, f.h, a), cut55Group(t, f.h, moved, moved)}
				seed, want = []string{"m"}, []string{"m", "sentinel"}
			case "replace_content":
				changed := a
				changed.TTL = &ttlB
				groups = []CommitGroup{cut55Group(t, f.h, a, changed)}
				seed, want = []string{"a"}, []string{"a", "sentinel"}
			case "replay":
				groups = []CommitGroup{cut55Group(t, f.h, a, a, b)}
				want = []string{"a", "b", "sentinel"}
			case "selector_failure":
				f.selector.updateErr = fmt.Errorf("selector fixture failure")
				want = []string{"a", "b", "sentinel"}
			}
			if mode == "deferred_exact" || mode == "deferred_cidr" {
				f.h.quiescer = cut53Receipt(func() error { return fmt.Errorf("Rc fixture failure") })
			}
			hcB06SeedPPS(f.h, seed...)
			counts, times := maps.Clone(f.h.lastRuleDropCount), maps.Clone(f.h.lastRuleStatsTime)
			if mode == "selector_failure" {
				body := hcB03Body(t, cut55HTTP(t, f.h, groups), 500)
				if hcB03String(t, body, "code") != "commit_failed" {
					t.Errorf("commit failure code=%s", body["code"])
				}
			} else {
				result := cut55Commit(t, f.h, groups...)
				if (mode == "deferred_exact" || mode == "deferred_cidr") && result.Receipt != "deferred" {
					t.Errorf("receipt=%q want=deferred", result.Receipt)
				}
				if mode == "replay" && result.Code != "unchanged" {
					t.Errorf("replay code=%q want=unchanged", result.Code)
				}
			}
			hcB06PPS(t, f.h, counts, times, want...)
		})
	}
}
