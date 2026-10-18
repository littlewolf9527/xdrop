//go:build linux && integration

package api

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func cut54Pay(t *testing.T, h *Handlers) {
	t.Helper()
	h.syncMu.Lock()
	h.publishMu.Lock()
	h.rulesMu.Lock()
	err := h.payPendingLogicalLocked()
	h.rulesMu.Unlock()
	h.publishMu.Unlock()
	h.syncMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCut54MissingConditionDiagnostic(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprintf("cidr=%v", isCIDR), func(t *testing.T) {
			h, router, p, _ := b7ELFCollection(t)
			candidate := cut53Pure(isCIDR, "candidate", 17)
			candidate.TTL = cut4BString("64")
			fallback := candidate
			fallback.ID = "fallback"
			fallback.LogicalID = 18
			fallback.Protocol = ""
			fallback.TTL = nil
			if out, err := h.DoAtomicSync([]Rule{candidate, fallback}); err != nil || out.Added != 2 {
				t.Fatalf("seed=%+v %v", out, err)
			}
			var key []byte
			condition := h.activeCond()
			if isCIDR {
				key = cidrRuleKeyToBytes(h.cidrRules[candidate.ID].Key)
				condition = h.activeCidrCond()
			} else {
				key = ruleKeyToBytes(h.rules[candidate.ID].Key)
			}
			if err := condition.Delete(key); err != nil {
				t.Fatal(err)
			}
			read := func() uint64 {
				var slots []uint64
				if err := h.condRowMissing.Lookup(uint32(0), &slots); err != nil {
					t.Fatal(err)
				}
				var n uint64
				for _, v := range slots {
					n += v
				}
				return n
			}
			before := read()
			cut53Verdict(t, p, cut53Packet([4]byte{192, 0, 2, 1}, 64), 1)
			if read() != before+1 {
				t.Fatalf("missing condition row diagnostic did not increment once: %d -> %d", before, read())
			}
			counts, err := ReadLogicalRuleCounters(h.idCounts, 18)
			if err != nil || counts.Match != 1 || counts.Drop != 1 {
				t.Fatalf("missing condition row failed fallback: %+v %v", counts, err)
			}
			w := jiaCall(t, router, "GET", "/api/v1/stats", "")
			var response map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || string(response["cond_row_missing"]) != fmt.Sprint(before+1) {
				t.Fatalf("stats must expose cond_row_missing: %d %s", w.Code, w.Body.String())
			}
		})
	}
	t.Log("CUT54_COND_MISSING lookup_paths=2 fallback_drops=2 diagnostic_increments=2 stats_fields=2")
}
func TestCut54ListMissingRowIsZero(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		h, router, _ := b7Handler(t)
		r := cut53Pure(isCIDR, "r", 17)
		if result, err := h.DoAtomicSync([]Rule{r}); err != nil || result.Added != 1 {
			t.Fatalf("seed=%+v %v", result, err)
		}
		b7SetLogicalCounts(t, h, 17, 37, 29)
		table, key := cut4Table(h, isCIDR)
		if err := table.Delete(key); err != nil {
			t.Fatal(err)
		}
		for _, query := range []string{"", "?page=1"} {
			w := jiaCall(t, router, "GET", "/api/v1/rules"+query, "")
			var body struct{ Rules []Rule }
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Rules) != 1 {
				t.Fatalf("list=%s %v", w.Body.String(), err)
			}
			stats := body.Rules[0].Stats
			if stats == nil || stats.MatchCount != 0 || stats.DropCount != 0 {
				t.Fatalf("missing row must report zero despite live logical counters: %+v", stats)
			}
		}
	}
	t.Log("CUT54_LIST_MISSING kinds=2 modes=2 zero_counts=4")
}
func TestCut54ZeroLogicalEntrypoints(t *testing.T) {
	cells := 0
	for _, isCIDR := range []bool{false, true} {
		for _, group := range []bool{false, true} {
			for _, entry := range []string{"atomic"} {
				t.Run(fmt.Sprintf("cidr=%v/group=%v/%s", isCIDR, group, entry), func(t *testing.T) {
					h, router, _ := b7Handler(t)
					r := cut53Pure(isCIDR, "zero", 0)
					if group {
						r.TTL = cut4BString("64")
					}
					method, path := "POST", "/api/v1/rules"
					var body any = r
					if entry == "put" {
						method, path = "PUT", "/api/v1/rules/missing"
					}
					if entry == "batch" || entry == "atomic" {
						body = map[string]any{"rules": []Rule{r}}
						path = "/api/v1/rules/batch"
						if entry == "atomic" {
							path = "/api/v1/sync/atomic"
						}
					}
					before := cut53BusinessSnapshot(t, h)
					w := cut53Request(t, router, method, path, body)
					want, fragment := 400, "logical_id must be nonzero"
					if entry == "batch" {
						want = 200
					}
					if entry == "atomic" {
						want = 200
					}
					if group {
						want, fragment = 409, "condition_group_required"
						if entry == "atomic" {
							fragment = "missing/duplicate logical_id 0"
						}
					}
					if w.Code != want || !strings.Contains(w.Body.String(), fragment) {
						t.Fatalf("zero-ID entry=%s response=%d %s want=%d/%s", entry, w.Code, w.Body.String(), want, fragment)
					}
					if entry != "atomic" || group {
						if !reflect.DeepEqual(before, cut53BusinessSnapshot(t, h)) {
							t.Fatal("zero-ID rejection wrote business state")
						}
					}
					if len(h.rules)+len(h.cidrRules) != 0 || len(h.cidrMgr.ListSrcCIDRs()) != 0 || len(h.pendingLogicalIDs) != 0 {
						t.Fatal("zero-ID request reserved ID or retained rule")
					}
					cells++
				})
			}
		}
	}
	t.Logf("CUT54_ZERO_ID cells=%d public=4 direct_cidr=0 pure_atomic_partial=2", cells)
}
