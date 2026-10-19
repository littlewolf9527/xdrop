//go:build linux && integration

package api

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

func cut53WrapTries(coll *ebpf.Collection) (*cidr.Manager, []*dingTrie) {
	var wrapped []*dingTrie
	for _, name := range []string{"sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "sv4_cidr_trie_b", "dv4_cidr_trie_b", "sv6_cidr_trie_b", "dv6_cidr_trie_b"} {
		wrapped = append(wrapped, &dingTrie{table: coll.Maps[name]})
	}
	return cidr.NewManager(wrapped[0], wrapped[1], wrapped[2], wrapped[3], wrapped[4], wrapped[5], wrapped[6], wrapped[7]), wrapped
}
func cut53MakeUnknown(t *testing.T, h *Handlers, ws []*dingTrie) {
	t.Helper()
	slot := 1 - int(h.activeRuleSlot.Load())
	if _, err := h.cidrMgr.ReserveSrcID("10.93.250.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := h.cidrMgr.Align(slot, h.cidrMgr.Snapshot([2][]string{})); err != nil {
		t.Fatal(err)
	}
	if err := h.cidrMgr.ReleaseSrcID("10.93.250.0/24"); err != nil {
		t.Fatal(err)
	}
	ws[slot*4].failDelete = true
	if err := h.cidrMgr.Align(slot, h.cidrMgr.Snapshot([2][]string{})); err == nil {
		t.Fatal("unknown-copy fixture did not fail deletion")
	}
	if !dingHasPrefix(t, ws[slot*4].table, 24, [4]byte{10, 93, 250, 0}) {
		t.Fatal("unknown-copy stale prefix absent")
	}
}
func TestCut53I6KernelPreflight(t *testing.T) {
	cells := 0
	for _, cidrKey := range []bool{false, true} {
		for _, kind := range []string{"member_zero_id", "encoder_zero_id", "capacity_five", "invalid_member"} {
			t.Run(fmt.Sprintf("cidr=%v/%s", cidrKey, kind), func(t *testing.T) {
				h, router, program, coll := b7ELFCollection(t)
				var ws []*dingTrie
				h.cidrMgr, ws = cut53WrapTries(coll)
				sentinel := Rule{ID: "sentinel", LogicalID: 91, SrcIP: "198.51.100.9", Action: "drop"}
				if _, err := h.DoAtomicSync([]Rule{sentinel}); err != nil {
					t.Fatal(err)
				}
				cut53MakeUnknown(t, h, ws)
				cut53SeedPendingLogical(h, 90)
				h.logicalRetireThreshold = 1
				cut5SeedLogical(t, h, 90)
				rules := []Rule{cut53Pure(cidrKey, "bad-a", 17), cut53Pure(cidrKey, "bad-b", 18)}
				reason := "missing/duplicate logical_id 0"
				switch kind {
				case "member_zero_id":
					rules[1].LogicalID = 0
				case "encoder_zero_id":
					rules = rules[:1]
					rules[0].LogicalID = 0
					rules[0].TTL = cut4BString("64")
				case "capacity_five":
					rules = nil
					for i := 1; i <= 5; i++ {
						rules = append(rules, cut53Pure(cidrKey, fmt.Sprintf("member-%d", i), uint32(i)))
					}
					reason = "physical candidates 5 exceed 4"
				case "invalid_member":
					rules[1].Action = "invalid"
					reason = "invalid action"
				}
				before, state := cut53AllMapBytes(t, coll), cut53State(h)
				deletions, puts := ws[0].deletes, ws[0].puts
				receiptCalls := 0
				h.quiescer = cut5ReceiptFunc(func() error { receiptCalls++; return nil })
				w := yiAtomicCall(t, router, rules)
				var got struct {
					Code      string
					Conflicts []atomicConditionConflict
				}
				if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if w.Code != 409 || got.Code != "condition_group_invalid" || len(got.Conflicts) != len(rules) {
					t.Fatalf("I6 response=%d %s", w.Code, w.Body.String())
				}
				for i, c := range got.Conflicts {
					if c.ID != rules[i].ID || !strings.Contains(c.Reason, reason) {
						t.Fatalf("I6 conflict=%+v want id=%s reason=%s", c, rules[i].ID, reason)
					}
				}
				if receiptCalls != 0 || h.logicalPayments != 0 || h.logicalPaymentFailures != 0 {
					t.Fatalf("I6 paid before validation receipt=%d", receiptCalls)
				}
				if !reflect.DeepEqual(before, cut53AllMapBytes(t, coll)) || state != cut53State(h) || ws[0].deletes != deletions || ws[0].puts != puts {
					t.Fatal("I6 preflight changed maps, Manager, debt, or called ClearWithdrawals")
				}
				cut53Verdict(t, program, cut53Packet([4]byte{198, 51, 100, 9}, 64), 1)
				cells++
			})
		}
	}
	t.Logf("CUT53_I6 preflight_cells=%d all_map_readbacks=21 per_cell business_writes=0 receipt_calls=0", cells)
}
func TestCut53I6ConstructionFixtures(t *testing.T) {
	cells := 0
	for _, cidrKey := range []bool{false, true} {
		for _, kind := range []string{"existing_shadow_write", "existing_reservation", "existing_unknown_copy"} {
			t.Run(fmt.Sprintf("cidr=%v/%s", cidrKey, kind), func(t *testing.T) {
				h, router, program, coll := b7ELFCollection(t)
				var ws []*dingTrie
				h.cidrMgr, ws = cut53WrapTries(coll)
				old := Rule{ID: "old", LogicalID: 91, SrcCIDR: "198.51.100.0/24", Action: "drop"}
				if _, err := h.DoAtomicSync([]Rule{old}); err != nil {
					t.Fatal(err)
				}
				if kind == "existing_unknown_copy" {
					cut53MakeUnknown(t, h, ws)
					ws[0].failDelete = false
				}
				rules := []Rule{}
				if kind == "existing_shadow_write" {
					rules = append(rules, Rule{ID: "earlier", LogicalID: 92, SrcIP: "203.0.113.5", Action: "drop"})
				}
				if kind == "existing_reservation" {
					rules = append(rules, Rule{ID: "earlier", LogicalID: 92, SrcCIDR: "192.0.2.0/25", Action: "drop"})
				}
				bad := cut53Pure(cidrKey, "conditional", 17)
				bad.TTL = cut4BString("64")
				// A separate destination prefix avoids a nested-prefix precondition.
				if cidrKey {
					bad.SrcCIDR = "192.0.2.128/25"
				}
				rules = append(rules, bad)
				target := h.shadowCond()
				if cidrKey {
					target = h.shadowCidrCond()
				}
				b7Freeze(t, target)
				active := []*ebpf.Map{p7ActiveBlacklist(h), p7ActiveCIDR(h), h.activeCond(), h.activeCidrCond(), h.activeMap(), h.activeConfig}
				snapshots := make([]map[string]string, len(active))
				for i, m := range active {
					snapshots[i] = b7Snapshot(t, m)
				}
				trieBefore := make([]map[string]string, len(ws))
				for i, w := range ws {
					trieBefore[i] = b7Snapshot(t, w.table)
				}
				oldSources := fmt.Sprint(h.cidrMgr.ListSrcCIDRs())
				oldRule := h.cidrRules["old"]
				w := yiAtomicCall(t, router, rules)
				if w.Code != 500 || strings.Contains(w.Body.String(), `"code":`) || !strings.Contains(w.Body.String(), "write shadow") || !strings.Contains(w.Body.String(), "condition") {
					t.Fatalf("construction fault branch not reached: %d %s", w.Code, w.Body.String())
				}
				for i, m := range active {
					if !reflect.DeepEqual(snapshots[i], b7Snapshot(t, m)) {
						t.Fatalf("construction failure changed active table %d", i)
					}
				}
				if !reflect.DeepEqual(h.cidrRules["old"], oldRule) || fmt.Sprint(h.cidrMgr.ListSrcCIDRs()) != oldSources || len(h.rules) != 0 || len(h.cidrRules) != 1 {
					t.Fatal("construction failure changed old rules or CIDR references")
				}
				for i, w := range ws {
					if !reflect.DeepEqual(trieBefore[i], b7Snapshot(t, w.table)) {
						t.Fatalf("construction changed trie copy/table %d", i)
					}
				}
				if kind == "existing_shadow_write" && len(b7Snapshot(t, h.shadowBlacklist())) != 1 {
					t.Fatal("fixture did not reach an earlier shadow write")
				}
				if kind == "existing_reservation" && len(b7Snapshot(t, h.shadowCidrBlacklist())) != 1 {
					t.Fatal("fixture did not reach an earlier CIDR reservation/write")
				}
				cut53Verdict(t, program, cut53Packet([4]byte{198, 51, 100, 9}, 64), 1)
				cells++
			})
		}
	}
	t.Logf("CUT53_I6 construction_cells=%d active_generation_unchanged=6 old_packet_drop=6", cells)
}
