//go:build linux && integration

package api

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

// These fixtures deliberately have no withdrawal debt. A delayed preflight
// must reach its destructive step instead of being stopped by Step 0.
func TestCut53I6BeforeShadowClear(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprint(isCIDR), func(t *testing.T) {
			h, _, _, coll := b7ELFCollection(t)
			marker := cut53Pure(false, "shadow-marker", 91)
			key, err := h.ruleToKey(marker)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.shadowBlacklist().Update(ruleKeyToBytes(key), ruleValueToBytes(RuleValue{Action: ActionDrop}), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if len(b7Snapshot(t, h.shadowBlacklist())) != 1 {
				t.Fatal("late-preflight fixture guard")
			}
			bad := cut53Pure(isCIDR, "node-only-zero", 0)
			bad.TTL = cut4BString("64")
			if _, err := h.prepareAtomicRule(bad); err != nil {
				t.Fatalf("old validation ate node-only witness: %v", err)
			}
			before := cut53AllMapBytes(t, coll)
			stages, receipts := 0, 0
			h.quiescer = cut53Receipt(func() error { receipts++; return nil })
			atomicStageTestHook = func(stage string, got *Handlers) {
				if got == h && stage == "1" {
					stages++
				}
			}
			defer func() { atomicStageTestHook = nil }()
			w := cut53Request(t, cut53MemoryRouter(h), "POST", "/atomic", map[string]any{"rules": []Rule{bad}})
			if w.Code != 409 {
				t.Fatalf("I6 node-only group failure was partially published: status=%d %s", w.Code, w.Body.String())
			}
			b7Code(t, w, 409, "condition_group_invalid")
			if !reflect.DeepEqual(before, cut53AllMapBytes(t, coll)) || stages != 0 || receipts != 0 {
				t.Fatalf("I6 late preflight cleared shadow: step1=%d receipts=%d", stages, receipts)
			}
		})
	}
	t.Log("CUT53_I6_BEFORE_CLEAR cells=2 node_validation_passed=2 shadow_markers=2 step1=0")
}

func TestCut53DeterministicGroupActionRate(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		h, _, _, _ := b7ELFCollection(t)
		a := cut53Pure(isCIDR, "loose", 17)
		a.Action, a.RateLimit, a.TTL = "rate_limit", 123, cut4BString("64")
		b := cut53Pure(isCIDR, "strict", 18)
		b.TTL, b.DSCP = cut4BString("64"), cut4BString("0")
		var prior map[string]string
		for order, rules := range [][]Rule{{a, b}, {b, a}} {
			if _, err := h.DoAtomicSync(rules); err != nil {
				t.Fatal(err)
			}
			m := p7ActiveBlacklist(h)
			if isCIDR {
				m = p7ActiveCIDR(h)
			}
			rows := b7Snapshot(t, m)
			if len(rows) != 1 {
				t.Fatal("group did not produce one row")
			}
			for _, raw := range rows {
				v := []byte(raw)
				if v[0] != ActionDrop || binary.LittleEndian.Uint32(v[4:8]) != 0 {
					t.Fatalf("E4 strictest candidate action/rate=%x", v)
				}
			}
			if order == 1 && !reflect.DeepEqual(prior, rows) {
				t.Fatal("E4 request order changed rule wire")
			}
			prior = rows
		}
	}
	t.Log("CUT53_E4 kinds=2 orders=2 strictest_candidate=4 byte_identical=2")
}

// Original TD075G4 same-key fixture must now fail before Step 0. Debt makes a
// hidden ClearWithdrawals call observable, in addition to complete map reads.
func TestCut53TD075OriginalGroupZeroWrite(t *testing.T) {
	h, router, _, coll := b7ELFCollection(t)
	var tries []*dingTrie
	h.cidrMgr, tries = cut53WrapTries(coll)
	cut53MakeUnknown(t, h, tries)
	before, state, deletes := cut53AllMapBytes(t, coll), cut53State(h), tries[0].deletes
	rules := []Rule{{ID: "parent", SrcCIDR: "10.0.0.0/16", Action: "drop"}, {ID: "child", SrcCIDR: "10.0.1.0/24", Action: "drop"}, {ID: "duplicate", SrcCIDR: "10.0.1.0/24", Action: "drop"}}
	w := yiAtomicCall(t, router, rules)
	body := td075Body(t, w)
	if w.Code != 409 || body.Code != "condition_group_invalid" || len(body.Conflicts) != 2 || body.Conflicts[0].ID != "child" || body.Conflicts[1].ID != "duplicate" {
		t.Fatalf("TD075 original group did not produce I6: %d %s", w.Code, w.Body.String())
	}
	if tries[0].deletes != deletes || state != cut53State(h) || !reflect.DeepEqual(before, cut53AllMapBytes(t, coll)) {
		t.Fatal("TD075 I6 touched withdrawals, manager, rules, conditions or config")
	}
	t.Log("CUT53_TD075_ORIGINAL I6=409 conflicts=2 withdrawal_calls=0 maps_unchanged=21")
}
