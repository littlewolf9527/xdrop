// rule_value_layout_test.go — v2.6 Phase 4 layout contract.
//
// Hard asserts that RuleValue stays at 32 bytes and that MatchAnomaly occupies
// offset 3 (the former pad byte). These are load-bearing invariants of the
// byte-budget decision documented in proposal §7.2.0 — if this test fails,
// the struct has silently grown, the BPF map's value_size changes, and
// Phase 3 reconcilePinnedMaps will auto-wipe all rules on the next upgrade
// (~7s rule-empty window).
//
// A failing test means: roll back the struct change OR explicitly accept the
// schema drift and update the proposal + ops runbook.
package api

import (
	"testing"
	"unsafe"
)

func TestRuleValueSize32Bytes(t *testing.T) {
	const want = 32
	if got := unsafe.Sizeof(RuleValue{}); got != want {
		t.Fatalf("sizeof(RuleValue) = %d, want %d — byte budget violated (§7.2.0)", got, want)
	}
}

func TestRuleValueMatchAnomalyOffset(t *testing.T) {
	var v RuleValue
	base := uintptr(unsafe.Pointer(&v))
	off := uintptr(unsafe.Pointer(&v.MatchAnomaly)) - base
	if off != 3 {
		t.Errorf("MatchAnomaly offset = %d, want 3 (matches xdrop.h C struct layout)", off)
	}
}

func TestRuleValueSerializeWritesMatchAnomalyAtOffset3(t *testing.T) {
	// Round-trip check: non-zero MatchAnomaly lands at byte 3 in the wire
	// format read by the BPF map.
	v := RuleValue{MatchAnomaly: AnomalyBadFragment | AnomalyInvalid}
	wire := ruleValueToBytes(v)
	if len(wire) != 32 {
		t.Fatalf("ruleValueToBytes returned %d bytes, want 32", len(wire))
	}
	if wire[3] != byte(AnomalyBadFragment|AnomalyInvalid) {
		t.Errorf("wire[3] = 0x%02x, want 0x%02x",
			wire[3], AnomalyBadFragment|AnomalyInvalid)
	}
}

func TestRuleValueZeroMatchAnomalyBackwardCompat(t *testing.T) {
	// Critical regression: any old rule (without match_anomaly) serializes
	// with wire[3]=0. The BPF anomaly_matches helper treats 0 as "don't
	// check", so existing rules continue matching as before.
	v := RuleValue{Action: ActionDrop}
	wire := ruleValueToBytes(v)
	if wire[3] != 0 {
		t.Errorf("legacy rule without MatchAnomaly produced wire[3]=0x%02x, want 0x00", wire[3])
	}
}
