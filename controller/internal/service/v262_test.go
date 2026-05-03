// v262_test.go — regression tests for v2.6.2 bugfixes.
// Covers: AUD-001 anomaly guard, B-1 IP validation, AUD-006 scalar bounds,
// AUD-007 DiffSync (mock), B-2 sync response, Update rate_limit semantics.
package service

import (
	"math"
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

// ---- AUD-001: validateAnomalyFields ----

func TestValidateAnomalyFields_RateLimit(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 1, Action: "rate_limit", DstIP: "10.0.0.1"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for anomaly+rate_limit, got nil")
	}
}

func TestValidateAnomalyFields_NoTarget(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 1, Action: "drop"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for anomaly without target, got nil")
	}
}

func TestValidateAnomalyFields_BadFragmentIPv6(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 1, Action: "drop", DstIP: "2001:db8::1"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for bad_fragment + IPv6, got nil")
	}
}

func TestValidateAnomalyFields_InvalidIPv6Allowed(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 2, Action: "drop", DstIP: "2001:db8::1"}
	if err := validateAnomalyFields(req); err != nil {
		t.Fatalf("invalid decoder should allow IPv6, got: %v", err)
	}
}

func TestValidateAnomalyFields_CompoundBitIPv6(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 3, Action: "drop", DstIP: "2001:db8::1"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for compound bit (incl. bad_fragment) + IPv6")
	}
}

func TestValidateAnomalyFields_UnknownBit(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 0xFF, Action: "drop", DstCIDR: "10.0.0.0/8"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for unknown anomaly bit")
	}
}

func TestValidateAnomalyFields_NegativeBitmask(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: -1, Action: "drop", DstCIDR: "10.0.0.0/8"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for negative match_anomaly")
	}
}

func TestValidateAnomalyFields_WildcardSrcIPv4(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 1, Action: "drop", SrcIP: "0.0.0.0"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for wildcard src_ip 0.0.0.0")
	}
}

func TestValidateAnomalyFields_WildcardDstIPv6(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 1, Action: "drop", DstIP: "::"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for wildcard dst_ip ::")
	}
}

func TestValidateAnomalyFields_DefaultRouteSrcCIDR(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 1, Action: "drop", SrcCIDR: "0.0.0.0/0"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for default route src_cidr")
	}
}

func TestValidateAnomalyFields_DefaultRouteDstCIDRv6(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 1, Action: "drop", DstCIDR: "::/0"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for default route dst_cidr ::/0")
	}
}

func TestValidateAnomalyFields_AlternateDefaultRoute(t *testing.T) {
	// "0.0.0.0/00" is non-canonical but ParseCIDR resolves to /0
	req := &model.RuleRequest{MatchAnomaly: 1, Action: "drop", SrcCIDR: "0.0.0.0/00"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for non-canonical default route")
	}
}

func TestValidateAnomalyFields_MappedV6Wildcard(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 1, Action: "drop", SrcIP: "::ffff:0.0.0.0"}
	if err := validateAnomalyFields(req); err == nil {
		t.Fatal("expected error for IPv4-mapped wildcard")
	}
}

func TestValidateAnomalyFields_ValidBoundedTarget(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 1, Action: "drop", DstCIDR: "10.99.0.0/24"}
	if err := validateAnomalyFields(req); err != nil {
		t.Fatalf("expected success for bounded CIDR target, got: %v", err)
	}
}

func TestValidateAnomalyFields_Zero_NoOp(t *testing.T) {
	req := &model.RuleRequest{MatchAnomaly: 0, Action: "drop"}
	if err := validateAnomalyFields(req); err != nil {
		t.Fatalf("match_anomaly=0 should be no-op, got: %v", err)
	}
}

// ---- AUD-001 Update path (effective values) ----

func TestValidateAnomalyFieldsForUpdate_EffectiveTarget(t *testing.T) {
	existing := &model.Rule{DstIP: "10.0.0.1", Action: "drop"}
	req := &model.RuleRequest{MatchAnomaly: 2} // invalid bit, IPv6 allowed
	if err := validateAnomalyFieldsForUpdate(req, existing); err != nil {
		t.Fatalf("should pass: existing dst_ip is IPv4, match_anomaly=2 (invalid), got: %v", err)
	}
}

func TestValidateAnomalyFieldsForUpdate_NotMisrejected(t *testing.T) {
	// PUT {"match_anomaly":2} on rule with dst_ip="2001:db8::1" — should succeed (invalid allows v6)
	existing := &model.Rule{DstIP: "2001:db8::1", Action: "drop"}
	req := &model.RuleRequest{MatchAnomaly: 2}
	if err := validateAnomalyFieldsForUpdate(req, existing); err != nil {
		t.Fatalf("invalid decoder + IPv6 dst should be allowed, got: %v", err)
	}
}

func TestValidateAnomalyFieldsForUpdate_BadFragmentIPv6Blocked(t *testing.T) {
	existing := &model.Rule{DstIP: "2001:db8::1", Action: "drop", MatchAnomaly: 2}
	req := &model.RuleRequest{MatchAnomaly: 1} // switching to bad_fragment on an IPv6 rule
	if err := validateAnomalyFieldsForUpdate(req, existing); err == nil {
		t.Fatal("expected error: bad_fragment does not support IPv6 target")
	}
}

// ---- B-1: validateIPFields ----

func TestValidateIPFields_RejectCIDRInIPField(t *testing.T) {
	req := &model.RuleRequest{SrcIP: "0.0.0.0/0"}
	if err := validateIPFields(req); err == nil {
		t.Fatal("expected error for CIDR in src_ip")
	}
}

func TestValidateIPFields_RejectGarbage(t *testing.T) {
	req := &model.RuleRequest{DstIP: "not-an-ip"}
	if err := validateIPFields(req); err == nil {
		t.Fatal("expected error for garbage dst_ip")
	}
}

func TestValidateIPFields_AcceptZeroAsAny(t *testing.T) {
	req := &model.RuleRequest{SrcIP: "0.0.0.0"}
	if err := validateIPFields(req); err != nil {
		t.Fatalf("0.0.0.0 is valid any-match IP, got: %v", err)
	}
}

func TestValidateIPFields_NormalizeMappedV6(t *testing.T) {
	req := &model.RuleRequest{SrcIP: "::ffff:1.2.3.4"}
	if err := validateIPFields(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.SrcIP != "1.2.3.4" {
		t.Fatalf("expected normalized to 1.2.3.4, got %q", req.SrcIP)
	}
}

func TestValidateIPFields_EmptyIsNoOp(t *testing.T) {
	req := &model.RuleRequest{}
	if err := validateIPFields(req); err != nil {
		t.Fatalf("empty IP fields should be no-op, got: %v", err)
	}
}

// ---- AUD-006: validateRuleScalarBounds ----

func TestValidateRuleScalarBounds_PortNeg(t *testing.T) {
	req := &model.RuleRequest{SrcPort: -1, Action: "drop"}
	if err := validateRuleScalarBounds(req); err == nil {
		t.Fatal("expected error for src_port=-1")
	}
}

func TestValidateRuleScalarBounds_PortOver(t *testing.T) {
	req := &model.RuleRequest{DstPort: 70000, Action: "drop"}
	if err := validateRuleScalarBounds(req); err == nil {
		t.Fatal("expected error for dst_port=70000")
	}
}

func TestValidateRuleScalarBounds_PktLenOver(t *testing.T) {
	v := 70000
	req := &model.RuleRequest{PktLenMin: &v, Action: "drop", SrcIP: "1.2.3.4"}
	if err := validateRuleScalarBounds(req); err == nil {
		t.Fatal("expected error for pkt_len_min=70000")
	}
}

func TestValidateRuleScalarBounds_RateLimitNeg(t *testing.T) {
	req := &model.RuleRequest{RateLimit: -1, Action: "rate_limit"}
	if err := validateRuleScalarBounds(req); err == nil {
		t.Fatal("expected error for rate_limit=-1")
	}
}

func TestValidateRuleScalarBounds_RateLimitOverUint32(t *testing.T) {
	req := &model.RuleRequest{RateLimit: math.MaxUint32 + 1, Action: "rate_limit"}
	if err := validateRuleScalarBounds(req); err == nil {
		t.Fatal("expected error for rate_limit > MaxUint32")
	}
}

func TestValidateRuleScalarBounds_DropWithRateLimit(t *testing.T) {
	req := &model.RuleRequest{Action: "drop", RateLimit: 1000}
	if err := validateRuleScalarBounds(req); err == nil {
		t.Fatal("expected error for action=drop with rate_limit>0")
	}
}

func TestValidateRuleScalarBounds_Valid(t *testing.T) {
	min, max := 60, 1500
	req := &model.RuleRequest{SrcPort: 80, DstPort: 443, PktLenMin: &min, PktLenMax: &max, Action: "rate_limit", RateLimit: 1000}
	if err := validateRuleScalarBounds(req); err != nil {
		t.Fatalf("unexpected error for valid bounds: %v", err)
	}
}

// ---- AUD-006: validateWhitelistScalarBounds ----

func TestValidateWhitelistScalarBounds_PortNeg(t *testing.T) {
	req := &model.WhitelistRequest{SrcPort: -1}
	if err := validateWhitelistScalarBounds(req); err == nil {
		t.Fatal("expected error for whitelist src_port=-1")
	}
}

func TestValidateWhitelistScalarBounds_PortOver(t *testing.T) {
	req := &model.WhitelistRequest{DstPort: 70000}
	if err := validateWhitelistScalarBounds(req); err == nil {
		t.Fatal("expected error for whitelist dst_port=70000")
	}
}

// ---- Update rate_limit semantics (R3-002 / R4-003) ----
// These require a full RuleService with repo so they live in rule_service_integration_test.go.
// The validator helper unit tests below cover the guard logic directly.

func TestValidateRuleScalarBounds_DropWithPositiveRateLimit(t *testing.T) {
	req := &model.RuleRequest{Action: "drop", RateLimit: 500}
	err := validateRuleScalarBounds(req)
	if err == nil {
		t.Fatal("expected error: action=drop with rate_limit=500")
	}
	if !strings.Contains(err.Error(), "rate_limit") {
		t.Fatalf("error should mention rate_limit, got: %v", err)
	}
}

// ---- hasBoundedAnomalyTarget (internal helper) ----

func TestHasBoundedAnomalyTarget_EmptyIsFalse(t *testing.T) {
	if hasBoundedAnomalyTarget("", "", "", "") {
		t.Fatal("empty fields should not be bounded")
	}
}

func TestHasBoundedAnomalyTarget_DefaultRouteIsFalse(t *testing.T) {
	if hasBoundedAnomalyTarget("", "", "0.0.0.0/0", "") {
		t.Fatal("0.0.0.0/0 should not be bounded")
	}
	if hasBoundedAnomalyTarget("", "", "", "::/0") {
		t.Fatal("::/0 should not be bounded")
	}
}

func TestHasBoundedAnomalyTarget_WildcardIPIsFalse(t *testing.T) {
	if hasBoundedAnomalyTarget("0.0.0.0", "", "", "") {
		t.Fatal("0.0.0.0 exact IP should not be bounded")
	}
	if hasBoundedAnomalyTarget("", "::", "", "") {
		t.Fatal(":: exact IP should not be bounded")
	}
}

func TestHasBoundedAnomalyTarget_InvalidCIDRIsFalse(t *testing.T) {
	if hasBoundedAnomalyTarget("", "", "garbage", "") {
		t.Fatal("invalid CIDR should not be bounded")
	}
}

func TestHasBoundedAnomalyTarget_ValidCIDRIsTrue(t *testing.T) {
	if !hasBoundedAnomalyTarget("", "", "10.99.0.0/24", "") {
		t.Fatal("10.99.0.0/24 should be bounded")
	}
}

func TestHasBoundedAnomalyTarget_ValidIPIsTrue(t *testing.T) {
	if !hasBoundedAnomalyTarget("", "1.2.3.4", "", "") {
		t.Fatal("1.2.3.4 should be bounded")
	}
}

// ---- B-10 (rev8): portless protocol + port → BPF dead rule rejection ----

func TestValidatePortProtocolCompat_GREWithSrcPort(t *testing.T) {
	if err := validatePortProtocolCompat("gre", 500, 0); err == nil {
		t.Fatal("expected reject: gre + src_port=500")
	}
}

func TestValidatePortProtocolCompat_ESPWithDstPort(t *testing.T) {
	if err := validatePortProtocolCompat("esp", 0, 500); err == nil {
		t.Fatal("expected reject: esp + dst_port=500")
	}
}

func TestValidatePortProtocolCompat_IGMPWithBothPorts(t *testing.T) {
	if err := validatePortProtocolCompat("igmp", 1, 2); err == nil {
		t.Fatal("expected reject: igmp + src_port + dst_port")
	}
}

func TestValidatePortProtocolCompat_ICMPWithSrcPort(t *testing.T) {
	if err := validatePortProtocolCompat("icmp", 100, 0); err == nil {
		t.Fatal("expected reject: icmp + src_port=100")
	}
}

func TestValidatePortProtocolCompat_ICMPv6WithSrcPort(t *testing.T) {
	if err := validatePortProtocolCompat("icmpv6", 1, 0); err == nil {
		t.Fatal("expected reject: icmpv6 + src_port=1")
	}
}

func TestValidatePortProtocolCompat_TCPAcceptPort(t *testing.T) {
	if err := validatePortProtocolCompat("tcp", 0, 80); err != nil {
		t.Fatalf("tcp + dst_port=80 should be accepted, got: %v", err)
	}
}

func TestValidatePortProtocolCompat_UDPAcceptPort(t *testing.T) {
	if err := validatePortProtocolCompat("udp", 0, 53); err != nil {
		t.Fatalf("udp + dst_port=53 should be accepted, got: %v", err)
	}
}

func TestValidatePortProtocolCompat_AllAcceptsPort(t *testing.T) {
	// "all" is a wildcard that may match TCP/UDP packets — port stays valid.
	if err := validatePortProtocolCompat("all", 0, 80); err != nil {
		t.Fatalf("all + dst_port=80 should be accepted, got: %v", err)
	}
	if err := validatePortProtocolCompat("", 0, 80); err != nil {
		t.Fatalf("empty protocol + dst_port=80 should be accepted, got: %v", err)
	}
}

func TestValidatePortProtocolCompat_PortlessZeroPortAccepted(t *testing.T) {
	// Portless protocol with zero ports is the legitimate case.
	for _, p := range []string{"icmp", "icmpv6", "igmp", "gre", "esp"} {
		if err := validatePortProtocolCompat(p, 0, 0); err != nil {
			t.Fatalf("%s + zero ports should be accepted, got: %v", p, err)
		}
	}
}
