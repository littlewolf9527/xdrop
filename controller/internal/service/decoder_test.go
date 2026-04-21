// decoder_test.go — Phase 2 / Phase 4 decoder sugar unit tests.
//
// Tests at the helper level (normalizeDecoder). Service-level integration
// tests (Create / Update / BatchCreate end-to-end with decoder) live in
// rule_service_test.go and run against a real SQLite repo.
package service

import (
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

func ptr(s string) *string { return &s }

func TestNormalizeDecoder_TcpAck(t *testing.T) {
	req := &model.RuleRequest{Decoder: "tcp_ack", DstIP: "10.99.0.3"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", req.Protocol)
	}
	if req.TcpFlags == nil || *req.TcpFlags != "ACK,!SYN" {
		t.Errorf("tcp_flags = %v, want pointer to \"ACK,!SYN\"", req.TcpFlags)
	}
	if req.Decoder != "" {
		t.Errorf("decoder should be cleared after normalize, got %q", req.Decoder)
	}
	// The decoder must NOT leak into persisted fields in unrelated ways.
	if req.DstIP != "10.99.0.3" {
		t.Errorf("dst_ip mutated unexpectedly: %q", req.DstIP)
	}
}

func TestNormalizeDecoder_TcpRst(t *testing.T) {
	req := &model.RuleRequest{Decoder: "tcp_rst"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Protocol != "tcp" || req.TcpFlags == nil || *req.TcpFlags != "RST" {
		t.Errorf("want protocol=tcp tcp_flags=RST, got proto=%q flags=%v",
			req.Protocol, req.TcpFlags)
	}
}

func TestNormalizeDecoder_TcpFin(t *testing.T) {
	req := &model.RuleRequest{Decoder: "tcp_fin"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Protocol != "tcp" || req.TcpFlags == nil || *req.TcpFlags != "FIN" {
		t.Errorf("want protocol=tcp tcp_flags=FIN, got proto=%q flags=%v",
			req.Protocol, req.TcpFlags)
	}
}

func TestNormalizeDecoder_EmptyIsNoOp(t *testing.T) {
	req := &model.RuleRequest{Decoder: "", Protocol: "udp"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Protocol != "udp" {
		t.Errorf("protocol changed: %q", req.Protocol)
	}
}

func TestNormalizeDecoder_UnknownRejected(t *testing.T) {
	req := &model.RuleRequest{Decoder: "tcp_xyz"}
	err := normalizeDecoder(req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown decoder") {
		t.Errorf("error does not mention 'unknown decoder': %v", err)
	}
}

func TestNormalizeDecoder_ConflictWithExplicitProtocol(t *testing.T) {
	req := &model.RuleRequest{Decoder: "tcp_ack", Protocol: "tcp"}
	err := normalizeDecoder(req)
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if !strings.Contains(err.Error(), "explicit protocol") {
		t.Errorf("error does not mention protocol conflict: %v", err)
	}
}

func TestNormalizeDecoder_ConflictWithExplicitProtocolNonTCP(t *testing.T) {
	// Variant: conflict should trigger even when the explicit protocol would
	// be mutually inconsistent with the decoder's expansion.
	req := &model.RuleRequest{Decoder: "tcp_ack", Protocol: "udp"}
	err := normalizeDecoder(req)
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
}

func TestNormalizeDecoder_ConflictWithExplicitTcpFlags(t *testing.T) {
	req := &model.RuleRequest{Decoder: "tcp_ack", TcpFlags: ptr("ACK,!SYN")}
	err := normalizeDecoder(req)
	if err == nil {
		t.Fatal("expected conflict error even when strings happen to agree; silent agreement invites future drift")
	}
}

func TestNormalizeDecoder_EmptyTcpFlagsPointerIsNotConflict(t *testing.T) {
	// tcp_flags=nil or *tcp_flags=="" → not considered "explicitly set".
	empty := ""
	req := &model.RuleRequest{Decoder: "tcp_ack", TcpFlags: &empty}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("empty tcp_flags pointer should not conflict, got: %v", err)
	}
	if req.TcpFlags == nil || *req.TcpFlags != "ACK,!SYN" {
		t.Errorf("expansion did not overwrite empty tcp_flags: %v", req.TcpFlags)
	}
}

func TestNormalizeDecoder_PreservesCIDR(t *testing.T) {
	// P2-UT-16 / P2-UT-17: decoder + CIDR coexist; normalizer must not stomp
	// dst_cidr / src_cidr.
	req := &model.RuleRequest{Decoder: "tcp_ack", DstCIDR: "10.99.0.0/24"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.DstCIDR != "10.99.0.0/24" {
		t.Errorf("dst_cidr mutated: %q", req.DstCIDR)
	}

	req = &model.RuleRequest{Decoder: "tcp_rst", SrcCIDR: "192.168.0.0/16"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.SrcCIDR != "192.168.0.0/16" {
		t.Errorf("src_cidr mutated: %q", req.SrcCIDR)
	}
}

func TestNormalizeDecoder_BadFragmentExpansion(t *testing.T) {
	// Phase 4 sugar: bad_fragment sets AnomalyBadFragment bit. Requires an
	// explicit IPv4 target per §7.4.1.
	req := &model.RuleRequest{Decoder: "bad_fragment", DstIP: "10.99.0.3"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("bad_fragment sugar should normalize, got: %v", err)
	}
	if req.Decoder != "" {
		t.Errorf("decoder not cleared: %q", req.Decoder)
	}
	if req.MatchAnomaly != int(AnomalyBadFragment) {
		t.Errorf("match_anomaly = %d, want %d", req.MatchAnomaly, AnomalyBadFragment)
	}
}

func TestNormalizeDecoder_InvalidExpansion(t *testing.T) {
	req := &model.RuleRequest{Decoder: "invalid", DstIP: "10.99.0.3"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("invalid decoder sugar should normalize, got: %v", err)
	}
	if req.Decoder != "" {
		t.Errorf("decoder not cleared: %q", req.Decoder)
	}
	if req.MatchAnomaly != int(AnomalyInvalid) {
		t.Errorf("match_anomaly = %d, want %d", req.MatchAnomaly, AnomalyInvalid)
	}
}

func TestNormalizeDecoder_BadFragmentRejectsIPv6DstIP(t *testing.T) {
	req := &model.RuleRequest{Decoder: "bad_fragment", DstIP: "2001:db8::1"}
	err := normalizeDecoder(req)
	if err == nil {
		t.Fatal("expected IPv6 scope-guard rejection, got nil")
	}
	if !strings.Contains(err.Error(), "not supported for IPv6 target in v1.3") ||
		!strings.Contains(err.Error(), "deferred to v1.4") {
		t.Errorf("diagnosis missing stable substring: %v", err)
	}
}

func TestNormalizeDecoder_BadFragmentRejectsIPv6DstCIDR(t *testing.T) {
	req := &model.RuleRequest{Decoder: "bad_fragment", DstCIDR: "2001:db8::/32"}
	if err := normalizeDecoder(req); err == nil {
		t.Fatal("expected IPv6 CIDR scope-guard rejection, got nil")
	}
}

func TestNormalizeDecoder_BadFragmentRejectsIPv6SrcIP(t *testing.T) {
	req := &model.RuleRequest{Decoder: "bad_fragment", SrcIP: "2001:db8::1"}
	if err := normalizeDecoder(req); err == nil {
		t.Fatal("expected IPv6 src scope-guard rejection, got nil")
	}
}

func TestNormalizeDecoder_BadFragmentRejectsIPv6SrcCIDR(t *testing.T) {
	req := &model.RuleRequest{Decoder: "bad_fragment", SrcCIDR: "2001:db8::/32"}
	if err := normalizeDecoder(req); err == nil {
		t.Fatal("expected IPv6 src CIDR scope-guard rejection, got nil")
	}
}

func TestNormalizeDecoder_BadFragmentAcceptsIPv4(t *testing.T) {
	// Reverse assertion: v4 target must NOT be rejected.
	req := &model.RuleRequest{Decoder: "bad_fragment", DstIP: "10.99.0.3"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("bad_fragment on v4 should be accepted, got: %v", err)
	}
}

func TestNormalizeDecoder_InvalidAcceptsIPv6(t *testing.T) {
	// invalid decoder IS supported on IPv6 (TCP doff<5 fires on direct-TCP v6
	// packets). Scope guard must NOT reject it.
	req := &model.RuleRequest{Decoder: "invalid", DstIP: "2001:db8::1"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("invalid decoder on v6 should be accepted, got: %v", err)
	}
	if req.MatchAnomaly != int(AnomalyInvalid) {
		t.Errorf("match_anomaly = %d, want %d", req.MatchAnomaly, AnomalyInvalid)
	}
}

func TestNormalizeDecoder_AnomalyRequiresExplicitTarget(t *testing.T) {
	req := &model.RuleRequest{Decoder: "bad_fragment"}
	err := normalizeDecoder(req)
	if err == nil {
		t.Fatal("expected empty-target rejection, got nil")
	}
	if !strings.Contains(err.Error(), "anomaly decoder requires explicit") {
		t.Errorf("diagnosis missing stable substring: %v", err)
	}

	// Empty target for `invalid` decoder: same rule.
	if err := normalizeDecoder(&model.RuleRequest{Decoder: "invalid"}); err == nil {
		t.Fatal("expected empty-target rejection for invalid decoder too")
	}
}

func TestNormalizeDecoder_AnomalyConflictWithExplicitMatchAnomaly(t *testing.T) {
	req := &model.RuleRequest{Decoder: "bad_fragment", MatchAnomaly: 1, DstIP: "10.99.0.3"}
	err := normalizeDecoder(req)
	if err == nil {
		t.Fatal("expected match_anomaly conflict error, got nil")
	}
	if !strings.Contains(err.Error(), "match_anomaly") {
		t.Errorf("error does not mention match_anomaly conflict: %v", err)
	}
}

func TestNormalizeDecoder_AnomalyPreservesCIDR(t *testing.T) {
	req := &model.RuleRequest{Decoder: "bad_fragment", DstCIDR: "10.99.0.0/24"}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if req.DstCIDR != "10.99.0.0/24" {
		t.Errorf("dst_cidr mutated: %q", req.DstCIDR)
	}
}

func TestNormalizeDecoder_AnomalyRejectsRateLimit(t *testing.T) {
	// codex round 9 P1.1: Controller must reject action=rate_limit on anomaly
	// rules until the dataplane implements real cross-program token-bucket.
	// Previously the Controller accepted rate_limit and anomaly_verify
	// silently mapped it to XDP_DROP — rule declared as rate_limit behaved
	// as drop. See v2.6.1-deploy-summary.md known-simplifications.
	cases := []struct{ name, decoder string }{
		{"bad_fragment", "bad_fragment"},
		{"invalid", "invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &model.RuleRequest{
				Decoder: tc.decoder,
				Action:  "rate_limit",
				DstIP:   "10.99.0.3",
			}
			err := normalizeDecoder(req)
			if err == nil {
				t.Fatalf("expected rejection for %s + rate_limit, got nil", tc.decoder)
			}
			// Stable diagnosis substrings — ops scripts may grep these.
			for _, want := range []string{
				"does not support action=rate_limit",
				"anomaly rules are drop-only",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("diagnosis missing %q; got: %s", want, err.Error())
				}
			}
		})
	}
}

func TestNormalizeDecoder_AnomalyAllowsDrop(t *testing.T) {
	// Reverse assertion: action=drop MUST still be accepted on anomaly rules.
	req := &model.RuleRequest{
		Decoder: "bad_fragment",
		Action:  "drop",
		DstIP:   "10.99.0.3",
	}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("bad_fragment + drop should be accepted, got: %v", err)
	}
	if req.MatchAnomaly != int(AnomalyBadFragment) {
		t.Errorf("match_anomaly = %d, want %d", req.MatchAnomaly, AnomalyBadFragment)
	}
}

func TestNormalizeDecoder_NonAnomalyAllowsRateLimit(t *testing.T) {
	// Reverse assertion: rate_limit on non-anomaly decoders (tcp_ack/rst/fin)
	// stays allowed — the dataplane rate_limit path works for those.
	req := &model.RuleRequest{
		Decoder: "tcp_ack",
		Action:  "rate_limit",
		DstIP:   "10.99.0.3",
	}
	if err := normalizeDecoder(req); err != nil {
		t.Fatalf("tcp_ack + rate_limit should be accepted, got: %v", err)
	}
}

func TestNormalizeDecoder_DiagnosisStringStable(t *testing.T) {
	// Ops scripts grep these substrings. Changing them = contract break.
	req := &model.RuleRequest{Decoder: "bad_fragment", DstIP: "2001:db8::1"}
	err := normalizeDecoder(req)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, want := range []string{
		"not supported for IPv6",
		"deferred to v1.4",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("diagnosis missing %q; got: %s", want, msg)
		}
	}
}
