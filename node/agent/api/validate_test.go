// validate_test.go — unit tests for protocol / TCP flag parsing helpers.
//
// v2.6 Phase 1: adds coverage for gre / esp / igmp enum + roundtrip.
// v2.6 Phase 2: additional tcp_flags coverage lands here when needed; node
// parseTcpFlags itself is untouched by the decoder-sugar work (that sugar
// lives in the Controller). The bit-level assertions below are the contract
// the Controller's normalizeDecoder depends on.
package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseProtocolKnownValues(t *testing.T) {
	cases := []struct {
		in   string
		want uint8
	}{
		{"tcp", ProtoTCP},
		{"udp", ProtoUDP},
		{"icmp", ProtoICMP},
		{"icmpv6", ProtoICMPv6},
		{"igmp", ProtoIGMP},
		{"gre", ProtoGRE},
		{"esp", ProtoESP},
	}
	for _, c := range cases {
		if got := parseProtocolLenient(c.in); got != c.want {
			t.Errorf("parseProtocolLenient(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestParseProtocolLenientStillFallsBackToAll pins what the lenient helper does.
//
// 🔴 Rewritten 2026-09-14 (S0-6). The previous version carried this rationale:
// "the deliberately permissive Node parser ... Controller validateProtocol is
// the real reject boundary". That premise is dead. The Agent exposes its own
// rule-write API, so the Controller is NOT the only way in — external audit
// D-09 walked a typo'd protocol straight through it into a valid wildcard
// combo. The owner decided on 2026-09-05 that the Agent rejects instead.
//
// The helper itself still maps unknown strings to ProtoAll, and that is fine
// where it is still used ("is this TCP?" guards, where a non-TCP answer makes
// the guard fire). What changed is that no key-building path calls it any more.
// TestRuleToKeyRejectsUnknownProtocol below is the assertion that matters now.
func TestParseProtocolLenientStillFallsBackToAll(t *testing.T) {
	for _, s := range []string{"sctp", "ospf", "banana", ""} {
		if got := parseProtocolLenient(s); got != ProtoAll {
			t.Errorf("parseProtocolLenient(%q) = %d, want ProtoAll(0)", s, got)
		}
	}
}

func TestProtocolToStringRoundtrip(t *testing.T) {
	for _, name := range []string{"tcp", "udp", "icmp", "icmpv6", "igmp", "gre", "esp"} {
		got := protocolToString(parseProtocolLenient(name))
		if got != name {
			t.Errorf("roundtrip %q: got %q", name, got)
		}
	}
}

func TestProtocolConstantValues(t *testing.T) {
	// Lock IANA numbers so a future edit can't silently redefine them.
	cases := []struct {
		name string
		got  uint8
		want uint8
	}{
		{"ProtoICMP", ProtoICMP, 1},
		{"ProtoIGMP", ProtoIGMP, 2},
		{"ProtoTCP", ProtoTCP, 6},
		{"ProtoUDP", ProtoUDP, 17},
		{"ProtoGRE", ProtoGRE, 47},
		{"ProtoESP", ProtoESP, 50},
		{"ProtoICMPv6", ProtoICMPv6, 58},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d (IANA)", c.name, c.got, c.want)
		}
	}
}

// T56: parseProtocolStrict rejects unknown protocols instead of silently
// mapping them to ProtoAll (Phase 8 P2-1 whitelist combo broadening fix).
func TestParseProtocolStrict_RejectsUnknown(t *testing.T) {
	for _, s := range []string{"sctp", "ospf", "banana", "TCP", "UDP"} {
		_, err := parseProtocolStrict(s)
		if err == nil {
			t.Errorf("parseProtocolStrict(%q) should return error for unknown protocol", s)
		}
	}
}

func TestParseProtocolStrict_AcceptsKnown(t *testing.T) {
	for _, s := range []string{"", "all", "tcp", "udp", "icmp", "icmpv6", "igmp", "gre", "esp"} {
		_, err := parseProtocolStrict(s)
		if err != nil {
			t.Errorf("parseProtocolStrict(%q) returned unexpected error: %v", s, err)
		}
	}
}

// T55: Stats struct must have tailcall_fail JSON field (Phase 8 fail-open observability).
func TestStats_TailcallFailFieldExists(t *testing.T) {
	s := Stats{TailcallFail: 42}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal Stats: %v", err)
	}
	if !strings.Contains(string(data), `"tailcall_fail":42`) {
		t.Errorf("Stats JSON missing tailcall_fail field: %s", string(data))
	}
}
