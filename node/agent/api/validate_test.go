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
		if got := parseProtocol(c.in); got != c.want {
			t.Errorf("parseProtocol(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestParseProtocolUnknownFallsBackToAll locks the deliberately permissive Node
// parser: unknown strings → ProtoAll. Controller validateProtocol is the real
// reject boundary (see rule_service_protocol_test.go).
func TestParseProtocolUnknownFallsBackToAll(t *testing.T) {
	for _, s := range []string{"sctp", "ospf", "banana", ""} {
		if got := parseProtocol(s); got != ProtoAll {
			t.Errorf("parseProtocol(%q) = %d, want ProtoAll(0)", s, got)
		}
	}
}

func TestProtocolToStringRoundtrip(t *testing.T) {
	for _, name := range []string{"tcp", "udp", "icmp", "icmpv6", "igmp", "gre", "esp"} {
		got := protocolToString(parseProtocol(name))
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
