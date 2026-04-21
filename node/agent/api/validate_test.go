// validate_test.go — unit tests for protocol / TCP flag parsing helpers.
//
// v2.6 Phase 1: adds coverage for gre / esp / igmp enum + roundtrip.
// v2.6 Phase 2: additional tcp_flags coverage lands here when needed; node
// parseTcpFlags itself is untouched by the decoder-sugar work (that sugar
// lives in the Controller). The bit-level assertions below are the contract
// the Controller's normalizeDecoder depends on.
package api

import "testing"

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
