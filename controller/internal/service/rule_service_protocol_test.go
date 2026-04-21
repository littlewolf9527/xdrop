// rule_service_protocol_test.go — Phase 1 unit tests for protocol validation.
//
// Covers: controller-side protocol whitelist. Controller's validateProtocol is
// the authoritative reject boundary; Node parseProtocol is deliberately
// permissive (falls back to ProtoAll).
package service

import "testing"

func TestValidateProtocolAcceptsAllKnown(t *testing.T) {
	accepted := []string{"", "all", "tcp", "udp", "icmp", "icmpv6", "igmp", "gre", "esp"}
	for _, p := range accepted {
		if err := validateProtocol(p); err != nil {
			t.Errorf("validateProtocol(%q) rejected known value: %v", p, err)
		}
	}
}

func TestValidateProtocolRejectsUnknown(t *testing.T) {
	rejected := []string{"sctp", "ospf", "banana", "TCP", "Gre", "ipv6-icmp"}
	for _, p := range rejected {
		if err := validateProtocol(p); err == nil {
			t.Errorf("validateProtocol(%q) accepted unknown value", p)
		}
	}
}

func TestValidProtocolsMapEntries(t *testing.T) {
	// Lock the membership so a future edit must update this test.
	want := map[string]bool{
		"":       true,
		"all":    true,
		"tcp":    true,
		"udp":    true,
		"icmp":   true,
		"icmpv6": true,
		"igmp":   true,
		"gre":    true,
		"esp":    true,
	}
	if len(validProtocols) != len(want) {
		t.Fatalf("validProtocols size=%d, want %d", len(validProtocols), len(want))
	}
	for k := range want {
		if !validProtocols[k] {
			t.Errorf("validProtocols missing %q", k)
		}
	}
}
