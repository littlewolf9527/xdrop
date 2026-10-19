// protocol_strict_test.go — an unrecognised protocol name must be rejected at
// every site that builds a rule key (S0-6, 2026-09-14, external audit D-09,
// owner decision 2026-09-05).
//
// The lenient parser maps anything it does not recognise to ProtoAll, and
// ProtoAll in a key means "match every protocol". So a typo — "tpc" for "tcp" —
// silently turned a rule aimed at one protocol into one matching all of them,
// and the resulting combo was perfectly valid, so nothing downstream objected.
// The whitelist path had used the strict parser all along; the rule paths had not.
//
// The audit named only ruleToKey. Sweeping the callers turned up three more key
// builders on the CIDR paths with the same shape; all four were fixed.
//
// 🔴 Coverage, stated precisely (re-checked 2026-10-19):
//
//	ruleToKey                 ✅ direct (tests below)
//	addCIDRRuleFromSync       — removed with the per-rule / batch entries (protocol 7)
//	AddRule → addCIDRRule     — removed with the per-rule / batch entries (protocol 7)
//	CIDR key builders today   ⛔ NOT covered by this file: prepareAtomicRule
//	                             (condition_atomic.go) and classifyRuleKey
//	                             (condition_groups.go). Do not read this file as
//	                             behavioural proof for those paths.
package api

import (
	"testing"

	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

func TestRuleToKeyRejectsUnknownProtocol(t *testing.T) {
	h := &Handlers{}
	for _, proto := range []string{"tpc", "sctp", "ospf", "banana"} {
		t.Run(proto, func(t *testing.T) {
			key, err := h.ruleToKey(Rule{DstIP: "192.0.2.10", Protocol: proto, Action: "drop"})
			if err == nil {
				t.Fatalf("unknown protocol %q accepted; key.Protocol=%d (ProtoAll=%d) — "+
					"the rule would match every protocol", proto, key.Protocol, ProtoAll)
			}
		})
	}
}

// Control: the strict parser must still accept everything real. Without this,
// a ruleToKey that rejects unconditionally would satisfy the test above.
func TestRuleToKeyAcceptsKnownProtocols(t *testing.T) {
	h := &Handlers{}
	for _, tc := range []struct {
		proto string
		want  uint8
	}{
		{"", ProtoAll},
		{"all", ProtoAll},
		{"tcp", ProtoTCP},
		{"udp", ProtoUDP},
		{"icmp", ProtoICMP},
	} {
		t.Run("proto="+tc.proto, func(t *testing.T) {
			key, err := h.ruleToKey(Rule{DstIP: "192.0.2.10", Protocol: tc.proto, Action: "drop"})
			if err != nil {
				t.Fatalf("known protocol %q rejected: %v", tc.proto, err)
			}
			if key.Protocol != tc.want {
				t.Errorf("protocol %q → %d, want %d", tc.proto, key.Protocol, tc.want)
			}
		})
	}
}

func newProtoTestHandlers() *Handlers {
	srcV4, dstV4 := newFakeTrie(), newFakeTrie()
	srcV6, dstV6 := newFakeTrie(), newFakeTrie()
	return &Handlers{cidrMgr: cidr.NewManager(srcV4, dstV4, srcV6, dstV6, newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie())}
}

// Instrument check: the CIDR manager list observes allocations (its original subject test was retired with protocol 7).
// Without this, "nothing was allocated" would also be the reading if
// ListSrcCIDRs could never return anything.
func TestCIDRManagerListReflectsAllocation(t *testing.T) {
	h := newProtoTestHandlers()
	if _, err := h.cidrMgr.ReserveSrcID("192.0.2.0/24"); err != nil {
		t.Fatalf("ReserveSrcID: %v", err)
	}
	if got := h.cidrMgr.ListSrcCIDRs(); len(got) != 1 {
		t.Fatalf("the allocation instrument does not observe allocations: %v", got)
	}
}

// No key-building site may use the lenient parser. This is the invariant the
// rename (parseProtocol → parseProtocolLenient) exists to make visible; the
// facts gate asserts the source-level version of it.
func TestLenientParserStillLenient(t *testing.T) {
	if got := parseProtocolLenient("tpc"); got != ProtoAll {
		t.Fatalf("parseProtocolLenient changed behaviour (%d) — the remaining "+
			"callers are 'is this TCP?' guards that rely on it", got)
	}
}
