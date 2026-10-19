//go:build linux && integration

package api

import (
	"testing"

	"github.com/cilium/ebpf"
)

// TestTD149AtomicFlipPreservesPass: atomic sync copies every active config slot
// to the shadow before flipping, so slot 12 (deep chains pass) written at
// startup must survive two flips (blind review r1 P2-3; real maps because the
// atomic path reconciles logical-state maps).
func TestTD149AtomicFlipPreservesPass(t *testing.T) {
	h, _ := jiaHandler(t)
	for _, m := range []*ebpf.Map{h.configA, h.configB} {
		if err := m.Update(uint32(ConfigIPv6DeepChainPass), uint64(1), ebpf.UpdateExist); err != nil {
			t.Fatal(err)
		}
	}
	r := Rule{ID: "a", LogicalID: 1, SrcIP: "192.0.2.1", Protocol: "tcp", Action: "drop"}
	for step, rules := range [][]Rule{{r}, nil} {
		before := h.activeSlot
		if _, err := h.DoAtomicSync(rules); err != nil {
			t.Fatal(err)
		}
		_, active, _ := h.configPublishTables()
		var got uint64
		if err := active.Lookup(uint32(ConfigIPv6DeepChainPass), &got); err != nil {
			t.Fatal(err)
		}
		if h.activeSlot == before || got != 1 {
			t.Fatalf("step=%d flipped=%t active slot12=%d want 1", step, h.activeSlot != before, got)
		}
	}
	t.Log("TD149_ATOMIC_FLIP flips=2 active_slot12=1")
}
