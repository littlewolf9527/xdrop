//go:build linux && integration

// AUD-PH3-001 regression test: initDynamicConfig must zero ALL
// dynamic-scope config slots on startup, including
// ConfigFastForwardEnabled and ConfigFilterIfindex. Before this fix,
// they were left alone because pre-Phase-3 the config arrays were
// recreated empty on every boot. With map pinning, a pinned config
// map survives restart — if the previous life left FF_ENABLED=1 and
// the next boot is traditional mode, the BPF program would still
// branch into fast-forward code. This test locks in the fix by
// pre-populating FF slots with non-zero values, running
// initDynamicConfig, and asserting they come out zero.
//
// Integration-tagged because it creates a real ebpf.Map (needs CAP_BPF).
package api

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

func newConfigArrayForTest(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "xdrop_cfgut",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: ConfigMapEntries,
	})
	if err != nil {
		t.Skipf("ebpf.NewMap (need CAP_BPF): %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// readSlot returns the uint64 value at config slot idx.
func readSlot(t *testing.T, m *ebpf.Map, idx uint32) uint64 {
	t.Helper()
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, idx)
	var buf [8]byte
	if err := m.Lookup(key, &buf); err != nil {
		t.Fatalf("Lookup slot %d: %v", idx, err)
	}
	return binary.LittleEndian.Uint64(buf[:])
}

// writeSlot stores v at config slot idx.
func writeSlot(t *testing.T, m *ebpf.Map, idx uint32, v uint64) {
	t.Helper()
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, idx)
	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, v)
	if err := m.Update(key, val, ebpf.UpdateExist); err != nil {
		t.Fatalf("Update slot %d: %v", idx, err)
	}
}

// TestInitDynamicConfig_ZerosFFSlots is the AUD-PH3-001 regression
// anchor. Pre-populate a config_a-like array with FF_ENABLED=1 and
// FILTER_IFINDEX=5 (simulating the residue of a previous FF-mode
// agent life on a pinned config map), then run initDynamicConfig,
// and assert those slots come out zero.
func TestInitDynamicConfig_ZerosFFSlots(t *testing.T) {
	m := newConfigArrayForTest(t)

	writeSlot(t, m, ConfigFastForwardEnabled, 1)
	writeSlot(t, m, ConfigFilterIfindex, 5)
	// Also plant non-zero values in the slots that were already being
	// zeroed pre-fix; they should remain zeroed post-fix (no regression).
	writeSlot(t, m, ConfigBlacklistCount, 42)
	writeSlot(t, m, ConfigRuleBitmap, 0xdeadbeef)

	h := &Handlers{}
	if err := h.initDynamicConfig(m); err != nil {
		t.Fatalf("initDynamicConfig: %v", err)
	}

	for _, slot := range []struct {
		name string
		idx  uint32
	}{
		{"ConfigFastForwardEnabled", ConfigFastForwardEnabled},
		{"ConfigFilterIfindex", ConfigFilterIfindex},
		{"ConfigBlacklistCount", ConfigBlacklistCount},
		{"ConfigWhitelistCount", ConfigWhitelistCount},
		{"ConfigRuleBitmap", ConfigRuleBitmap},
		{"ConfigCIDRRuleCount", ConfigCIDRRuleCount},
		{"ConfigCIDRBitmap", ConfigCIDRBitmap},
		{"ConfigRuleMapSelector", ConfigRuleMapSelector},
	} {
		if got := readSlot(t, m, slot.idx); got != 0 {
			t.Errorf("slot %s (idx=%d) = %d after init, want 0", slot.name, slot.idx, got)
		}
	}
}

// TestInitDynamicConfig_LeavesReservedSlotsUntouched confirms the two
// reserved slot indices (3 = ConfigBitmapValid, 8 = ConfigCIDRBitmapValid)
// are explicitly NOT part of the init list — they're preserved as-is.
// This is a negative control that catches an accidental expansion of
// the init list (which would zero operator-written values in those
// reserved slots if they ever get repurposed for compatibility).
func TestInitDynamicConfig_LeavesReservedSlotsUntouched(t *testing.T) {
	m := newConfigArrayForTest(t)

	// Plant sentinels in reserved slots 3 and 8.
	writeSlot(t, m, 3, 0xcafe)
	writeSlot(t, m, 8, 0xbabe)

	h := &Handlers{}
	if err := h.initDynamicConfig(m); err != nil {
		t.Fatalf("initDynamicConfig: %v", err)
	}

	if got := readSlot(t, m, 3); got != 0xcafe {
		t.Errorf("reserved slot 3 was overwritten: got 0x%x, want 0xcafe", got)
	}
	if got := readSlot(t, m, 8); got != 0xbabe {
		t.Errorf("reserved slot 8 was overwritten: got 0x%x, want 0xbabe", got)
	}
}
