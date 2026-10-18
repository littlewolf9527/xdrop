//go:build linux && integration

// FF slots survive startup; traditional-mode clearing is tested in the root package.
// Integration-tagged because this creates a real ebpf.Map.
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

// Preserve FF while retaining business-slot initialization.
func TestInitDynamicConfig_PreservesFFSlots(t *testing.T) {
	m := newConfigArrayForTest(t)

	writeSlot(t, m, ConfigFastForwardEnabled, 1)
	writeSlot(t, m, ConfigFilterIfindex, 5)
	writeSlot(t, m, ConfigRLCPUDivisor, 99)
	// Also plant non-zero values in the slots that were already being
	// zeroed pre-fix; they should remain zeroed post-fix (no regression).
	writeSlot(t, m, ConfigBlacklistCount, 42)
	writeSlot(t, m, ConfigRuleBitmap, 0xdeadbeef)

	h := &Handlers{}
	if err := h.initDynamicConfig(m); err != nil {
		t.Fatalf("initDynamicConfig: %v", err)
	}

	for slot, want := range map[uint32]uint64{ConfigFastForwardEnabled: 1, ConfigFilterIfindex: 5} {
		if got := readSlot(t, m, slot); got != want {
			t.Errorf("FF slot %d = %d want preserved %d", slot, got, want)
		}
	}
	for _, slot := range []struct {
		name string
		idx  uint32
	}{
		{"ConfigBlacklistCount", ConfigBlacklistCount},
		{"ConfigWhitelistCount", ConfigWhitelistCount},
		{"ConfigRuleBitmap", ConfigRuleBitmap},
		{"ConfigWLBitmap", ConfigWLBitmap}, // Phase 8: slot 3
		{"ConfigCIDRRuleCount", ConfigCIDRRuleCount},
		{"ConfigCIDRBitmap", ConfigCIDRBitmap},
		{"ConfigWLMapSelector", ConfigWLMapSelector}, // Phase 8: slot 8
		{"ConfigRuleMapSelector", ConfigRuleMapSelector},
		{"ConfigRLCPUDivisor", ConfigRLCPUDivisor},
	} {
		if got := readSlot(t, m, slot.idx); got != 0 {
			t.Errorf("slot %s (idx=%d) = %d after init, want 0", slot.name, slot.idx, got)
		}
	}
}

// TestInitDynamicConfig_ZerosPhase8Slots confirms that Phase 8 slots 3 (ConfigWLBitmap)
// and 8 (ConfigWLMapSelector) are explicitly initialized to 0 by initDynamicConfig.
// These were formerly reserved (ConfigBitmapValid / ConfigCIDRBitmapValid) and are now
// repurposed for whitelist dual-buffer control. The old "leave untouched" behavior is
// replaced by "zero on boot" to prevent stale values from surviving agent restarts.
func TestInitDynamicConfig_ZerosPhase8Slots(t *testing.T) {
	m := newConfigArrayForTest(t)

	// Pre-populate Phase 8 slots with non-zero sentinels (simulating stale pinned state).
	writeSlot(t, m, ConfigWLBitmap, 0xcafe)
	writeSlot(t, m, ConfigWLMapSelector, 0xbabe)

	h := &Handlers{}
	if err := h.initDynamicConfig(m); err != nil {
		t.Fatalf("initDynamicConfig: %v", err)
	}

	if got := readSlot(t, m, ConfigWLBitmap); got != 0 {
		t.Errorf("ConfigWLBitmap (slot 3) = 0x%x after init, want 0 (must be zeroed on boot)", got)
	}
	if got := readSlot(t, m, ConfigWLMapSelector); got != 0 {
		t.Errorf("ConfigWLMapSelector (slot 8) = 0x%x after init, want 0 (must be zeroed on boot)", got)
	}
}
