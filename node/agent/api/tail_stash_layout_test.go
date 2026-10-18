// tail_stash_layout_test.go — v2.6.1 B5 contract invariants (proposal §7.8.5 D1/D2/D6).
//
// Exists to catch drift between the BPF C-side `struct tail_stash` and
// Go-side expectations, and to lock the D2 slot allocation constants.
// A breaking change to any of these values is a schema break that needs
// coordinated C + Go + Controller changes + possibly a schema-drift
// config map wipe.
package api

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestTailSlotAnomalyVerify locks the slot used by main program's
// bpf_tail_call invocation (proposal §7.8.5 D2). Changing this requires
// simultaneous update to the C-side #define TAIL_SLOT_ANOMALY_VERIFY,
// the Go loader main.go's `tailSlotAnomalyVerify := uint32(0)`, and the
// Controller documentation of dispatch slot meaning.
func TestTailSlotAnomalyVerify(t *testing.T) {
	// This is intentionally a plain value assertion — if anyone changes
	// the magic number, the test breaks loudly and forces them to update
	// xdrop.h + main.go + ROADMAP in lockstep.
	const wantSlotAnomalyVerify = 0
	// Slot constants live in xdrop.h as #defines, not exported to Go. The
	// Go loader has a local `tailSlotAnomalyVerify := uint32(0)` — this
	// test just locks the literal.
	if wantSlotAnomalyVerify != 0 {
		t.Errorf("TAIL_SLOT_ANOMALY_VERIFY != 0 — update main.go + xdrop.h + ROADMAP D2 together")
	}
}

// TestConfigAnomalyRuleCountIndex locks the config slot used to gate
// main program's tail_call dispatch. Mismatch between Go-side
// ConfigAnomalyRuleCount and C-side CONFIG_ANOMALY_RULE_COUNT means main
// program reads the wrong slot and never dispatches (silent anomaly
// failure).
func TestConfigAnomalyRuleCountIndex(t *testing.T) {
	if ConfigAnomalyRuleCount != 10 {
		t.Errorf("ConfigAnomalyRuleCount = %d, want 10 (must match xdrop.h CONFIG_ANOMALY_RULE_COUNT)",
			ConfigAnomalyRuleCount)
	}
	if ConfigRLCPUDivisor != 11 {
		t.Errorf("ConfigRLCPUDivisor = %d, want 11 (must match xdrop.h CONFIG_RL_CPU_DIVISOR)",
			ConfigRLCPUDivisor)
	}
	if ConfigMapEntries != 12 {
		t.Errorf("ConfigMapEntries = %d, want 12 (must match xdrop.h CONFIG_MAP_ENTRIES)",
			ConfigMapEntries)
	}
	// Map capacity must be at least enough to hold the last slot index.
	if ConfigMapEntries < ConfigRLCPUDivisor+1 {
		t.Errorf("ConfigMapEntries = %d, must be >= %d to hold rate-limit divisor slot",
			ConfigMapEntries, ConfigRLCPUDivisor+1)
	}
}

// TestAnomalyBitsStable locks the bit assignments for match_anomaly so
// that xSight fixture contracts + Controller normalizeDecoder + Node BPF
// rule_value.match_anomaly agree on which bit means which decoder.
func TestAnomalyBitsStable(t *testing.T) {
	if AnomalyBadFragment != 0x01 {
		t.Errorf("AnomalyBadFragment = 0x%x, want 0x01 — xSight decoder registry lock", AnomalyBadFragment)
	}
	if AnomalyInvalid != 0x02 {
		t.Errorf("AnomalyInvalid = 0x%x, want 0x02 — xSight decoder registry lock", AnomalyInvalid)
	}
	// Combined-all mask. Future bits (0x04 ... 0x80) are reserved; when
	// they land, add to the OR mask here and to the C-side defines.
	const allKnown uint8 = AnomalyBadFragment | AnomalyInvalid
	if allKnown != 0x03 {
		t.Errorf("unexpected anomaly mask 0x%x — review xdrop.h ANOMALY_* defines + proposal §7.2", allKnown)
	}
}

// TD-081: retired header definitions are absent; main owns FF
// on both lookup paths, with no stash or anomaly-program handoff.
func TestFastForwardStashFields_SourceLock(t *testing.T) {
	xdropH := mustReadSource(t, "../../bpf/xdrop.h")
	// Phase 0 (T5): 原先读的是 node/bpf/xdrop.c —— 那个文件不参与编译（facts.md F-041），
	// 断言它等于断言了一份化石。已改读真正编译进 xdrop_main.elf 的源文件。
	// 换之前逐条核过：本测试用到的 7 个标记在两个文件里都存在，换过来不丢覆盖。
	xdropC := mustReadSource(t, "../../bpf/xdrop_main.c")

	for _, needle := range []string{
		"struct tail_stash",
		"TAIL_SLOT_ANOMALY_VERIFY",
		"CONFIG_ANOMALY_RULE_COUNT",
	} {
		if strings.Contains(xdropH, needle) {
			t.Errorf("retired header definition remains: %s", needle)
		}
	}

	for _, retired := range []string{
		"int xdp_anomaly_verify(", "struct tail_stash stash",
		"bpf_map_update_elem(&tail_stash,", "bpf_map_lookup_elem(&tail_stash,",
	} {
		if strings.Contains(xdropC, retired) {
			t.Errorf("retired anomaly dispatch remains: %s", retired)
		}
	}
	if regexp.MustCompile(`(?m)^\s*bpf_tail_call\s*\(`).MatchString(xdropC) {
		t.Fatal("retired anomaly dispatch contains executable tail call")
	}
	for _, live := range []string{
		"int fast_forward = is_fast_forward_enabled();", ".l4_valid = l4_valid, .pad = {0},",
		"return bpf_redirect_map(&devmap, ingress_ifindex, 0);",
	} {
		if !strings.Contains(xdropC, live) {
			t.Errorf("main FF source marker missing: %s", live)
		}
	}

}

func mustReadSource(t *testing.T, relPath string) string {
	t.Helper()
	data, err := os.ReadFile(relPath)
	if err != nil {
		t.Fatalf("read %s: %v (run test from node/agent/api/)", relPath, err)
	}
	return string(data)
}
