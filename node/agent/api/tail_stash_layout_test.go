// tail_stash_layout_test.go — config-slot, anomaly-bit and retired-dispatch locks.
//
// struct tail_stash and the anomaly tail-call program are retired (TD-081);
// TestFastForwardStashFields_SourceLock asserts they stay gone. The other
// tests lock config slot indices and match_anomaly bit assignments.
package api

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestConfigAnomalyRuleCountIndex locks the config slot indices the agent writes.
// Slot 10 (ConfigAnomalyRuleCount) is retired and must not be reused; slots 11
// and 12 must match xdrop.h CONFIG_RL_CPU_DIVISOR / CONFIG_MAP_ENTRIES (this
// test does not read xdrop.h).
func TestConfigAnomalyRuleCountIndex(t *testing.T) {
	if ConfigAnomalyRuleCount != 10 {
		t.Errorf("ConfigAnomalyRuleCount = %d, want 10 (retired slot: xdrop.h says \"Config slot 10 is retired\"; initDynamicConfig keeps it zero)",
			ConfigAnomalyRuleCount)
	}
	if ConfigRLCPUDivisor != 11 {
		t.Errorf("ConfigRLCPUDivisor = %d, want 11 (must match xdrop.h CONFIG_RL_CPU_DIVISOR)",
			ConfigRLCPUDivisor)
	}
	if ConfigMapEntries != 13 {
		t.Errorf("ConfigMapEntries = %d, want 13 (must match xdrop.h CONFIG_MAP_ENTRIES)",
			ConfigMapEntries)
	}
	// Map capacity must be at least enough to hold the last slot index.
	if ConfigMapEntries < ConfigRLCPUDivisor+1 {
		t.Errorf("ConfigMapEntries = %d, must be >= %d to hold rate-limit divisor slot",
			ConfigMapEntries, ConfigRLCPUDivisor+1)
	}
}

// TestAnomalyBitsStable binds the Go anomaly bits and the node validator's accepted mask to xdrop.h ANOMALY_* defines.
func TestAnomalyBitsStable(t *testing.T) {
	xdropH := mustReadSource(t, "../../bpf/xdrop.h")
	defines := regexp.MustCompile(`(?m)^#define[ \t]+ANOMALY_([A-Z0-9_]+)[ \t]+0x([0-9A-Fa-f]+)\b`)
	bits := make(map[string]uint8)
	for _, match := range defines.FindAllStringSubmatch(xdropH, -1) {
		value, err := strconv.ParseUint(match[2], 16, 8)
		if err != nil {
			t.Fatalf("ANOMALY_%s: %v", match[1], err)
		}
		bits[match[1]] = uint8(value)
	}
	for _, name := range []string{"BAD_FRAGMENT", "INVALID"} {
		if _, ok := bits[name]; !ok {
			t.Fatalf("xdrop.h ANOMALY_%s define missing", name)
		}
	}
	if bits["BAD_FRAGMENT"] != AnomalyBadFragment {
		t.Errorf("ANOMALY_BAD_FRAGMENT = 0x%x, Go AnomalyBadFragment = 0x%x", bits["BAD_FRAGMENT"], AnomalyBadFragment)
	}
	if bits["INVALID"] != AnomalyInvalid {
		t.Errorf("ANOMALY_INVALID = 0x%x, Go AnomalyInvalid = 0x%x", bits["INVALID"], AnomalyInvalid)
	}
	if AnomalyBadFragment != 0x01 {
		t.Errorf("AnomalyBadFragment = 0x%x, want 0x01 — xSight decoder registry lock", AnomalyBadFragment)
	}
	if AnomalyInvalid != 0x02 {
		t.Errorf("AnomalyInvalid = 0x%x, want 0x02 — xSight decoder registry lock", AnomalyInvalid)
	}
	var mask uint8
	for _, value := range bits {
		mask |= value
	}
	for i := 0; i < 8; i++ {
		bit := uint8(1 << i)
		err := validateNodeAnomalyFields(bit, "drop", "", "198.51.100.1", "", "")
		if (err == nil) != (bit&mask != 0) {
			t.Errorf("anomaly bit=0x%02x mask=0x%02x err=%v", bit, mask, err)
		}
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
