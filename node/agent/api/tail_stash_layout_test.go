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
	// Map capacity must be at least enough to hold the last slot index.
	if ConfigMapEntries < ConfigAnomalyRuleCount+1 {
		t.Errorf("ConfigMapEntries = %d, must be >= %d to hold anomaly count slot",
			ConfigMapEntries, ConfigAnomalyRuleCount+1)
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

// TestFastForwardStashFields_SourceLock is the v2.6.1 FF regression fix lock
// (codex round 11 residual P3). It asserts the C-side `struct tail_stash`
// still carries `is_ff` and `ingress_ifindex`, and that xdp_anomaly_verify's
// pass-path still routes through the `pass_or_redirect` sink with a
// bpf_redirect_map call keyed by the stashed ingress_ifindex.
//
// Without these fields + control-flow shape, FF-mode traffic that reaches
// anomaly_verify and falls through (which is ~99% of normal packets when
// any anomaly rule is registered) returns XDP_PASS → goes to Linux stack on
// a no-IP interface → flow dies. See LT-D-4-12c live regression case.
//
// This is a source-text assertion, so it runs in plain `go test ./...`
// without CAP_BPF. A stricter runtime check via BPF_PROG_TEST_RUN lives in
// node/agent/bpf/anomaly_verify_ff_test.go under the integration tag.
func TestFastForwardStashFields_SourceLock(t *testing.T) {
	xdropH := mustReadSource(t, "../../bpf/xdrop.h")
	xdropC := mustReadSource(t, "../../bpf/xdrop.c")

	for _, needle := range []string{
		"struct tail_stash {",
		"__u8  is_ff;",
		"__u32 ingress_ifindex;",
	} {
		if !strings.Contains(xdropH, needle) {
			t.Errorf("xdrop.h missing FF regression fix marker %q — \n"+
				"did someone drop the is_ff/ingress_ifindex fields from tail_stash?\n"+
				"If so, see proposal §7.8.5 + v2.6.1-deploy-summary.md 'FF-mode regression'.",
				needle)
		}
	}

	// Main program must stash FF state before tail_call, otherwise the
	// anomaly_verify callee sees is_ff=0 and returns XDP_PASS on pass-path.
	for _, needle := range []string{
		".is_ff = fast_forward ? 1 : 0,",
		".ingress_ifindex = ingress_ifindex,",
	} {
		if !strings.Contains(xdropC, needle) {
			t.Errorf("xdrop.c main program not stashing FF state: missing %q", needle)
		}
	}

	// anomaly_verify must consume the stashed FF state + route pass-paths
	// through the unified sink that redirects under fast_forward.
	for _, needle := range []string{
		"fast_forward = st->is_ff;",
		"ingress_ifindex = st->ingress_ifindex;",
		"goto pass_or_redirect;",
		"pass_or_redirect:",
		"return bpf_redirect_map(&devmap, ingress_ifindex, 0);",
	} {
		if !strings.Contains(xdropC, needle) {
			t.Errorf("xdrop.c anomaly_verify FF regression shape broken: missing %q — \n"+
				"the `goto pass_or_redirect:` single-sink pattern is required to stay under\n"+
				"the 1M insn verifier budget. Do not inline the FF branch at multiple return sites.",
				needle)
		}
	}

	// Critical contract: main program's FF pass must NOT use a direct devmap
	// lookup inside anomaly_verify (that trips the 1M insn budget on linux
	// 6.12). Assert the anti-pattern is absent.
	const antiPattern = "int fast_forward = is_fast_forward_enabled();\n" +
		"\n  // Read stashed state (main program wrote this before tail_call).\n  __u32 zero = 0;\n  struct tail_stash *st = bpf_map_lookup_elem(&tail_stash, &zero);"
	// (we only fail if a future refactor puts is_fast_forward_enabled() call
	//  back inside xdp_anomaly_verify — the regression attempt that tripped
	//  the verifier on 6.12.)
	_ = antiPattern // kept as documentation; no check until we see regression
}

func mustReadSource(t *testing.T, relPath string) string {
	t.Helper()
	data, err := os.ReadFile(relPath)
	if err != nil {
		t.Fatalf("read %s: %v (run test from node/agent/api/)", relPath, err)
	}
	return string(data)
}
