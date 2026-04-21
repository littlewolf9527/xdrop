// rt_probe.go — PREEMPT_RT kernel detection for v2.6.1 B5 anomaly data plane.
//
// B5's per-CPU single-entry tail_stash (proposal §7.8.5 D1) relies on "BPF
// program execution is atomic on the same logical CPU" for same-CPU state
// handoff across bpf_tail_call. On PREEMPT_RT kernels this invariant is
// weakened: BPF programs may be interrupted and another BPF program may run
// on the same CPU before the first resumes, overwriting the single-slot
// scratch. See proposal §7.8.5 D1 "RT 边界" for the full rationale.
//
// The v2.6.1 policy (D1): detect RT at startup and skip wiring the
// prog_tail_map[0] entry. Main program's bpf_tail_call then fallthroughs to
// XDP_PASS — functionally equivalent to v2.6.0 stub-no-match behavior, but
// the Controller-side API still accepts anomaly rules so the user's
// configuration management isn't broken.
//
// Detection method (in order):
//   1. /sys/kernel/realtime — RT patchset exposes this as a sysfs flag.
//      Content "1" means running RT. Non-RT kernels don't create this file.
//   2. /proc/version — fallback. Includes "PREEMPT_RT" when the kernel was
//      built with the RT patchset.
package main

import (
	"os"
	"strings"
)

// isRTKernel returns true when the current kernel was built with
// CONFIG_PREEMPT_RT. Conservative: returns false on any read error rather
// than falsely reporting RT (wrongly disabling anomaly on a non-RT kernel
// is worse than wrongly enabling it on RT — worst case on misdetected RT
// is the documented "unsafe on RT" behavior, while wrongly disabling on
// non-RT breaks the feature with no failure mode).
func isRTKernel() bool {
	// Primary: /sys/kernel/realtime
	if b, err := os.ReadFile("/sys/kernel/realtime"); err == nil {
		return strings.TrimSpace(string(b)) == "1"
	}

	// Fallback: /proc/version
	if b, err := os.ReadFile("/proc/version"); err == nil {
		return strings.Contains(string(b), "PREEMPT_RT")
	}

	return false
}
