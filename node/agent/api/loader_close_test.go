//go:build linux && integration

// NEW-UT-05 (§8.1.2 + §7 "coll.Close() not called on all exit paths"
// mitigation): after loading a cilium/ebpf Collection and then Closing it,
// no BPF fds should leak. Phase 2 main.go calls coll.Close() in the
// shutdown goroutine — this test verifies the fd-release behaviour on
// cilium's side directly, independently of the Agent lifecycle so a
// regression in cilium or an accidental fd copy surfaces here instead
// of as a lab-only slow leak.
//
// Run via: `go test -tags=integration -race -run TestCollectionClose ./api`
// on the lab host (needs CAP_BPF).
package api

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// countFDs returns the number of open file descriptors for the current
// process by enumerating /proc/self/fd. The count naturally includes
// stdin/stdout/stderr + runtime-held fds; we care only about the delta.
func countFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// TestCollectionClose_ReleasesAllFDs asserts that creating and then closing
// a multi-map Collection does not leak fds. Baseline is sampled twice to
// wash out any runtime lazily-opened fds that happen on first reflection
// through the ebpf package.
func TestCollectionClose_ReleasesAllFDs(t *testing.T) {
	// Warm up cilium/ebpf's internal lazy init (feature probes, etc.) —
	// these open fds that stay for the lifetime of the process and would
	// otherwise pollute the first sample.
	warm, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "xdrop_warm",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("cannot create warm-up map (no CAP_BPF?): %v", err)
	}
	_ = warm.Close()

	baseline := countFDs(t)

	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"m1": {Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 4},
			"m2": {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 4},
			"m3": {Type: ebpf.LPMTrie, KeySize: 8, ValueSize: 4, MaxEntries: 4, Flags: 1},
		},
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection: %v", err)
	}
	afterLoad := countFDs(t)
	if delta := afterLoad - baseline; delta < 3 {
		t.Fatalf("NewCollection opened %d fds, expected at least 3 (one per map)", delta)
	}

	coll.Close()

	afterClose := countFDs(t)
	if delta := afterClose - baseline; delta != 0 {
		t.Errorf("Collection.Close() leaked %d fds (baseline=%d, afterClose=%d)",
			delta, baseline, afterClose)
	}
}
