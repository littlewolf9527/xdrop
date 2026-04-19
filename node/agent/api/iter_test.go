//go:build linux && integration

// NEW-UT-07 (§8.1.2): replacing goebpf's GetNextKey-based iteration with
// cilium's `iter := m.Iterate(); iter.Next(&k, &v)` must preserve the
// "visit every key exactly once" contract that xdrop's clearMap relies on
// (config.go). A silent regression here would leave shadow maps partially
// cleared between AtomicSync cycles and let stale rules survive.
//
// Run via: `go test -tags=integration -race -run TestIteration ./api` on
// the lab host (needs CAP_BPF).
package api

import (
	"testing"

	"github.com/cilium/ebpf"
)

// TestIterationParity_VisitsEachKeyOnce populates a 100-entry HASH map and
// asserts that one full m.Iterate() run yields every key exactly once.
func TestIterationParity_VisitsEachKeyOnce(t *testing.T) {
	const n = 100

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "xdrop_iter",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: n,
	})
	if err != nil {
		t.Skipf("NewMap (need CAP_BPF): %v", err)
	}
	defer m.Close()

	// Populate with deterministic keys 0..n-1 so we can later compare
	// against the expected set.
	for i := uint32(0); i < n; i++ {
		if err := m.Put(i, i*3+1); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}

	seen := make(map[uint32]int, n)
	iter := m.Iterate()
	var k, v uint32
	for iter.Next(&k, &v) {
		seen[k]++
		if got, want := v, k*3+1; got != want {
			t.Errorf("value for key %d: got %d, want %d", k, got, want)
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterator error: %v", err)
	}

	if got := len(seen); got != n {
		t.Fatalf("iteration visited %d distinct keys, expected %d", got, n)
	}
	for i := uint32(0); i < n; i++ {
		if seen[i] != 1 {
			t.Errorf("key %d visited %d times, expected 1", i, seen[i])
		}
	}
}

// TestIterationParity_EmptyMapYieldsNothing locks in the edge case used
// by clearMap when the shadow is already empty: iter.Next must return
// false on the very first call, iter.Err must be nil.
func TestIterationParity_EmptyMapYieldsNothing(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "xdrop_iter_empty",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 4,
	})
	if err != nil {
		t.Skipf("NewMap (need CAP_BPF): %v", err)
	}
	defer m.Close()

	iter := m.Iterate()
	var k, v uint32
	if iter.Next(&k, &v) {
		t.Fatal("empty-map iterator yielded an entry on first Next")
	}
	if err := iter.Err(); err != nil {
		t.Errorf("empty-map iterator Err: %v", err)
	}
}
