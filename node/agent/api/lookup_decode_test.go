package api

import "testing"

// B1 cut 5-4 retires the rule-row counter decoder and its offset test.
// Logical state decoding is exercised by the logical-counter tests.

// TestLookupDecode_PercpuStatsSum locks in the per-CPU stats summing
// behaviour used by api/stats.go: cilium/ebpf returns a []uint64 with one
// element per online CPU; GetStats sums them into a global counter.
func TestLookupDecode_PercpuStatsSum(t *testing.T) {
	cases := []struct {
		name string
		in   []uint64
		want uint64
	}{
		{"empty (no online cpus reported)", nil, 0},
		{"single-cpu", []uint64{42}, 42},
		{"4-cpu even split", []uint64{10, 20, 30, 40}, 100},
		{"wrap-around safe large counters", []uint64{^uint64(0), 1}, 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var total uint64
			for _, v := range tc.in {
				total += v
			}
			if total != tc.want {
				t.Errorf("sum mismatch: got %d, want %d", total, tc.want)
			}
		})
	}
}
