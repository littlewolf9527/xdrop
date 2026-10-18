//go:build linux && integration

package bpf

import "testing"

// This witness checks state location AFTER a packet reaches the pure rule.
// Structural map retirement is checked last so a tuple-map mutant cannot be
// rejected by an earlier ELF-shape guard instead of exercising the bucket path.
func TestCut54PureStateLocation(t *testing.T) {
	cpus := td074Environment(t)
	for _, path := range []string{"exact-tuple", "cidr-tuple"} {
		t.Run(path, func(t *testing.T) {
			c := b1LogicalLoad(t, "")
			rig := td074Setup(t, c, path, cpus[0], 1, 4096)
			td074Pinned(t, cpus[0], func() {
				if got := rig.run(t); got != srcXDPPass {
					t.Fatalf("pure rate cold packet failed before state readback: %d", got)
				}
			})
			t.Logf("CUT54_PURE_STATE_REACHED path=%s flag=0 packet=1 verdict=PASS", path)
			counts := b1LogicalCounts(t, c, 778)
			if counts.Match != 1 || counts.Drop != 0 {
				t.Fatalf("flag-zero hit must increment id_counts[778] to 1/0: %+v", counts)
			}
			var values []b1Bucket
			if err := c.Maps["id_rl_states"].Lookup(uint32(778), &values); err != nil {
				t.Fatalf("flag-zero rate must create id_rl_states[778]: %v", err)
			}
			seen := 0
			for _, v := range values {
				if v.Last != 0 {
					seen++
					if v.Tokens != 0 {
						t.Fatalf("pure logical token balance=%d want=0", v.Tokens)
					}
				}
			}
			if seen != 1 {
				t.Fatalf("pure logical initialized CPUs=%d want=1", seen)
			}
			for _, name := range []string{"rl_states", "cidr_rl_states"} {
				if c.Maps[name] != nil {
					t.Fatalf("retired tuple map remains after logical path witness: %s", name)
				}
			}
		})
	}
	t.Log("CUT54_PURE_STATE cases=2 reached_flag_zero=2 logical_counter_increments=2 logical_buckets=2 tuple_maps=0")
}
