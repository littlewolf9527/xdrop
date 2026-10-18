//go:build linux && integration

package bpf

import (
	"crypto/sha256"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
)

// Baseline mode is only for the investigation's historical column; it does not
// relax any TestTD074ELF* acceptance test or alter the production/model sources.
func TestTD074Investigation(t *testing.T) {
	cpus := td074Environment(t)
	if len(cpus) != 8 || mustPossibleCPUs(t) != 8 {
		t.Fatalf("TD074_PROBE requires the PLAN eight-CPU lab, available=%d possible=%d", len(cpus), mustPossibleCPUs(t))
	}
	baseline := os.Getenv("TD074_PROBE_BASELINE") == "1"
	c := b1LogicalLoad(t, "")
	for _, tc := range []struct {
		name               string
		rate               uint32
		all                bool
		newBurst, oldBurst uint64
	}{
		{"S2", 100, true, 25, 26}, {"S1", 100, false, 25, 26}, {"S3", 1, true, 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := td074Setup(t, c, "exact-tuple", cpus[0], tc.rate, 8)
			burst := tc.newBurst
			if baseline {
				burst = tc.oldBurst
			}
			selected := cpus
			if !tc.all {
				selected = cpus[:1]
			}
			var total uint64
			for _, cpu := range selected {
				r.cpu = cpu
				td074Pinned(t, cpu, func() {
					if !baseline {
						td074Cold(t, r, burst)
						total += burst
						return
					}
					// Old cold start: keep the entire burst below one old refill period.
					accepted := false
					for attempt := 0; attempt < 20; attempt++ {
						r.put(t, ratelimit.State{})
						a := td074Clock(t)
						var passed uint64
						for n := uint64(0); n <= burst; n++ {
							if got := r.run(t); got == srcXDPPass {
								passed++
							} else if got != srcXDPDrop {
								t.Fatalf("TD074_PROBE invalid verdict=%d", got)
							}
						}
						b := td074Clock(t)
						if b-a >= ratelimit.NS/((uint64(tc.rate)+7)/8) {
							continue
						}
						if passed != burst {
							t.Fatalf("TD074_PROBE baseline %s cold=%d want=%d", tc.name, passed, burst)
						}
						total += passed
						accepted = true
						break
					}
					if !accepted {
						t.Fatal("TD074_PROBE baseline cold valid=0")
					}
				})
			}
			expected := burst * uint64(len(selected))
			if total != expected {
				t.Fatalf("TD074_PROBE %s total=%d want=%d", tc.name, total, expected)
			}
			t.Logf("TD074_PROBE baseline=%v case=%s expected=%d observed=%d CPUs=%d", baseline, tc.name, expected, total, len(selected))
		})
	}
	// Baseline is a displayed investigation reading; current-tree nonstraddles
	// must agree packet by packet with the shared model, from an emptied bucket.
	for _, tc := range []struct {
		rate uint32
		d    uint64
		pps  int
	}{{100, 8, 20}, {100, 8, 49}, {100, 1, 180}} {
		r := td074Setup(t, c, "exact-tuple", cpus[0], tc.rate, tc.d)
		td074Pinned(t, cpus[0], func() {
			start := td074Clock(t)
			state := ratelimit.State{Tokens: 0, LastUpdate: start}
			r.put(t, state)
			spacing := ratelimit.NS / uint64(tc.pps)
			expected, observed, observedValid, valid, straddle, pauses, disagreements := 0, 0, 0, 0, 0, 0, 0
			for i := 0; i < tc.pps*4; i++ {
				target := start + uint64(i+1)*spacing
				if now := td074Clock(t); now < target {
					time.Sleep(time.Duration(target - now))
				}
				a := td074Clock(t)
				if a > target+spacing {
					pauses++
				}
				got := r.run(t)
				b := td074Clock(t)
				actual := r.read(t)
				lo, hi := ratelimit.ModelTake(state, a, tc.rate, tc.d), ratelimit.ModelTake(state, b, tc.rate, tc.d)
				if got == srcXDPPass {
					observed++
				} else if got != srcXDPDrop {
					t.Fatalf("TD074_PACED invalid verdict=%d", got)
				}
				if !td074SameSignature(lo, hi) {
					straddle++
				} else {
					valid++
					if got == srcXDPPass {
						observedValid++
					}
					if lo.Allowed {
						expected++
					}
					if (got == srcXDPPass) != lo.Allowed {
						disagreements++
					}
					if !baseline {
						td074Check(t, "paced", state, a, b, got, actual, lo)
					}
				}
				state = actual // Always actual previous writeback, including straddling packets.
			}
			if valid == 0 {
				t.Fatal("TD074_PACED valid=0")
			}
			if !baseline && disagreements != 0 {
				t.Fatalf("TD074_PACED mismatch=%d", disagreements)
			}
			t.Logf("TD074_PACED baseline=%v R=%d d=%d pps=%d expected_valid=%d observed_valid=%d observed_total=%d valid=%d straddle=%d scheduling_pauses=%d decision_mismatch=%d", baseline, tc.rate, tc.d, tc.pps, expected, observedValid, observed, valid, straddle, pauses, disagreements)
		})
	}
}

func TestTD074Verifier(t *testing.T) {
	td074Environment(t)
	processed := regexp.MustCompile(`processed ([0-9]+) insns`)
	read := func(path string, expected []string) map[string]int {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		spec, e := ebpf.LoadCollectionSpec(path)
		if e != nil {
			t.Fatal(e)
		}
		if len(spec.Programs) != len(expected) {
			t.Fatalf("TD074_VERIFIER entry set mismatch actual=%d expected=%v", len(spec.Programs), expected)
		}
		for name, m := range spec.Maps {
			if m.Pinning != ebpf.PinNone {
				t.Fatalf("TD074_VERIFIER unexpected pinning %s", name)
			}
		}
		c, e := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}})
		if e != nil {
			t.Fatalf("TD074_VERIFIER load: %+v", e)
		}
		defer c.Close()
		out := map[string]int{}
		for _, name := range expected {
			p := c.Programs[name]
			if p == nil {
				t.Fatalf("TD074_VERIFIER missing program=%s", name)
			}
			t.Logf("TD074_VERIFIER_RAW elf_sha256=%x program=%s\n%s", sha256.Sum256(raw), name, p.VerifierLog)
			matches := processed.FindAllStringSubmatch(p.VerifierLog, -1)
			if len(matches) != 1 {
				t.Fatalf("TD074_VERIFIER processed instruction summary count=%d", len(matches))
			}
			n, e := strconv.Atoi(matches[0][1])
			if e != nil || n <= 0 {
				t.Fatalf("TD074_VERIFIER invalid processed count %q %v", matches[0][1], e)
			}
			out[name] = n
		}
		return out
	}
	beforeEntries, afterEntries := cut54VerifierEntries(t)
	before := read(os.Getenv("XDROP_BASE_BPF_ELF"), beforeEntries)
	after := read(os.Getenv("XDROP_BPF_ELF"), afterEntries)
	if before["xdp_firewall_main"] != 382604 {
		t.Fatalf("CUT54 baseline must be 7e405a7 main=382604, got=%d", before["xdp_firewall_main"])
	}
	gate := read(os.Getenv("XDROP_GATE_ELF"), []string{"xdp_whitelist_gate"})
	delta := after["xdp_firewall_main"] - before["xdp_firewall_main"]
	t.Logf("TD074_VERIFIER main_before=%d main_after=%d delta=%d anomaly=%d gate=%d", before["xdp_firewall_main"], after["xdp_firewall_main"], delta, after["xdp_anomaly_verify"], gate["xdp_whitelist_gate"])
	// Owner ruling #2: retain at least half the kernel's instruction budget
	// per program and limit main's growth independently of the observed counts.
	for stage, counts := range map[string]map[string]int{"before": before, "after": after, "gate": gate} {
		for name, count := range counts {
			if count > 500000 {
				t.Errorf("TD074_VERIFIER stage=%s program=%s processed=%d exceeds 500000", stage, name, count)
			}
		}
	}
	// TD-119: ruling #2's growth limit restarts at main after TD-114; the
	// 7e405a7 identity check above is unchanged.
	if growth := after["xdp_firewall_main"] - td119MainBaseline; growth > 20000 {
		t.Fatalf("TD074_VERIFIER main growth=%d over baseline %d exceeds 20000", growth, td119MainBaseline)
	}
}

// td119MainBaseline is xdp_firewall_main's processed-instruction count on the
// lab kernel after TD-114 (d5c4021, owner-approved +30,347).
const td119MainBaseline = 405692
