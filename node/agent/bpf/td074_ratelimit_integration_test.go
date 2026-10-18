//go:build linux && integration

package bpf

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
	"golang.org/x/sys/unix"
)

func td074Clock(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Sec)*ratelimit.NS + uint64(ts.Nsec)
}
func td074Environment(t *testing.T) []int {
	t.Helper()
	self, e := os.Readlink("/proc/self/ns/time")
	if e != nil {
		t.Fatal(e)
	}
	init, e := os.Readlink("/proc/1/ns/time")
	if e != nil {
		t.Fatal(e)
	}
	if self != init {
		t.Fatalf("TD074_PRECONDITION initial time namespace required: self=%s pid1=%s", self, init)
	}
	if os.Geteuid() != 0 {
		t.Fatal("TD074_PRECONDITION root required")
	}
	n, e := ebpf.PossibleCPU()
	if e != nil {
		t.Fatal(e)
	}
	var set unix.CPUSet
	if e = unix.SchedGetaffinity(0, &set); e != nil {
		t.Fatal(e)
	}
	var cpus []int
	for cpu := 0; cpu < n && cpu < 1024; cpu++ {
		if set.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) == 0 {
		t.Fatal("TD074_PRECONDITION no available CPU")
	}
	return cpus
}
func td074Pinned(t *testing.T, cpu int, fn func()) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var old, one unix.CPUSet
	if e := unix.SchedGetaffinity(0, &old); e != nil {
		t.Fatal(e)
	}
	one.Set(cpu)
	if e := unix.SchedSetaffinity(0, &one); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := unix.SchedSetaffinity(0, &old); e != nil {
			t.Error(e)
		}
	}()
	fn()
}

type td074Rig struct {
	c       *ebpf.Collection
	bucket  *ebpf.Map
	key     any
	path    string
	cpu, n  int
	rate    uint32
	divisor uint64
}

func td074Setup(t *testing.T, c *ebpf.Collection, path string, cpu int, rate uint32, d uint64) *td074Rig {
	t.Helper()
	cidr := path == "cidr-tuple" || path == "cidr-conditional"
	conditional := path == "exact-conditional" || path == "cidr-conditional"
	b1LogicalReset(t, c, cidr, 0, 0)
	b1Put(t, c, "config_a", uint32(api.ConfigRLCPUDivisor), d)
	key := b1Key(cidr, 6, true)
	r, _, _, _ := b1Maps(cidr, 0)
	rig := &td074Rig{c: c, path: path, cpu: cpu, n: mustPossibleCPUs(t), rate: rate, divisor: d}
	if conditional {
		row := b1OpenRow(1)
		row.Action[0] = api.ActionRateLimit
		row.Rate[0] = rate
		row.RuleID[0] = 777
		b1SetRow(t, c, cidr, 0, 6, row)
		rig.bucket = c.Maps["id_rl_states"]
		rig.key = uint32(777)
	} else {
		b1Put(t, c, r, key, b1Wire(t, api.RuleValue{LogicalID: 778, Action: api.ActionRateLimit, RateLimit: rate}))
		rig.bucket = c.Maps["id_rl_states"]
		rig.key = uint32(778)
	}
	return rig
}
func (r *td074Rig) put(t *testing.T, s ratelimit.State) {
	t.Helper()
	values := make([]ratelimit.State, r.n)
	values[r.cpu] = s
	if e := r.bucket.Put(r.key, values); e != nil {
		t.Fatal(e)
	}
}
func (r *td074Rig) read(t *testing.T) ratelimit.State {
	t.Helper()
	var values []ratelimit.State
	if e := r.bucket.Lookup(r.key, &values); e != nil {
		t.Fatal(e)
	}
	if len(values) != r.n {
		t.Fatalf("TD074_BUCKET CPU count=%d want=%d", len(values), r.n)
	}
	return values[r.cpu]
}
func (r *td074Rig) run(t *testing.T) uint32 {
	t.Helper()
	var got uint32
	// t.Run executes in another goroutine, so pin at the syscall boundary,
	// even when a parent test has already pinned its own OS thread.
	td074Pinned(t, r.cpu, func() {
		var e error
		got, e = r.c.Programs["xdp_firewall_main"].Run(&ebpf.RunOptions{Data: b1LogicalPacket(64), Repeat: 1})
		if e != nil {
			t.Fatal(e)
		}
	})
	return got
}

// PLAN signature includes future normalization and symbolic assignment "now".
func td074SameSignature(lo, hi ratelimit.Result) bool {
	if lo.Allowed != hi.Allowed || lo.State.Tokens != hi.State.Tokens || lo.Branch != hi.Branch || lo.NormalizedFuture != hi.NormalizedFuture {
		return false
	}
	if lo.Branch == "advance" {
		return lo.Advance == hi.Advance
	}
	if (lo.Branch == "addzero" || lo.Branch == "drop") && !lo.NormalizedFuture {
		return lo.State.LastUpdate == hi.State.LastUpdate
	}
	return true
}
func td074Check(t *testing.T, label string, initial ratelimit.State, a, b uint64, got uint32, state ratelimit.State, want ratelimit.Result) {
	t.Helper()
	verdict := uint32(srcXDPDrop)
	if want.Allowed {
		verdict = srcXDPPass
	}
	if got != verdict || state.Tokens != want.State.Tokens {
		t.Fatalf("TD074_WITNESS %s verdict=%d tokens=%d want verdict=%d tokens=%d branch=%s initial=%+v a=%d b=%d", label, got, state.Tokens, verdict, want.State.Tokens, want.Branch, initial, a, b)
	}
	if want.Branch == "new" || want.Branch == "full" || want.NormalizedFuture {
		if state.LastUpdate < a || state.LastUpdate > b {
			t.Fatalf("TD074_WITNESS %s last=%d want now in [%d,%d] branch=%s", label, state.LastUpdate, a, b, want.Branch)
		}
	} else if state.LastUpdate != want.State.LastUpdate {
		t.Fatalf("TD074_WITNESS %s last=%d want=%d delta=%d want_delta=%d branch=%s", label, state.LastUpdate, want.State.LastUpdate, state.LastUpdate-initial.LastUpdate, want.State.LastUpdate-initial.LastUpdate, want.Branch)
	}
}

// Only single-packet trials reset state. Continuations consume actual writeback.
func td074Trial(t *testing.T, r *td074Rig, label string, initial func(uint64) ratelimit.State, requireAddZero bool) (ratelimit.State, uint64, int) {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		a := td074Clock(t)
		s := initial(a)
		r.put(t, s)
		got := r.run(t)
		b := td074Clock(t)
		state := r.read(t)
		lo, hi := ratelimit.ModelTake(s, a, r.rate, r.divisor), ratelimit.ModelTake(s, b, r.rate, r.divisor)
		// The named full/add=0 cell additionally requires add=0 throughout its
		// bracket: otherwise mutation 7 could be hidden by the add>0 guard.
		if !td074SameSignature(lo, hi) || (requireAddZero && (lo.Add != 0 || hi.Add != 0)) {
			continue
		}
		if requireAddZero {
			t.Run("first-writeback", func(t *testing.T) { td074Check(t, r.path+"/"+label, s, a, b, got, state, lo) })
		} else {
			td074Check(t, r.path+"/"+label, s, a, b, got, state, lo)
		}
		return state, a, attempt
	}
	t.Fatalf("TD074_WITNESS %s/%s valid=0 after 20 attempts", r.path, label)
	return ratelimit.State{}, 0, 20
}

func TestTD074ELFWitnesses(t *testing.T) {
	cpus := td074Environment(t)
	c := b1LogicalLoad(t, "")
	for _, path := range []string{"exact-tuple", "cidr-tuple", "exact-conditional", "cidr-conditional"} {
		t.Run(path, func(t *testing.T) {
			for _, tc := range []struct {
				name         string
				rate         uint32
				d, tokens, x uint64
				zero         bool
			}{
				{"nonfull-advance", 17, 1, 2, 88235294, false},
				{"empty-long-idle", 1, 8, 0, 8500000000, false},
				{"full-addzero", 1, 8, 1, 7999000000, true},
				{"old-over-capacity", 17, 1, 999, 1000000, false},
				{"refill-over-capacity", 17, 1, 33, 150000000, false},
				{"old-u64-tokens", 17, 1, ^uint64(0), 88235294, false},
				{"addzero-preserves-last", 17, 1, 5, 1000000, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := td074Setup(t, c, path, cpus[0], tc.rate, tc.d)
					if tc.name == "full-addzero" {
						straddle := td074FullPair(t, r)
						t.Logf("TD074_CELL path=%s cell=%s valid=1 straddle=%d", path, tc.name, straddle)
						return
					}
					_, _, straddle := td074Trial(t, r, tc.name, func(now uint64) ratelimit.State {
						if now <= tc.x {
							t.Fatal("monotonic uptime too short")
						}
						return ratelimit.State{Tokens: tc.tokens, LastUpdate: now - tc.x}
					}, tc.zero)
					t.Logf("TD074_CELL path=%s cell=%s valid=1 straddle=%d", path, tc.name, straddle)
				})
			}
			t.Run("ordinary-future", func(t *testing.T) {
				r := td074Setup(t, c, path, cpus[0], 17, 1)
				_, _, straddle := td074Trial(t, r, "ordinary-future", func(a uint64) ratelimit.State { return ratelimit.State{Tokens: 1, LastUpdate: a + 1000000000} }, false)
				t.Logf("TD074_CELL path=%s cell=ordinary-future valid=1 straddle=%d", path, straddle)
			})
			for _, tc := range []struct {
				rate     uint32
				d, burst uint64
			}{{17, 1, 34}, {1, 8, 1}} {
				t.Run(fmt.Sprintf("cold-R%d-D%d", tc.rate, tc.d), func(t *testing.T) { r := td074Setup(t, c, path, cpus[0], tc.rate, tc.d); td074Cold(t, r, tc.burst) })
			}
		})
	}
}
func td074Cold(t *testing.T, r *td074Rig, want uint64) {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		r.put(t, ratelimit.State{})
		state := ratelimit.State{}
		passed := uint64(0)
		valid := true
		for i := uint64(0); i <= want; i++ {
			a := td074Clock(t)
			got := r.run(t)
			b := td074Clock(t)
			actual := r.read(t)
			lo, hi := ratelimit.ModelTake(state, a, r.rate, r.divisor), ratelimit.ModelTake(state, b, r.rate, r.divisor)
			if !td074SameSignature(lo, hi) || lo.Add != 0 || hi.Add != 0 {
				valid = false
				break
			}
			td074Check(t, r.path+"/cold", state, a, b, got, actual, lo)
			if got == srcXDPPass {
				passed++
			}
			state = actual
		}
		if !valid {
			continue
		}
		if passed != want {
			t.Fatalf("TD074_COLD %s passes=%d want=%d", r.path, passed, want)
		}
		t.Logf("TD074_COLD path=%s R=%d d=%d passes=%d valid=1 straddle=%d", r.path, r.rate, r.divisor, passed, attempt)
		return
	}
	t.Fatal("TD074_COLD valid=0 after 20 attempts")
}
func TestTD074ELFDifferential(t *testing.T) {
	cpus := td074Environment(t)
	c := b1LogicalLoad(t, "")
	rng := rand.New(rand.NewSource(74031))
	counts := map[string]int{}
	valid, straddle := 0, 0
	td074Pinned(t, cpus[0], func() {
		for _, branch := range []string{"new", "full", "advance", "addzero", "drop"} {
			for n := 0; n < 200; n++ {
				d := []uint64{1, 2, 3, 8, 64, 256, 4096}[rng.Intn(7)]
				rate := uint32(1 + rng.Intn(10000000))
				if branch == "advance" || branch == "addzero" || branch == "drop" {
					rate = uint32(d * uint64(2+rng.Intn(49)))
				}
				r := td074Setup(t, c, "exact-tuple", cpus[0], rate, d)
				period := d * ratelimit.NS / uint64(rate)
				tokens, x := uint64(0), uint64(0)
				switch branch {
				case "full":
					tokens = ratelimit.ModelCapacity(rate, d) + uint64(rng.Intn(100))
					x = uint64(rng.Intn(10000000))
				case "advance":
					tokens = 1
					x = period + period/3
				case "addzero":
					tokens = 1
					x = period / 4
				case "drop":
					x = period / 4
				}
				accepted := false
				for attempt := 0; attempt < 20; attempt++ {
					a := td074Clock(t)
					state := ratelimit.State{Tokens: tokens, LastUpdate: a - x}
					if branch == "new" {
						state.LastUpdate = 0
					}
					r.put(t, state)
					got := r.run(t)
					b := td074Clock(t)
					actual := r.read(t)
					lo, hi := ratelimit.ModelTake(state, a, rate, d), ratelimit.ModelTake(state, b, rate, d)
					if !td074SameSignature(lo, hi) {
						straddle++
						continue
					}
					if lo.Branch != branch {
						t.Fatalf("TD074_DIFF apparatus requested=%s constructed=%s", branch, lo.Branch)
					}
					td074Check(t, "differential/"+branch, state, a, b, got, actual, lo)
					valid++
					counts[branch]++
					accepted = true
					break
				}
				if !accepted {
					t.Fatalf("TD074_DIFF branch=%s sample=%d valid=0 after 20 attempts", branch, n)
				}
			}
		}
	})
	if valid < 1000 {
		t.Fatalf("TD074_DIFF valid=%d want>=1000", valid)
	}
	for _, branch := range []string{"new", "full", "advance", "addzero", "drop"} {
		if counts[branch] < 50 {
			t.Fatalf("TD074_DIFF branch=%s count=%d want>=50", branch, counts[branch])
		}
	}
	t.Logf("TD074_DIFF valid=%d straddle=%d mismatch=0 branch=new:%d/full:%d/advance:%d/addzero:%d/drop:%d", valid, straddle, counts["new"], counts["full"], counts["advance"], counts["addzero"], counts["drop"])
}

func TestTD074ELFDivisorBounds(t *testing.T) {
	cpus := td074Environment(t)
	c := b1LogicalLoad(t, "")
	for _, d := range []uint64{0, 4096, 4097, ^uint64(0)} {
		t.Run(fmt.Sprintf("raw-%d", d), func(t *testing.T) {
			r := td074Setup(t, c, "exact-tuple", cpus[0], 4096, d)
			td074Cold(t, r, ratelimit.ModelCapacity(4096, d))
			_, _, straddle := td074Trial(t, r, "divisor-normalization", func(a uint64) ratelimit.State { return ratelimit.State{Tokens: 0, LastUpdate: a - 1500000000} }, false)
			t.Logf("TD074_DIVISOR_ELF raw=%d effective=%d valid=1 straddle=%d", d, ratelimit.ModelDivisor(d), straddle)
		})
	}
}

// Retry the complete two-packet cell on a straddling clock bracket. Within a
// trial the second packet always starts from the first packet's actual writeback.
func td074FullPair(t *testing.T, r *td074Rig) int {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		a := td074Clock(t)
		if a <= 7999000000 {
			t.Fatal("monotonic uptime too short")
		}
		initial := ratelimit.State{Tokens: 1, LastUpdate: a - 7999000000}
		r.put(t, initial)
		firstVerdict := r.run(t)
		b := td074Clock(t)
		first := r.read(t)
		lo, hi := ratelimit.ModelTake(initial, a, 1, 8), ratelimit.ModelTake(initial, b, 1, 8)
		if !td074SameSignature(lo, hi) || lo.Add != 0 || hi.Add != 0 {
			continue
		}
		firstOK := firstVerdict == srcXDPPass && first.Tokens == 0 && first.LastUpdate >= a && first.LastUpdate <= b
		for td074Clock(t) < a+1000000 {
			time.Sleep(100 * time.Microsecond)
		}
		a2 := td074Clock(t)
		secondVerdict := r.run(t)
		b2 := td074Clock(t)
		second := r.read(t)
		low2, high2 := ratelimit.ModelTake(first, a2, 1, 8), ratelimit.ModelTake(first, b2, 1, 8)
		if !td074SameSignature(low2, high2) {
			if !firstOK {
				td074Check(t, r.path+"/full-addzero-first", initial, a, b, firstVerdict, first, lo)
			}
			continue
		}
		// A scheduling pause of an entire refill period no longer exercises the
		// named second-packet cell. Only reject it if the first state was correct;
		// a mutant's stale timestamp must never be mistaken for a scheduling pause.
		if firstOK && low2.Allowed {
			continue
		}
		t.Run("first-writeback", func(t *testing.T) {
			td074Check(t, r.path+"/full-addzero-first", initial, a, b, firstVerdict, first, lo)
		})
		if secondVerdict != srcXDPDrop {
			t.Fatalf("TD074_WITNESS full-addzero-second verdict=%d want=DROP", secondVerdict)
		}
		td074Check(t, r.path+"/full-addzero-second", first, a2, b2, secondVerdict, second, low2)
		return attempt
	}
	t.Fatal("TD074_WITNESS full-addzero pair valid=0 after 20 attempts")
	return 20
}
