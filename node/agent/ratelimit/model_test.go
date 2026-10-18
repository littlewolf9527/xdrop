package ratelimit

import (
	"fmt"
	"math/bits"
	"testing"
)

func TestTD074CapacityColdBurst(t *testing.T) {
	for _, tc := range []struct {
		r    uint32
		d, c uint64
	}{
		{17, 1, 34}, {100, 8, 25}, {1, 8, 1}, {4, 8, 1}, {5, 8, 2}, {7, 8, 2}, {3, 8, 1}, {7, 3, 5},
		{4294967295, 1, 8589934590}, {4294967295, 4096, 2097152}, {1, 4096, 1},
	} {
		t.Run(fmt.Sprintf("R%d_D%d", tc.r, tc.d), func(t *testing.T) {
			if got := ModelCapacity(tc.r, tc.d); got != tc.c {
				t.Fatalf("TD074_CAPACITY got=%d want=%d", got, tc.c)
			}
			first := ModelTake(State{}, 10000000000, tc.r, tc.d)
			if !first.Allowed || first.State != (State{tc.c - 1, 10000000000}) || first.Branch != "new" {
				t.Fatalf("TD074_COLD initial=%+v want tokens=%d", first, tc.c-1)
			}
			// With elapsed zero there is no replenishment: the first pass plus the
			// remaining whole tokens is the cold burst, including multi-billion capacities.
			if 1+first.State.Tokens != tc.c {
				t.Fatalf("TD074_COLD budget=%d want=%d", 1+first.State.Tokens, tc.c)
			}
			if tc.c <= 100 {
				state := State{}
				var passed uint64
				for i := uint64(0); i <= tc.c; i++ {
					out := ModelTake(state, 10000000000, tc.r, tc.d)
					state = out.State
					if out.Allowed {
						passed++
					}
				}
				if passed != tc.c {
					t.Fatalf("TD074_COLD passes=%d want=%d", passed, tc.c)
				}
			} else {
				// Sample every power-of-two token boundary; each must consume exactly one.
				for n := uint64(1); n < tc.c; n *= 2 {
					out := ModelTake(State{n, 10000000000}, 10000000000, tc.r, tc.d)
					if !out.Allowed || out.State != (State{n - 1, 10000000000}) {
						t.Fatalf("TD074_COLD decrement tokens=%d result=%+v", n, out)
					}
				}
			}
			last := ModelTake(State{1, 10000000000}, 10000000000, tc.r, tc.d)
			empty := ModelTake(last.State, 10000000000, tc.r, tc.d)
			if !last.Allowed || last.State.Tokens != 0 || empty.Allowed || empty.State.Tokens != 0 {
				t.Fatalf("TD074_COLD last=%+v empty=%+v", last, empty)
			}
		})
	}
}

func TestTD074ArithmeticWitnesses(t *testing.T) {
	const base uint64 = 20000000000
	for _, tc := range []struct {
		name                                                   string
		r                                                      uint32
		d, tokens, elapsed, wantTokens, wantLast, add, advance uint64
		allowed                                                bool
		branch                                                 string
	}{
		{"nonfull-advance", 17, 1, 2, 88235294, 2, base + 58823530, 1, 58823530, true, "advance"},
		{"empty-long-idle", 1, 8, 0, 8500000000, 0, base + 8500000000, 1, 0, true, "full"},
		{"full-addzero", 1, 8, 1, 7999000000, 0, base + 7999000000, 0, 0, true, "full"},
		{"old-over-capacity", 17, 1, 999, 1000000, 33, base + 1000000, 0, 0, true, "full"},
		{"refill-over-capacity", 17, 1, 33, 150000000, 33, base + 150000000, 2, 0, true, "full"},
		{"old-u64-tokens", 17, 1, ^uint64(0), 88235294, 33, base + 88235294, 1, 0, true, "full"},
		{"addzero-preserves-last", 17, 1, 5, 1000000, 4, base, 0, 0, true, "addzero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ModelTake(State{tc.tokens, base}, base+tc.elapsed, tc.r, tc.d)
			want := Result{State: State{tc.wantTokens, tc.wantLast}, Allowed: tc.allowed, Branch: tc.branch, Add: tc.add, Advance: tc.advance}
			if got != want {
				t.Fatalf("TD074_WITNESS %s got=%+v want=%+v", tc.name, got, want)
			}
		})
	}
	t.Run("full-addzero-second", func(t *testing.T) {
		first := ModelTake(State{1, base}, base+7999000000, 1, 8)
		second := ModelTake(first.State, base+8000000000, 1, 8)
		if !first.Allowed || second.Allowed || second.State != (State{0, base + 7999000000}) {
			t.Fatalf("TD074_WITNESS full-addzero-second first=%+v second=%+v want=pass/drop", first, second)
		}
	})
	t.Run("ordinary-future", func(t *testing.T) {
		got := ModelTake(State{1, base + 1000000000}, base, 17, 1)
		want := Result{State: State{0, base}, Allowed: true, Branch: "addzero", NormalizedFuture: true}
		if got != want {
			t.Fatalf("TD074_WITNESS ordinary-future got=%+v want=%+v", got, want)
		}
	})
	t.Run("future-wrap", func(t *testing.T) {
		state := State{0, ^uint64(0) - 999999999}
		for i, now := range []uint64{100000000, 101000000, 102000000} {
			got := ModelTake(state, now, 1, 1)
			if got.Allowed || got.State != (State{0, 100000000}) || got.Branch != "drop" || got.NormalizedFuture != (i == 0) {
				t.Errorf("TD074_WITNESS future-wrap packet=%d got=%+v want=drop tokens=0 last=100000000", i+1, got)
			}
			state = got.State
		}
	})
}

func TestTD074OverflowBounds(t *testing.T) {
	mul := func(label string, a, b uint64) uint64 {
		t.Helper()
		hi, lo := bits.Mul64(a, b)
		if hi != 0 {
			t.Fatalf("TD074_OVERFLOW %s high=%d a=%d b=%d", label, hi, a, b)
		}
		return lo
	}
	for _, r := range []uint64{1, 17, 4294967295} {
		for _, d := range []uint64{1, 2, 3, 8, 64, 256, 4096} {
			c := ModelCapacity(uint32(r), d)
			cd := mul("capacity*divisor", c, d)
			if cd >= 2*r+d {
				t.Fatal("TD074_OVERFLOW C*d < 2R+d violated")
			}
			cdns := mul("capacity*divisor*NS", cd, NS)
			capNS := (cdns + r - 1) / r
			elapsedR := mul("cap_ns*R", capNS, r)
			if elapsedR >= cdns+r {
				t.Fatal("TD074_OVERFLOW cap_ns*R bound violated")
			}
			add := elapsedR / (d * NS)
			addDNS := mul("add*d*NS", mul("add*d", add, d), NS)
			if addDNS > elapsedR {
				t.Fatal("TD074_OVERFLOW add*d*NS <= elapsed*R violated")
			}
			upper := mul("(3R+d)*NS", 3*r+d, NS)
			if upper >= 13000000000000000000 {
				t.Fatal("TD074_OVERFLOW global bound violated")
			}
		}
	}
	for _, d := range []uint64{0, 4097, ^uint64(0)} {
		want := uint64(4096)
		if d == 0 {
			want = 256
		}
		if got := ModelDivisor(d); got != want {
			t.Fatalf("divisor=%d got=%d want=%d", d, got, want)
		}
	}
}
