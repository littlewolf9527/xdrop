package rules

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func seedPrefix(i int) string { return fmt.Sprintf("10.%d.%d.0/24", i/256, i%256) }

// seedRules measures no service work: every canonical row is inserted directly
// in one transaction. All timed calls below start after the commit.
func seedRules(t *testing.T, s *Service, cidrs, exact int) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stamp := s.now().UTC().Format(timeFormat)
	for i := 0; i < cidrs+exact; i++ {
		in := RuleInput{Protocol: "tcp", Action: "drop"}
		if i < cidrs {
			in.SrcCIDR = seedPrefix(i)
		} else {
			in.DstIP, in.SrcPort = "192.0.2.1", i-cidrs+1
		}
		c, e := Canonicalize(in)
		if e != nil {
			t.Fatal(e)
		}
		r := store.Rule{Match: c.RuleInput, ID: fmt.Sprintf("rule_%032x", i+1), LogicalID: int64(i + 1), Kind: c.Kind, GroupKey: c.GroupKey, CondKey: c.CondKey, Enabled: true, CreatedAt: stamp, UpdatedAt: stamp, CreatedBy: "ui", UpdatedBy: "ui"}
		if err := store.InsertRule(tx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec("UPDATE logical_id_hw SET high_water=?", cidrs+exact); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func timedCreate(t *testing.T, s *Service, p RulePatch) (Result, time.Duration, *Error) {
	t.Helper()
	start := time.Now()
	r, e := s.Create(ui, "", p)
	elapsed := time.Since(start)
	return r, elapsed, e
}

func TestCtlCut1Perf(t *testing.T) {
	s, _ := setup(t)
	seedRules(t, s, 49999, 50000)
	t.Run("PERF-admit", func(t *testing.T) {
		for _, item := range []struct {
			name string
			p    RulePatch
		}{
			{"cidr", RulePatch{SrcCIDR: ptr(seedPrefix(49999)), Protocol: ptr("tcp")}},
			{"exact", RulePatch{DstIP: ptr("192.0.2.1"), SrcPort: ptr(50001), Protocol: ptr("tcp")}},
		} {
			r, elapsed, e := timedCreate(t, s, item.p)
			t.Logf("seed=99999 kind=%s Create=%s limit=1s", item.name, elapsed)
			check(t, e == nil && !r.Existing, "create", r, e)
			check(t, elapsed <= time.Second, "Create exceeded 1s", elapsed)
		}
	})
	t.Run("PERF-prepare", func(t *testing.T) {
		start := time.Now()
		r, err := Prepare(s.db)
		elapsed := time.Since(start)
		t.Logf("seed=99999 Prepare=%s violations=%d limit=10s", elapsed, len(r.Violations))
		check(t, err == nil && len(r.Violations) == 0, "prepare", r, err)
		check(t, elapsed <= 10*time.Second, "Prepare exceeded 10s", elapsed)
	})
	t.Run("PERF-trie-limit", func(t *testing.T) {
		// This also works when only this leaf is selected by go test -run.
		r, e := s.Create(ui, "", RulePatch{SrcCIDR: ptr(seedPrefix(49999)), Protocol: ptr("tcp")})
		check(t, e == nil, r, e)
		_, elapsed, e := timedCreate(t, s, RulePatch{SrcCIDR: ptr(seedPrefix(50000)), Protocol: ptr("tcp")})
		t.Logf("prefix=50001 Create=%s error=%v", elapsed, e)
		code(t, e, "table_full")
		check(t, e.Table == "sv4", e)
	})
}

func TestCtlCut1PerfComparison(t *testing.T) {
	for _, size := range []int{1020, 5040, 10060} {
		t.Run(fmt.Sprintf("SIZE-%d", size), func(t *testing.T) {
			s, _ := setup(t)
			cidrs, exact := size/5, size-size/5
			seedRules(t, s, cidrs, exact)
			var total time.Duration
			const samples = 20
			for i := 0; i < samples; i++ {
				p := RulePatch{DstIP: ptr("192.0.2.1"), SrcPort: ptr(exact + 1), Protocol: ptr("tcp")}
				if i%5 == 0 {
					p = RulePatch{SrcCIDR: ptr(seedPrefix(cidrs)), Protocol: ptr("tcp")}
				}
				r, elapsed, e := timedCreate(t, s, p)
				check(t, e == nil && !r.Existing, r, e)
				total += elapsed
				check(t, s.ForceDelete(ui, r.Rule.ID) == nil, "cleanup failed")
			}
			t.Logf("FIX1 size=%d cidr=%d samples=%d average_ns=%d", size, cidrs, samples, total.Nanoseconds()/samples)
		})
	}
}

func TestCtlCut1OverlapDiff(t *testing.T) {
	t.Run("OVL-diff", func(t *testing.T) {
		for seed := int64(0); seed < 60; seed++ {
			rng := rand.New(rand.NewSource(seed))
			rows := []store.Rule{}
			add := func(bucket int, raw string) {
				in := RuleInput{Protocol: "tcp"}
				if bucket%2 == 0 {
					in.SrcCIDR = raw
				} else {
					in.DstCIDR = raw
				}
				c, e := Canonicalize(in)
				check(t, e == nil, "seed", seed, e)
				rows = append(rows, store.Rule{ID: fmt.Sprintf("s%d-r%d", seed, len(rows)), Match: c.RuleInput, Kind: c.Kind, GroupKey: c.GroupKey, CondKey: c.CondKey, Enabled: true})
			}
			for bucket := 0; bucket < 4; bucket++ {
				chain := []string{"10.1.0.0/16", "10.1.0.0/17", "10.1.0.0/18", "10.1.0.0/18", "10.2.0.0/16", "10.250.0.0/24"}
				if bucket >= 2 {
					chain = []string{"2001:db8:1::/48", "2001:db8:1::/49", "2001:db8:1::/50", "2001:db8:1::/50", "2001:db8:2::/48", "2001:db8:fffe::/64"}
				}
				for _, p := range chain {
					add(bucket, p)
				}
			}
			for n := 200 + rng.Intn(81); len(rows) < n; {
				bucket := rng.Intn(4)
				raw := fmt.Sprintf("10.%d.%d.%d/%d", rng.Intn(8), rng.Intn(256), rng.Intn(256), 16+rng.Intn(17))
				if bucket >= 2 {
					raw = fmt.Sprintf("2001:db8:%x:%x::/%d", rng.Intn(8), rng.Intn(65536), 48+rng.Intn(49))
				}
				add(bucket, raw)
			}
			// Independent quadratic oracle, with explicit direction and family
			// checks. Compare the complete set of violating rule IDs.
			want := map[string]bool{}
			for i, a := range rows {
				for _, b := range rows[:i] {
					for direction, raw := range []string{a.SrcCIDR, a.DstCIDR} {
						other := []string{b.SrcCIDR, b.DstCIDR}[direction]
						if raw == "" || other == "" || raw == other {
							continue
						}
						ip, x, _ := net.ParseCIDR(raw)
						jp, y, _ := net.ParseCIDR(other)
						if (ip.To4() != nil) == (jp.To4() != nil) && (x.Contains(y.IP) || y.Contains(x.IP)) {
							want[a.ID], want[b.ID] = true, true
						}
					}
				}
			}
			got := map[string]bool{}
			for _, e := range constraints(rows, 50000) {
				if e.Code == "cidr_overlap" {
					for _, id := range e.RuleIDs {
						got[id] = true
					}
				}
			}
			if !reflect.DeepEqual(got, want) {
				missing, extra := []string{}, []string{}
				for id := range want {
					if !got[id] {
						missing = append(missing, id)
					}
				}
				for id := range got {
					if !want[id] {
						extra = append(extra, id)
					}
				}
				sort.Strings(missing)
				sort.Strings(extra)
				t.Fatalf("seed=%d count=%d missing=%v extra=%v", seed, len(rows), missing, extra)
			}
		}
		t.Log("seeds=60 prefixes_per_seed=200..280 families=2 directions=2 duplicate_prefixes=yes nested_chains=yes ID_sets_equal=true")
	})
}
