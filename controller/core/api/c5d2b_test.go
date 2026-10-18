package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func c5d2ShareFixture(t *testing.T) (*fixture, *c5cSource, *c5cQuery) {
	t.Helper()
	f, s, q := c5cFixture(t)
	for i, id := range []string{"A", "B", "C"} {
		target := ""
		if id != "C" {
			target = fmt.Sprintf("192.0.2.%d", i+1)
		}
		r := store.Rule{ID: id, LogicalID: int64(i + 1), Kind: "exact", GroupKey: id, CondKey: id, Match: store.Match{DstIP: target, Action: "drop"}}
		require(t, store.InsertRule(f.db, r) == nil, "seed rule", id)
	}
	s.byNode["a"] = map[string]orch.RuleRate{"A": {PPS: 100}, "B": {PPS: 300}, "C": {PPS: 100}, "D": {PPS: 500}}
	return f, s, q
}
func c5d2Sum(in orch.TrafficInput) float64 {
	var sum float64
	for _, r := range in.Rates {
		sum += r.PPS
	}
	return sum
}
func c5d2Shares(t *testing.T, out topResponse, want map[string]float64) {
	t.Helper()
	require(t, len(out.Rules) == len(want), "rule set", out)
	for _, row := range out.Rules {
		value, exists := want[row.RuleID]
		require(t, exists && row.Share != nil && math.Float64bits(*row.Share) == math.Float64bits(value), "independent share", row, value)
	}
}
func TestC5D2Share(t *testing.T) {
	t.Run("fixed-order", func(t *testing.T) {
		f, s, _ := c5cFixture(t)
		for i, id := range []string{"A", "B", "C"} {
			r := store.Rule{ID: id, LogicalID: int64(i + 1), Kind: "exact", GroupKey: id, CondKey: id, Match: store.Match{DstIP: "192.0.2.1", Action: "drop"}}
			require(t, store.InsertRule(f.db, r) == nil, "seed shared target", id)
		}
		s.byNode["a"] = map[string]orch.RuleRate{"A": {PPS: 100000000}, "B": {PPS: 0.1}, "C": {PPS: 0.1}}
		targets, err := store.TrafficTargets(f.db.Reader(), []string{"A", "B", "C"})
		require(t, err == nil && len(targets) == 3 && targets["A"] == "192.0.2.1" && targets["B"] == targets["A"] && targets["C"] == targets["A"], "shared target readback", targets)
		t.Logf("targets=%v rates_sum_witness=%.17g", targets, c5d2Sum(s.TrafficInput()))
		want := map[string]float64{"A": float64(100000000.0) / float64(100000000.19999999), "B": float64(0.1) / float64(100000000.19999999), "C": float64(0.1) / float64(100000000.19999999)}
		for i := 0; i < 128; i++ {
			s.input.Key = fmt.Sprintf("fixed-order-%d", i)
			out := c5cTop(t, f, "?n="+[]string{"1", "5", "20", "all"}[i%4])
			require(t, len(out.Targets) == 1 && (i%4 == 0 && len(out.Rules) == 1 || i%4 != 0 && len(out.Rules) == 3), "cold ranking shape", i)
			target := out.Targets[0]
			require(t, target.Share != nil && math.Float64bits(target.PPS) == math.Float64bits(100000000.19999999) && math.Float64bits(*target.Share) == math.Float64bits(1), "ordered target bits", i, target)
			for _, row := range out.Rules {
				value, exists := want[row.RuleID]
				require(t, exists && row.Share != nil && math.Float64bits(*row.Share) == math.Float64bits(value), "ordered rule share bits", i, row.RuleID, row.Share, value)
			}
		}
		t.Log("cold_reads=128 n=1,5,20,all target_pps_bits=literal target_share_bits=1 rule_share_bits=independent_literals")
	})
	t.Run("all-rates", func(t *testing.T) {
		f, s, _ := c5d2ShareFixture(t)
		in := s.TrafficInput()
		targets, err := store.TrafficTargets(f.db.Reader(), []string{"A", "B", "C", "D"})
		require(t, err == nil && len(targets) == 3 && targets["C"] == "" && in.Rates["D"].PPS == 500, "targetless and deleted witnesses")
		_, exists := targets["D"]
		require(t, !exists && c5d2Sum(in) == 1000 && in.DroppedPPS == 3000, "different denominators")
		out := c5cTop(t, f, "?n=all")
		for _, id := range []string{"A", "B", "C", "D"} {
			id := id
			t.Run(id, func(t *testing.T) {
				c5d2Shares(t, out, map[string]float64{"A": .1, "B": .3, "C": .1})
				require(t, len(out.Targets) == 2 && out.Targets[0].Share != nil && out.Targets[1].Share != nil, "targets present")
				require(t, *out.Targets[0].Share == .3 && *out.Targets[1].Share == .1 && *out.Targets[0].Share+*out.Targets[1].Share == .4, "target share sum")
			})
		}
		t.Log("rates_sum=1000 stats_pps=3000 targetless_C=100 deleted_D=500 targets_share_sum=0.4")
	})
	for _, mode := range []string{"db-only", "missing-stats"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			f, s, q := c5d2ShareFixture(t)
			before := c5cTop(t, f, "")
			if mode == "db-only" {
				require(t, store.PutNode(f.db, store.Node{Name: "db-only", BaseURL: "http://192.0.2.20", KeyNonce: []byte{}, KeyCipher: []byte{}}, true) == nil, "add missing node")
			} else {
				s.input.Key = "missing"
				s.input.DenominatorMissing, s.input.Incomplete = true, true
				require(t, s.TrafficInput().DenominatorMissing && s.TrafficInput().Incomplete, "missing flags witness")
			}
			out := c5cTop(t, f, "")
			c5d2Shares(t, out, map[string]float64{"A": .1, "B": .3, "C": .1})
			require(t, out.Incomplete && reflect.DeepEqual(before.Rules, out.Rules) && reflect.DeepEqual(before.Targets, out.Targets) && q.batches == 2, "incomplete with unchanged shares")
			t.Logf("mode=%s denominator_missing_path=1 incomplete=true shares_unchanged=1", mode)
		})
	}
	t.Run("zero-rates", func(t *testing.T) {
		f, s, _ := c5d2ShareFixture(t)
		for id := range s.byNode["a"] {
			s.byNode["a"][id] = orch.RuleRate{}
		}
		require(t, c5d2Sum(s.TrafficInput()) == 0, "zero rates witness")
		out := c5cTop(t, f, "")
		require(t, len(out.Rules) == 0 && len(out.Targets) == 0 && out.TotalPPS == 3000 && out.TotalBytesPS == 300000, "empty rankings retain Stats")
	})
	t.Run("zero-stats", func(t *testing.T) {
		f, s, _ := c5d2ShareFixture(t)
		s.input.DroppedPPS = 0
		c5d2Shares(t, c5cTop(t, f, ""), map[string]float64{"A": .1, "B": .3, "C": .1})
	})
	t.Run("bounds-200", func(t *testing.T) {
		f, s, _ := c5d2ShareFixture(t)
		rng := rand.New(rand.NewSource(5162026))
		for i := 0; i < 200; i++ {
			s.input.Key = fmt.Sprint(i)
			for _, id := range []string{"A", "B", "C", "D"} {
				s.byNode["a"][id] = orch.RuleRate{PPS: rng.Float64()*1e8 + 1}
			}
			out := c5cTop(t, f, "?n=all")
			require(t, len(out.Rules) == 3 && len(out.Targets) == 2, "random nonempty rankings")
			for _, r := range out.Rules {
				require(t, r.Share != nil && *r.Share > 0 && *r.Share <= 1+1e-9, "rule bound", i, r)
			}
			for _, r := range out.Targets {
				require(t, r.Share != nil && *r.Share > 0 && *r.Share <= 1+1e-9, "target bound", i, r)
			}
		}
		t.Log("seed=5162026 groups=200 rule_checks=600 target_checks=400")
	})
	t.Run("n-independent", func(t *testing.T) {
		f, _, _ := c5d2ShareFixture(t)
		all := c5cTop(t, f, "?n=all")
		require(t, len(all.Rules) == 3 && len(all.Targets) == 2, "n1 truncation witness")
		for _, n := range []string{"1", "5", "20", "all"} {
			n := n
			t.Run(n, func(t *testing.T) {
				out := c5cTop(t, f, "?n="+n)
				for i, row := range out.Rules {
					require(t, row.RuleID == all.Rules[i].RuleID && row.Share != nil && math.Float64bits(*row.Share) == math.Float64bits(*all.Rules[i].Share), "rule bits", n)
				}
				for i, row := range out.Targets {
					require(t, row.Target == all.Targets[i].Target && row.Share != nil && math.Float64bits(*row.Share) == math.Float64bits(*all.Targets[i].Share), "target bits", n)
				}
				t.Logf("n=%s rules=%d targets=%d all_rules=3 all_targets=2", n, len(out.Rules), len(out.Targets))
			})
		}
	})
	t.Run("stats-totals", func(t *testing.T) {
		f, s, _ := c5d2ShareFixture(t)
		require(t, c5d2Sum(s.TrafficInput()) == 1000 && s.TrafficInput().DroppedPPS == 3000, "distinct sources")
		out := c5cTop(t, f, "")
		require(t, out.TotalPPS == 3000 && out.TotalBytesPS == 300000, "Stats totals", out)
		t.Log("rates_sum=1000 stats_pps=3000 stats_bytes_ps=300000")
	})
}

type c5d2Source struct {
	*c5cSource
	statsSeq, hitsSeq int
}

func (s *c5d2Source) TrafficInput() orch.TrafficInput {
	in := s.c5cSource.TrafficInput()
	in.Key += fmt.Sprintf("/%d/%d", s.statsSeq, s.hitsSeq)
	return in
}
func (s *c5d2Source) Status() []orch.NodeStatus {
	out := s.Manager.Status()
	out[0].Rates = map[string]float64{"dropped_packets": s.input.DroppedPPS, "dropped_bytes": s.input.DroppedBytesPS}
	return out
}
func TestC5D2CacheEvents(t *testing.T) {
	f, base, q := c5d2ShareFixture(t)
	s := &c5d2Source{c5cSource: base}
	tick := make(chan time.Time, 1)
	beat := make(chan time.Time)
	var a *API
	e, h := NewWithHub(f.s, s, testActor, nil, Options{trafficQuery: q, nodeAPI: func(v *API) { a = v }, eventsTick: func(d time.Duration) (<-chan time.Time, func()) {
		if d == time.Second {
			return tick, func() {}
		}
		return beat, func() {}
	}})
	f.e = e
	defer h.Close()
	initial, key0, err := a.trafficTopKey(5)
	require(t, err == nil, "initial top")
	c5d2Shares(t, initial, map[string]float64{"A": .1, "B": .3, "C": .1})
	var stats topResponse
	var key1 string
	t.Run("stats-only", func(t *testing.T) {
		s.input.DroppedPPS, s.input.DroppedBytesPS = 6000, 600000
		s.statsSeq++
		stats, key1, err = a.trafficTopKey(5)
		require(t, err == nil && key1 != key0 && c5d2Sum(s.TrafficInput()) == 1000 && stats.TotalPPS == 6000 && stats.TotalBytesPS == 600000, "Stats key and totals")
		require(t, reflect.DeepEqual(initial.Rules, stats.Rules) && reflect.DeepEqual(initial.Targets, stats.Targets), "Stats preserve shares")
		t.Logf("statsSeq=%d key_before=%s key_after=%s rates_sum=1000 total=6000", s.statsSeq, key0, key1)
	})
	want := map[string]float64{"A": 200.0 / 1100, "B": 300.0 / 1100, "C": 100.0 / 1100}
	var changed topResponse
	t.Run("hits-relative", func(t *testing.T) {
		before := s.TrafficInput()
		s.byNode["a"]["A"] = orch.RuleRate{PPS: 200}
		s.hitsSeq++
		after := s.TrafficInput()
		require(t, before.Key != after.Key && c5d2Sum(before) == 1000 && c5d2Sum(after) == 1100 && before.Rates["A"].PPS/before.Rates["B"].PPS != after.Rates["A"].PPS/after.Rates["B"].PPS, "relative and sum change witness")
		changed = c5cTop(t, f, "?n=5")
		c5d2Shares(t, changed, want)
		require(t, !reflect.DeepEqual(stats.Rules, changed.Rules) && changed.TotalPPS == 6000, "Hits change shares only")
		t.Logf("hitsSeq=%d key_before=%s key_after=%s sum_before=1000 sum_after=1100 A=200 B=300 C=100", s.hitsSeq, before.Key, after.Key)
	})
	t.Run("cache-hit", func(t *testing.T) {
		batches, key := q.batches, s.TrafficInput().Key
		hit := c5cTop(t, f, "?n=5")
		c5d2Shares(t, hit, want)
		require(t, reflect.DeepEqual(changed, hit) && q.batches == batches && key == s.TrafficInput().Key, "same-key cache bits")
	})
	t.Run("sse-rest", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := &c5d0Writer{ResponseRecorder: httptest.NewRecorder(), ready: make(chan struct{}), cancel: cancel}
		r := httptest.NewRequest("GET", "/api/v1/events", nil).WithContext(ctx)
		r.Header.Set("X-Xdrop-Actor", "ui")
		done := make(chan struct{})
		go func() { f.e.ServeHTTP(w, r); close(done) }()
		c5dWait(t, w.ready, "SSE prelude")
		tick <- time.Now()
		c5dWait(t, done, "SSE traffic")
		frames := strings.Split(strings.TrimSpace(w.Body.String()), "\n\n")
		require(t, len(frames) == 4 && strings.HasPrefix(frames[3], "event: traffic\ndata: "), "traffic event")
		var payload struct{ Top topResponse }
		require(t, json.Unmarshal([]byte(strings.TrimPrefix(frames[3], "event: traffic\ndata: ")), &payload) == nil, "traffic JSON")
		c5d2Shares(t, payload.Top, want)
		require(t, reflect.DeepEqual(payload.Top, c5cTop(t, f, "?n=5")), "SSE REST shares and totals")
	})
}
