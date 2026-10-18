package orch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type c5cTick struct {
	kind  string
	d     time.Duration
	next  time.Time
	ch    chan time.Time
	fired bool
}
type c5cClock struct {
	mu    sync.Mutex
	at    time.Time
	ticks []*c5cTick
}

func c5cNewClock() *c5cClock       { return &c5cClock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }
func (c *c5cClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *c5cClock) tick(kind string, d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.ticks = append(c.ticks, &c5cTick{kind: kind, d: d, next: c.at.Add(d), ch: ch})
	return ch
}
func (c *c5cClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
	for _, tick := range c.ticks {
		if tick.fired || tick.next.After(c.at) {
			continue
		}
		select {
		case tick.ch <- c.at:
		default:
		}
		if tick.kind == "hits" {
			tick.fired = true
		} else {
			tick.next = tick.next.Add((c.at.Sub(tick.next)/tick.d + 1) * tick.d)
		}
	}
}
func (c *c5cClock) registered(kind string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, x := range c.ticks {
		if x.kind == kind {
			n++
		}
	}
	return n
}
func c5cSpin(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("fixture barrier deadline")
		}
		runtime.Gosched()
	}
}
func c5cReply(status int, body string) (*http.Response, error) {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
}
func c5cHits(now uint64, hits ...nc.RuleHit) string {
	if hits == nil {
		hits = []nc.RuleHit{}
	}
	b, _ := json.Marshal(nc.HitsResponse{NowNS: now, Hits: hits})
	return string(b)
}
func c5cDirect(t *testing.T, c *c5cClock, o Options) (*Manager, *node) {
	o.now, o.tick = c.now, c.tick
	m := New([]NodeSpec{c5bSpec("a")}, o)
	m.ctx, m.cancel = context.WithCancel(context.Background())
	n := m.nodes[0]
	n.ctx, n.cancel = context.WithCancel(m.ctx)
	t.Cleanup(m.cancel)
	return m, n
}
func c5cHitter(t *testing.T, m *Manager, n *node) {
	done := make(chan struct{})
	go func() { m.hitter(n); close(done) }()
	t.Cleanup(func() { m.cancel(); c5bWait(t, done, time.Second) })
}

func TestC5CHits(t *testing.T) {
	for _, mode := range []string{"500", "429", "timeout", "shape"} {
		mode := mode
		t.Run("backoff-"+mode, func(t *testing.T) {
			c := c5cNewClock()
			origin := c.now()
			var mu sync.Mutex
			starts := []time.Duration{}
			since := []string{}
			o := Options{Client: nc.Options{Timeouts: map[nc.Route]time.Duration{nc.HitsRoute: time.Millisecond}}}
			o.Client.Transport = c5bTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				starts = append(starts, c.now().Sub(origin))
				since = append(since, r.URL.Query().Get("since_ns"))
				count := len(starts)
				mu.Unlock()
				if count <= 6 {
					switch mode {
					case "500":
						return c5cReply(500, `{}`)
					case "429":
						return c5cReply(429, `{"error":"rate_limited"}`)
					case "shape":
						return c5cReply(200, `{"now_ns":"bad"}`)
					case "timeout":
						c.advance(5 * time.Second)
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
				}
				return c5cReply(200, c5cHits(5000000000))
			})
			m, n := c5cDirect(t, c, o)
			c5cHitter(t, m, n)
			for i := 1; i <= 8; i++ {
				i := i
				c5cSpin(t, func() bool { return c.registered("hits") == i })
				c.mu.Lock()
				next := c.ticks[len(c.ticks)-1].next
				at := c.at
				c.mu.Unlock()
				c.advance(next.Sub(at))
				c5cSpin(t, func() bool { return c.registered("hits") == i+1 })
			}
			want := []time.Duration{5, 15, 35, 75, 135, 195, 255, 260}
			for i := range want {
				want[i] *= time.Second
			}
			mu.Lock()
			defer mu.Unlock()
			need(t, reflect.DeepEqual(starts, want), "start schedule", starts, want)
			need(t, len(since) == 8 && since[0] == "0" && since[6] == "0" && since[7] == "5000000000", "successful cursor", since)
			t.Logf("failure_kind=%s failures=6 first=5s starts=%v adjacent=10,20,40,60,60,60,5 since=%v", mode, starts, since)
		})
	}
	for _, duration := range []time.Duration{4 * time.Second, 7 * time.Second} {
		duration := duration
		t.Run(fmt.Sprintf("start-%ds", int(duration.Seconds())), func(t *testing.T) {
			c := c5cNewClock()
			var mu sync.Mutex
			starts := []time.Time{}
			o := Options{Client: nc.Options{Transport: c5bTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				starts = append(starts, c.now())
				mu.Unlock()
				c.advance(duration)
				return c5cReply(200, c5cHits(uint64(c.now().UnixNano())))
			})}}
			m, n := c5cDirect(t, c, o)
			c5cHitter(t, m, n)
			for i := 1; i <= 4; i++ {
				i := i
				c5cSpin(t, func() bool { return c.registered("hits") == i })
				c.mu.Lock()
				d := c.ticks[len(c.ticks)-1].next.Sub(c.at)
				c.mu.Unlock()
				c.advance(d)
				c5cSpin(t, func() bool { return c.registered("hits") == i+1 })
			}
			want := 5 * time.Second
			if duration == 7*time.Second {
				want = 10 * time.Second
			}
			mu.Lock()
			defer mu.Unlock()
			for i := 1; i < len(starts); i++ {
				need(t, starts[i].Sub(starts[i-1]) == want, "start cadence", starts)
			}
			t.Logf("requests=4 duration=%s adjacent=%s", duration, want)
		})
	}
	t.Run("single-flight-stats-cancel", func(t *testing.T) {
		c := c5cNewClock()
		f := newFake()
		entered, cancelled := make(chan struct{}), make(chan struct{})
		var cancelOnce sync.Once
		var inFlight, maximum, hits, stats atomic.Int32
		o := c5bOptions()
		o.now, o.tick = c.now, c.tick
		o.StatsInterval = 5 * time.Second
		o.Client.Timeouts = map[nc.Route]time.Duration{nc.HitsRoute: 30 * time.Second}
		o.Client.Transport = c5bTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == string(nc.HitsRoute) {
				if hits.Add(1) == 1 {
					close(entered)
				}
				v := inFlight.Add(1)
				for old := maximum.Load(); v > old && !maximum.CompareAndSwap(old, v); old = maximum.Load() {
				}
				<-r.Context().Done()
				inFlight.Add(-1)
				if r.Context().Err() == context.Canceled {
					cancelOnce.Do(func() { close(cancelled) })
				}
				return nil, r.Context().Err()
			}
			if r.URL.Path == string(nc.StatsRoute) {
				stats.Add(1)
			}
			return f.RoundTrip(r)
		})
		m, s := c5bManager(t, []NodeSpec{c5bSpec("a")}, o)
		m.Start(s)
		c5cSpin(t, func() bool { return c.registered("hits") == 1 && stats.Load() == 1 })
		c.advance(5 * time.Second)
		c5bWait(t, entered, time.Second)
		need(t, m.ctx.Err() == nil, "parent live")
		c5cSpin(t, func() bool { return stats.Load() == 2 })
		for i := 0; i < 3; i++ {
			before := stats.Load()
			c.advance(5 * time.Second)
			c5cSpin(t, func() bool { return stats.Load() > before })
		}
		need(t, hits.Load() == 1 && maximum.Load() == 1 && stats.Load() == 5, "blocked hits interfered", hits.Load(), maximum.Load(), stats.Load())
		done := make(chan struct{})
		go func() { m.RemoveNode("a"); close(done) }()
		c5bWait(t, done, time.Second)
		c5bWait(t, cancelled, time.Second)
		before := hits.Load()
		c.advance(time.Minute)
		need(t, hits.Load() == before && m.ctx.Err() == nil, "request after remove")
		t.Logf("blocked_ticks=3 max_in_flight=%d hits=%d stats=%d cancelled=1 removal_under_1s=1", maximum.Load(), hits.Load(), stats.Load())
	})
	t.Run("rates", func(t *testing.T) {
		c := c5cNewClock()
		m, n := c5cDirect(t, c, Options{})
		hit := func(ns, count, bytes uint64) {
			m.acceptHits(n, nc.HitsResponse{NowNS: ns * 1e9, Hits: []nc.RuleHit{{RuleID: "r", LogicalID: 1, DropCount: count, DropBytes: bytes}}}, c.now())
		}
		hit(5, 100, 10000)
		need(t, len(n.hits.rates) == 0, "first unknown")
		hit(10, 5100, 510000)
		need(t, n.hits.rates["r"].PPS == 1000 && n.hits.rates["r"].BytesPS == 100000, "delta")
		before := n.hits
		before.base = map[uint32]hitBaseline{}
		for k, v := range n.hits.base {
			before.base[k] = v
		}
		before.rates = map[string]RuleRate{}
		for k, v := range n.hits.rates {
			before.rates[k] = v
		}
		m.acceptHits(n, nc.HitsResponse{NowNS: 10e9, Hits: []nc.RuleHit{}}, c.now())
		need(t, reflect.DeepEqual(before, n.hits), "same snapshot changed state")
		hidden := nc.RuleHit{RuleID: "r", LogicalID: 1, DropCount: 10100, DropBytes: 1010000, LastHitNS: 9e9}
		hotNS := uint64(9e9)
		need(t, hidden.DropCount > n.hits.base[1].count && hidden.LastHitNS < n.hits.lastNow && hotNS < n.hits.lastNow, "scan overlap prerequisite")
		filtered := []nc.RuleHit{}
		if hotNS >= n.hits.lastNow && hidden.LastHitNS >= n.hits.lastNow {
			filtered = append(filtered, hidden)
		}
		m.acceptHits(n, nc.HitsResponse{NowNS: 15e9, Hits: filtered}, c.now())
		_, known := n.hits.rates["r"]
		need(t, !known, "scanning overlap absent must be unknown, not zero")
		hit(20, 20100, 2010000)
		need(t, len(n.hits.rates) == 0, "gap recovery unknown")
		hit(25, 25100, 2510000)
		need(t, n.hits.rates["r"].PPS == 1000, "adjacent recovery")
		hit(30, 1, 2511000)
		need(t, len(n.hits.rates) == 0, "packet decrease unknown")
		hit(35, 5001, 3011000)
		need(t, n.hits.rates["r"].PPS == 1000, "packet recovery")
		hit(40, 10001, 1)
		need(t, len(n.hits.rates) == 0, "bytes alone decreased")
		hit(45, 15001, 500001)
		need(t, n.hits.rates["r"].PPS == 1000, "bytes recovery")
		hit(1, 1, 1)
		need(t, len(n.hits.rates) == 0, "host reset")
		hit(6, 5001, 500001)
		need(t, n.hits.rates["r"].PPS == 1000, "host recovery")
		c.advance(61 * time.Second)
		m.acceptHits(n, nc.HitsResponse{NowNS: 67e9}, c.now())
		need(t, len(n.hits.base) == 0, "baseline expiry")
		t.Log("first_unknown=1 same_snapshot_different_rows_equal=1 absent_unknown=1 recovered_unknown=1 adjacent_pps=1000 packet_reset=1 byte_only_reset=1 host_reset=1 expired_baselines=1")
	})
}

func TestC5CStatsPriority(t *testing.T) {
	for _, slow := range []string{"health", "stats"} {
		slow := slow
		t.Run(slow, func(t *testing.T) {
			c := c5cNewClock()
			checks := make(chan struct{}, 10)
			release := make(chan struct{}, 10)
			calls := make(chan string, 20)
			channels := map[string]chan time.Time{}
			ready := make(chan struct{})
			var injected atomic.Bool
			var enabled atomic.Bool
			o := Options{HealthInterval: time.Hour, StatsInterval: time.Hour}
			o.statsPriority = func() { checks <- struct{}{}; <-release }
			o.Client.Transport = c5bTransport(func(r *http.Request) (*http.Response, error) {
				kind := "health"
				if r.URL.Path == string(nc.StatsRoute) {
					kind = "stats"
				}
				calls <- kind
				if enabled.Load() && kind == slow {
					if slow == "health" {
						c.advance(2900 * time.Millisecond)
					} else {
						c.advance(4900 * time.Millisecond)
					}
					if injected.CompareAndSwap(false, true) {
						channels["health"] <- c.now()
						channels["stats"] <- c.now()
						close(ready)
					}
				}
				if kind == "health" {
					return c5cReply(200, `{"status":"ok","rules_synced":true,"whitelist_synced":true}`)
				}
				return c5cReply(200, `{"total_packets":100,"dropped_packets":60,"passed_packets":40}`)
			})
			m, n := c5cDirect(t, c, o)
			done := make(chan struct{})
			go func() { m.sampler(n); close(done) }()
			t.Cleanup(func() {
				m.cancel()
				for i := 0; i < 4; i++ {
					select {
					case release <- struct{}{}:
					default:
					}
				}
				c5bWait(t, done, time.Second)
			})
			need(t, <-calls == "health" && <-calls == "stats", "startup")
			c5bWait(t, checks, time.Second)
			enabled.Store(true)
			c.mu.Lock()
			for _, x := range c.ticks {
				channels[x.kind] = x.ch
			}
			c.mu.Unlock()
			due := c.now()
			channels[slow] <- due
			release <- struct{}{}
			need(t, <-calls == slow, "slow request prerequisite")
			c5bWait(t, ready, time.Second)
			t.Log("prerequisite: both timers ready before slow request returns")
			c5bWait(t, checks, time.Second)
			release <- struct{}{}
			need(t, <-calls == "stats", "stats priority after slow request")
			c5bWait(t, checks, time.Second)
			channels["stats"] <- c.now()
			release <- struct{}{}
			need(t, <-calls == "stats", "every select priority")
			c5bWait(t, checks, time.Second)
			t.Logf("slow=%s priority_checks=4 simultaneous_ready=2 due_stats=2 actual_stats=2 start_delay=0", slow)
		})
	}
}

func TestC5CHistory(t *testing.T) {
	t.Run("ring-aggregate-retry", func(t *testing.T) {
		c := c5cNewClock()
		db, e := store.Open(filepath.Join(t.TempDir(), "traffic.db"))
		need(t, e == nil, e)
		defer db.Close()
		m := New([]NodeSpec{c5bSpec("a"), c5bSpec("b")}, Options{now: c.now, History: db})
		start := c.now()
		add := func(i int, at time.Time, p float64) {
			m.addTraffic(m.nodes[i], at, map[string]float64{"dropped_packets": p, "passed_packets": 2 * p, "dropped_bytes": 100 * p, "passed_bytes": 200 * p})
		}
		add(0, start, 10)
		add(1, start, 1)
		add(0, start.Add(5*time.Second), 1)
		add(1, start.Add(5*time.Second), 10)
		add(1, start.Add(time.Second), 3)
		c.advance(5 * time.Second)
		rows, _, _ := m.TrafficMemory("", time.Hour)
		need(t, len(rows) == 2 && rows[0].T == start.Unix() && rows[0].Avg[0] == 13, "alignment/overwrite", rows)
		m.addTraffic(m.nodes[0], start.Add(10*time.Second), nil)
		need(t, len(m.traffic.minutes("", start.Add(time.Minute))) == 1, "nil sample")
		m.flushHistory(start.Add(59 * time.Second))
		var count int
		need(t, db.QueryRow("SELECT COUNT(*) FROM traffic_1m").Scan(&count) == nil && count == 0, "early write")
		_, e = db.Exec("CREATE TRIGGER traffic_fail BEFORE INSERT ON traffic_1m BEGIN SELECT RAISE(ABORT,'TEST_ONLY_FAILURE'); END")
		need(t, e == nil, e)
		m.flushHistory(start.Add(time.Minute))
		need(t, m.traffic.next == start.Unix(), "failed write advanced cursor")
		_, e = db.Exec("DROP TRIGGER traffic_fail")
		need(t, e == nil, e)
		m.flushHistory(start.Add(time.Minute))
		rows, e = store.ReadTraffic(db.Reader(), false, "", start.Unix(), start.Add(time.Minute).Unix())
		need(t, e == nil && len(rows) == 1, e, rows)
		need(t, rows[0].N == 2 && rows[0].Avg[0] == 12 && rows[0].Max[0] == 13, "aggregate exact", rows)
		a, _ := store.ReadTraffic(db.Reader(), false, "a", 0, start.Add(time.Minute).Unix())
		b, _ := store.ReadTraffic(db.Reader(), false, "b", 0, start.Add(time.Minute).Unix())
		need(t, rows[0].Max[0] < a[0].Max[0]+b[0].Max[0], "sum of maxima")
		need(t, db.QueryRow("SELECT COUNT(*) FROM traffic_1m").Scan(&count) == nil && count == 3, "one row per sequence")
		m.flushHistory(start.Add(2 * time.Minute))
		need(t, db.QueryRow("SELECT COUNT(*) FROM traffic_1m").Scan(&count) == nil && count == 3, "duplicate minute")
		t.Log("minute_before_end_rows=0 failed_write_cursor_unchanged=1 retry_rows=3 aggregate_n=2 avg=12 max=13 node_max_sum=20")
	})
	t.Run("partial-overwritten-membership", func(t *testing.T) {
		c := c5cNewClock()
		c.advance(10 * time.Second)
		m, n := c5cDirect(t, c, Options{})
		start := c.now()
		m.addTraffic(n, start, map[string]float64{"dropped_packets": 7})
		need(t, len(n.traffic.minutes("a", start.Add(time.Minute))) == 0, "partial startup minute")
		m.addTraffic(n, start.Add(time.Minute), map[string]float64{"dropped_packets": 9})
		need(t, len(n.traffic.minutes("a", start.Add(2*time.Minute))) == 1, "full minute")
		need(t, len(n.traffic.minutes("a", start.Add(2*time.Hour))) == 0, "overwritten unflushed minute")
		m.nodes = nil
		m.addTraffic(n, start.Add(3*time.Minute), map[string]float64{"dropped_packets": 999})
		rows, _, _ := m.TrafficMemory("", time.Hour)
		for _, r := range rows {
			need(t, r.Avg[0] != 999, "removed sample in aggregate")
		}
		need(t, len(m.TrafficInput().Rates) == 0, "removed Top contribution")
		t.Log("partial_skipped=1 overwritten_skipped=1 removed_late_sample_excluded=1")
	})
	t.Run("transaction-unlocked", func(t *testing.T) {
		c := c5cNewClock()
		db, e := store.Open(filepath.Join(t.TempDir(), "traffic.db"))
		need(t, e == nil, e)
		defer db.Close()
		s := rules.New(db, nil)
		counts := map[string]int{}
		returned := 0
		o := Options{now: c.now, History: db}
		o.historyTx = func(phase string) {
			counts[phase]++
			done := make(chan *rules.Error, 1)
			go func() { _, err := s.Occupancy(); done <- err }()
			select {
			case err := <-done:
				need(t, err == nil, err)
				returned++
			case <-time.After(time.Second):
				t.Error("fixture released after occupancy lock timeout")
			}
		}
		m := New([]NodeSpec{c5bSpec("a")}, o)
		m.svc = s
		m.addTraffic(m.nodes[0], c.now(), map[string]float64{"dropped_packets": 1})
		m.flushHistory(c.now().Add(time.Minute))
		need(t, counts["write"] > 0 && counts["delete"] > 0, "hook counts", counts)
		t.Logf("history_transaction_hooks=%v occupancy_returned_inside_hooks=%d", counts, returned)
	})
}

func TestC5CInput(t *testing.T) {
	c := c5cNewClock()
	m, n := c5cDirect(t, c, Options{})
	n.status.Rates = map[string]float64{"dropped_packets": 100, "dropped_bytes": 10000}
	m.acceptHits(n, nc.HitsResponse{NowNS: 5e9, Truncated: true}, c.now())
	out := m.TrafficInput()
	need(t, out.Incomplete && !out.DenominatorMissing, "isolated truncated")
	m.acceptHits(n, nc.HitsResponse{NowNS: 10e9}, c.now())
	need(t, !m.TrafficInput().Incomplete, "unknown only")
	first := m.TrafficInput().Key
	m.Changed(rules.Change{Gen: 1, RuleKeys: []string{"a"}})
	need(t, m.TrafficInput().Key != first, "generation key")
	first = m.TrafficInput().Key
	n.statsSeq++
	need(t, m.TrafficInput().Key != first, "stats sequence key")
	n.status.Rates = nil
	need(t, m.TrafficInput().Incomplete && m.TrafficInput().DenominatorMissing, "missing Stats")
	t.Log("truncated_only_incomplete=1 unknown_only_incomplete=0 gen_invalidates=1 stats_invalidates=1 missing_stats_incomplete=1")
}
func TestC5CFailureStateKey(t *testing.T) {
	c := c5cNewClock()
	calls := 0
	o := Options{Client: nc.Options{Transport: c5bTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return c5cReply(500, `{}`)
		}
		return c5cReply(200, c5cHits(5e9))
	})}}
	m, n := c5cDirect(t, c, o)
	n.status.Rates = map[string]float64{"dropped_packets": 1, "dropped_bytes": 1}
	m.acceptHits(n, nc.HitsResponse{NowNS: 5e9}, c.now())
	before := m.TrafficInput()
	c5cHitter(t, m, n)
	c5cSpin(t, func() bool { return c.registered("hits") == 1 })
	c.advance(5 * time.Second)
	c5cSpin(t, func() bool { return c.registered("hits") == 2 })
	failed := m.TrafficInput()
	need(t, failed.Incomplete && failed.Key != before.Key, "failure invalidates")
	c.advance(10 * time.Second)
	c5cSpin(t, func() bool { return c.registered("hits") == 3 })
	recovered := m.TrafficInput()
	need(t, !recovered.Incomplete && recovered.Key != failed.Key && recovered.At == before.At, "same snapshot recovery invalidates")
	t.Log("success_snapshot_unchanged=1 failure_key_changed=1 recovery_key_changed=1 incomplete=false,true,false")
}
func TestC5CRingBound(t *testing.T) {
	c := c5cNewClock()
	db, e := store.Open(filepath.Join(t.TempDir(), "ring.db"))
	need(t, e == nil, e)
	defer db.Close()
	m, n := c5cDirect(t, c, Options{History: db})
	for i := 0; i < 800; i++ {
		m.addTraffic(n, c.now(), map[string]float64{"dropped_packets": float64(i)})
		c.advance(5 * time.Second)
	}
	rows, _, _ := m.TrafficMemory("", time.Hour)
	need(t, len(rows) == 720, "ring bound", len(rows))
	c.advance(2 * time.Hour)
	m.flushHistory(c.now())
	var count int
	need(t, db.Reader().QueryRow("SELECT COUNT(*) FROM traffic_1m").Scan(&count) == nil && count == 0 && m.traffic.next == c.now().Unix()/60*60, "overwritten minute advanced")
	t.Log("inserted_points=800 slots=720 overwritten_minutes_discarded=1 cursor_advanced=1 persisted_rows=0")
}
