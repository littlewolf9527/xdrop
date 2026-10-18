package orch

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type c3bTransport map[string]*fakeNode

func (f c3bTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if node := f[r.URL.Host]; node != nil {
		return node.RoundTrip(r)
	}
	return nil, fmt.Errorf("unknown fixture host")
}
func c3bCapacity(f *fakeNode, values rules.Values) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cap := map[string]any{}
	for i, name := range rules.DimensionNames() {
		if values[i] != 0 {
			cap[name] = map[string]any{"limit": values[i], "used": 1}
		}
	}
	f.stats["capacity"] = cap
}
func TestC3BLimits(t *testing.T) {
	t.Run("CAP-limits", func(t *testing.T) {
		fs := c3bTransport{"a.invalid": newFake(), "b.invalid": newFake()}
		m := New([]NodeSpec{{Name: "a", BaseURL: "http://a.invalid"}, {Name: "b", BaseURL: "http://b.invalid"}}, Options{Client: nc.Options{Transport: fs}})
		m.ctx = context.Background()
		for _, n := range m.nodes {
			n.ctx = m.ctx
		}
		builtin := rules.Values{500000, 500000, 500000, 500000, 50000, 50000, 50000, 50000, 50000, 1000000}
		expected := func(values rules.Values, source string, overloaded int) {
			t.Helper()
			got := m.Limits()
			need(t, got.Values == values && len(got.Overloaded) == overloaded, "minimum", got, values, source)
			for _, s := range got.Sources {
				need(t, s == source, "source", got.Sources, source)
			}
		}
		for _, n := range m.nodes {
			m.sampleStats(n)
		}
		expected(builtin, "builtin", 0)
		small := rules.Values{12, 11, 10, 9, 8, 7, 6, 5, 4, 1500}
		c3bCapacity(fs["a.invalid"], small)
		m.sampleStats(m.nodes[0])
		expected(small, "a", 0)
		m.nodes[0].status.Online = false
		expected(small, "a", 0)
		fs["a.invalid"].setScript(func(route string, _ int, _ []byte) fault {
			if route == string(nc.StatsRoute) {
				return fault{status: 500, body: "{}"}
			}
			return fault{}
		})
		m.sampleStats(m.nodes[0])
		expected(small, "a", 0)
		fs["a.invalid"].setScript(nil)
		m.nodes[0].overloaded = true
		m.nodes[0].status.Overload = []rules.Overload{{Dim: "blacklist", Limit: 12, Used: 13}}
		expected(builtin, "builtin", 1)
		got := m.Limits()
		need(t, got.Overloaded[0].Name == "a" && got.Overloaded[0].Dims[0].Used == 13, "overload list", got)
		got.Overloaded[0].Dims[0].Used = 0
		need(t, m.Limits().Overloaded[0].Dims[0].Used == 13, "overload copy")
		m.nodes[1].overloaded = true
		expected(builtin, "builtin", 2)
		m.nodes[0].overloaded, m.nodes[1].overloaded = false, false
		large := rules.Values{600000, 600000, 600000, 600000, 60000, 60000, 60000, 60000, 60000, 2000000}
		c3bCapacity(fs["a.invalid"], large)
		m.sampleStats(m.nodes[0])
		expected(builtin, "builtin", 0)
		c3bCapacity(fs["b.invalid"], large)
		m.sampleStats(m.nodes[1])
		expected(large, "a", 0)
		m.nodes[1].status.Incompatible = true
		expected(builtin, "builtin", 0)
		m.nodes[1].status.Incompatible = false
		fs["a.invalid"].mu.Lock()
		fs["a.invalid"].stats["capacity"] = map[string]any{"blacklist": map[string]any{"limit": 7, "used": 0}, "cidr_blacklist": map[string]any{"limit": 0}, "cond": map[string]any{"limit": -1}, "cidr_cond": map[string]any{"limit": 1.5}, "whitelist": map[string]any{"limit": "5"}}
		fs["a.invalid"].mu.Unlock()
		m.sampleStats(m.nodes[0])
		want := builtin
		want[0] = 7
		need(t, m.Limits().Values == want, "per-dimension parser/fallback", m.Limits(), want)
		fs["a.invalid"].mu.Lock()
		delete(fs["a.invalid"].stats, "capacity")
		fs["a.invalid"].mu.Unlock()
		m.sampleStats(m.nodes[0])
		expected(builtin, "builtin", 0)
	})
}

type c3bHarness struct {
	m      *Manager
	s      *rules.Service
	fs     c3bTransport
	rows   []store.Rule
	paused chan struct{}
	resume chan struct{}
	rounds int
}

func (h *c3bHarness) pause(t *testing.T) {
	t.Helper()
	select {
	case <-h.paused:
		h.rounds++
	case <-time.After(3 * time.Second):
		t.Fatal("worker round did not finish")
	}
}
func (h *c3bHarness) step(t *testing.T) {
	t.Helper()
	select {
	case h.resume <- struct{}{}:
	case <-time.After(3 * time.Second):
		t.Fatal("worker round not paused")
	}
	h.pause(t)
}
func (h *c3bHarness) two(t *testing.T) {
	t.Helper()
	before := h.rounds
	h.step(t)
	h.step(t)
	need(t, h.rounds-before == 2, "complete rounds", h.rounds-before)
	t.Logf("worker_complete_rounds=%d", h.rounds-before)
}
func (h *c3bHarness) full(t *testing.T, want bool) {
	t.Helper()
	h.m.mu.Lock()
	got := [2]bool{h.m.nodes[0].sides[0].full, h.m.nodes[0].sides[1].full}
	h.m.mu.Unlock()
	need(t, got == ([2]bool{want, want}), "full guard", got, want)
}
func c3bWrites(f *fakeNode) [3]int {
	return [3]int{len(f.records(nc.AtomicRoute)), len(f.records(nc.SyncWLRoute)), len(f.records(nc.CommitRoute))}
}
func c3bEvents(m *Manager, node, side, state, reason string) int {
	n := 0
	for _, e := range m.Events() {
		if e.Node == node && e.Side == side && e.To == state && e.Reason == reason {
			n++
		}
	}
	return n
}
func newC3B(t *testing.T) *c3bHarness {
	t.Helper()
	h := &c3bHarness{fs: c3bTransport{"a.invalid": newFake(), "b.invalid": newFake()}, paused: make(chan struct{}, 1), resume: make(chan struct{})}
	opts := fastOptions()
	opts.HealthInterval, opts.StatsInterval = time.Hour, time.Hour
	opts.Client.Transport = h.fs
	opts.roundDone = func(name string) {
		if name != "a" {
			return
		}
		select {
		case h.paused <- struct{}{}:
		case <-h.m.ctx.Done():
			return
		}
		select {
		case <-h.resume:
		case <-h.m.ctx.Done():
		}
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	need(t, err == nil, err)
	h.m = New([]NodeSpec{{Name: "a", BaseURL: "http://a.invalid"}, {Name: "b", BaseURL: "http://b.invalid"}}, opts)
	h.s = rules.New(db, h.m)
	h.s.UseLimits(h.m.Limits)
	t.Cleanup(func() { h.m.Stop(); db.Close() })
	for i := 0; i < 3; i++ {
		h.rows = append(h.rows, h.create(t, i+1))
	}
	_, e := h.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: "192.0.2.10"})
	need(t, e == nil, e)
	h.m.Start(h.s)
	h.pause(t)
	for i := 0; i < 10 && (h.m.Status()[0].Rules.State != "normal" || h.m.Status()[0].Whitelist.State != "normal"); i++ {
		h.step(t)
	}
	eventually(t, func() bool {
		s := h.m.Status()
		return s[0].Rules.State == "normal" && s[0].Whitelist.State == "normal" && s[1].Rules.State == "normal" && s[1].Whitelist.State == "normal"
	})
	for _, n := range h.m.nodes {
		h.m.sampleHealth(n)
	}
	h.full(t, false)
	return h
}
func (h *c3bHarness) create(t *testing.T, port int) store.Rule {
	t.Helper()
	r, e := h.s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{SrcIP: p("192.0.2.1"), DstPort: p(port), Protocol: p("tcp")})
	need(t, e == nil, e)
	return r.Rule
}
func (h *c3bHarness) overload(t *testing.T) [3]int {
	t.Helper()
	before := c3bWrites(h.fs["a.invalid"])
	c3bCapacity(h.fs["a.invalid"], rules.Values{0: 1})
	h.m.sampleStats(h.m.nodes[0])
	h.two(t)
	h.full(t, false)
	s := h.m.Status()[0]
	need(t, s.Rules.State == "overloaded" && s.Whitelist.State == "overloaded" && s.Rules.Reason == "capacity" && s.Whitelist.Reason == "capacity", "overloaded states", s)
	need(t, !s.Rules.Confirmable && !s.Whitelist.Confirmable, "direct Confirmable projection before any full operation", s)
	need(t, reflect.DeepEqual(s.Overload, []rules.Overload{{Dim: "blacklist", Limit: 1, Used: 3}}), "overload dimensions", s.Overload)
	need(t, c3bWrites(h.fs["a.invalid"]) == before, "overload writes")
	for _, side := range []string{"rules", "whitelist"} {
		need(t, c3bEvents(h.m, "a", side, "overloaded", "capacity") == 1, "transition", side, h.m.Events())
	}
	return before
}
func TestC3BOverload(t *testing.T) {
	t.Run("CAP-overload-idle", func(t *testing.T) {
		var rounds atomic.Uint64
		opts := fastOptions()
		opts.CheckInterval = 20 * time.Millisecond
		opts.HealthInterval, opts.StatsInterval, opts.ReconcileInterval = time.Hour, time.Hour, time.Hour
		opts.roundDone = func(string) { rounds.Add(1) }
		r := newRig(t, opts, 3, true)
		c3bCapacity(r.f, rules.Values{0: 1})
		r.m.sampleStats(r.m.nodes[0])
		eventually(t, func() bool {
			s := r.m.Status()[0]
			return s.Rules.State == "overloaded" && s.Whitelist.State == "overloaded"
		})
		before := c3bWrites(r.f)
		r.create(t, 4)
		r.m.ForceSync("a")
		r.m.mu.Lock()
		n := r.m.nodes[0]
		pending := n.overloaded && n.status.Online && n.sides[0].full && n.sides[1].full && len(n.dirty) > 0
		r.m.mu.Unlock()
		need(t, pending, "overloaded node must retain full and dirty work")
		const intervals = 12
		// Allow three rounds per interval plus five boundary/queued wake rounds.
		// With hourly samplers, only periodic checks and the two writes above wake us.
		const bound = 3*intervals + 5
		start := rounds.Load()
		time.Sleep(intervals * opts.CheckInterval)
		completed := rounds.Load() - start
		after := c3bWrites(r.f)
		writes := (after[0] - before[0]) + (after[1] - before[1]) + (after[2] - before[2])
		t.Logf("intervals=%d rounds=%d bound=%d writes=%d", intervals, completed, bound, writes)
		need(t, completed > 0 && completed <= bound, "overloaded worker scheduling bound", completed, bound)
		need(t, writes == 0 && after == before, "overloaded worker wrote", before, after)
		s := r.m.Status()[0]
		need(t, s.Rules.State == "overloaded" && s.Whitelist.State == "overloaded", "idle overload states", s)
	})

	t.Run("CAP-overload-recover", func(t *testing.T) {
		h := newC3B(t)
		before := h.overload(t)
		extra := h.create(t, 4)
		h.two(t)
		eventually(t, func() bool { return h.fs["b.invalid"].row(extra.ID) != nil })
		need(t, c3bWrites(h.fs["a.invalid"]) == before, "write during Changed")
		need(t, h.s.ForceDelete(rules.Actor{Kind: rules.UI}, extra.ID) == nil, "delete while overloaded")
		h.two(t)
		need(t, c3bWrites(h.fs["a.invalid"]) == before, "write during delete")
		h.full(t, false)
		for _, r := range h.rows[:2] {
			need(t, h.s.ForceDelete(rules.Actor{Kind: rules.UI}, r.ID) == nil, "capacity reduction")
		}
		h.two(t)
		h.full(t, false)
		got := c3bWrites(h.fs["a.invalid"])
		need(t, got == ([3]int{before[0] + 1, before[1] + 1, before[2]}), "recovery must send one full per side", before, got)
		s := h.m.Status()[0]
		need(t, len(s.Overload) == 0 && s.Rules.State == "normal" && s.Whitelist.State == "normal", "recovered", s)
		for _, side := range []string{"rules", "whitelist"} {
			need(t, c3bEvents(h.m, "a", side, "pending", "capacity_recovered") == 1, "recovery event", side)
		}
		eventually(t, func() bool {
			return h.fs["b.invalid"].row(extra.ID) == nil && h.fs["b.invalid"].row(h.rows[0].ID) == nil && h.fs["b.invalid"].row(h.rows[1].ID) == nil && h.fs["b.invalid"].row(h.rows[2].ID) != nil
		})
	})
	for _, name := range []string{"force", "reconnect", "worker-restart", "version"} {
		name := name
		t.Run("CAP-overload-hold-"+name, func(t *testing.T) {
			h := newC3B(t)
			before := h.overload(t)
			n := h.m.nodes[0]
			f := h.fs["a.invalid"]
			switch name {
			case "force":
				h.m.ForceSync("a")
				h.full(t, true)
			case "reconnect":
				f.setScript(func(route string, _ int, _ []byte) fault {
					if route == string(nc.HealthRoute) {
						return fault{status: 500, body: "{}"}
					}
					return fault{}
				})
				h.m.sampleHealth(n)
				h.m.sampleHealth(n)
				need(t, !h.m.Status()[0].Online, "offline established")
				f.setScript(nil)
				h.m.sampleHealth(n)
				need(t, h.m.Status()[0].Online, "reconnected")
				h.full(t, true)
			case "worker-restart":
				f.mu.Lock()
				f.flags[0] = false
				f.mu.Unlock()
				h.m.sampleHealth(n)
				h.create(t, 4)
				h.full(t, false)
				h.m.mu.Lock()
				dirty, bad := len(n.dirty) > 0, n.sides[0].badHealth
				h.m.mu.Unlock()
				need(t, dirty && bad, "worker restart preconditions", dirty, bad)
			case "version":
				f.mu.Lock()
				f.protocol = 9
				f.mu.Unlock()
				need(t, !h.m.probe(n, 0) && h.m.Status()[0].Incompatible, "real Probe must establish protocol 9")
				f.mu.Lock()
				f.protocol = 11
				f.mu.Unlock()
				h.m.mu.Lock()
				n.probeAt = time.Time{}
				h.m.mu.Unlock()
			}
			h.two(t)
			s := h.m.Status()[0]
			need(t, c3bWrites(f) == before && s.Rules.State == "overloaded" && s.Whitelist.State == "overloaded", "hold guard", name, before, c3bWrites(f), s)
			if name == "worker-restart" {
				h.m.mu.Lock()
				full := n.sides[0].full
				h.m.mu.Unlock()
				need(t, full, "worker !commitReady branch not reached")
			}
			if name == "version" {
				need(t, !s.Incompatible && c3bEvents(h.m, "a", "incompatible", "false", "version_recovered") == 1, "recoverVersion not executed")
			}
		})
	}
}
