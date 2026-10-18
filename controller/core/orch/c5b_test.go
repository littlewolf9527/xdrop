package orch

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type c5bTransport func(*http.Request) (*http.Response, error)

func (f c5bTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func c5bOptions() Options {
	o := fastOptions()
	o.HealthInterval, o.StatsInterval, o.CheckInterval = time.Hour, time.Hour, time.Hour
	return o
}
func c5bManager(t *testing.T, specs []NodeSpec, o Options) (*Manager, *rules.Service) {
	t.Helper()
	db, e := store.Open(filepath.Join(t.TempDir(), "nodes.db"))
	need(t, e == nil, "database")
	m := New(specs, o)
	s := rules.New(db, m)
	t.Cleanup(func() { m.Stop(); db.Close() })
	return m, s
}
func c5bSpec(name string) NodeSpec {
	return NodeSpec{Name: name, BaseURL: "http://" + name + ".invalid", Key: nc.Secret("TEST_ONLY_NODE_KEY")}
}
func c5bWait(t *testing.T, ch <-chan struct{}, limit time.Duration) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(limit):
		t.Fatal("fixture deadline")
	}
}
func c5bNormal(t *testing.T, m *Manager, name string) {
	t.Helper()
	eventually(t, func() bool {
		for _, n := range m.Status() {
			if n.Name == name {
				return n.Rules.State == "normal" && n.Whitelist.State == "normal" && !n.StatsAt.IsZero()
			}
		}
		return false
	})
}

func TestC5BOrch(t *testing.T) {
	t.Run("C5B-add-full", func(t *testing.T) {
		a, b := newFake(), newFake()
		o := c5bOptions()
		o.Client.Transport = c5bTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "a.invalid" {
				return a.RoundTrip(r)
			}
			return b.RoundTrip(r)
		})
		var m *Manager
		pending := false
		o.atRegister = func() {
			n := m.nodes[len(m.nodes)-1]
			pending = n.sides[0].status.State == "pending" && n.sides[1].status.State == "pending" && n.sides[0].full && n.sides[1].full
		}
		m, s := c5bManager(t, []NodeSpec{c5bSpec("a")}, o)
		m.Start(s)
		c5bNormal(t, m, "a")
		before := len(a.records(""))
		need(t, m.AddNode(c5bSpec("b")) == nil, "add")
		c5bNormal(t, m, "b")
		need(t, pending && len(b.records(nc.AtomicRoute)) == 1 && len(b.records(nc.SyncWLRoute)) == 1, "pending to full normal")
		need(t, len(a.records("")) == before, "unrelated requests")
		need(t, m.AddNode(c5bSpec("b")) == ErrDuplicate, "duplicate")
		t.Logf("pending_sides=2 normal_sides=2 atomic=1 unrelated_extra_requests=0")
	})
	t.Run("C5B-lifecycle", func(t *testing.T) {
		m, s := c5bManager(t, nil, c5bOptions())
		need(t, m.AddNode(c5bSpec("before")) == ErrNotRunning, "before start")
		m.Start(s)
		m.Stop()
		need(t, m.AddNode(c5bSpec("after")) == ErrNotRunning && len(m.Status()) == 0, "after stop")
		t.Log("before_start_rejected=1 after_stop_rejected=1 registered_nodes=0")
	})
	t.Run("C5B-register", func(t *testing.T) {
		var m *Manager
		locked := false
		var n *node
		stopped := make(chan struct{})
		o := c5bOptions()
		o.atRegister = func() {
			acquired := m.mu.TryLock()
			if acquired {
				m.mu.Unlock()
			}
			locked = !acquired
		}
		o.afterAddRegister = func() {
			m.mu.Lock()
			n = m.nodes[0]
			m.mu.Unlock()
			go func() { m.Stop(); close(stopped) }()
			eventually(t, func() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.closed })
		}
		m, s := c5bManager(t, nil, o)
		m.Start(s)
		need(t, m.AddNode(NodeSpec{Name: "a"}) == nil, "registered add")
		c5bWait(t, stopped, time.Second)
		c5bWait(t, n.done, time.Millisecond)
		need(t, locked, "registration outside lock")
		t.Log("atRegister_trylock=false stop_returned_with_done_closed=1")
	})
	t.Run("C5B-remove-waits-done", func(t *testing.T) {
		f := newFake()
		entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var enterOnce, cancelOnce, releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		defer unblock()
		o := c5bOptions()
		o.Client.Timeouts = map[nc.Route]time.Duration{nc.AtomicRoute: 30 * time.Second}
		o.Client.Transport = c5bTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != string(nc.AtomicRoute) {
				return f.RoundTrip(r)
			}
			enterOnce.Do(func() { close(entered) })
			select {
			case <-r.Context().Done():
				if r.Context().Err() == context.Canceled {
					cancelOnce.Do(func() { close(cancelled) })
				}
			case <-release:
				return nil, context.Canceled
			}
			<-release
			return nil, r.Context().Err()
		})
		m, s := c5bManager(t, []NodeSpec{c5bSpec("a")}, o)
		n := m.nodes[0]
		m.Start(s)
		c5bWait(t, entered, time.Second)
		need(t, m.ctx.Err() == nil, "request prerequisite: parent alive")
		removed := make(chan struct{})
		go func() { m.RemoveNode("a"); close(removed) }()
		c5bWait(t, cancelled, time.Second)
		need(t, m.ctx.Err() == nil, "removal cancelled parent")
		t.Log("request_entered=1 parent_alive=1 cancelled=1 release_pending=1")
		select {
		case <-removed:
			unblock()
			t.Fatal("RemoveNode returned while cancelled request was still blocked")
		case <-time.After(200 * time.Millisecond):
		}
		unblock()
		c5bWait(t, removed, time.Second)
		select {
		case <-n.done:
		default:
			t.Fatal("RemoveNode returned before done closed")
		}
		m.mu.Lock()
		exits := n.exits
		m.mu.Unlock()
		need(t, exits == 3, "worker, sampler and hitter did not all exit")
		t.Log("request_entered=1 parent_alive=1 cancelled=1 held_ms=200 remove_returned_before_release=0 done_closed_on_return=1 node_exits=3")
	})
	for _, route := range []nc.Route{nc.AtomicRoute, nc.StatsRoute, nc.RulesRoute} {
		route := route
		t.Run("C5B-cancel-"+string(route)[1:], func(t *testing.T) {
			f, other := newFake(), newFake()
			entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var enterOnce, cancelOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			o := c5bOptions()
			o.StatsInterval = 10 * time.Millisecond
			o.Client.Timeouts = map[nc.Route]time.Duration{route: 30 * time.Second}
			o.Client.Transport = c5bTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "b.invalid" {
					return other.RoundTrip(r)
				}
				if r.URL.Path == string(route) {
					enterOnce.Do(func() { close(entered) })
					select {
					case <-r.Context().Done():
						if r.Context().Err() == context.Canceled {
							cancelOnce.Do(func() { close(cancelled) })
						}
						return nil, r.Context().Err()
					case <-release:
					}
				}
				return f.RoundTrip(r)
			})
			m, s := c5bManager(t, []NodeSpec{c5bSpec("a"), c5bSpec("b")}, o)
			m.Start(s)
			c5bNormal(t, m, "b")
			if route == nc.RulesRoute {
				c5bNormal(t, m, "a")
				m.ReconcileNow("a")
			}
			c5bWait(t, entered, time.Second)
			need(t, m.ctx.Err() == nil, "parent cancelled before removal")
			removed := make(chan struct{})
			start := time.Now()
			go func() { m.RemoveNode("a"); close(removed) }()
			select {
			case <-removed:
			case <-time.After(time.Second):
				unblock()
				t.Fatal("Remove exceeded 1 second")
			}
			c5bWait(t, cancelled, time.Millisecond)
			need(t, m.ctx.Err() == nil, "parent cancelled by removal")
			before := len(other.records(nc.AtomicRoute))
			m.ForceSync("b")
			eventually(t, func() bool { return len(other.records(nc.AtomicRoute)) > before })
			t.Logf("route=%s blocked=1 parent_alive=1 timeout_seconds=30 cancelled=1 remove_ms=%d other_sync=1", route, time.Since(start).Milliseconds())
		})
	}
	for _, path := range []string{"worker", "sampler", "reconcile"} {
		path := path
		t.Run("C5B-no-request-"+path, func(t *testing.T) {
			f := newFake()
			o := c5bOptions()
			o.Client.Transport = f
			o.StatsInterval = 10 * time.Millisecond
			m, s := c5bManager(t, []NodeSpec{c5bSpec("a")}, o)
			m.Start(s)
			c5bNormal(t, m, "a")
			route := nc.AtomicRoute
			if path == "sampler" {
				route = nc.StatsRoute
			}
			if path == "reconcile" {
				route = nc.RulesRoute
				m.ReconcileNow("a")
				eventually(t, func() bool { return len(f.records(route)) > 0 })
			}
			need(t, len(f.records(route)) > 0, "path never requested")
			m.mu.Lock()
			n := m.nodes[0]
			m.mu.Unlock()
			m.RemoveNode("a")
			before := len(f.records(""))
			m.ForceSync("a")
			m.ReconcileNow("a")
			wake(n)
			m.Changed(rules.Change{Whitelist: true})
			time.Sleep(40 * time.Millisecond)
			need(t, len(f.records("")) == before, "post-remove request")
			t.Logf("path=%s requests_before=%d requests_after=%d witness_route=%s", path, before, len(f.records("")), route)
		})
	}
	t.Run("C5B-event-unlinked", func(t *testing.T) {
		f := newFake()
		o := c5bOptions()
		o.Client.Transport = f
		entered, release := make(chan struct{}, 1), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		f.setScript(func(path string, _ int, _ []byte) fault {
			if path == string(nc.AtomicRoute) {
				return fault{block: release, entered: entered}
			}
			return fault{}
		})
		var unlinked atomic.Bool
		observed := make(chan bool, 8)
		o.onRecord = func(name string, kept bool) {
			if name == "a" && unlinked.Load() {
				observed <- kept
			}
		}
		var boundary int
		var m *Manager
		var observedKept, missing bool
		o.afterRemoveUnlink = func() {
			boundary = len(m.Events())
			unlinked.Store(true)
			unblock()
			select {
			case observedKept = <-observed:
			case <-time.After(time.Second):
				missing = true
			}
		}
		m, s := c5bManager(t, []NodeSpec{c5bSpec("a")}, o)
		m.Start(s)
		c5bWait(t, entered, time.Second)
		removed := make(chan struct{})
		go func() { m.RemoveNode("a"); close(removed) }()
		c5bWait(t, removed, 2*time.Second)
		need(t, !missing && !observedKept, "record witness absent or kept")
		for _, e := range m.Events()[boundary:] {
			need(t, e.Node != "a", "deleted node event")
		}
		t.Log("onRecord_after_unlink=1 kept=false observed_before_remove_return=1")
	})
	t.Run("C5B-race-1000", func(t *testing.T) {
		m, s := c5bManager(t, nil, c5bOptions())
		m.Start(s)
		var adds, removes, status, changed, limits atomic.Int32
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			for i := 0; i < 1000; i++ {
				m.Status()
				status.Add(1)
				m.Changed(rules.Change{})
				changed.Add(1)
				m.Limits()
				limits.Add(1)
			}
		}()
		mutated := make(chan struct{})
		go func() {
			defer close(mutated)
			for i := 0; i < 1000; i++ {
				if m.AddNode(NodeSpec{Name: "a"}) == nil {
					adds.Add(1)
				}
				m.RemoveNode("a")
				removes.Add(1)
			}
		}()
		c5bWait(t, mutated, 10*time.Second)
		c5bWait(t, finished, time.Second)
		for _, n := range []int32{adds.Load(), removes.Load(), status.Load(), changed.Load(), limits.Load()} {
			need(t, n == 1000, "operation execution count", n)
		}
		t.Logf("add=%d remove=%d Status=%d Changed=%d Limits=%d", adds.Load(), removes.Load(), status.Load(), changed.Load(), limits.Load())
	})
}
