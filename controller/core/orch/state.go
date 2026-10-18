// Package orch asynchronously converges each node to committed service data.
package orch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
)

const DefaultReconcileInterval = 15 * time.Minute

var reconcileNow = time.Now

func (m *Manager) SetReconcileInterval(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.opts.ReconcileInterval = d
	deadline := reconcileNow().Add(d)
	for _, n := range m.nodes {
		for i, next := range n.nextReconcile {
			if next.After(deadline) {
				n.nextReconcile[i] = deadline
			}
		}
	}
}

type NodeSpec = nc.NodeSpec
type Options struct {
	History                                                          History
	now                                                              func() time.Time
	tick                                                             func(string, time.Duration) <-chan time.Time
	historyTx                                                        func(string)
	historyLimits                                                    [2]int
	hitsInterval                                                     time.Duration
	statsPriority                                                    func()
	Client                                                           nc.Options
	MergeWindow, RetryBase, RetryMax, CheckInterval                  time.Duration
	HealthInterval, StatsInterval, ReconcileInterval, ExpireInterval time.Duration
	OnEvent                                                          func(Event)
	atRegister, afterAddRegister, afterRemoveUnlink                  func()
	onRecord                                                         func(string, bool)
	roundDone                                                        func(string)                         // test scheduling barrier; nil in production
	mergeTick                                                        func(time.Duration) <-chan time.Time // test clock; nil uses the real timer
}
type Event struct {
	At                           time.Time
	Node, Side, From, To, Reason string
}
type LastError struct {
	Route         nc.Route
	HTTPStatus    int
	Code, Message string
}
type Rejected struct {
	Key, Fingerprint, Code, Error, ID string
	RuleIDs                           []string
}
type SideStatus struct {
	State, Reason       string
	Since               time.Time
	ConsecutiveFailures int
	LastError           LastError
	ConfirmedGen        uint64
	Confirmable         bool
	Rejected            []Rejected
}
type Diff struct {
	Extra, Missing, Different          int
	ExtraIDs, MissingIDs, DifferentIDs []string
}
type ReconcileStatus struct {
	LastAt   time.Time
	Duration time.Duration
	Pages    int
	Result   string
	Diff     Diff
}
type NodeStatus struct {
	Overload                          []rules.Overload
	Name                              string
	Online, Incompatible              bool
	HealthAt                          time.Time
	Health                            nc.Health
	Rules, Whitelist                  SideStatus
	StatsAt                           time.Time
	Stats                             map[string]any
	Rates                             map[string]float64
	RuleReconcile, WhitelistReconcile ReconcileStatus
	RuleStatsCount                    int
	RuleStatsAt                       time.Time
}
type side struct {
	status     SideStatus
	full       bool
	due        time.Time
	fullAt     time.Time
	badHealth  bool
	persistent bool
	driftWrite bool
	lastDrift  string
	corrected  bool
}
type movement struct {
	rules.Move
	gen uint64
}
type node struct {
	hits           hitState
	statsSeq       uint64
	traffic        trafficRing
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan struct{}
	exits          int
	limits         rules.Values
	overloaded     bool
	status         NodeStatus
	client         *nc.Client
	clientErr      error
	wake           chan struct{}
	dirty          map[string]bool
	wlDirty        bool
	pending        []rules.Move
	moves          []movement
	drainGen       uint64
	sides          [2]side
	blocked        map[string]Rejected
	ids            map[string]Rejected
	probeAt        time.Time
	nextReconcile  [2]time.Time
	healthFailures int
	connected      bool
	previous       map[string]uint64
	growing        map[string]bool
	ruleStats      map[string]map[string]any
}
type Manager struct {
	traffic     trafficRing
	historyHour int64
	cappedAt    time.Time
	nodeVersion uint64
	snapMu      sync.Mutex
	mu          sync.Mutex
	svc         *rules.Service
	opts        Options
	nodes       []*node
	lastGen     uint64
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closed      bool
	events      []Event
	callbacks   []Event
	snapshot    struct {
		valid bool
		gen   uint64
		body  []byte
		n     int
		ids   map[string]bool
	}
}

func New(specs []NodeSpec, opts Options) *Manager {
	for _, d := range []struct {
		p     *time.Duration
		value time.Duration
	}{
		{&opts.MergeWindow, 200 * time.Millisecond}, {&opts.RetryBase, time.Second}, {&opts.RetryMax, 60 * time.Second}, {&opts.CheckInterval, 60 * time.Second},
		{&opts.HealthInterval, 2 * time.Second}, {&opts.StatsInterval, 5 * time.Second}, {&opts.ReconcileInterval, DefaultReconcileInterval}, {&opts.ExpireInterval, 30 * time.Second},
	} {
		if *d.p <= 0 {
			*d.p = d.value
		}
	}
	m := &Manager{opts: opts}
	m.traffic = newTrafficRing(m.now())
	for _, spec := range specs {
		m.nodes = append(m.nodes, m.newNode(spec))
	}
	return m
}
func (m *Manager) newNode(spec NodeSpec) *node {
	c, err := nc.New(spec, m.opts.Client)
	n := &node{status: NodeStatus{Name: spec.Name}, client: c, clientErr: err, wake: make(chan struct{}, 1), dirty: map[string]bool{}, blocked: map[string]Rejected{}, ids: map[string]Rejected{}, growing: map[string]bool{}, done: make(chan struct{})}
	n.traffic = newTrafficRing(m.now())
	for i := 0; i < 2; i++ {
		n.sides[i] = side{status: SideStatus{State: "pending", Reason: "startup", Since: time.Now()}, full: true}
		n.nextReconcile[i] = time.Now().Add(m.opts.ReconcileInterval)
	}
	return n
}

var ErrNotRunning = errors.New("orchestrator not running")
var ErrDuplicate = errors.New("node already registered")

func (m *Manager) AddNode(spec NodeSpec) error {
	m.mu.Lock()
	if m.ctx == nil || m.closed {
		m.mu.Unlock()
		return ErrNotRunning
	}
	for _, n := range m.nodes {
		if n.status.Name == spec.Name {
			m.mu.Unlock()
			return ErrDuplicate
		}
	}
	n := m.newNode(spec)
	n.ctx, n.cancel = context.WithCancel(m.ctx)
	m.nodes = append(m.nodes, n)
	m.nodeVersion++
	if m.opts.atRegister != nil {
		m.opts.atRegister()
	}
	m.wg.Add(3)
	m.mu.Unlock()
	if m.opts.afterAddRegister != nil {
		m.opts.afterAddRegister()
	}
	m.startNode(n)
	return nil
}
func (m *Manager) RemoveNode(name string) {
	m.mu.Lock()
	var removed *node
	for i, n := range m.nodes {
		if n.status.Name == name {
			removed = n
			m.nodes = append(m.nodes[:i], m.nodes[i+1:]...)
			m.nodeVersion++
			break
		}
	}
	m.mu.Unlock()
	if removed == nil {
		return
	}
	if m.opts.afterRemoveUnlink != nil {
		m.opts.afterRemoveUnlink()
	}
	if removed.cancel != nil {
		removed.cancel()
		<-removed.done
	}
}
func (m *Manager) startNode(n *node) {
	run := func(work func(*node)) {
		defer m.wg.Done()
		defer func() {
			m.mu.Lock()
			n.exits++
			if n.exits == 3 {
				close(n.done)
			}
			m.mu.Unlock()
		}()
		work(n)
	}
	go run(m.worker)
	go run(m.sampler)
	go run(m.hitter)
}

func wake(n *node) {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}
func (m *Manager) Changed(c rules.Change) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastGen = c.Gen
	for _, n := range m.nodes {
		for _, k := range c.RuleKeys {
			n.dirty[k] = true
		}
		n.pending = append(n.pending, c.Moves...)
		n.wlDirty = n.wlDirty || c.Whitelist
		if !n.status.Incompatible {
			if len(c.RuleKeys) > 0 {
				m.transition(n, 0, "pending", "changes")
			}
			if c.Whitelist {
				m.transition(n, 1, "pending", "changes")
			}
		}
		wake(n)
	}
}
func (m *Manager) record(n *node, e Event) {
	kept := n == nil
	for _, current := range m.nodes {
		if current == n {
			kept = true
			break
		}
	}
	if m.opts.onRecord != nil {
		m.opts.onRecord(e.Node, kept)
	}
	if !kept {
		return
	}
	if len(m.events) == 1000 {
		copy(m.events, m.events[1:])
		m.events = m.events[:999]
	}
	m.events = append(m.events, e)
	if m.opts.OnEvent != nil {
		m.callbacks = append(m.callbacks, e)
	}
}
func (m *Manager) transition(n *node, i int, state, reason string) {
	if n.overloaded && state != "overloaded" {
		return
	}
	s := &n.sides[i].status
	if s.State != state {
		sideName := []string{"rules", "whitelist"}[i]
		m.record(n, Event{time.Now(), n.status.Name, sideName, s.State, state, reason})
		s.Since = time.Now()
	}
	s.State, s.Reason = state, reason
}
func (m *Manager) dispatch() {
	m.mu.Lock()
	pending := m.callbacks
	m.callbacks = nil
	m.mu.Unlock()
	for _, e := range pending {
		m.opts.OnEvent(e)
	}
}
func (m *Manager) Start(svc *rules.Service) {
	m.mu.Lock()
	m.svc = svc
	m.ctx, m.cancel = context.WithCancel(context.Background())
	initial := append([]*node{}, m.nodes...)
	for _, n := range initial {
		n.ctx, n.cancel = context.WithCancel(m.ctx)
		m.wg.Add(3)
	}
	m.wg.Add(1)
	m.mu.Unlock()
	for _, n := range initial {
		m.startNode(n)
	}
	go func() {
		defer m.wg.Done()
		ticks, stop := m.ticks("expire", m.opts.ExpireInterval)
		defer stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticks:
				now := m.now()
				if err := svc.ExpireDue(now); err != nil {
					m.mu.Lock()
					m.record(nil, Event{At: now, Side: "expiry", Reason: "local_read_failed"})
					m.mu.Unlock()
					m.dispatch()
				}
				m.flushHistory(now)
			}
		}
	}()
}
func (m *Manager) Stop() {
	m.mu.Lock()
	m.closed = true
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		m.wg.Wait()
	}
}
func (m *Manager) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event{}, m.events...)
}
func (m *Manager) Status() []NodeStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []NodeStatus{}
	for _, n := range m.nodes {
		s := n.status
		s.Rules = n.sides[0].status
		s.Whitelist = n.sides[1].status
		s.Rules.Confirmable, s.Whitelist.Confirmable = !n.sides[0].full && !n.sides[0].fullAt.IsZero() && !n.sides[0].badHealth && !n.overloaded, !n.sides[1].full && !n.sides[1].fullAt.IsZero() && !n.sides[1].badHealth && !n.overloaded
		s.Rules.Rejected = []Rejected{}
		for _, r := range n.blocked {
			s.Rules.Rejected = append(s.Rules.Rejected, r)
		}
		for _, r := range n.ids {
			s.Rules.Rejected = append(s.Rules.Rejected, r)
		}
		sort.Slice(s.Rules.Rejected, func(i, j int) bool {
			return s.Rules.Rejected[i].Key+s.Rules.Rejected[i].ID < s.Rules.Rejected[j].Key+s.Rules.Rejected[j].ID
		})
		out = append(out, s)
	}
	// Copies nested maps, slices and expression pointers before returning ownership.
	b, _ := json.Marshal(out)
	var clone []NodeStatus
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	_ = d.Decode(&clone)
	return clone
}
func (m *Manager) ForceSync(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.nodes {
		if n.status.Name == name {
			for i := 0; i < 2; i++ {
				n.sides[i].full = true
				n.sides[i].due = time.Time{}
				n.sides[i].driftWrite = false
				if !n.status.Incompatible {
					m.transition(n, i, "pending", "manual")
				}
			}
			wake(n)
		}
	}
}
func (m *Manager) ReconcileNow(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.nodes {
		if n.status.Name == name {
			n.nextReconcile = [2]time.Time{}
			wake(n)
		}
	}
}

// effectiveLimit is shared by admission limits and overload evaluation.
func effectiveLimit(n *node, dim int) (int, string) {
	if !n.status.Incompatible && n.limits[dim] > 0 {
		return n.limits[dim], n.status.Name
	}
	return rules.BuiltinLimits().Values[dim], "builtin"
}
func (m *Manager) Limits() rules.Limits {
	m.mu.Lock()
	defer m.mu.Unlock()
	out, first := rules.BuiltinLimits(), true
	for _, n := range m.nodes {
		if n.overloaded {
			out.Overloaded = append(out.Overloaded, rules.OverloadedNode{Name: n.status.Name, Dims: append([]rules.Overload{}, n.status.Overload...)})
			continue
		}
		for i := range out.Values {
			value, source := effectiveLimit(n, i)
			if first || value < out.Values[i] {
				out.Values[i], out.Sources[i] = value, source
			}
		}
		first = false
	}
	return out
}
func (m *Manager) checkOverload(n *node) {
	occupancy, e := m.svc.Occupancy()
	if e != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	dims := []rules.Overload{}
	for i, name := range rules.DimensionNames() {
		limit, _ := effectiveLimit(n, i)
		if occupancy.Used[i] > limit {
			dims = append(dims, rules.Overload{Dim: name, Limit: limit, Used: occupancy.Used[i]})
		}
	}
	was := n.overloaded
	n.status.Overload = dims
	n.overloaded = len(dims) > 0
	for i := 0; i < 2; i++ {
		if n.overloaded {
			m.transition(n, i, "overloaded", "capacity")
		} else if was {
			n.sides[i].full = true
			n.sides[i].due = time.Time{}
			m.transition(n, i, "pending", "capacity_recovered")
		}
	}
}
