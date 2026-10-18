package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type gate struct {
	entered, release chan struct{}
	seen, once       sync.Once
}

func newGate(t *testing.T) *gate {
	g := &gate{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(g.open)
	return g
}
func (g *gate) open() { g.once.Do(func() { close(g.release) }) }
func (g *gate) wait(ctx context.Context) error {
	g.seen.Do(func() { close(g.entered) })
	select {
	case <-g.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (g *gate) arrived(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(4 * time.Second):
		t.Fatal("node gate not reached")
	}
}

type fault struct {
	gate  *gate
	after bool
	code  string
	index int
}
type wireNode struct {
	mu           sync.Mutex
	flags        [2]bool
	offline      bool
	protocol     int
	rules        map[string]nc.Rule
	keys         map[string]string
	script       func(string, []byte) fault
	healthGate   *gate
	healthBudget int
}

func newWire() *wireNode {
	return &wireNode{protocol: 11, rules: map[string]nc.Rule{}, keys: map[string]string{}}
}
func (f *wireNode) set(fn func()) { f.mu.Lock(); defer f.mu.Unlock(); fn() }
func (f *wireNode) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	f.mu.Lock()
	script, offline := f.script, f.offline
	var hold *gate
	if r.URL.Path == string(nc.HealthRoute) && f.healthGate != nil {
		if f.healthBudget == 0 {
			hold = f.healthGate
		} else {
			f.healthBudget--
		}
	}
	f.mu.Unlock()
	if offline {
		return nil, errors.New("fixture offline")
	}
	if hold != nil {
		if err := hold.wait(r.Context()); err != nil {
			return nil, err
		}
	}
	a := fault{}
	if script != nil {
		a = script(r.URL.Path, body)
	}
	if a.gate != nil && !a.after {
		if err := a.gate.wait(r.Context()); err != nil {
			return nil, err
		}
	}
	w := httptest.NewRecorder()
	if a.code != "" {
		status := 409
		if a.code == "validation_rejected" {
			status = 400
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": a.code, "error": "fixture rejection", "groups": []any{map[string]any{"index": a.index, "code": a.code}}})
	} else {
		f.respond(w, r.URL.Path, body)
	}
	if a.gate != nil && a.after {
		if err := a.gate.wait(r.Context()); err != nil {
			return nil, err
		}
	}
	return w.Result(), nil
}
func (f *wireNode) respond(w http.ResponseWriter, path string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch path {
	case "/":
		reply(map[string]any{"sync_protocol": f.protocol})
	case string(nc.HealthRoute):
		reply(map[string]any{"status": "degraded", "rules_synced": f.flags[0], "whitelist_synced": f.flags[1]})
	case string(nc.StatsRoute):
		reply(map[string]any{"total_packets": 0, "dropped_packets": 0, "passed_packets": 0})
	case string(nc.SyncWLRoute):
		var in struct {
			Entries []nc.Entry `json:"entries"`
		}
		_ = json.Unmarshal(body, &in)
		f.flags[1] = true
		reply(map[string]any{"total": len(in.Entries), "failed": 0})
	case string(nc.AtomicRoute):
		var in struct {
			Rules []nc.Rule `json:"rules"`
		}
		_ = json.Unmarshal(body, &in)
		f.rules = map[string]nc.Rule{}
		f.keys = map[string]string{}
		for _, r := range in.Rules {
			f.rules[r.ID] = r
			f.keys[r.ID] = fmt.Sprint(r.DstPort)
		}
		f.flags[0] = true
		reply(map[string]any{"success": true, "added": len(in.Rules), "failed": 0, "rules": len(in.Rules), "cidr_rules": 0, "rejected": []any{}})
	case string(nc.CommitRoute):
		var in struct {
			Groups []nc.Group `json:"groups"`
		}
		_ = json.Unmarshal(body, &in)
		results := []any{}
		for i, g := range in.Groups {
			var key struct {
				DstPort int `json:"dst_port"`
			}
			_ = json.Unmarshal(g.Key, &key)
			p := fmt.Sprint(key.DstPort)
			for id, old := range f.keys {
				if old == p {
					delete(f.rules, id)
					delete(f.keys, id)
				}
			}
			for _, r := range g.Rules {
				f.rules[r.ID] = r
				f.keys[r.ID] = p
			}
			results = append(results, map[string]any{"index": i, "result": "replaced"})
		}
		reply(map[string]any{"code": "committed", "groups": results})
	default:
		w.WriteHeader(404)
	}
}
func groupIndex(body []byte, port int) int {
	var in struct {
		Groups []nc.Group `json:"groups"`
	}
	_ = json.Unmarshal(body, &in)
	for i, g := range in.Groups {
		var k struct {
			DstPort int `json:"dst_port"`
		}
		_ = json.Unmarshal(g.Key, &k)
		if k.DstPort == port {
			return i
		}
	}
	return -1
}

type deliveryFixture struct {
	db *store.DB
	s  *rules.Service
	m  *orch.Manager
	e  *gin.Engine
	f  *wireNode
}

func deliverySetup(t *testing.T, f *wireNode, seed bool) *deliveryFixture {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "delivery.db"))
	require(t, err == nil, err)
	t.Cleanup(func() { db.Close() })
	if seed {
		port, ip := 80, "192.0.2.10"
		_, e := rules.New(db, nil).Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{DstPort: &port, DstIP: &ip})
		require(t, e == nil, e)
	}
	m := orch.New([]nc.NodeSpec{{Name: "n1", BaseURL: "http://192.0.2.2", Key: nc.Secret("NODE-KEY-SENTINEL")}}, orch.Options{Client: nc.Options{Transport: f}, MergeWindow: 200 * time.Millisecond, HealthInterval: 10 * time.Millisecond, StatsInterval: time.Hour, ReconcileInterval: time.Hour, ExpireInterval: time.Hour})
	s := rules.New(db, m, DeliveryStatus(m))
	e := New(s, m, testActor, log.New(io.Discard, "", 0))
	m.Start(s)
	t.Cleanup(m.Stop)
	return &deliveryFixture{db, s, m, e, f}
}
func await(t *testing.T, reason string, ok func() bool) {
	t.Helper()
	end := time.Now().Add(4 * time.Second)
	for time.Now().Before(end) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out: " + reason)
}
func (d *deliveryFixture) normal(t *testing.T) {
	t.Helper()
	await(t, "normal synced", func() bool {
		n := d.m.Status()[0]
		return n.Rules.State == "normal" && n.Whitelist.State == "normal" && n.Rules.Confirmable && n.Health.RulesSynced
	})
}
func (d *deliveryFixture) create(t *testing.T, port int) CreateResponse {
	return decoded[CreateResponse](t, request(t, d.e, "POST", "/api/v1/rules", "machine:a", body(port), 201))
}
func (d *deliveryFixture) view(t *testing.T, r CreateResponse) DeliveryResponse {
	return decoded[DeliveryResponse](t, request(t, d.e, "GET", fmt.Sprintf("/api/v1/rules/%s/delivery?gen=%d&epoch=%s", r.ID, r.Gen, r.Epoch), "ui", "", 200))
}
func (d *deliveryFixture) state(t *testing.T, r CreateResponse, want string) {
	t.Helper()
	v := d.view(t, r)
	require(t, len(v.Nodes) == 1 && v.Nodes[0].State == want, "delivery", v, "want", want)
}
func (d *deliveryFixture) confirmed(t *testing.T, r CreateResponse) {
	t.Helper()
	await(t, "receipt confirmed", func() bool { return d.view(t, r).Nodes[0].State == "confirmed" })
}
func (d *deliveryFixture) duplicate(t *testing.T) CreateResponse {
	return decoded[CreateResponse](t, request(t, d.e, "POST", "/api/v1/rules", "machine:a", body(80), 200))
}
func rejectPort(port int, code string) func(string, []byte) fault {
	return func(path string, b []byte) fault {
		if path == string(nc.CommitRoute) {
			if i := groupIndex(b, port); i >= 0 {
				return fault{code: code, index: i}
			}
		}
		return fault{}
	}
}

func TestCtlCut3Delivery(t *testing.T) {
	t.Run("API-delivery", func(t *testing.T) {
		f := newWire()
		d := deliverySetup(t, f, false)
		d.normal(t)
		g := newGate(t)
		f.set(func() {
			f.script = func(path string, _ []byte) fault {
				if path == string(nc.CommitRoute) {
					return fault{gate: g}
				}
				return fault{}
			}
		})
		r := d.create(t, 80)
		g.arrived(t)
		d.state(t, r, "pending")
		g.open()
		d.confirmed(t, r)
		require(t, d.m.Status()[0].Rules.ConfirmedGen == r.Gen, "equality witness missing")
		f.set(func() { f.script = rejectPort(81, "condition_capacity") })
		s := d.create(t, 81)
		await(t, "rejected", func() bool { return d.view(t, s).Nodes[0].State == "rejected" })
		require(t, d.view(t, s).Nodes[0].Code == "condition_capacity", "rejection code missing")
		w := request(t, d.e, "GET", "/api/v1/nodes", "ui", "", 200)
		require(t, !strings.Contains(w.Body.String(), "NODE-KEY-SENTINEL") && !strings.Contains(strings.ToLower(w.Body.String()), "fingerprint"), "node secret or private rejection field")
		f.set(func() { f.protocol = 0 })
		d.create(t, 82)
		await(t, "incompatible", func() bool { return d.m.Status()[0].Incompatible })
		d.state(t, r, "incompatible")
		f.set(func() { f.offline = true })
		await(t, "offline", func() bool { return !d.m.Status()[0].Online })
		d.state(t, r, "offline")
		request(t, d.e, "PUT", "/api/v1/rules/"+r.ID+"/enabled", "ui", `{"enabled":false}`, 200)
		d.state(t, r, "disabled")
		e := decoded[Error](t, request(t, d.e, "GET", "/api/v1/rules/"+r.ID+"/delivery?gen=1&epoch=wrong", "ui", "", 409))
		require(t, e.Code == "gen_epoch_mismatch", e)
		request(t, d.e, "GET", "/api/v1/rules/missing/delivery?gen=0&epoch="+d.s.Epoch(), "ui", "", 404)
	})
	t.Run("DV-wl", func(t *testing.T) {
		f := newWire()
		d := deliverySetup(t, f, false)
		d.normal(t)
		r := d.create(t, 80)
		d.confirmed(t, r)
		request(t, d.e, "POST", "/api/v1/whitelist", "ui", `{"dst_ip":"192.0.2.20"}`, 201)
		await(t, "whitelist confirmed", func() bool { return d.m.Status()[0].Whitelist.ConfirmedGen > r.Gen })
		dup := d.duplicate(t)
		require(t, dup.Gen == r.Gen, "whitelist advanced receipt")
		d.state(t, dup, "confirmed")
	})
	t.Run("DV-unrelated", func(t *testing.T) {
		f := newWire()
		d := deliverySetup(t, f, false)
		d.normal(t)
		r := d.create(t, 80)
		d.confirmed(t, r)
		f.set(func() { f.script = rejectPort(81, "condition_capacity") })
		s := d.create(t, 81)
		await(t, "unrelated rejected", func() bool { return d.view(t, s).Nodes[0].State == "rejected" })
		dup := d.duplicate(t)
		require(t, dup.Gen == r.Gen, "unrelated advanced receipt")
		d.state(t, dup, "confirmed")
	})
	t.Run("DV-startup", func(t *testing.T) {
		f := newWire()
		f.flags = [2]bool{true, true}
		g := newGate(t)
		f.script = func(path string, _ []byte) fault {
			if path == string(nc.AtomicRoute) {
				return fault{gate: g}
			}
			return fault{}
		}
		d := deliverySetup(t, f, true)
		g.arrived(t)
		// Seed used protocol all; repeat exactly that stored identity.
		r := decoded[CreateResponse](t, request(t, d.e, "POST", "/api/v1/rules", "machine:a", `{"dst_ip":"192.0.2.10","dst_port":80}`, 200))
		n := d.m.Status()[0]
		require(t, r.Gen == 0 && n.Health.RulesSynced && !n.Rules.Confirmable, "startup independent guard witness", n)
		d.state(t, r, "pending")
		g.open()
		d.confirmed(t, r)
	})
	t.Run("DV-reconnect", func(t *testing.T) {
		f := newWire()
		d := deliverySetup(t, f, false)
		d.normal(t)
		r := d.create(t, 80)
		d.confirmed(t, r)
		f.set(func() { f.offline = true })
		await(t, "offline before reconnect", func() bool { return !d.m.Status()[0].Online })
		g := newGate(t)
		f.set(func() {
			f.offline = false
			f.script = func(path string, _ []byte) fault {
				if path == string(nc.AtomicRoute) {
					return fault{gate: g}
				}
				return fault{}
			}
		})
		g.arrived(t)
		n := d.m.Status()[0]
		require(t, n.Health.RulesSynced && !n.Rules.Confirmable, "reconnect guard witness")
		d.state(t, r, "pending")
		g.open()
		d.confirmed(t, r)
	})
	t.Run("DV-badhealth", func(t *testing.T) {
		f := newWire()
		d := deliverySetup(t, f, false)
		d.normal(t)
		r := d.create(t, 80)
		d.confirmed(t, r)
		g := newGate(t)
		f.set(func() {
			f.script = func(path string, _ []byte) fault {
				if path == string(nc.CommitRoute) || path == string(nc.SyncWLRoute) {
					return fault{gate: g}
				}
				return fault{}
			}
		})
		d.create(t, 81)
		request(t, d.e, "POST", "/api/v1/whitelist", "ui", `{"dst_ip":"192.0.2.20"}`, 201)
		g.arrived(t)
		f.set(func() { f.flags = [2]bool{}; f.rules = map[string]nc.Rule{} })
		await(t, "unsynced sample", func() bool {
			n := d.m.Status()[0]
			return n.Online && !n.Health.RulesSynced && !n.Rules.Confirmable && n.Rules.State == "pending" && n.Whitelist.State == "pending"
		})
		d.state(t, r, "pending")
	})
	t.Run("DV-stale", func(t *testing.T) {
		f := newWire()
		d := deliverySetup(t, f, false)
		d.normal(t)
		r := d.create(t, 80)
		d.confirmed(t, r)
		late, health := newGate(t), newGate(t)
		f.set(func() {
			f.script = func(path string, _ []byte) fault {
				if path == string(nc.AtomicRoute) {
					return fault{gate: late, after: true}
				}
				return fault{}
			}
		})
		d.m.ForceSync("n1")
		late.arrived(t)
		f.set(func() { f.flags = [2]bool{}; f.rules = map[string]nc.Rule{}; f.healthGate = health; f.healthBudget = 1 })
		await(t, "restart health before late response", func() bool { return !d.m.Status()[0].Health.RulesSynced })
		health.arrived(t)
		late.open()
		await(t, "late success cleared guard", func() bool { n := d.m.Status()[0]; return n.Rules.Confirmable && !n.Health.RulesSynced })
		d.state(t, r, "pending")
	})
	t.Run("DV-batch", func(t *testing.T) {
		f := newWire()
		d := deliverySetup(t, f, false)
		d.normal(t)
		r := d.create(t, 80)
		d.confirmed(t, r)
		f.set(func() { f.script = rejectPort(81, "condition_capacity") })
		b := decoded[BatchResponse](t, request(t, d.e, "POST", "/api/v1/rules/batch", "machine:a", `{"items":[`+body(80)+`,`+body(81)+`]}`, 200))
		require(t, len(b.Results) == 2 && b.Results[0].Gen != nil && *b.Results[0].Gen == r.Gen && b.Results[1].Gen != nil && *b.Results[1].Gen > r.Gen, "batch receipt generations", b)
		s := CreateResponse{RuleDTO: *b.Results[1].Rule, Gen: *b.Results[1].Gen, Epoch: b.Epoch}
		await(t, "batch new group rejected", func() bool { return d.view(t, s).Nodes[0].State == "rejected" })
		r.Gen = *b.Results[0].Gen
		d.state(t, r, "confirmed")
	})
	t.Run("DV-move", func(t *testing.T) {
		f := newWire()
		d := deliverySetup(t, f, false)
		d.normal(t)
		u, b := newGate(t), newGate(t)
		f.set(func() {
			f.script = func(path string, body []byte) fault {
				if path == string(nc.CommitRoute) {
					if groupIndex(body, 82) >= 0 {
						return fault{gate: b}
					}
					if i := groupIndex(body, 80); i >= 0 {
						return fault{code: "validation_rejected", index: i}
					}
					if groupIndex(body, 81) >= 0 {
						return fault{gate: u, after: true}
					}
				}
				return fault{}
			}
		})
		r := d.create(t, 80)
		other := d.create(t, 81)
		require(t, r.Gen == 1 && other.Gen == 2, "move initial gens")
		u.arrived(t)
		n := d.m.Status()[0]
		require(t, len(n.Rules.Rejected) > 0 && n.Rules.Rejected[0].ID == "" && len(n.Rules.Rejected[0].RuleIDs) == 0, "key-only rejection missing")
		request(t, d.e, "PATCH", "/api/v1/rules/"+r.ID, "ui", `{"dst_port":82}`, 200)
		u.open()
		b.arrived(t)
		n = d.m.Status()[0]
		_, target, _, err := d.s.DeliveryView(r.ID)
		f.mu.Lock()
		_, exists := f.rules[r.ID]
		f.mu.Unlock()
		require(t, err == nil && !exists && target == 3 && n.Rules.ConfirmedGen == 2 && n.Rules.Confirmable && n.Health.RulesSynced, "move observation window", target, n, exists, err)
		d.state(t, r, "pending")
	})
}
