package orch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

// The script arms this barrier inside RoundTrip; arrival witnesses the completed
// worker round, including response validation and publication under Manager.mu.
type td126Barrier struct {
	armed   atomic.Bool
	arrived chan struct{}
	release chan struct{}
	once    sync.Once
}

func td126Gate(t *testing.T, opts *Options) *td126Barrier {
	t.Helper()
	g := &td126Barrier{arrived: make(chan struct{}), release: make(chan struct{})}
	opts.roundDone = func(string) {
		if g.armed.Swap(false) {
			close(g.arrived)
			<-g.release
		}
	}
	return g
}
func (g *td126Barrier) open() { g.once.Do(func() { close(g.release) }) }
func (g *td126Barrier) wait(t *testing.T) {
	t.Helper()
	select {
	case <-g.arrived:
	case <-time.After(3 * time.Second):
		t.Fatal(t.Name(), "roundDone barrier did not arrive")
	}
}
func td126Options() Options {
	opts := fastOptions()
	opts.HealthInterval, opts.StatsInterval = time.Hour, time.Hour
	return opts
}
func td126Create(t *testing.T, r *rig, actor rules.Actor, ref string, patch rules.RulePatch) store.Rule {
	t.Helper()
	row, err := r.s.Create(actor, ref, patch)
	need(t, err == nil, t.Name(), err)
	return row.Rule
}
func td126Patch(ttl string) rules.RulePatch {
	return rules.RulePatch{SrcIP: p("192.0.2.41"), Protocol: p("tcp"), TTL: p(ttl)}
}
func td126Reject(f *fakeNode, body []byte, rejected ...string) fault {
	var payload struct{ Rules []wireRule }
	_ = json.Unmarshal(body, &payload)
	ids := map[string]bool{}
	rejections := []map[string]string{}
	for _, id := range rejected {
		ids[id] = true
		rejections = append(rejections, map[string]string{"id": id, "reason": "TD126-TEST-REJECTION"})
	}
	f.mu.Lock()
	f.groups = map[string][]wireRule{}
	for _, row := range payload.Rules {
		if !ids[textField(row, "id")] {
			key := wireKey(row)
			f.groups[key] = append(f.groups[key], row)
		}
	}
	f.flags[0] = true
	f.mu.Unlock()
	accepted := len(payload.Rules) - len(rejected)
	b, _ := json.Marshal(map[string]any{"success": true, "added": accepted, "failed": len(rejected), "rules": accepted, "cidr_rules": 0, "rejected": rejections})
	return fault{status: 200, body: string(b)}
}
func td126IDs(t *testing.T, m *Manager, want ...string) {
	t.Helper()
	got := []string{}
	for _, r := range m.Status()[0].Rules.Rejected {
		got = append(got, r.ID)
	}
	sort.Strings(got)
	want = append([]string{}, want...)
	sort.Strings(want)
	need(t, reflect.DeepEqual(got, want), t.Name(), "rejected IDs", got, "want", want)
}
func td126Committed(t *testing.T, r *rig, key string, ids ...string) {
	t.Helper()
	want := append([]string{}, ids...)
	sort.Strings(want)
	for _, req := range r.f.records(nc.CommitRoute) {
		if req.Status != 200 {
			continue
		}
		for _, g := range requestGroups(t, req) {
			if string(g.Key) != key {
				continue
			}
			got := []string{}
			for _, row := range g.Rules {
				got = append(got, textField(row, "id"))
			}
			sort.Strings(got)
			if reflect.DeepEqual(got, want) {
				return
			}
		}
	}
	t.Fatal(t.Name(), "successful commit missing expected group members", key, want)
}

func TestTD126StateHygiene(t *testing.T) {
	ui := rules.Actor{Kind: rules.UI}
	for _, kind := range []string{"delete", "disable", "expire", "release", "shared", "other", "idkey"} {
		t.Run("G1-"+kind, func(t *testing.T) {
			r := newRig(t, td126Options(), 0, false)
			actor, ref, patch := ui, "", td126Patch("64")
			if kind == "release" {
				actor, ref = rules.Actor{Kind: rules.Machine, Name: "TD126-TEST-MACHINE"}, "TD126-TEST-CLAIM"
			}
			if kind == "expire" {
				patch.ExpiresIn = p("1h")
			}
			x := td126Create(t, r, actor, ref, patch)
			var y store.Rule
			if kind == "shared" {
				y = td126Create(t, r, ui, "", td126Patch("63"))
				need(t, y.GroupKey == x.GroupKey, t.Name(), "fixture must share group")
			}
			r.f.setScript(func(route string, count int, body []byte) fault {
				if route == string(nc.AtomicRoute) && count == 1 {
					return td126Reject(r.f, body, x.ID)
				}
				return fault{}
			})
			r.m.Start(r.s)
			r.normal(t)
			td126IDs(t, r.m, x.ID)
			if kind == "idkey" {
				need(t, r.m.Status()[0].Rules.Rejected[0].Key == "", t.Name(), "ID rejection exposed group Key")
				return
			}
			if kind == "other" {
				other := r.create(t, 41)
				r.normal(t)
				td126Committed(t, r, other.GroupKey, other.ID)
				td126IDs(t, r.m, x.ID)
			}
			switch kind {
			case "disable":
				need(t, r.s.SetEnabled(ui, x.ID, false) == nil, t.Name(), "disable")
			case "expire":
				need(t, x.ExpiresAt != nil, t.Name(), "expiry fixture missing deadline")
				expiry, err := time.Parse(time.RFC3339Nano, *x.ExpiresAt)
				need(t, err == nil, t.Name(), err)
				need(t, r.s.ExpireDue(expiry.Add(time.Second)) == nil, t.Name(), "expire")
			case "release":
				need(t, r.s.ReleaseClaim(actor, x.ID, ref) == nil, t.Name(), "release")
			default:
				need(t, r.s.ForceDelete(ui, x.ID) == nil, t.Name(), "delete")
			}
			r.normal(t)
			td126IDs(t, r.m)
			if kind == "shared" {
				td126Committed(t, r, x.GroupKey, y.ID)
				need(t, r.f.row(y.ID) != nil, t.Name(), "peer not delivered")
			} else {
				td126Committed(t, r, x.GroupKey)
			}
		})
	}
	// A rejected group before the insertion point is still not a member.
	t.Run("G1-other-before", func(t *testing.T) {
		r := newRig(t, td126Options(), 0, false)
		x := td126Create(t, r, ui, "", td126Patch("64"))
		r.f.setScript(func(route string, count int, body []byte) fault {
			if route == string(nc.AtomicRoute) && count == 1 {
				return td126Reject(r.f, body, x.ID)
			}
			return fault{}
		})
		r.m.Start(r.s)
		r.normal(t)
		td126IDs(t, r.m, x.ID)
		y := td126Create(t, r, ui, "", rules.RulePatch{SrcIP: p("198.51.100.44"), Protocol: p("tcp")})
		need(t, x.GroupKey < y.GroupKey, t.Name(), "fixture must put rejected group before committed group")
		r.normal(t)
		td126Committed(t, r, y.GroupKey, y.ID)
		need(t, r.f.row(x.ID) == nil, t.Name(), "rejected rule unexpectedly installed")
		need(t, r.f.row(y.ID) != nil, t.Name(), "unrelated group was not committed")
		got := r.m.Status()[0].Rules.Rejected
		need(t, len(got) == 1 && got[0].ID == x.ID, t.Name(), "unrelated greater group cleared rejected ID; rejected count", len(got), "want", 1)
	})
	for _, kind := range []string{"retry", "peer"} {
		t.Run("G1-"+kind, func(t *testing.T) {
			opts := td126Options()
			opts.RetryBase, opts.RetryMax = time.Hour, time.Hour
			gate := td126Gate(t, &opts)
			r := newRig(t, opts, 0, false)
			defer gate.open() // release before newRig's Stop cleanup, even on Fatal
			x := td126Create(t, r, ui, "", td126Patch("64"))
			rejected := []string{x.ID}
			var y store.Rule
			if kind == "peer" {
				y = td126Create(t, r, ui, "", td126Patch("63"))
				rejected = append(rejected, y.ID)
				need(t, x.GroupKey == y.GroupKey, t.Name(), "fixture must share group")
			}
			r.f.setScript(func(route string, count int, body []byte) fault {
				if route == string(nc.AtomicRoute) && count == 1 {
					return td126Reject(r.f, body, rejected...)
				}
				if route == string(nc.CommitRoute) && count == 1 {
					gate.armed.Store(true)
					if kind == "peer" {
						return fault{status: 409, body: `{"code":"table_full"}`}
					}
					return fault{status: 500}
				}
				return fault{}
			})
			r.m.Start(r.s)
			r.normal(t)
			td126IDs(t, r.m, rejected...)
			need(t, r.s.ForceDelete(ui, x.ID) == nil, t.Name(), "delete")
			gate.wait(t)
			td126IDs(t, r.m, rejected...)
			need(t, len(r.f.records(nc.CommitRoute)) == 1, t.Name(), "exactly one failed commit before release")
			r.m.mu.Lock()
			r.m.nodes[0].sides[0].due = time.Time{}
			wake(r.m.nodes[0])
			r.m.mu.Unlock()
			gate.open()
			r.normal(t)
			td126IDs(t, r.m)
			if kind == "peer" {
				td126Committed(t, r, x.GroupKey, y.ID)
			}
		})
	}
	for _, kind := range []string{"kept", "deleted", "disabled", "move"} {
		name := "G1-race/" + kind
		if kind == "move" {
			name = "G1-move"
		}
		t.Run(name, func(t *testing.T) {
			opts := td126Options()
			gate := td126Gate(t, &opts)
			r := newRig(t, opts, 0, false)
			defer gate.open()
			x := td126Create(t, r, ui, "", td126Patch("64"))
			var moved store.Rule
			var changeErr *rules.Error
			r.f.setScript(func(route string, count int, body []byte) fault {
				if route != string(nc.AtomicRoute) || count != 1 {
					return fault{}
				}
				switch kind {
				case "deleted":
					changeErr = r.s.ForceDelete(ui, x.ID)
				case "disabled":
					changeErr = r.s.SetEnabled(ui, x.ID, false)
				case "move":
					moved, changeErr = r.s.Update(ui, x.ID, rules.RulePatch{SrcIP: p("198.51.100.42")})
				}
				gate.armed.Store(true)
				return td126Reject(r.f, body, x.ID)
			})
			r.m.Start(r.s)
			gate.wait(t)
			need(t, changeErr == nil, t.Name(), changeErr)
			if kind == "kept" || kind == "move" {
				td126IDs(t, r.m, x.ID)
			} else {
				td126IDs(t, r.m)
			}
			if kind == "move" {
				r.m.mu.Lock()
				got := r.m.nodes[0].ids[x.ID].group
				r.m.mu.Unlock()
				need(t, moved.GroupKey != x.GroupKey && got == moved.GroupKey, t.Name(), "atomic must record current group", got, moved.GroupKey)
			}
			gate.open()
			r.normal(t)
			if kind == "move" {
				td126IDs(t, r.m)
				td126Committed(t, r, moved.GroupKey, x.ID)
			}
		})
	}
}

func TestTD142Pending(t *testing.T) {
	for _, kind := range []string{"offline", "incompat", "online"} {
		t.Run("G2-"+kind, func(t *testing.T) {
			var rounds atomic.Uint64
			opts := fastOptions()
			opts.roundDone = func(string) { rounds.Add(1) }
			r := newRig(t, opts, 0, true)
			before := len(r.f.records(nc.AtomicRoute))
			if kind == "online" {
				row := r.create(t, 42)
				r.normal(t)
				td126Committed(t, r, row.GroupKey, row.ID)
				need(t, r.f.row(row.ID) != nil && len(r.f.records(nc.AtomicRoute)) == before, t.Name(), "online change must use commit")
				return
			}
			var offline atomic.Bool
			offline.Store(true)
			if kind == "offline" {
				r.f.setScript(func(route string, _ int, _ []byte) fault {
					if route == string(nc.HealthRoute) && offline.Load() {
						return fault{status: 503}
					}
					return fault{}
				})
				eventually(t, func() bool { return !r.m.Status()[0].Online })
			} else {
				r.f.mu.Lock()
				r.f.protocol = 9
				r.f.mu.Unlock()
				r.m.ForceSync("a")
				eventually(t, func() bool { return r.m.Status()[0].Incompatible })
			}
			rows := []store.Rule{}
			for i := 0; i < 30; i++ {
				rows = append(rows, td126Create(t, r, rules.Actor{Kind: rules.UI}, "", rules.RulePatch{SrcIP: p(fmt.Sprintf("192.0.2.%d", i+1)), Protocol: p("tcp")}))
			}
			rows[0] = r.update(t, rows[0].ID, rules.RulePatch{SrcIP: p("198.51.100.43")})
			start := rounds.Load()
			eventually(t, func() bool {
				if rounds.Load() < start+2 {
					return false
				}
				r.m.mu.Lock()
				defer r.m.mu.Unlock()
				n := r.m.nodes[0]
				return len(n.dirty) == 0 && n.pending == nil
			})
			if kind == "offline" {
				offline.Store(false)
			} else {
				r.f.mu.Lock()
				r.f.protocol = 11
				r.f.mu.Unlock()
				r.m.mu.Lock()
				r.m.nodes[0].probeAt = time.Time{}
				wake(r.m.nodes[0])
				r.m.mu.Unlock()
			}
			r.normal(t)
			need(t, len(r.f.records(nc.AtomicRoute)) == before+1, t.Name(), "recovery must add exactly one atomic")
			for _, row := range rows {
				got := r.f.row(row.ID)
				need(t, got != nil && wireKey(got) == row.GroupKey, t.Name(), "missing or stale rule", row.ID)
			}
			r.f.mu.Lock()
			total := 0
			for _, group := range r.f.groups {
				total += len(group)
			}
			r.f.mu.Unlock()
			need(t, total == 30, t.Name(), "recovery rule count", total)
		})
	}
}

const td140NodeSecret = "TD140-OBVIOUS-TEST-NODE-SECRET"
const td144StatsSecret = "TD144-OBVIOUS-TEST-STATS-SECRET"

type td140Log struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	manager *Manager
	locked  int
}

func (w *td140Log) Write(p []byte) (int, error) {
	locked := false
	if w.manager != nil {
		if w.manager.mu.TryLock() {
			w.manager.mu.Unlock()
		} else {
			locked = true
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if locked {
		w.locked++
	}
	return w.buf.Write(p)
}
func (w *td140Log) text() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
func td140Capture(t *testing.T) *td140Log {
	t.Helper()
	writer, flags, prefix := log.Writer(), log.Flags(), log.Prefix()
	out := &td140Log{}
	log.SetOutput(out)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() { log.SetOutput(writer); log.SetFlags(flags); log.SetPrefix(prefix) })
	return out
}
func td140Key(t *testing.T, r *rig) {
	t.Helper()
	// newRig has not started: replace only the client so NodeSpec.Key is unique.
	c, err := nc.New(NodeSpec{Name: "a", BaseURL: "http://a.invalid", Key: nc.Secret(td140NodeSecret)}, nc.Options{Transport: r.f})
	need(t, err == nil, t.Name(), err)
	r.m.nodes[0].client = c
}
func td140ContainsSecret(s string) bool {
	return strings.Contains(s, td140NodeSecret) || strings.Contains(s, td144StatsSecret)
}

type td140History struct{}

func (td140History) WriteTraffic([]store.TrafficRow, int64, time.Time, [2]int, func(string)) (bool, error) {
	return false, errors.New("TD140-HISTORY-SENTINEL")
}
func td144NaN(m *Manager) {
	m.mu.Lock()
	m.nodes[0].status.Stats = map[string]any{"x": math.NaN(), "s": td144StatsSecret}
	m.mu.Unlock()
}

func TestTD144StatusAndLogs(t *testing.T) {
	var captured strings.Builder
	for _, kind := range []string{"G5", "G5-success", "G6-expiry", "G6-history", "G6-protocol", "G6-quiet", "G6-unlocked"} {
		t.Run(kind, func(t *testing.T) {
			out := td140Capture(t)
			r := newRig(t, td126Options(), 0, false)
			td140Key(t, r)
			switch kind {
			case "G5":
				td144NaN(r.m)
				status := r.m.Status()
				need(t, len(status) == 1 && status[0].Name == "a", t.Name(), "copy error returned blank status")
				_, err := json.Marshal(status)
				need(t, err != nil, t.Name(), "fallback unexpectedly JSON encodable")
			case "G5-success":
				r.m.mu.Lock()
				r.m.nodes[0].status.Stats = map[string]any{"nested": map[string]any{"counter": json.Number("9007199254740993")}}
				r.m.mu.Unlock()
				status := r.m.Status()
				need(t, len(status) == 1, t.Name(), "missing status")
				nested := status[0].Stats["nested"].(map[string]any)
				need(t, nested["counter"] == json.Number("9007199254740993"), t.Name(), "UseNumber lost precision/type")
				nested["counter"] = json.Number("7")
				r.m.mu.Lock()
				original := r.m.nodes[0].status.Stats["nested"].(map[string]any)["counter"]
				r.m.mu.Unlock()
				need(t, original == json.Number("9007199254740993"), t.Name(), "successful copy aliases internal state")
			case "G6-expiry":
				r.m.opts.ExpireInterval = 10 * time.Millisecond
				need(t, r.db.Close() == nil, t.Name(), "close database")
				r.m.Start(r.s)
				eventually(t, func() bool { return codesEvents(r.m, "expiry", "local_read_failed") > 0 })
			case "G6-history":
				r.m.opts.History = td140History{}
				r.m.flushHistory(time.Now())
			case "G6-protocol":
				r.m.Start(r.s)
				r.normal(t)
				r.f.mu.Lock()
				r.f.protocol = 9
				r.f.mu.Unlock()
				r.m.probe(r.m.nodes[0], 0)
				r.m.probe(r.m.nodes[0], 0)
				r.f.mu.Lock()
				r.f.protocol = 11
				r.f.mu.Unlock()
				r.m.mu.Lock()
				r.m.nodes[0].probeAt = time.Time{}
				wake(r.m.nodes[0])
				r.m.mu.Unlock()
				eventually(t, func() bool { return !r.m.Status()[0].Incompatible })
				r.normal(t)
			case "G6-quiet":
				r.m.Start(r.s)
				r.normal(t)
				row := r.create(t, 44)
				r.normal(t)
				r.update(t, row.ID, rules.RulePatch{TTL: p("64")})
				r.normal(t)
				need(t, r.s.SetEnabled(rules.Actor{Kind: rules.UI}, row.ID, false) == nil, t.Name(), "disable")
				r.normal(t)
				need(t, r.s.ForceDelete(rules.Actor{Kind: rules.UI}, row.ID) == nil, t.Name(), "delete")
				r.normal(t)
				r.m.ForceSync("a")
				r.normal(t)
				need(t, reconcileOnce(t, r, 0).Result == "equal", t.Name(), "reconcile")
			case "G6-unlocked":
				// No Manager goroutines can contend with the writer's TryLock.
				out.manager = r.m
				n := r.m.nodes[0]
				n.ctx = context.Background()
				r.m.svc = r.s
				r.f.protocol = 9
				r.m.probe(n, 0)
				r.f.protocol = 11
				r.m.recoverVersion(n)
				td144NaN(r.m)
				r.m.Status()
			}
			r.m.Stop()
			text := out.text()
			captured.WriteString(text)
			lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
			switch kind {
			case "G5":
				need(t, len(lines) == 1 && strings.HasPrefix(lines[0], "node status copy failed: json: unsupported value: NaN"), t.Name(), "copy failure log", text)
			case "G5-success", "G6-quiet":
				need(t, text == "", t.Name(), "unexpected log", text)
			case "G6-expiry":
				found := false
				for _, line := range lines {
					found = found || strings.HasPrefix(line, "expiry sweep failed: internal: ")
				}
				need(t, found, t.Name(), "missing expiry log", text)
			case "G6-history":
				need(t, text == "traffic history write failed: TD140-HISTORY-SENTINEL\n", t.Name(), "history log", text)
			case "G6-protocol", "G6-unlocked":
				need(t, strings.Count(text, "node incompatible; node=\"a\" reason=protocol_mismatch\n") == 1, t.Name(), "incompatible count", text)
				need(t, strings.Count(text, "node compatible; node=\"a\" reason=version_recovered\n") == 1, t.Name(), "compatible count", text)
				want := 2
				if kind == "G6-unlocked" {
					want = 3
					need(t, strings.Count(text, "node status copy failed: json: unsupported value: NaN\n") == 1, t.Name(), "copy log count")
					need(t, out.locked == 0, t.Name(), "locked log writes", out.locked)
				}
				need(t, len(lines) == want, t.Name(), "unexpected extra logs", text)
			}
			need(t, !td140ContainsSecret(text), t.Name(), "log leaked test secret")
		})
	}
	t.Run("G6-secret", func(t *testing.T) {
		text := captured.String()
		need(t, !td140ContainsSecret(text), t.Name(), "combined log leaked test secret")
		need(t, td140ContainsSecret(text+td140NodeSecret), t.Name(), "node-secret positive control failed")
		need(t, td140ContainsSecret(text+td144StatsSecret), t.Name(), "stats-secret positive control failed")
	})
}
