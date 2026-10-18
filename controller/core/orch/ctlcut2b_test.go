package orch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type cut2bRig struct {
	*rig
	path    string
	stopped bool
}

// Mutations can strand Service.mu. Cleanup must never hide a leaf failure.
func newCut2bRig(t *testing.T, retry time.Duration) *cut2bRig {
	t.Helper()
	opts := fastOptions()
	opts.RetryBase, opts.RetryMax = retry, retry
	f := newFake()
	opts.Client.Transport = f
	path := filepath.Join(t.TempDir(), "rules.db")
	db, err := store.Open(path)
	need(t, err == nil, err)
	m := New([]NodeSpec{{Name: "a", BaseURL: "http://a.invalid", Key: nc.Secret("cut2b-test-secret")}}, opts)
	r := &cut2bRig{rig: &rig{m, rules.New(db, m), db, f}, path: path}
	t.Cleanup(func() {
		if r.stop(t) {
			rules.SnapshotTestHook = nil
			need(t, db.Close() == nil, "cleanup close")
		}
	})
	return r
}

func (r *cut2bRig) stop(t *testing.T) bool {
	t.Helper()
	if r.stopped {
		return true
	}
	done := make(chan struct{})
	go func() { r.m.Stop(); close(done) }()
	select {
	case <-done:
		r.stopped = true
		return true
	case <-time.After(2 * time.Second):
		t.Log("bounded cleanup: Manager.Stop did not return within 2s; abandoned")
		return false
	}
}

func cut2bSide(r *cut2bRig, kind string) SideStatus {
	s := r.m.Status()[0]
	if kind == "whitelist" {
		return s.Whitelist
	}
	return s.Rules
}

func cut2bFailure(t *testing.T, r *cut2bRig, kind string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if cut2bSide(r, kind).Reason == "local_read_failed" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expected local_read_failed, got %+v", cut2bSide(r, kind))
}

func cut2bWL(t *testing.T, r *cut2bRig, ip string) store.Whitelist {
	t.Helper()
	w, e := r.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: ip})
	need(t, e == nil, e)
	return w.Whitelist
}

func cut2bHas(r *cut2bRig, kind, id string) bool {
	if kind != "whitelist" {
		return r.f.row(id) != nil
	}
	r.f.mu.Lock()
	defer r.f.mu.Unlock()
	for _, w := range r.f.entries {
		if textField(w, "id") == id {
			return true
		}
	}
	return false
}

func cut2bRows(t *testing.T, request wireRequest) []wireRule {
	t.Helper()
	var body struct {
		Rules   []wireRule  `json:"rules"`
		Entries []wireRule  `json:"entries"`
		Groups  []wireGroup `json:"groups"`
	}
	need(t, json.Unmarshal(request.Body, &body) == nil, "decode request")
	rows := append(body.Rules, body.Entries...)
	for _, g := range body.Groups {
		rows = append(rows, g.Rules...)
	}
	return rows
}

func cut2bRoute(kind string) nc.Route {
	if kind == "groups" {
		return nc.CommitRoute
	}
	if kind == "whitelist" {
		return nc.SyncWLRoute
	}
	return nc.AtomicRoute
}

// Prime enabled only through a notifying Service write after the startup body.
func cut2bPrime(t *testing.T, r *cut2bRig, kind string) store.Rule {
	t.Helper()
	r.m.Start(r.s)
	r.normal(t)
	if kind != "whitelist" {
		a := r.create(t, 80)
		r.normal(t)
		return a
	}
	return store.Rule{}
}

func cut2bTrigger(t *testing.T, r *cut2bRig, kind string, a store.Rule) (string, string) {
	t.Helper()
	switch kind {
	case "enabled":
		r.m.ForceSync("a")
		return a.ID, ""
	case "groups":
		updated := r.update(t, a.ID, rules.RulePatch{TTL: p("64")})
		need(t, updated.GroupKey == a.GroupKey && updated.CondKey != a.CondKey, "trigger must change condition in same group")
		return a.ID, "64"
	default:
		return cut2bWL(t, r, "192.0.2.11").ID, ""
	}
}

type cut2bWrite struct {
	id, group, cond string
	err             *rules.Error
	timedOut        bool
}

func cut2bAsyncWrite(r *cut2bRig, kind string) cut2bWrite {
	done := make(chan cut2bWrite, 1)
	go func() {
		if kind == "whitelist" {
			w, e := r.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: "192.0.2.12"})
			done <- cut2bWrite{id: w.Whitelist.ID, err: e}
			return
		}
		patch := rules.RulePatch{SrcIP: p("192.0.2.1"), DstPort: p(81), Protocol: p("tcp")}
		if kind == "groups" {
			patch.DstPort, patch.TTL = p(80), p("63")
		}
		b, e := r.s.Create(rules.Actor{Kind: rules.UI}, "", patch)
		done <- cut2bWrite{id: b.Rule.ID, group: b.Rule.GroupKey, cond: b.Rule.CondKey, err: e}
	}()
	select {
	case result := <-done:
		return result
	case <-time.After(2 * time.Second):
		return cut2bWrite{timedOut: true}
	}
}

func TestCtlCut2b(t *testing.T) {
	for _, kind := range []string{"enabled", "groups", "whitelist"} {
		kind := kind
		t.Run("SN-pinned/"+kind, func(t *testing.T) { cut2bPinned(t, kind) })
		t.Run("SN-readfail/"+kind, func(t *testing.T) { cut2bReadfail(t, kind) })
	}
	for _, kind := range []string{"pin", "scan", "inlock"} {
		kind := kind
		t.Run("SN-readfail/"+kind, func(t *testing.T) { cut2bFault(t, kind) })
	}
	t.Run("SN-release", cut2bRelease)
}

func cut2bPinned(t *testing.T, kind string) {
	r := newCut2bRig(t, 1500*time.Millisecond)
	var armed atomic.Bool
	var calls atomic.Int32
	result := make(chan cut2bWrite, 1)
	rules.SnapshotTestHook = func(s *rules.Service, got string) error {
		if s == r.s && got == kind+"_pinned" && armed.CompareAndSwap(true, false) {
			calls.Add(1)
			result <- cut2bAsyncWrite(r, kind)
		}
		return nil
	}
	a := cut2bPrime(t, r, kind)
	route := cut2bRoute(kind)
	base := len(r.f.records(route))
	armed.Store(true)
	aID, ttl := cut2bTrigger(t, r, kind, a)
	var b cut2bWrite
	select {
	case b = <-result:
	case <-time.After(3 * time.Second):
		t.Fatal("pinned intervention not reached")
	}
	need(t, calls.Load() == 1, "intervention count", calls.Load())
	t.Logf("guard: pinned intervention_count=%d", calls.Load())
	need(t, !b.timedOut && b.err == nil && b.id != "", "pinned Service write did not complete within 2s", b)
	if kind == "groups" {
		need(t, b.group == a.GroupKey && b.cond != a.CondKey, "B must share group and differ in condition")
	}
	eventually(t, func() bool { return len(r.f.records(route)) > base })
	first := r.f.records(route)[base]
	foundA := false
	for _, row := range cut2bRows(t, first) {
		need(t, textField(row, "id") != b.id, "first snapshot contains B", string(first.Body))
		if textField(row, "id") == aID {
			foundA = true
			if ttl != "" {
				need(t, textField(row, "ttl") == ttl, "A condition not updated", row)
			}
		}
	}
	need(t, foundA, "first snapshot missing A", string(first.Body))
	r.normal(t)
	need(t, cut2bHas(r, kind, b.id) && cut2bHas(r, kind, aID), "node did not converge to A and B")
	need(t, calls.Load() == 1, "intervention repeated", calls.Load())
}

func cut2bReadfail(t *testing.T, kind string) {
	r := newCut2bRig(t, 1500*time.Millisecond)
	var armed atomic.Bool
	var calls atomic.Int32
	rules.SnapshotTestHook = func(s *rules.Service, got string) error {
		if s == r.s && got == kind+"_pinned" && armed.CompareAndSwap(true, false) {
			calls.Add(1)
			return errors.New("cut2b pinned read failure")
		}
		return nil
	}
	a := cut2bPrime(t, r, kind)
	route := cut2bRoute(kind)
	base := len(r.f.records(route))
	gen := cut2bSide(r, kind).ConfirmedGen
	armed.Store(true)
	aID, _ := cut2bTrigger(t, r, kind, a)
	eventually(t, func() bool { return calls.Load() == 1 })
	t.Logf("guard: readfail intervention_count=%d", calls.Load())
	cut2bFailure(t, r, kind)
	need(t, calls.Load() == 1, "intervention count", calls.Load())
	need(t, len(r.f.records(route)) == base, "request sent despite local read failure")
	need(t, cut2bSide(r, kind).ConfirmedGen == gen, "generation advanced on failure")
	r.m.mu.Lock()
	n := r.m.nodes[0]
	restored := n.sides[0].full
	if kind == "groups" {
		restored = n.dirty[a.GroupKey]
	} else if kind == "whitelist" {
		restored = n.wlDirty
	}
	r.m.mu.Unlock()
	need(t, restored, "drained work not restored")
	r.normal(t)
	need(t, cut2bHas(r, kind, aID), "retry did not deliver A")
	if kind == "groups" {
		need(t, textField(r.f.row(aID), "ttl") == "64", "retry lost updated condition")
	}
	need(t, calls.Load() == 1, "intervention repeated")
}

func cut2bFault(t *testing.T, kind string) {
	retry := time.Minute
	if kind == "inlock" {
		retry = 1500 * time.Millisecond
	}
	r := newCut2bRig(t, retry)
	var armed atomic.Bool
	var calls, pinned atomic.Int32
	var a store.Rule
	injected := make(chan error, 1)
	rules.SnapshotTestHook = func(s *rules.Service, got string) error {
		if s != r.s {
			return nil
		}
		if got == "enabled_pinned" && calls.Load() > 0 {
			pinned.Add(1)
		}
		if got == "enabled" && armed.CompareAndSwap(true, false) {
			calls.Add(1)
			var err error
			switch kind {
			case "pin":
				_, err = r.db.Exec("DELETE FROM logical_id_hw")
			case "scan":
				_, err = r.db.Exec("UPDATE rules SET src_port='cut2b_bad_int' WHERE id=?", a.ID)
			}
			injected <- err
			if kind == "inlock" {
				return errors.New("cut2b in-lock failure")
			}
			return err
		}
		return nil
	}
	a = cut2bPrime(t, r, "enabled")
	gen := cut2bSide(r, "enabled").ConfirmedGen
	base := len(r.f.records(nc.AtomicRoute))
	armed.Store(true)
	r.m.ForceSync("a")
	select {
	case err := <-injected:
		need(t, err == nil, "fault injection failed", err)
	case <-time.After(time.Second):
		t.Fatal("in-lock intervention not reached")
	}
	need(t, calls.Load() == 1, "pre-failure intervention count", calls.Load())
	if kind == "scan" {
		eventually(t, func() bool { return pinned.Load() == 1 })
		t.Logf("guard: scan injection succeeded; intervention_count=%d enabled_pinned=%d", calls.Load(), pinned.Load())
	}
	cut2bFailure(t, r, "enabled")
	need(t, calls.Load() == 1, "intervention count", calls.Load())
	wantPinned := int32(0)
	if kind == "scan" {
		wantPinned = 1
	}
	need(t, pinned.Load() == wantPinned, "error origin guard", pinned.Load(), wantPinned)
	t.Logf("guard: local_read_failed observed; intervention_count=%d enabled_pinned=%d", calls.Load(), pinned.Load())
	need(t, len(r.f.records(nc.AtomicRoute)) == base, "atomic sent despite failed snapshot")
	need(t, cut2bSide(r, "enabled").ConfirmedGen == gen, "generation advanced on failed snapshot")
	if kind != "scan" {
		writeKind := "enabled"
		if kind == "pin" {
			writeKind = "whitelist"
		}
		b := cut2bAsyncWrite(r, writeKind)
		need(t, !b.timedOut && b.err == nil && b.id != "", "error path retained write lock: Service write did not complete within 2s", b)
		if kind == "inlock" {
			r.normal(t)
			need(t, cut2bHas(r, "enabled", b.id), "write did not converge")
		}
	}
}

func cut2bRelease(t *testing.T) {
	r := newCut2bRig(t, time.Minute)
	var armed atomic.Bool
	var calls atomic.Int32
	rules.SnapshotTestHook = func(s *rules.Service, got string) error {
		if s == r.s && got == "enabled_pinned" && armed.CompareAndSwap(true, false) {
			calls.Add(1)
			return errors.New("cut2b release on error")
		}
		return nil
	}
	first := r.create(t, 80)
	r.m.Start(r.s)
	r.normal(t)
	second := r.create(t, 81)
	r.normal(t)
	armed.Store(true)
	r.m.ForceSync("a")
	cut2bFailure(t, r, "enabled")
	need(t, calls.Load() == 1, "intervention count", calls.Load())
	need(t, r.stop(t), "Manager.Stop did not return")
	need(t, r.db.Close() == nil, "close after failed snapshot")
	entries, err := os.ReadDir(filepath.Dir(r.path))
	need(t, err == nil && len(entries) == 1 && entries[0].Name() == filepath.Base(r.path), "snapshot leaked: database is not a single file", entries, err)
	b, err := os.ReadFile(r.path)
	need(t, err == nil, err)
	copyPath := filepath.Join(t.TempDir(), "copy.db")
	need(t, os.WriteFile(copyPath, b, 0600) == nil, "copy main database")
	db, err := store.Open(copyPath)
	need(t, err == nil, err)
	defer db.Close()
	rows, err := store.List(db)
	need(t, err == nil && len(rows) == 2, "main-only copy lost committed rules", rows, err)
	ids := map[string]bool{}
	for _, row := range rows {
		ids[row.ID] = true
	}
	need(t, ids[first.ID] && ids[second.ID], "committed identities missing", ids)
}
