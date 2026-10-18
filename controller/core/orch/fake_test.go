package orch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type wireRule map[string]any
type wireGroup struct {
	Key   json.RawMessage `json:"key"`
	Rules []wireRule      `json:"rules"`
}
type wireRequest struct {
	Route   string
	Body    []byte
	At, End time.Time
	Code    string
	Status  int
}
type fault struct {
	status  int
	body    string
	err     error
	block   <-chan struct{}
	entered chan<- struct{}
	publish bool
}
type fakeNode struct {
	mu       sync.Mutex
	groups   map[string][]wireRule
	entries  []wireRule
	flags    [2]bool
	protocol int
	requests []*wireRequest
	counts   map[string]int
	script   func(string, int, []byte) fault
	readRule func(wireRule) wireRule
	pageHook func(int, map[string]any)
	stats    map[string]any
}

func newFake() *fakeNode {
	return &fakeNode{groups: map[string][]wireRule{}, entries: []wireRule{}, protocol: 11, counts: map[string]int{}, stats: map[string]any{"total_packets": 0, "dropped_packets": 0, "passed_packets": 0, "cond_row_missing": 0, "tailcall_fail": 0}}
}
func cloneWire(r wireRule) wireRule {
	b, _ := json.Marshal(r)
	var out wireRule
	_ = json.Unmarshal(b, &out)
	return out
}
func wireKey(r wireRule) string {
	kind := "exact"
	if textField(r, "src_cidr") != "" || textField(r, "dst_cidr") != "" {
		kind = "cidr"
	}
	g := struct {
		Kind     string `json:"kind"`
		SrcIP    string `json:"src_ip,omitempty"`
		DstIP    string `json:"dst_ip,omitempty"`
		SrcCIDR  string `json:"src_cidr,omitempty"`
		DstCIDR  string `json:"dst_cidr,omitempty"`
		SrcPort  int    `json:"src_port"`
		DstPort  int    `json:"dst_port"`
		Protocol string `json:"protocol"`
	}{Kind: kind, SrcIP: textField(r, "src_ip"), DstIP: textField(r, "dst_ip"), SrcCIDR: textField(r, "src_cidr"), DstCIDR: textField(r, "dst_cidr"), SrcPort: intField(r, "src_port"), DstPort: intField(r, "dst_port"), Protocol: textField(r, "protocol")}
	if g.Protocol == "" {
		g.Protocol = "all"
	}
	b, _ := json.Marshal(g)
	return string(b)
}
func textField(r wireRule, key string) string { s, _ := r[key].(string); return s }
func intField(r wireRule, key string) int {
	f, _ := r[key].(float64)
	if i, ok := r[key].(int); ok {
		return i
	}
	return int(f)
}
func wireRead(r wireRule) wireRule {
	r = cloneWire(r)
	delete(r, "comment")
	if textField(r, "protocol") == "" {
		r["protocol"] = "all"
	}
	if textField(r, "action") == "" {
		r["action"] = "drop"
	}
	for _, k := range []string{"src_cidr", "dst_cidr"} {
		if p, e := netip.ParsePrefix(textField(r, k)); e == nil {
			r[k] = p.Masked().String()
		}
	}
	if flags := textField(r, "tcp_flags"); flags != "" {
		parts := strings.Split(flags, ",")
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		r["tcp_flags"] = strings.ToLower(strings.Join(parts, ","))
	}
	r["stats"] = map[string]any{"match_count": 0, "drop_count": 0, "drop_pps": 0}
	return r
}
func (f *fakeNode) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	record := &wireRequest{Route: r.URL.Path, Body: append([]byte{}, body...), At: time.Now()}
	f.mu.Lock()
	f.counts[r.URL.Path]++
	count := f.counts[r.URL.Path]
	f.requests = append(f.requests, record)
	script := f.script
	f.mu.Unlock()
	action := fault{}
	if script != nil {
		action = script(r.URL.Path, count, body)
	}
	if action.entered != nil {
		select {
		case action.entered <- struct{}{}:
		default:
		}
	}
	if action.block != nil {
		select {
		case <-action.block:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	w := httptest.NewRecorder()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if action.publish || (action.status == 0 && action.err == nil) {
			f.handle(w, r, body)
			return
		}
		w.WriteHeader(action.status)
		io.WriteString(w, action.body)
	})
	if action.err == nil || action.publish {
		h.ServeHTTP(w, r)
	}
	f.mu.Lock()
	record.End = time.Now()
	record.Status = w.Code
	var obj map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &obj)
	record.Code, _ = obj["code"].(string)
	f.mu.Unlock()
	if action.err != nil {
		return nil, action.err
	}
	return w.Result(), nil
}
func (f *fakeNode) handle(w http.ResponseWriter, r *http.Request, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	fail := func(status int, code string, index int) {
		reply(status, map[string]any{"code": code, "error": "scripted rejection", "groups": []any{map[string]any{"index": index, "code": code, "rule_ids": []string{"member"}}}})
	}
	switch r.URL.Path {
	case "/":
		reply(200, map[string]any{"sync_protocol": f.protocol})
	case string(nc.HealthRoute):
		if f.flags[0] && f.flags[1] {
			reply(200, map[string]any{"status": "healthy"})
		} else {
			reply(200, map[string]any{"status": "degraded", "rules_synced": f.flags[0], "whitelist_synced": f.flags[1]})
		}
	case string(nc.StatsRoute):
		reply(200, f.stats)
	case string(nc.SyncWLRoute):
		var payload struct {
			Entries []wireRule `json:"entries"`
		}
		if json.Unmarshal(body, &payload) != nil {
			reply(400, map[string]any{"error": "bad body"})
			return
		}
		f.entries = payload.Entries
		f.flags[1] = true
		reply(200, map[string]any{"total": len(f.entries), "failed": 0})
	case string(nc.WhitelistRoute):
		entries := []wireRule{}
		for _, entry := range f.entries {
			entries = append(entries, cloneWire(entry))
		}
		reply(200, map[string]any{"entries": entries, "count": len(entries)})
	case string(nc.AtomicRoute):
		var payload struct {
			Rules []wireRule `json:"rules"`
		}
		if json.Unmarshal(body, &payload) != nil {
			reply(400, map[string]any{"error": "bad body"})
			return
		}
		groups := map[string][]wireRule{}
		exact, cidr := 0, 0
		for _, rule := range payload.Rules {
			key := wireKey(rule)
			groups[key] = append(groups[key], rule)
			if textField(rule, "src_cidr") != "" || textField(rule, "dst_cidr") != "" {
				cidr++
			} else {
				exact++
			}
		}
		if prefixOverlap(groups, nil) {
			reply(409, map[string]any{"code": "cidr_overlap", "error": "nested"})
			return
		}
		f.groups = groups
		f.flags[0] = true
		reply(200, map[string]any{"success": true, "added": len(payload.Rules), "failed": 0, "rules": exact, "cidr_rules": cidr, "rejected": []any{}})
	case string(nc.CommitRoute):
		var payload struct {
			Groups []wireGroup `json:"groups"`
		}
		if json.Unmarshal(body, &payload) != nil {
			reply(400, map[string]any{"code": "validation_rejected", "groups": []any{}})
			return
		}
		declared := map[string]bool{}
		incoming := map[string][]wireRule{}
		for _, g := range payload.Groups {
			declared[string(g.Key)] = true
			incoming[string(g.Key)] = g.Rules
		}
		seen := map[string]bool{}
		for i, g := range payload.Groups {
			for _, rule := range g.Rules {
				id := textField(rule, "id")
				if seen[id] {
					fail(409, "duplicate_id", i)
					return
				}
				seen[id] = true
				for oldKey, oldRows := range f.groups {
					for _, old := range oldRows {
						if textField(old, "id") == id && oldKey != string(g.Key) && !declared[oldKey] {
							fail(409, "group_undeclared", i)
							return
						}
					}
				}
			}
		}
		if prefixOverlap(incoming, f.groups) {
			fail(409, "cidr_overlap", 0)
			return
		}
		groups := []any{}
		for i, g := range payload.Groups {
			if len(g.Rules) == 0 {
				delete(f.groups, string(g.Key))
			} else {
				f.groups[string(g.Key)] = g.Rules
			}
			groups = append(groups, map[string]any{"index": i, "result": "replaced"})
		}
		reply(200, map[string]any{"code": "committed", "groups": groups})
	case string(nc.RulesRoute):
		rows := []wireRule{}
		for _, members := range f.groups {
			for _, rule := range members {
				row := wireRead(rule)
				if f.readRule != nil {
					row = f.readRule(row)
				}
				rows = append(rows, row)
			}
		}
		sort.Slice(rows, func(i, j int) bool { return textField(rows[i], "id") < textField(rows[j], "id") })
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if page < 1 || limit != 1000 {
			reply(400, map[string]any{"error": "pagination"})
			return
		}
		start := min((page-1)*limit, len(rows))
		end := min(start+limit, len(rows))
		part := append([]wireRule{}, rows[start:end]...)
		obj := map[string]any{"rules": part, "count": len(rows), "pagination": map[string]any{"page": page, "limit": limit, "total": len(rows), "pages": (len(rows) + limit - 1) / limit}}
		if f.pageHook != nil {
			f.pageHook(page, obj)
		}
		reply(200, obj)
	default:
		reply(404, map[string]any{"error": "unknown route"})
	}
}
func prefixOverlap(a, b map[string][]wireRule) bool {
	for _, direction := range []string{"src_cidr", "dst_cidr"} {
		prefixes := map[string]netip.Prefix{}
		for _, groups := range []map[string][]wireRule{a, b} {
			for _, rows := range groups {
				for _, r := range rows {
					s := textField(r, direction)
					if p, e := netip.ParsePrefix(s); e == nil {
						prefixes[p.Masked().String()] = p.Masked()
					}
				}
			}
		}
		for ka, pa := range prefixes {
			for kb, pb := range prefixes {
				if ka != kb && pa.Addr().BitLen() == pb.Addr().BitLen() && (pa.Contains(pb.Addr()) || pb.Contains(pa.Addr())) {
					return true
				}
			}
		}
	}
	return false
}
func (f *fakeNode) setScript(fn func(string, int, []byte) fault) {
	f.mu.Lock()
	f.script = fn
	f.mu.Unlock()
}
func (f *fakeNode) records(route nc.Route) []wireRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []wireRequest{}
	for _, r := range f.requests {
		if route == "" || r.Route == string(route) {
			copy := *r
			copy.Body = append([]byte{}, r.Body...)
			out = append(out, copy)
		}
	}
	return out
}
func (f *fakeNode) row(id string) wireRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rows := range f.groups {
		for _, r := range rows {
			if textField(r, "id") == id {
				return cloneWire(r)
			}
		}
	}
	return nil
}
func p[T any](v T) *T { return &v }
func need(t *testing.T, ok bool, args ...any) {
	t.Helper()
	if !ok {
		t.Fatal(args...)
	}
}
func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not converge within 3s")
}
func fastOptions() Options {
	return Options{MergeWindow: 30 * time.Millisecond, RetryBase: 20 * time.Millisecond, RetryMax: 80 * time.Millisecond, CheckInterval: 100 * time.Millisecond, HealthInterval: 10 * time.Millisecond, StatsInterval: 50 * time.Millisecond, ReconcileInterval: time.Hour, ExpireInterval: time.Hour}
}

type rig struct {
	m  *Manager
	s  *rules.Service
	db *store.DB
	f  *fakeNode
}

func newRig(t *testing.T, opts Options, seed int, start bool) *rig {
	t.Helper()
	f := newFake()
	opts.Client.Transport = f
	db, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	m := New([]NodeSpec{{Name: "a", BaseURL: "http://a.invalid", Key: nc.Secret("orch-test-secret")}}, opts)
	svc := rules.New(db, m)
	r := &rig{m, svc, db, f}
	t.Cleanup(func() { m.Stop(); db.Close() })
	for i := 0; i < seed; i++ {
		r.create(t, i+1)
	}
	if start {
		m.Start(svc)
		r.normal(t)
	}
	return r
}
func (r *rig) normal(t *testing.T) {
	t.Helper()
	eventually(t, func() bool { s := r.m.Status()[0]; return s.Rules.State == "normal" && s.Whitelist.State == "normal" })
}
func (r *rig) create(t *testing.T, port int) store.Rule {
	t.Helper()
	row, e := r.s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{SrcIP: p("192.0.2.1"), DstPort: p(port), Protocol: p("tcp")})
	if e != nil {
		t.Fatal(e)
	}
	return row.Rule
}
func (r *rig) update(t *testing.T, id string, patch rules.RulePatch) store.Rule {
	t.Helper()
	row, e := r.s.Update(rules.Actor{Kind: rules.UI}, id, patch)
	if e != nil {
		t.Fatal(e)
	}
	return row
}
func requestGroups(t *testing.T, r wireRequest) []wireGroup {
	t.Helper()
	var v struct {
		Groups []wireGroup `json:"groups"`
	}
	if err := json.Unmarshal(r.Body, &v); err != nil {
		t.Fatal(err)
	}
	return v.Groups
}
func codesEvents(m *Manager, side, reason string) int {
	n := 0
	for _, e := range m.Events() {
		if e.Side == side && e.Reason == reason {
			n++
		}
	}
	return n
}
func allRoutes(f *fakeNode) []string {
	out := []string{}
	for _, r := range f.records("") {
		if r.Route == "/" || strings.Contains(r.Route, "/sync/") || r.Route == string(nc.CommitRoute) {
			out = append(out, r.Route)
		}
	}
	return out
}

// These imports also support fault scripts without opening any listener.
var _ = bytes.Equal
var _ = context.Background
var _ = errors.New
