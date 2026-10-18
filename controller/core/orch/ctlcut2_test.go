package orch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func TestCtlCut2(t *testing.T) {
	responseTests(t)
	samplerTests(t)
	reconcileTests(t)
	t.Run("LAB-oracle", reviewLabOracle)
	t.Run("CV-rule", func(t *testing.T) {
		r := store.NodeRow{ID: "r", LogicalID: 7, Match: store.Match{SrcIP: "192.0.2.1", Protocol: "all", Action: "drop"}}
		b, e := json.Marshal(nodeRule(r))
		need(t, e == nil && string(b) == `{"id":"r","logical_id":7,"src_ip":"192.0.2.1","protocol":"all","action":"drop"}`, string(b), e)
		r.Match = store.Match{SrcCIDR: "192.0.2.0/24", DstCIDR: "2001:db8::/64", Protocol: "tcp", Action: "rate_limit", RateLimit: 10, TCPFlags: "SYN,!ACK", MatchAnomaly: 1, TTL: p("64"), DSCP: p("0"), ICMPType: p("8"), ICMPCode: p("0"), Fragment: p("none"), PktLen: p("64")}
		b, e = json.Marshal(nodeRule(r))
		need(t, e == nil, string(b), e)
		var obj map[string]any
		need(t, json.Unmarshal(b, &obj) == nil, "JSON")
		for _, key := range []string{"logical_id", "src_cidr", "dst_cidr", "protocol", "action", "rate_limit", "tcp_flags", "match_anomaly", "ttl", "dscp", "icmp_type", "icmp_code", "fragment", "pkt_len"} {
			need(t, obj[key] != nil, "missing", key)
		}
		for _, key := range []string{"comment", "stats", "pkt_len_min", "pkt_len_max"} {
			_, exists := obj[key]
			need(t, !exists, "unexpected", key)
		}
	})
	t.Run("CV-group", func(t *testing.T) {
		key := `{"kind":"exact","src_port":0,"dst_port":0,"protocol":"all"}`
		b, e := json.Marshal(group(key, nil))
		need(t, e == nil && string(b) == `{"key":`+key+`,"rules":[]}`, string(b), e)
		g := group(key, []store.Rule{{ID: "r", LogicalID: 1, Match: store.Match{Protocol: "all"}}})
		need(t, string(g.Key) == key && len(g.Rules) == 1, "members/key")
	})
	t.Run("CV-wl", func(t *testing.T) {
		for _, rows := range [][]store.Whitelist{nil, {{ID: "a", SrcIP: "192.0.2.1"}, {ID: "b", DstPort: 80, Protocol: "tcp"}, {ID: "c", DstIP: "2001:db8::1"}}} {
			b, e := json.Marshal(struct {
				Entries []nc.Entry `json:"entries"`
			}{whitelistRows(rows)})
			need(t, e == nil, e)
			want := `{"entries":[]}`
			if len(rows) > 0 {
				want = `{"entries":[{"id":"a","src_ip":"192.0.2.1"},{"id":"b","dst_port":80,"protocol":"tcp"},{"id":"c","dst_ip":"2001:db8::1"}]}`
			}
			need(t, string(b) == want, string(b))
		}
	})
	t.Run("SN-enabled", func(t *testing.T) {
		r := newRig(t, fastOptions(), 2, false)
		all, e := r.s.List()
		need(t, e == nil, e)
		need(t, r.s.SetEnabled(rules.Actor{Kind: rules.UI}, all[0].ID, false) == nil, "disable")
		rows, e := r.s.SnapshotEnabled(func() {})
		need(t, e == nil && len(rows) == 1, "enabled", rows, e)
		need(t, rows[0].ID == all[1].ID && rows[0].LogicalID == all[1].LogicalID && reflect.DeepEqual(rows[0].Match, all[1].Match), "narrow fields differ")
		_, groups, e := r.s.SnapshotGroups(func() []string { return []string{all[0].GroupKey, "missing"} })
		need(t, e == nil && groups["missing"] != nil && len(groups["missing"]) == 0 && len(groups[all[0].GroupKey]) == 0, "empty groups", e)
	})
	t.Run("SN-share", func(t *testing.T) {
		r := newRig(t, fastOptions(), 2, false)
		var reads atomic.Int32
		rules.SnapshotTestHook = func(s *rules.Service, kind string) error {
			if s == r.s && kind == "enabled" {
				reads.Add(1)
			}
			return nil
		}
		opts := fastOptions()
		opts.Client.Transport = r.f
		m := New([]NodeSpec{{Name: "a", BaseURL: "http://a.invalid"}, {Name: "b", BaseURL: "http://b.invalid"}}, opts)
		r.s = rules.New(r.db, m)
		r.m = m
		t.Cleanup(func() { m.Stop(); rules.SnapshotTestHook = nil })
		m.Start(r.s)
		eventually(t, func() bool { s := m.Status(); return s[0].Rules.State == "normal" && s[1].Rules.State == "normal" })
		requests := r.f.records(nc.AtomicRoute)
		need(t, len(requests) == 2 && reads.Load() == 1, "atomic/reads", len(requests), reads.Load())
		need(t, bytes.Equal(requests[0].Body, requests[1].Body), "snapshot bodies")
	})
	t.Run("SN-stale", func(t *testing.T) {
		r := newRig(t, fastOptions(), 1, false)
		b := newFake()
		var bOnline atomic.Bool
		opts := fastOptions()
		opts.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "b.invalid" {
				if !bOnline.Load() {
					return nil, errors.New("offline fixture")
				}
				return b.RoundTrip(req)
			}
			return r.f.RoundTrip(req)
		})
		r.m = New([]NodeSpec{{Name: "a", BaseURL: "http://a.invalid"}, {Name: "b", BaseURL: "http://b.invalid"}}, opts)
		r.s = rules.New(r.db, r.m)
		var reads atomic.Int32
		rules.SnapshotTestHook = func(s *rules.Service, kind string) error {
			if s == r.s && kind == "enabled" {
				reads.Add(1)
			}
			return nil
		}
		t.Cleanup(func() { r.m.Stop(); rules.SnapshotTestHook = nil })
		r.m.Start(r.s)
		r.normal(t)
		row := r.create(t, 20)
		r.normal(t)
		bOnline.Store(true)
		eventually(t, func() bool { return r.m.Status()[1].Rules.State == "normal" })
		requests := append(r.f.records(nc.AtomicRoute), b.records(nc.AtomicRoute)...)
		need(t, reads.Load() == 2 && len(requests) == 2, "reads", reads.Load(), len(requests))
		need(t, bytes.Contains(requests[1].Body, []byte(row.ID)), "stale snapshot")
	})
	t.Run("SN-boundary", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, false)
		created, e := r.s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{SrcCIDR: p("192.0.2.0/24"), Protocol: p("tcp")})
		need(t, e == nil, e)
		old := created.Rule
		r.m.Start(r.s)
		r.normal(t)
		var once sync.Once
		var blocked atomic.Bool
		done := make(chan struct{})
		rules.SnapshotTestHook = func(s *rules.Service, kind string) error {
			if s == r.s && kind == "groups" {
				once.Do(func() {
					go func() {
						_, _ = r.s.Update(rules.Actor{Kind: rules.UI}, old.ID, rules.RulePatch{SrcCIDR: p("192.0.2.0/25")})
						close(done)
					}()
					select {
					case <-done:
					case <-time.After(200 * time.Millisecond):
						blocked.Store(true)
					}
				})
			}
			return nil
		}
		t.Cleanup(func() { r.m.Stop(); rules.SnapshotTestHook = nil })
		need(t, r.s.SetEnabled(rules.Actor{Kind: rules.UI}, old.ID, true) == nil, "notify")
		eventually(t, func() bool { return len(r.f.records(nc.CommitRoute)) >= 2 })
		r.normal(t)
		need(t, blocked.Load(), "write crossed snapshot write exclusion")
		requests := r.f.records(nc.CommitRoute)
		first := requestGroups(t, requests[0])
		next := requestGroups(t, requests[1])
		need(t, len(first) == 1 && string(first[0].Key) == old.GroupKey && len(first[0].Rules) == 1, "first snapshot changed", first)
		need(t, len(next) == 2, "move split", next)
		for _, request := range requests {
			g := requestGroups(t, request)
			need(t, !(len(g) == 1 && string(g[0].Key) == old.GroupKey && len(g[0].Rules) == 0), "isolated deletion")
		}
	})
	t.Run("MG-start", func(t *testing.T) {
		r := newRig(t, fastOptions(), 2, false)
		b := newFake()
		opts := fastOptions()
		opts.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "b.invalid" {
				return b.RoundTrip(req)
			}
			return r.f.RoundTrip(req)
		})
		r.m = New([]NodeSpec{{Name: "a", BaseURL: "http://a.invalid"}, {Name: "b", BaseURL: "http://b.invalid"}}, opts)
		r.s = rules.New(r.db, r.m)
		t.Cleanup(r.m.Stop)
		r.m.Start(r.s)
		eventually(t, func() bool { s := r.m.Status(); return s[0].Rules.State == "normal" && s[1].Rules.State == "normal" })
		for _, f := range []*fakeNode{r.f, b} {
			routes := allRoutes(f)
			need(t, reflect.DeepEqual(routes, []string{"/", string(nc.SyncWLRoute), "/", string(nc.AtomicRoute)}), routes)
		}
	})
	t.Run("MG-pack", func(t *testing.T) {
		t.Run("manual-clock", func(t *testing.T) {
			opts := fastOptions()
			opts.MergeWindow = 200 * time.Millisecond
			entered := make(chan time.Duration, 1)
			tick := make(chan time.Time, 1)
			opts.mergeTick = func(d time.Duration) <-chan time.Time {
				select {
				case entered <- d:
				default:
				}
				return tick
			}
			r := newRig(t, opts, 0, true)
			// Explicit fixture time: SQLite fsync/host scheduling cannot advance this
			// input window or release the merge boundary before all 50 writes commit.
			start := time.Unix(0, 0)
			now := start
			for i := 0; i < 50; i++ {
				r.create(t, i+1)
				if i == 0 {
					select {
					case d := <-entered:
						need(t, d == 200*time.Millisecond, "merge duration", d)
					case <-time.After(time.Second):
						t.Fatal("merge clock was not armed")
					}
				}
				now = start.Add(time.Duration(i) * time.Millisecond)
			}
			need(t, now.Sub(start) < 50*time.Millisecond, "fixture writes too slow", now.Sub(start))
			need(t, len(r.f.records(nc.CommitRoute)) == 0, "commit before merge tick")
			tick <- start.Add(opts.MergeWindow)
			r.normal(t)
			requests := r.f.records(nc.CommitRoute)
			need(t, len(requests) == 1 && len(requestGroups(t, requests[0])) == 50, "not packed", len(requests))
			need(t, len(r.f.records(nc.AtomicRoute)) == 1, "daily atomic")
		})
		t.Run("real-timer", func(t *testing.T) {
			opts := fastOptions()
			opts.MergeWindow = 500 * time.Millisecond
			need(t, opts.mergeTick == nil, "real timer fixture must not install a clock hook")
			r := newRig(t, opts, 0, true)
			start := time.Now()
			rows := []store.Rule{r.create(t, 1), r.create(t, 2)}
			writes := time.Since(start)
			// Two writes exercise the production timer. Inspect recorded request
			// times so a delayed observer cannot turn a correct wait into a failure.
			time.Sleep(opts.MergeWindow / 4)
			early := 0
			for _, req := range r.f.records(nc.CommitRoute) {
				if req.At.Before(start.Add(opts.MergeWindow / 2)) {
					early++
				}
			}
			need(t, early == 0, "commit before half of real merge window", early)
			r.normal(t)
			requests := r.f.records(nc.CommitRoute)
			need(t, len(requests) == 1, "real timer did not pack writes", len(requests))
			need(t, !requests[0].At.Before(start.Add(opts.MergeWindow)), "commit before real timer deadline")
			groups := requestGroups(t, requests[0])
			need(t, len(groups) == len(rows), "real timer omitted groups", groups)
			ids := map[string]bool{}
			for _, g := range groups {
				for _, row := range g.Rules {
					ids[row["id"].(string)] = true
				}
			}
			for _, row := range rows {
				need(t, ids[row.ID] && r.f.row(row.ID) != nil, "real timer omitted write", row.ID)
			}
			need(t, len(r.f.records(nc.AtomicRoute)) == 1, "daily atomic")
			t.Logf("REAL_MERGE writes=2 write_duration=%s window=%s early_commits=%d commits=%d", writes, opts.MergeWindow, early, len(requests))
		})
	})
	t.Run("MG-gen", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		for i := 1; i < 5; i++ {
			r.create(t, i)
		}
		r.normal(t)
		need(t, r.m.Status()[0].Rules.ConfirmedGen == 4, "confirmed generation", r.m.Status())
	})
	t.Run("MG-confirm", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.CommitRoute) {
				return fault{block: release, entered: entered}
			}
			return fault{}
		})
		r.create(t, 1)
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("commit not entered")
		}
		status := r.m.Status()[0].Rules
		need(t, status.State == "pending" && status.ConfirmedGen == 0, "premature confirmation", status)
		close(release)
		r.normal(t)
		need(t, r.m.Status()[0].Rules.ConfirmedGen == 1, "not confirmed")
	})
	t.Run("MG-sink", func(t *testing.T) {
		opts := fastOptions()
		opts.MergeWindow = 200 * time.Millisecond
		r := newRig(t, opts, 1, true)
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.CommitRoute) && n == 1 {
				return fault{block: release, entered: entered}
			}
			return fault{}
		})
		r.create(t, 2)
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("no blocked commit")
		}
		for i := 0; i < 100; i++ {
			i := i
			start := time.Now()
			done := make(chan *rules.Error, 1)
			go func() {
				_, e := r.s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{SrcIP: p("192.0.2.1"), DstPort: p(100 + i), Protocol: p("tcp")})
				done <- e
			}()
			select {
			case e := <-done:
				need(t, e == nil, e)
			case <-time.After(50 * time.Millisecond):
				t.Fatal("sink blocked writer before return")
			}
			need(t, time.Since(start) < 50*time.Millisecond, "sink blocked writer")
		}
		close(release)
		r.normal(t)
		requests := r.f.records(nc.CommitRoute)
		need(t, len(requests) == 2 && len(requestGroups(t, requests[1])) == 100, "lost writes", len(requests))
	})
	t.Run("MG-move", func(t *testing.T) {
		r := newRig(t, fastOptions(), 1, true)
		rows, _ := r.s.List()
		old := rows[0]
		r.update(t, old.ID, rules.RulePatch{DstPort: p(2)})
		r.normal(t)
		g := requestGroups(t, r.f.records(nc.CommitRoute)[0])
		need(t, len(g) == 2, "move not paired")
		for _, group := range g {
			if string(group.Key) == old.GroupKey {
				need(t, len(group.Rules) == 0, "old membership")
			}
		}
		need(t, intField(r.f.row(old.ID), "dst_port") == 2, "node move")
	})
	t.Run("NC-secret", func(t *testing.T) {
		reviewSuccessSecrets(t)
		r := newRig(t, fastOptions(), 1, true)
		for _, v := range []any{r.m.Status(), r.m.Events()} {
			for _, format := range []string{"%v", "%+v", "%#v"} {
				need(t, !strings.Contains(fmt.Sprintf(format, v), "orch-test-secret"), "secret in status/event")
			}
			b, _ := json.Marshal(v)
			need(t, !bytes.Contains(b, []byte("orch-test-secret")), "secret in JSON")
		}
	})
	t.Run("CM-ok", func(t *testing.T) {
		for _, code := range []string{"committed", "unchanged", "bad-count"} {
			code := code
			t.Run(code, func(t *testing.T) {
				r := newRig(t, fastOptions(), 0, true)
				r.f.setScript(func(route string, n int, b []byte) fault {
					if route == string(nc.CommitRoute) {
						body := `{"code":"` + code + `","groups":[{"index":0,"result":"unchanged"}]}`
						if code == "bad-count" {
							body = `{"code":"committed","groups":[]}`
						}
						return fault{status: 200, body: body}
					}
					return fault{}
				})
				r.create(t, 1)
				if code == "bad-count" {
					eventually(t, func() bool { return r.m.Status()[0].Rules.Reason == "response_invalid" })
				} else {
					r.normal(t)
				}
			})
		}
	})
	t.Run("CM-S1", func(t *testing.T) {
		t.Run("all-rejected", func(t *testing.T) {
			r := newRig(t, fastOptions(), 0, true)
			confirmed := r.m.Status()[0].Rules.ConfirmedGen
			r.f.setScript(func(route string, n int, body []byte) fault {
				if route == string(nc.CommitRoute) {
					return fault{status: 400, body: `{"code":"validation_rejected","groups":[{"index":0}]}`}
				}
				return fault{}
			})
			for i := 1; i <= 3; i++ {
				r.create(t, i)
			}
			r.normal(t)
			s := r.m.Status()[0].Rules
			need(t, s.State == "normal" && s.ConfirmedGen == confirmed && len(s.Rejected) == 3, "all rejected acknowledgement", s)
			requests := r.f.records(nc.CommitRoute)
			need(t, len(requests) == 3, "all rejected request count", len(requests))
			for i, request := range requests {
				need(t, len(requestGroups(t, request)) == 3-i, "rejected group resent")
			}
			time.Sleep(2 * r.m.opts.CheckInterval)
			need(t, len(r.f.records(nc.CommitRoute)) == 3, "automatic quarantine retry")
		})
		r := newRig(t, fastOptions(), 0, true)
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.CommitRoute) && n == 1 {
				return fault{status: 400, body: `{"code":"validation_rejected","error":"bad group","groups":[{"index":1}]}`}
			}
			return fault{}
		})
		for i := 1; i <= 3; i++ {
			r.create(t, i)
		}
		r.normal(t)
		requests := r.f.records(nc.CommitRoute)
		need(t, len(requests) == 2, "requests", len(requests))
		first, next := requestGroups(t, requests[0]), requestGroups(t, requests[1])
		need(t, len(first) == 3 && len(next) == 2, "group counts")
		bad := string(first[1].Key)
		for _, g := range next {
			need(t, string(g.Key) != bad, "bad group retried")
		}
		rejected := r.m.Status()[0].Rules.Rejected
		need(t, len(rejected) == 1 && rejected[0].Key == bad && rejected[0].Code == "validation_rejected" && rejected[0].Fingerprint != "", "rejection", rejected)
	})
	t.Run("CM-S1-move", func(t *testing.T) { testMoveClosure(t, false, false) })
	t.Run("CM-closure", func(t *testing.T) {
		t.Run("unchanged-partner", func(t *testing.T) { testMoveClosure(t, true, false) })
		t.Run("undirtied-partner", func(t *testing.T) { testMoveClosure(t, true, true) })
	})
	t.Run("CM-rounds", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		release := make(chan struct{})
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.CommitRoute) {
				if n == 9 {
					return fault{block: release}
				}
				return fault{status: 400, body: `{"code":"validation_rejected","groups":[{"index":0}]}`}
			}
			return fault{}
		})
		for i := 1; i <= 10; i++ {
			r.create(t, i)
		}
		eventually(t, func() bool { return len(r.f.records(nc.CommitRoute)) == 9 })
		need(t, r.m.Status()[0].Rules.State == "pending", "round cap state")
		r.m.mu.Lock()
		held := len(r.m.nodes[0].blocked)
		r.m.mu.Unlock()
		need(t, held == 8, "round request cap", held)
		close(release)
		r.normal(t)
	})
}

func testMoveClosure(t *testing.T, retry, partner bool) {
	r := newRig(t, fastOptions(), 1, true)
	rows, _ := r.s.List()
	old := rows[0]
	var q store.Rule
	if retry {
		res, e := r.s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{SrcIP: p("192.0.2.1"), DstPort: p(1), Protocol: p("tcp"), TTL: p("63"), Enabled: p(partner)})
		need(t, e == nil, e)
		q = res.Rule
		r.normal(t)
	}
	base := len(r.f.records(nc.CommitRoute))
	r.f.setScript(func(route string, n int, b []byte) fault {
		if route == string(nc.CommitRoute) && n == base+1 {
			var payload struct {
				Groups []wireGroup `json:"groups"`
			}
			_ = json.Unmarshal(b, &payload)
			for i, g := range payload.Groups {
				for _, row := range g.Rules {
					if textField(row, "id") == old.ID {
						return fault{status: 409, body: fmt.Sprintf(`{"code":"condition_capacity","error":"capacity","groups":[{"index":%d,"rule_ids":["%s"]}]}`, i, old.ID)}
					}
				}
			}
		}
		return fault{}
	})
	updated := r.update(t, old.ID, rules.RulePatch{DstPort: p(2)})
	r.create(t, 3)
	r.normal(t)
	requests := r.f.records(nc.CommitRoute)
	need(t, len(requests) == base+2, "move retry requests", len(requests), base)
	second := requestGroups(t, requests[base+1])
	need(t, len(second) == 1 && string(second[0].Key) != old.GroupKey && string(second[0].Key) != updated.GroupKey, "partner deletion published", second)
	need(t, intField(r.f.row(old.ID), "dst_port") == 1, "old node version lost")
	need(t, len(r.m.Status()[0].Rules.Rejected) == 2, "closed rejection")
	if !retry {
		return
	}
	r.update(t, old.ID, rules.RulePatch{TTL: p("64")})
	if !partner {
		need(t, r.s.SetEnabled(rules.Actor{Kind: rules.UI}, q.ID, false) == nil, "notify unchanged old group")
	}
	r.normal(t)
	retried := r.f.records(nc.CommitRoute)
	need(t, len(retried) >= base+3, "closure did not issue retry", len(retried))
	last := requestGroups(t, retried[base+2])
	need(t, len(last) == 2, "closure not released")
	if partner {
		need(t, r.f.row(q.ID) != nil, "undirtied partner omitted")
	}
	r.m.mu.Lock()
	held, moves := len(r.m.nodes[0].blocked), len(r.m.nodes[0].moves)
	r.m.mu.Unlock()
	need(t, held == 0 && moves == 0, "accept did not clear", held, moves)
}

var _ = errors.New

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
