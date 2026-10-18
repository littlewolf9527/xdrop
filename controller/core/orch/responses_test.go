package orch

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
)

func responseTests(t *testing.T) {
	t.Run("CM-drift-class", func(t *testing.T) {
		for _, code := range []string{"cidr_overlap", "group_undeclared", "content_different", "duplicate_logical_id", "duplicate_id"} {
			code := code
			t.Run(code, func(t *testing.T) {
				r := newRig(t, fastOptions(), 0, true)
				reason := make(chan string, 1)
				r.f.setScript(func(route string, n int, b []byte) fault {
					if route == string(nc.CommitRoute) {
						return fault{status: 409, body: `{"code":"` + code + `","groups":[{"index":0}]}`}
					}
					if route == string(nc.AtomicRoute) {
						reason <- r.m.Status()[0].Rules.Reason
					}
					return fault{}
				})
				r.create(t, 1)
				r.normal(t)
				need(t, len(r.f.records(nc.CommitRoute)) == 1 && len(r.f.records(nc.AtomicRoute)) == 2, "fallback requests")
				select {
				case got := <-reason:
					need(t, got == "incremental_mismatch", got)
				default:
					t.Fatal("missing atomic")
				}
			})
		}
	})
	t.Run("CM-global", func(t *testing.T) {
		for _, status := range []int{400, 401, 404, 307} {
			status := status
			t.Run(fmt.Sprint(status), func(t *testing.T) {
				r := newRig(t, fastOptions(), 0, true)
				r.f.setScript(func(route string, n int, b []byte) fault {
					if route == string(nc.CommitRoute) {
						return fault{status: status, body: `{"code":"validation_rejected","groups":[]}`}
					}
					return fault{}
				})
				r.create(t, 1)
				eventually(t, func() bool { s := r.m.Status()[0].Rules; return s.State == "failed" && s.Reason == "request_malformed" })
				r.normal(t)
				need(t, len(r.f.records(nc.AtomicRoute)) == 2, "no full retry")
			})
		}
	})
	t.Run("CM-table-full", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.CommitRoute) {
				return fault{status: 409, body: `{"code":"table_full","groups":[{"index":0}]}`}
			}
			return fault{}
		})
		r.create(t, 1)
		eventually(t, func() bool { return r.m.Status()[0].Rules.Reason == "retry_exhausted" })
		need(t, len(r.m.Status()[0].Rules.Rejected) == 0, "table_full quarantined group 0")
		reqs := r.f.records(nc.CommitRoute)
		need(t, len(reqs) == 3, "incremental attempts", len(reqs))
		need(t, reqs[1].At.Sub(reqs[0].End) >= 15*time.Millisecond && reqs[2].At.Sub(reqs[1].End) >= 35*time.Millisecond, "backoff bypassed")
		need(t, codesEvents(r.m, "rules", "retry_exhausted") == 1, "exhaustion events")
		r.normal(t)
		need(t, len(r.f.records(nc.AtomicRoute)) == 2, "capacity did not switch to atomic")
	})
	t.Run("CM-unknown", func(t *testing.T) {
		t.Run("missing-index", reviewCommitMissingIndex)
		writeFailureCases(t, nc.CommitRoute)
		t.Run("local-read", func(t *testing.T) { localReadCase(t, "groups") })
	})
	t.Run("AT-codes", func(t *testing.T) {
		writeFailureCases(t, nc.AtomicRoute)
		for _, code := range []string{"duplicate_id", "duplicate_logical_id", "duplicate_key", "cidr_overlap", "condition_group_invalid", "table_full"} {
			code := code
			t.Run(code, func(t *testing.T) {
				r := newRig(t, fastOptions(), 1, false)
				r.f.setScript(func(route string, n int, b []byte) fault {
					if route == string(nc.AtomicRoute) && n == 1 {
						return fault{status: 409, body: `{"code":"` + code + `","added":123,"failed":999}`}
					}
					return fault{}
				})
				r.m.Start(r.s)
				want := "node_rejected_batch"
				if code == "table_full" {
					want = "capacity_retry"
				}
				eventually(t, func() bool { return r.m.Status()[0].Rules.Reason == want })
				need(t, r.m.Status()[0].Rules.ConfirmedGen == 0, "confirmed failed atomic")
				r.normal(t)
			})
		}
		t.Run("local-read", func(t *testing.T) { localReadCase(t, "enabled") })
	})
	t.Run("AT-count", func(t *testing.T) {
		for _, body := range []string{
			`{"success":true,"added":1,"failed":0,"rules":0,"cidr_rules":0,"rejected":[]}`,
			`{"success":true,"added":2,"failed":0,"rules":2,"cidr_rules":0,"rejected":[]}`,
			`{"success":true,"added":0,"failed":1,"rules":0,"cidr_rules":0,"rejected":[{"id":"not-sent","reason":"bad"}]}`,
		} {
			body := body
			t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
				r := newRig(t, fastOptions(), 1, false)
				r.f.setScript(func(route string, n int, b []byte) fault {
					if route == string(nc.AtomicRoute) {
						return fault{status: 200, body: body}
					}
					return fault{}
				})
				r.m.Start(r.s)
				eventually(t, func() bool { return r.m.Status()[0].Rules.Reason == "response_invalid" })
				need(t, r.m.Status()[0].Rules.State == "failed" && r.m.Status()[0].Rules.ConfirmedGen == 0, "invalid counts accepted")
			})
		}
	})
	t.Run("AT-drain", func(t *testing.T) { atomicDrainCase(t, false) })
	t.Run("AT-drain-move", func(t *testing.T) { atomicDrainCase(t, true) })
	t.Run("E4-withhold", func(t *testing.T) {
		r, id := quarantine(t)
		before := len(r.f.records(nc.CommitRoute))
		confirmed := r.m.Status()[0].Rules.ConfirmedGen
		var failed atomic.Bool
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.ProbeRoute) && failed.CompareAndSwap(false, true) {
				return fault{status: 500}
			}
			return fault{}
		})
		r.update(t, id, rules.RulePatch{Comment: p("metadata only")})
		eventually(t, func() bool { return r.m.Status()[0].Rules.Reason == "probe_unreachable" })
		failure := r.m.Status()[0].Rules
		need(t, failure.ConsecutiveFailures == 1, "missing failed probe")
		r.normal(t)
		need(t, len(r.f.records(nc.CommitRoute)) == before, "unchanged quarantine declared")
		need(t, r.f.row(id) != nil, "old version deleted")
		after := r.m.Status()[0].Rules
		t.Logf("WITHHELD_ONLY commits_before=%d commits_after=%d confirmed_before=%d confirmed_after=%d state=%s reason=%q", before, len(r.f.records(nc.CommitRoute)), confirmed, after.ConfirmedGen, after.State, after.Reason)
		need(t, after.ConfirmedGen == confirmed, "E2: confirmed generation advanced without successful write", confirmed, after.ConfirmedGen)
		need(t, after.State == "normal" && after.ConsecutiveFailures == failure.ConsecutiveFailures && after.LastError == failure.LastError, "pure withholding cleared failure or stayed pending", after)
	})
	t.Run("E4-retry", func(t *testing.T) {
		r, id := quarantine(t)
		before := len(r.f.records(nc.CommitRoute))
		r.update(t, id, rules.RulePatch{TTL: p("63")})
		r.normal(t)
		need(t, len(r.f.records(nc.CommitRoute)) == before+1, "changed quarantine not retried")
	})
	t.Run("E4-clear", func(t *testing.T) {
		t.Run("commit", func(t *testing.T) {
			r, id := quarantine(t)
			r.update(t, id, rules.RulePatch{TTL: p("63")})
			r.normal(t)
			need(t, len(r.m.Status()[0].Rules.Rejected) == 0, "accepted rejection remains")
		})
		t.Run("atomic", func(t *testing.T) {
			r, _ := quarantine(t)
			r.m.ForceSync("a")
			r.normal(t)
			need(t, len(r.m.Status()[0].Rules.Rejected) == 0, "atomic retained group rejection")
		})
	})
	t.Run("E4-atomic-reject", func(t *testing.T) {
		r := newRig(t, fastOptions(), 2, false)
		rows, _ := r.s.List()
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.AtomicRoute) {
				r.f.mu.Lock()
				r.f.flags[0] = true
				r.f.mu.Unlock()
				return fault{status: 200, body: fmt.Sprintf(`{"success":true,"added":0,"failed":2,"rules":0,"cidr_rules":0,"rejected":[{"id":"%s","reason":"bad-a"},{"id":"%s","reason":"bad-b"}]}`, rows[0].ID, rows[1].ID)}
			}
			return fault{}
		})
		r.m.Start(r.s)
		r.normal(t)
		rejected := r.m.Status()[0].Rules.Rejected
		need(t, len(rejected) == 2 && rejected[0].ID == rows[0].ID && rejected[1].ID == rows[1].ID && rejected[0].Error == "bad-a", "partial atomic rejection", rejected)
	})
	t.Run("WL-full", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		res, e := r.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: "192.0.2.99", Protocol: "all"})
		need(t, e == nil, e)
		r.normal(t)
		need(t, r.s.DeleteWhitelist(rules.Actor{Kind: rules.UI}, res.Whitelist.ID) == nil, "delete")
		r.normal(t)
		reqs := r.f.records(nc.SyncWLRoute)
		need(t, len(reqs) == 3 && string(reqs[2].Body) == `{"entries":[]}`, "empty whitelist", reqs)
	})
	t.Run("WL-fail", func(t *testing.T) {
		writeFailureCases(t, nc.SyncWLRoute)
		t.Run("rejected", func(t *testing.T) {
			r := newRig(t, fastOptions(), 0, true)
			r.f.setScript(func(route string, n int, b []byte) fault {
				if route == string(nc.SyncWLRoute) && n == 2 {
					return fault{status: 400, body: `{"error":"invalid entry"}`}
				}
				return fault{}
			})
			_, e := r.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: "192.0.2.9"})
			need(t, e == nil, e)
			eventually(t, func() bool { return r.m.Status()[0].Whitelist.Reason == "node_rejected_batch" })
			need(t, r.m.Status()[0].Rules.State == "normal" && len(r.f.records(nc.AtomicRoute)) == 1, "side isolation")
			r.normal(t)
		})
		t.Run("local-read", func(t *testing.T) { localReadCase(t, "whitelist") })
	})
}

func writeFailureCases(t *testing.T, route nc.Route) {
	cases := []struct {
		name   string
		action fault
		reason string
	}{
		{"transport", fault{err: errors.New("injected disconnect")}, "outcome_unknown"},
		{"timeout", fault{block: make(chan struct{})}, "outcome_unknown"},
		{"server-json", fault{status: 500, body: `{"code":"quiescence_failed","error":"failure"}`}, "outcome_unknown"},
		{"invalid-2xx", fault{status: 200, body: `not JSON`}, "outcome_unknown"},
		{"shape-2xx", fault{status: 200, body: `{"wrong":true}`}, "outcome_unknown"},
		{"duplicate-2xx", fault{status: 200, body: `{"extra":{"x":1,"x":2}}`}, "outcome_unknown"},
		{"large-2xx", fault{status: 200, body: strings.Repeat(" ", 2049)}, "outcome_unknown"},
	}
	for _, status := range []int{400, 404, 500, 503} {
		for _, kind := range []string{"empty", "text", "large"} {
			body := ""
			if kind == "text" {
				body = "not JSON"
			}
			if kind == "large" {
				body = strings.Repeat(" ", 2049)
			}
			reason := "request_malformed"
			if status >= 500 {
				reason = "outcome_unknown"
			}
			cases = append(cases, struct {
				name   string
				action fault
				reason string
			}{fmt.Sprintf("%d-%s", status, kind), fault{status: status, body: body}, reason})
		}
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			opts := fastOptions()
			opts.Client.Timeouts = map[nc.Route]time.Duration{route: 30 * time.Millisecond}
			opts.Client.Limits = map[nc.Route]int64{route: 2048}
			r := newRig(t, opts, 0, true)
			start := len(r.f.records(route))
			r.f.setScript(func(path string, n int, b []byte) fault {
				if path == string(route) && n == start+1 {
					return tc.action
				}
				return fault{}
			})
			i := 0
			if route == nc.SyncWLRoute {
				i = 1
				_, e := r.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: "192.0.2.10"})
				need(t, e == nil, e)
			} else if route == nc.AtomicRoute {
				r.m.ForceSync("a")
			} else {
				r.create(t, 1)
			}
			eventually(t, func() bool {
				s := r.m.Status()[0]
				side := s.Rules
				if i == 1 {
					side = s.Whitelist
				}
				return side.Reason == tc.reason
			})
			r.m.mu.Lock()
			confirmed := r.m.nodes[0].sides[i].status.ConfirmedGen
			r.m.mu.Unlock()
			need(t, confirmed == 0, "confirmed unknown outcome")
			r.normal(t)
			if route == nc.SyncWLRoute {
				need(t, len(r.f.records(nc.AtomicRoute)) == 1, "whitelist changed rules side")
			} else {
				need(t, len(r.f.records(nc.AtomicRoute)) == 2+boolInt(route == nc.AtomicRoute), "missing full retry", len(r.f.records(nc.AtomicRoute)))
			}
		})
	}
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func localReadCase(t *testing.T, kind string) {
	r := newRig(t, fastOptions(), 1, true)
	var fired atomic.Bool
	rules.SnapshotTestHook = func(s *rules.Service, got string) error {
		if s == r.s && got == kind && fired.CompareAndSwap(false, true) {
			return errors.New("injected local read failure")
		}
		return nil
	}
	t.Cleanup(func() { r.m.Stop(); rules.SnapshotTestHook = nil })
	before := r.m.Status()[0].Rules.ConfirmedGen
	baseAtomic := len(r.f.records(nc.AtomicRoute))
	baseCommit := len(r.f.records(nc.CommitRoute))
	baseWL := len(r.f.records(nc.SyncWLRoute))
	switch kind {
	case "groups":
		r.create(t, 2)
	case "enabled":
		r.create(t, 2)
		r.m.ForceSync("a")
	case "whitelist":
		_, e := r.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: "192.0.2.11"})
		need(t, e == nil, e)
	}
	i := 0
	if kind == "whitelist" {
		i = 1
	}
	eventually(t, func() bool {
		s := r.m.Status()[0].Rules
		if i == 1 {
			s = r.m.Status()[0].Whitelist
		}
		return s.Reason == "local_read_failed"
	})
	r.m.mu.Lock()
	n := r.m.nodes[0]
	full := n.sides[i].full
	dirty := len(n.dirty) > 0
	if i == 1 {
		dirty = n.wlDirty
	}
	gen := n.sides[0].status.ConfirmedGen
	r.m.mu.Unlock()
	need(t, dirty && gen == before, "drain not restored or generation advanced")
	need(t, full == (kind == "enabled"), "local error changed full flag")
	if i == 0 {
		need(t, len(r.f.records(nc.AtomicRoute)) == baseAtomic && len(r.f.records(nc.CommitRoute)) == baseCommit, "write despite local failure")
	} else {
		need(t, len(r.f.records(nc.SyncWLRoute)) == baseWL, "write despite local failure")
	}
	r.normal(t)
	need(t, fired.Load(), "hook not used")
}
func quarantine(t *testing.T) (*rig, string) {
	r := newRig(t, fastOptions(), 1, true)
	rows, _ := r.s.List()
	id := rows[0].ID
	r.f.setScript(func(route string, n int, b []byte) fault {
		if route == string(nc.CommitRoute) && n == 1 {
			return fault{status: 400, body: `{"code":"validation_rejected","error":"bad","groups":[{"index":0}]}`}
		}
		return fault{}
	})
	r.update(t, id, rules.RulePatch{TTL: p("64")})
	r.normal(t)
	need(t, len(r.m.Status()[0].Rules.Rejected) == 1, "missing quarantine")
	return r, id
}
func atomicDrainCase(t *testing.T, move bool) {
	r := newRig(t, fastOptions(), 1, true)
	rows, _ := r.s.List()
	old := rows[0]
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	r.f.setScript(func(route string, n int, b []byte) fault {
		if route == string(nc.AtomicRoute) && n == 2 {
			return fault{block: release, entered: entered}
		}
		if move && route == string(nc.CommitRoute) && n == 1 {
			var payload struct {
				Groups []wireGroup `json:"groups"`
			}
			_ = json.Unmarshal(b, &payload)
			for i, g := range payload.Groups {
				for _, row := range g.Rules {
					if textField(row, "id") == old.ID {
						return fault{status: 409, body: fmt.Sprintf(`{"code":"condition_capacity","groups":[{"index":%d}]}`, i)}
					}
				}
			}
		}
		return fault{}
	})
	r.m.ForceSync("a")
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("atomic not entered")
	}
	id := ""
	if move {
		r.update(t, old.ID, rules.RulePatch{DstPort: p(2)})
	} else {
		id = r.create(t, 2).ID
	}
	close(release)
	r.normal(t)
	reqs := r.f.records(nc.CommitRoute)
	need(t, len(reqs) == 1, "missing post-atomic commit", len(reqs))
	groups := requestGroups(t, reqs[0])
	if move {
		need(t, len(groups) == 2 && intField(r.f.row(old.ID), "dst_port") == 1 && len(r.m.Status()[0].Rules.Rejected) == 2, "in-flight move forgotten")
	} else {
		need(t, len(groups) == 1 && textField(groups[0].Rules[0], "id") == id, "in-flight write lost")
	}
}
