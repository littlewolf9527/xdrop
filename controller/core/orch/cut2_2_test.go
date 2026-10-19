package orch

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
)

func reviewCommitMissingIndex(t *testing.T) {
	opts := fastOptions()
	opts.RetryBase, opts.RetryMax = time.Hour, time.Hour
	r := newRig(t, opts, 1, true)
	before := r.m.Status()[0].Rules.ConfirmedGen
	r.f.setScript(func(route string, n int, b []byte) fault {
		if route == string(nc.CommitRoute) {
			return fault{status: 200, body: `{"code":"committed","groups":[{"result":"created"}]}`}
		}
		return fault{}
	})
	row := r.create(t, 2)
	eventually(t, func() bool { return r.m.Status()[0].Rules.Reason == "outcome_unknown" })
	s := r.m.Status()[0].Rules
	need(t, s.State == "pending" && s.ConfirmedGen == before, "missing index confirmed generation", s)
	need(t, r.f.row(row.ID) == nil && len(r.f.records(nc.CommitRoute)) == 1, "fixture published malformed success")
}

func reviewSuccessSecrets(t *testing.T) {
	const secret = "orch-test-secret"
	for _, kind := range []string{"atomic-success", "stats-success", "rule-stats-success"} {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			r := newRig(t, fastOptions(), 1, false)
			rows, e := r.s.List()
			need(t, e == nil, e)
			id := rows[0].ID
			if kind == "atomic-success" {
				r.f.setScript(func(route string, n int, b []byte) fault {
					if route == string(nc.AtomicRoute) {
						r.f.mu.Lock()
						r.f.flags[0] = true
						r.f.mu.Unlock()
						return fault{status: 200, body: fmt.Sprintf(`{"success":true,"added":0,"failed":1,"rules":0,"cidr_rules":0,"rejected":[{"id":%q,"reason":%q}]}`, id, "echo "+secret)}
					}
					return fault{}
				})
			} else if kind == "stats-success" {
				r.f.stats["diagnostic-"+secret] = []any{secret, map[string]any{secret: "nested " + secret}}
			} else {
				r.f.readRule = func(row wireRule) wireRule {
					row["stats"] = map[string]any{secret: secret, "match_count": 0}
					return row
				}
			}
			r.m.Start(r.s)
			r.normal(t)
			if kind == "atomic-success" {
				rejected := r.m.Status()[0].Rules.Rejected
				need(t, len(rejected) == 1 && rejected[0].ID == id && rejected[0].Error == "echo [redacted]", "diagnostic scrub or identity changed")
			} else if kind == "stats-success" {
				eventually(t, func() bool { return r.m.Status()[0].Stats != nil })
				need(t, r.m.Status()[0].Stats["diagnostic-[redacted]"] != nil, "stats sample missing")
			} else {
				need(t, reconcileOnce(t, r, 0).Result == "equal", "stats altered comparison")
			}
			for _, format := range []string{"%v", "%+v", "%#v"} {
				need(t, !strings.Contains(fmt.Sprintf(format, r.m.Status()), secret), "successful response leaked through Status")
			}
			b, err := json.Marshal(r.m.Status())
			need(t, err == nil && !strings.Contains(string(b), secret), "successful response leaked through Status JSON")
		})
	}
}

func reviewHealthDuringProbe(t *testing.T) {
	opts := fastOptions()
	opts.HealthInterval = time.Hour
	r := newRig(t, opts, 1, true)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	reason := make(chan string, 1)
	r.f.setScript(func(route string, n int, b []byte) fault {
		if route == string(nc.ProbeRoute) && n == 3 {
			return fault{block: release, entered: entered}
		}
		if route == string(nc.AtomicRoute) && n == 2 {
			reason <- r.m.Status()[0].Rules.Reason
		}
		return fault{}
	})
	row := r.create(t, 2)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("commit Probe did not block")
	}
	r.f.mu.Lock()
	r.f.flags[0] = false
	r.f.mu.Unlock()
	r.m.sampleHealth(r.m.nodes[0])
	r.m.mu.Lock()
	trusted := r.m.nodes[0].sides[0].badHealth
	full := r.m.nodes[0].sides[0].full
	r.m.mu.Unlock()
	need(t, trusted && !full && r.m.Status()[0].Rules.State == "pending", "C2 fixture did not record trusted false while pending")
	close(release)
	released = true
	r.normal(t)
	need(t, len(r.f.records(nc.CommitRoute)) == 0 && len(r.f.records(nc.AtomicRoute)) == 2, "commit sent after trusted false during Probe")
	need(t, r.f.row(row.ID) != nil && r.m.Status()[0].Rules.ConfirmedGen == 2, "fallback lost drained keys")
	select {
	case got := <-reason:
		need(t, got == "node_restarted", "fallback reason", got)
	default:
		t.Fatal("atomic missing")
	}
}

func reviewLabOracle(t *testing.T) {
	t.Run("logical-id", func(t *testing.T) {
		r := newRig(t, fastOptions(), 1, true)
		rows, e := r.s.List()
		need(t, e == nil && rows[0].LogicalID == 1, "fixture identity")
		h := &labHarness{t: t, db: r.db, direct: r.m.nodes[0].client}
		need(t, h.readbackDifference(nil) == nil, "independent oracle positive control")
		nodeEdit(r.f, rows[0].ID, func(row wireRule) wireRule { row["logical_id"] = 101; return row })
		// Even an incorrect production self-report must not bless these bytes.
		r.m.mu.Lock()
		r.m.nodes[0].status.RuleReconcile.Result = "equal"
		r.m.mu.Unlock()
		err := h.readbackDifference(nil)
		need(t, err != nil && strings.Contains(err.Error(), "differs"), "lab oracle accepted logical_id 1 vs 101")
		t.Log("LAB_ORACLE database_logical_id=1 node_logical_id=101 independent_result=red")
	})
}

func reviewFieldDrift(t *testing.T) {
	for _, tc := range []struct {
		field   string
		patch   rules.RulePatch
		changed any
	}{
		{"ttl", rules.RulePatch{TTL: p("64")}, "63"},
		{"dscp", rules.RulePatch{DSCP: p("10")}, "11"},
		{"icmp_type", rules.RulePatch{Protocol: p("icmp"), ICMPType: p("8")}, "0"},
		{"icmp_code", rules.RulePatch{Protocol: p("icmp"), ICMPCode: p("0")}, "1"},
		{"fragment", rules.RulePatch{Fragment: p("nofrag")}, "first"},
		{"pkt_len", rules.RulePatch{PktLen: p("64")}, "65"},
		{"tcp_flags", rules.RulePatch{TCPFlags: p("SYN")}, "ACK"},
		{"match_anomaly", rules.RulePatch{MatchAnomaly: p(1)}, 2},
		{"action", rules.RulePatch{Action: p("drop")}, "rate_limit"},
		{"rate_limit", rules.RulePatch{Action: p("rate_limit"), RateLimit: p(int64(100))}, 200},
		{"logical_id", rules.RulePatch{}, 101},
	} {
		tc := tc
		t.Run(tc.field, func(t *testing.T) {
			r := newRig(t, fastOptions(), 0, false)
			patch := tc.patch
			patch.SrcIP = p("192.0.2.1")
			if patch.Protocol == nil {
				patch.Protocol = p("tcp")
			}
			created, e := r.s.Create(rules.Actor{Kind: rules.UI}, "", patch)
			need(t, e == nil, e)
			r.m.Start(r.s)
			r.normal(t)
			nodeEdit(r.f, created.Rule.ID, func(row wireRule) wireRule { row[tc.field] = tc.changed; return row })
			result := reconcileOnce(t, r, 0)
			need(t, result.Result == "drift" && result.Diff.Different == 1 && result.Diff.Extra == 0 && result.Diff.Missing == 0, "single-field drift missed", tc.field, result)
			need(t, len(r.f.records(nc.AtomicRoute)) == 2, "no corrective atomic", tc.field)
			need(t, reconcileOnce(t, r, 0).Result == "equal", "field repair did not converge", tc.field)
		})
	}
}
