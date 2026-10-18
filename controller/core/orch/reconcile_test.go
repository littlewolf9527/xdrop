package orch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
)

func reconcileOnce(t *testing.T, r *rig, side int) ReconcileStatus {
	t.Helper()
	before := r.m.Status()[0].RuleReconcile.LastAt
	if side == 1 {
		before = r.m.Status()[0].WhitelistReconcile.LastAt
	}
	r.m.ReconcileNow("a")
	eventually(t, func() bool {
		s := r.m.Status()[0].RuleReconcile
		if side == 1 {
			s = r.m.Status()[0].WhitelistReconcile
		}
		return s.LastAt.After(before)
	})
	if side == 1 {
		return r.m.Status()[0].WhitelistReconcile
	}
	return r.m.Status()[0].RuleReconcile
}
func nodeEdit(f *fakeNode, id string, edit func(wireRule) wireRule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var changed wireRule
	for key, rows := range f.groups {
		keep := []wireRule{}
		for _, row := range rows {
			if textField(row, "id") == id {
				changed = edit(cloneWire(row))
			} else {
				keep = append(keep, row)
			}
		}
		if len(keep) == 0 {
			delete(f.groups, key)
		} else {
			f.groups[key] = keep
		}
	}
	if changed != nil {
		key := wireKey(changed)
		f.groups[key] = append(f.groups[key], changed)
	}
}
func reconcileTests(t *testing.T) {
	t.Run("RC-equal", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, false)
		for _, patch := range []rules.RulePatch{
			{SrcIP: p("192.0.2.1"), Comment: p("not transmitted")},
			{SrcCIDR: p("198.51.100.99/24"), Protocol: p("tcp"), TCPFlags: p("SYN,!ACK"), TTL: p("64"), Comment: p("metadata")},
		} {
			_, e := r.s.Create(rules.Actor{Kind: rules.UI}, "", patch)
			need(t, e == nil, e)
		}
		r.m.Start(r.s)
		r.normal(t)
		result := reconcileOnce(t, r, 0)
		need(t, result.Result == "equal" && len(r.f.records(nc.AtomicRoute)) == 1, "false drift", result)
		need(t, result.Pages == 1 && result.Duration > 0 && r.m.Status()[0].RuleStatsCount == 2, "reconcile measurements")
	})
	t.Run("RC-drift", func(t *testing.T) {
		reviewFieldDrift(t)
		for _, kind := range []string{"port", "logical", "extra", "missing"} {
			kind := kind
			t.Run(kind, func(t *testing.T) {
				r := newRig(t, fastOptions(), 1, true)
				rows, _ := r.s.List()
				id := rows[0].ID
				if kind == "extra" {
					r.f.mu.Lock()
					row := wireRule{"id": "external", "logical_id": 900001, "src_ip": "198.51.100.1", "protocol": "tcp", "dst_port": 80}
					r.f.groups[wireKey(row)] = []wireRule{row}
					r.f.mu.Unlock()
				} else {
					nodeEdit(r.f, id, func(row wireRule) wireRule {
						switch kind {
						case "port":
							row["dst_port"] = 222
						case "logical":
							row["logical_id"] = 900001
						case "missing":
							return nil
						}
						return row
					})
				}
				result := reconcileOnce(t, r, 0)
				need(t, result.Result == "drift" && len(r.f.records(nc.AtomicRoute)) == 2, "missed drift", kind, result)
				need(t, reconcileOnce(t, r, 0).Result == "equal", "repair did not converge")
			})
		}
	})
	t.Run("RC-rejected", func(t *testing.T) {
		r := newRig(t, fastOptions(), 1, false)
		rows, _ := r.s.List()
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.AtomicRoute) {
				r.f.mu.Lock()
				r.f.flags[0] = true
				r.f.mu.Unlock()
				return fault{status: 200, body: fmt.Sprintf(`{"success":true,"added":0,"failed":1,"rules":0,"cidr_rules":0,"rejected":[{"id":"%s","reason":"rejected"}]}`, rows[0].ID)}
			}
			return fault{}
		})
		r.m.Start(r.s)
		r.normal(t)
		need(t, reconcileOnce(t, r, 0).Result == "equal" && len(r.f.records(nc.AtomicRoute)) == 1, "rejected row counted as missing")
	})
	t.Run("RC-paging", func(t *testing.T) {
		r := newRig(t, fastOptions(), 2500, true)
		r.f.mu.Lock()
		r.f.pageHook = func(page int, obj map[string]any) {
			if page == 2 {
				obj["pagination"].(map[string]any)["total"] = 2501
			}
		}
		r.f.mu.Unlock()
		result := reconcileOnce(t, r, 0)
		need(t, result.Result == "void" && result.Pages == 3 && r.m.Status()[0].Rules.State == "normal" && len(r.f.records(nc.AtomicRoute)) == 1, "inconsistent pagination accepted", result)
	})
	t.Run("RC-void", func(t *testing.T) {
		t.Run("concurrent-write", func(t *testing.T) {
			r := newRig(t, fastOptions(), 1, true)
			var once sync.Once
			written := make(chan *rules.Error, 1)
			r.f.mu.Lock()
			r.f.pageHook = func(page int, obj map[string]any) {
				once.Do(func() {
					_, e := r.s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{SrcIP: p("192.0.2.22"), Protocol: p("tcp")})
					written <- e
				})
			}
			r.f.mu.Unlock()
			result := reconcileOnce(t, r, 0)
			need(t, result.Result == "void" && len(r.f.records(nc.AtomicRoute)) == 1, "read/write race called drift", result)
			need(t, <-written == nil, "fixture write failed")
			r.normal(t)
		})
		t.Run("local-read", func(t *testing.T) {
			r := newRig(t, fastOptions(), 1, true)
			var fired atomic.Bool
			rules.SnapshotTestHook = func(s *rules.Service, kind string) error {
				if s == r.s && kind == "enabled" && fired.CompareAndSwap(false, true) {
					return errors.New("local expected read failed")
				}
				return nil
			}
			t.Cleanup(func() { r.m.Stop(); rules.SnapshotTestHook = nil })
			result := reconcileOnce(t, r, 0)
			need(t, fired.Load() && result.Result == "void" && r.m.Status()[0].Rules.State == "normal" && len(r.f.records(nc.AtomicRoute)) == 1, "local reconcile error changed state", result)
		})
	})
	t.Run("RC-quarantine", func(t *testing.T) {
		for _, kind := range []string{"unrelated", "outside-to-held", "held-to-outside", "within-closure"} {
			kind := kind
			t.Run(kind, func(t *testing.T) {
				r, id := quarantine(t)
				if kind == "within-closure" {
					r.f.setScript(func(route string, n int, b []byte) fault {
						if route == string(nc.CommitRoute) {
							return fault{status: 409, body: `{"code":"condition_capacity","groups":[{"index":1}]}`}
						}
						return fault{}
					})
					r.update(t, id, rules.RulePatch{DstPort: p(2)})
					r.normal(t)
				} else if kind == "held-to-outside" {
					nodeEdit(r.f, id, func(row wireRule) wireRule { row["dst_port"] = 3; return row })
				} else {
					other := r.create(t, 2)
					r.normal(t)
					port := 3
					if kind == "outside-to-held" {
						port = 1
					}
					nodeEdit(r.f, other.ID, func(row wireRule) wireRule { row["dst_port"] = port; row["ttl"] = "62"; return row })
				}
				result := reconcileOnce(t, r, 0)
				if kind == "within-closure" {
					need(t, result.Result == "equal" && len(r.f.records(nc.AtomicRoute)) == 1, "held move misclassified", result)
				} else {
					need(t, result.Result == "drift" && len(r.f.records(nc.AtomicRoute)) == 2, "unrelated drift suppressed", kind, result)
				}
			})
		}
	})
	t.Run("RC-other-side", func(t *testing.T) {
		r := newRig(t, fastOptions(), 1, true)
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.SyncWLRoute) && n > 1 {
				return fault{status: 500, body: `{}`}
			}
			return fault{}
		})
		_, e := r.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: "192.0.2.44"})
		need(t, e == nil, e)
		eventually(t, func() bool { return r.m.Status()[0].Whitelist.State == "failed" })
		rows, _ := r.s.List()
		nodeEdit(r.f, rows[0].ID, func(row wireRule) wireRule { row["dst_port"] = 2; return row })
		need(t, reconcileOnce(t, r, 0).Result == "drift", "other side blocked reconciliation")
		need(t, reconcileOnce(t, r, 0).Result == "equal", "repair failed")
	})
	t.Run("RC-persist-exit", func(t *testing.T) {
		for _, kind := range []string{"force", "commit", "retry"} {
			kind := kind
			t.Run(kind, func(t *testing.T) {
				r, id := persistentRig(t)
				base := len(r.m.Events())
				switch kind {
				case "force":
					r.m.ForceSync("a")
					r.normal(t)
				case "commit":
					r.update(t, id, rules.RulePatch{Comment: p("local write")})
					r.normal(t)
				case "retry":
					count := len(r.f.records(nc.AtomicRoute))
					r.f.setScript(func(route string, n int, b []byte) fault {
						if route == string(nc.AtomicRoute) && n == count+1 {
							return fault{err: context.DeadlineExceeded}
						}
						return fault{}
					})
					reconcileOnce(t, r, 0)
					eventually(t, func() bool { return r.m.Status()[0].Rules.Reason == "outcome_unknown" })
					eventually(t, func() bool {
						return len(r.f.records(nc.AtomicRoute)) == count+2 && r.m.Status()[0].Rules.State == "failed"
					})
					need(t, r.m.Status()[0].Rules.Reason == "drift_persistent", "retry lost persistent marker", r.m.Status()[0].Rules)
					r.f.mu.Lock()
					r.f.readRule = nil
					r.f.mu.Unlock()
					need(t, reconcileOnce(t, r, 0).Result == "equal", "zero diff")
					r.normal(t)
				}
				normal := 0
				for _, e := range r.m.Events()[base:] {
					if e.Side == "rules" && e.To == "normal" {
						normal++
					}
				}
				need(t, normal == 1, "persistent exit events", r.m.Events()[base:])
			})
		}
	})
	t.Run("RC-persist", func(t *testing.T) {
		opts := fastOptions()
		opts.ReconcileInterval = time.Second
		r := newRig(t, opts, 1, true)
		r.f.mu.Lock()
		r.f.readRule = func(row wireRule) wireRule { row["dst_port"] = 2; return row }
		r.f.mu.Unlock()
		need(t, reconcileOnce(t, r, 0).Result == "drift", "initial drift")
		eventually(t, func() bool { return r.m.Status()[0].Rules.Reason == "drift_persistent" })
		base := len(r.m.Events())
		time.Sleep(5 * time.Second)
		need(t, r.m.Status()[0].Rules.State == "failed" && r.m.Status()[0].Rules.Reason == "drift_persistent", "atomic 200 cleared persistent state")
		reads, writes := len(r.f.records(nc.RulesRoute)), len(r.f.records(nc.AtomicRoute))
		need(t, reads >= 5 && reads <= 8 && writes == reads+1, "correction cadence", reads, writes)
		need(t, codesEvents(r.m, "rules", "drift_persistent") == 1, "repeated persistent events")
		for _, e := range r.m.Events()[base:] {
			need(t, e.Side != "rules" || e.To != "normal", "spurious normal during persistent drift", e)
		}
		r.f.mu.Lock()
		r.f.readRule = nil
		r.f.mu.Unlock()
		r.normal(t)
		normal := 0
		for _, e := range r.m.Events()[base:] {
			if e.Side == "rules" && e.To == "normal" {
				normal++
			}
		}
		need(t, normal == 1, "recovery normal events", normal)
	})
	t.Run("RC-wl", func(t *testing.T) {
		r := newRig(t, fastOptions(), 1, true)
		r.f.mu.Lock()
		r.f.entries = append(r.f.entries, wireRule{"id": "extra-wl", "src_ip": "192.0.2.88", "protocol": "all"})
		r.f.mu.Unlock()
		need(t, reconcileOnce(t, r, 1).Result == "drift" && len(r.f.records(nc.SyncWLRoute)) == 2 && len(r.f.records(nc.AtomicRoute)) == 1, "whitelist drift isolation")
	})
	t.Run("A13-table", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		row := r.create(t, 1)
		r.normal(t)
		r.m.ForceSync("a")
		r.normal(t)
		base := len(r.f.records(nc.HealthRoute))
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.HealthRoute) && (n == base+1 || n == base+2) {
				return fault{err: errors.New("offline")}
			}
			return fault{}
		})
		eventually(t, func() bool { return len(r.f.records(nc.AtomicRoute)) == 3 })
		r.normal(t)
		r.create(t, 2)
		r.normal(t)
		nodeEdit(r.f, row.ID, func(row wireRule) wireRule { row["dst_port"] = 33; return row })
		need(t, reconcileOnce(t, r, 0).Result == "drift", "missing drift")
		r.create(t, 3)
		r.normal(t)
		need(t, len(r.f.records(nc.AtomicRoute)) == 4 && len(r.f.records(nc.CommitRoute)) == 3, "A13 trigger table", allRoutes(r.f))
	})
}
func persistentRig(t *testing.T) (*rig, string) {
	r := newRig(t, fastOptions(), 1, true)
	rows, _ := r.s.List()
	r.f.mu.Lock()
	r.f.readRule = func(row wireRule) wireRule { row["dst_port"] = 2; return row }
	r.f.mu.Unlock()
	need(t, reconcileOnce(t, r, 0).Result == "drift", "first drift")
	need(t, reconcileOnce(t, r, 0).Result == "drift", "second drift")
	need(t, r.m.Status()[0].Rules.Reason == "drift_persistent", "persistent transition")
	return r, rows[0].ID
}
