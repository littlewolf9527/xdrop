package orch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
)

func samplerTests(t *testing.T) {
	t.Run("MG-health-gate", func(t *testing.T) {
		t.Run("during-probe", reviewHealthDuringProbe)
		t.Run("fresh-false", func(t *testing.T) {
			opts := fastOptions()
			opts.MergeWindow = 120 * time.Millisecond
			r := newRig(t, opts, 1, true)
			r.create(t, 2)
			r.f.mu.Lock()
			r.f.flags[0] = false
			r.f.mu.Unlock()
			eventually(t, func() bool { r.m.mu.Lock(); defer r.m.mu.Unlock(); return r.m.nodes[0].sides[0].badHealth })
			r.normal(t)
			need(t, len(r.f.records(nc.CommitRoute)) == 0 && len(r.f.records(nc.AtomicRoute)) == 2, "commit crossed false health")
		})
		t.Run("stale-false", func(t *testing.T) {
			r := newRig(t, fastOptions(), 1, true)
			atomicEntered := make(chan struct{}, 1)
			atomicRelease := make(chan struct{})
			healthEntered := make(chan struct{}, 1)
			healthRelease := make(chan struct{})
			var armed atomic.Bool
			var used atomic.Bool
			r.f.setScript(func(route string, n int, b []byte) fault {
				if route == string(nc.AtomicRoute) && n == 2 {
					armed.Store(true)
					return fault{block: atomicRelease, entered: atomicEntered}
				}
				if route == string(nc.HealthRoute) && armed.Load() && used.CompareAndSwap(false, true) {
					return fault{block: healthRelease, entered: healthEntered, status: 200, body: `{"status":"degraded","rules_synced":false,"whitelist_synced":true}`}
				}
				return fault{}
			})
			r.m.ForceSync("a")
			select {
			case <-atomicEntered:
			case <-time.After(time.Second):
				t.Fatal("no atomic")
			}
			select {
			case <-healthEntered:
			case <-time.After(time.Second):
				t.Fatal("no health")
			}
			close(atomicRelease)
			r.normal(t)
			close(healthRelease)
			r.create(t, 2)
			r.normal(t)
			need(t, len(r.f.records(nc.CommitRoute)) == 1 && len(r.f.records(nc.AtomicRoute)) == 2, "stale false caused full sync")
		})
	})
	t.Run("VG-every", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.CommitRoute) && n <= 2 {
				return fault{status: 400, body: `{"code":"validation_rejected","groups":[{"index":0}]}`}
			}
			return fault{}
		})
		for i := 1; i <= 3; i++ {
			r.create(t, i)
		}
		_, e := r.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: "192.0.2.19"})
		need(t, e == nil, e)
		r.normal(t)
		routes := allRoutes(r.f)
		writes := 0
		for i, route := range routes {
			if route != "/" {
				writes++
				need(t, i > 0 && routes[i-1] == "/", "write without adjacent probe", routes)
			}
		}
		need(t, len(r.f.records(nc.CommitRoute)) == 3 && writes == 6, "write witnesses", routes)
	})
	t.Run("VG-sticky", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		r.f.mu.Lock()
		r.f.protocol = 8
		r.f.mu.Unlock()
		for i := 1; i <= 5; i++ {
			r.create(t, i)
		}
		eventually(t, func() bool { return r.m.Status()[0].Incompatible })
		time.Sleep(150 * time.Millisecond)
		need(t, len(r.f.records(nc.CommitRoute)) == 0 && len(r.f.records(nc.AtomicRoute)) == 1 && len(r.f.records(nc.SyncWLRoute)) == 1, "incompatible write")
		r.f.mu.Lock()
		r.f.protocol = 11
		r.f.mu.Unlock()
		r.normal(t)
		need(t, !r.m.Status()[0].Incompatible && len(r.f.records(nc.CommitRoute)) == 0 && len(r.f.records(nc.AtomicRoute)) == 2 && len(r.f.records(nc.SyncWLRoute)) == 2, "version recovery bypassed full sync")
		routes := allRoutes(r.f)
		last := routes[len(routes)-4:]
		need(t, last[1] == string(nc.SyncWLRoute) && last[3] == string(nc.AtomicRoute), "recovery order", last)
	})
	t.Run("SP-online", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		firstBase := len(r.f.records(nc.HealthRoute))
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.HealthRoute) && n == firstBase+1 {
				return fault{err: errors.New("health failed")}
			}
			return fault{}
		})
		eventually(t, func() bool { return len(r.f.records(nc.HealthRoute)) >= firstBase+2 })
		need(t, r.m.Status()[0].Online && codesEvents(r.m, "online", "offline") == 0, "single failure went offline")
		secondBase := len(r.f.records(nc.HealthRoute))
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.HealthRoute) && (n == secondBase+1 || n == secondBase+2) {
				return fault{err: errors.New("health failed")}
			}
			return fault{}
		})
		eventually(t, func() bool {
			return codesEvents(r.m, "online", "offline") == 1 && len(r.f.records(nc.AtomicRoute)) >= 2
		})
		r.normal(t)
		need(t, len(r.f.records(nc.AtomicRoute)) == 2 && len(r.f.records(nc.SyncWLRoute)) == 2, "reconnected sync")
	})
	t.Run("SP-restart", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.SyncWLRoute) && n > 1 {
				return fault{status: 500, body: `{}`}
			}
			return fault{}
		})
		base := len(r.f.records(nc.HealthRoute))
		r.f.mu.Lock()
		r.f.flags = [2]bool{}
		r.f.mu.Unlock()
		eventually(t, func() bool { return len(r.f.records(nc.HealthRoute)) >= base+10 })
		need(t, len(r.f.records(nc.AtomicRoute)) == 2, "restart hot loop", len(r.f.records(nc.AtomicRoute)))
		need(t, r.m.Status()[0].Whitelist.State == "failed" && len(r.f.records(nc.SyncWLRoute)) >= 4, "whitelist did not continue retries")
	})
	t.Run("SP-rates", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, false)
		r.m.ctx = context.Background()
		r.m.nodes[0].ctx = r.m.ctx
		n := r.m.nodes[0]
		r.f.stats["total_packets"] = 100
		for _, key := range []string{"total_bytes", "dropped_bytes", "passed_bytes"} {
			r.f.stats[key] = 9000
		}
		r.f.stats["total_pps"] = 999999
		r.m.sampleStats(n)
		before := r.m.Status()[0]
		r.m.mu.Lock()
		beforeSample := n.status.StatsAt
		r.m.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		r.f.stats["total_packets"] = 160
		for _, key := range []string{"total_bytes", "dropped_bytes", "passed_bytes"} {
			r.f.stats[key] = 14400
		}
		r.m.sampleStats(n)
		after := r.m.Status()[0]
		r.m.mu.Lock()
		afterSample := n.status.StatsAt
		r.m.mu.Unlock()
		need(t, before.StatsAt.Equal(beforeSample) && after.StatsAt.Equal(afterSample), "public sampling timestamps differ")
		want := 60 / afterSample.Sub(beforeSample).Seconds()
		need(t, after.Rates["total_packets"] == want, "rate not locally calculated", after.Rates, want)
		for _, key := range []string{"total_bytes", "dropped_bytes", "passed_bytes"} {
			need(t, after.Rates[key] == 5400/afterSample.Sub(beforeSample).Seconds(), "byte rate", key, after.Rates)
		}
		r.f.stats["total_packets"] = 2
		r.m.sampleStats(n)
		need(t, r.m.Status()[0].Rates == nil, "negative/reset rate")
	})
	t.Run("SP-a10", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, false)
		r.m.ctx = context.Background()
		r.m.nodes[0].ctx = r.m.ctx
		for _, value := range []int{4, 4, 7, 9, 9, 11, 2, 2, 5} {
			r.f.stats["cond_row_missing"] = value
			r.f.stats["tailcall_fail"] = value
			r.m.sampleStats(r.m.nodes[0])
		}
		for _, key := range []string{"cond_row_missing", "tailcall_fail"} {
			need(t, codesEvents(r.m, "counter", key) == 3, "counter edge events", key, r.m.Events())
		}
	})
	t.Run("SP-single", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		var sampled, bad atomic.Int32
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.StatsRoute) {
				pcs := make([]uintptr, 32)
				n := runtime.Callers(0, pcs)
				frames := runtime.CallersFrames(pcs[:n])
				found := false
				for {
					frame, more := frames.Next()
					if strings.HasSuffix(frame.Function, ".(*Manager).sampleStats") {
						found = true
					}
					if !more {
						break
					}
				}
				sampled.Add(1)
				if !found {
					bad.Add(1)
				}
			}
			return fault{}
		})
		base := len(r.f.records(nc.StatsRoute))
		r.m.ReconcileNow("a")
		r.m.ForceSync("a")
		time.Sleep(time.Second)
		need(t, sampled.Load() > 0 && bad.Load() == 0 && int(sampled.Load()) == len(r.f.records(nc.StatsRoute))-base, "multiple stats readers", sampled.Load(), bad.Load())
	})
	t.Run("EX-expire", func(t *testing.T) {
		opts := fastOptions()
		opts.ExpireInterval = 100 * time.Millisecond
		r := newRig(t, opts, 0, true)
		res, e := r.s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{SrcIP: p("192.0.2.30"), Protocol: p("tcp"), ExpiresIn: p("1s")})
		need(t, e == nil, e)
		r.normal(t)
		eventually(t, func() bool { _, e := r.s.Get(res.Rule.ID); return e != nil && e.Code == "not_found" })
		r.normal(t)
		reqs := r.f.records(nc.CommitRoute)
		need(t, len(reqs) >= 2, "no expiry commit")
		groups := requestGroups(t, reqs[len(reqs)-1])
		need(t, len(groups) == 1 && len(groups[0].Rules) == 0 && string(groups[0].Key) == res.Rule.GroupKey, "expiry not empty group")
	})
	t.Run("E1-once", func(t *testing.T) {
		r := newRig(t, fastOptions(), 0, true)
		base := len(r.m.Events())
		var failures atomic.Int32
		r.f.setScript(func(route string, n int, b []byte) fault {
			if route == string(nc.CommitRoute) || route == string(nc.AtomicRoute) {
				if failures.Add(1) <= 10 {
					return fault{status: 500, body: `{}`}
				}
			}
			return fault{}
		})
		r.create(t, 1)
		r.normal(t)
		events := []Event{}
		for _, e := range r.m.Events()[base:] {
			if e.Side == "rules" {
				events = append(events, e)
			}
		}
		need(t, len(events) == 3, "repeated state events", events)
		need(t, events[0].From == "normal" && events[0].To == "pending" && events[1].To == "failed" && events[2].To == "normal", "transitions", events)
	})
	t.Run("E1-isolation", func(t *testing.T) {
		f := newFake()
		opts := fastOptions()
		opts.Client.Transport = transportDispatch{f: f}
		r := newRig(t, fastOptions(), 0, false)
		r.m = New([]NodeSpec{{Name: "a", BaseURL: "http://a.invalid"}, {Name: "b", BaseURL: "http://b.invalid"}}, opts)
		r.s = rules.New(r.db, r.m)
		t.Cleanup(r.m.Stop)
		start := time.Now()
		r.m.Start(r.s)
		eventually(t, func() bool { return r.m.Status()[0].Rules.State == "normal" })
		need(t, time.Since(start) < time.Second, "healthy node blocked")
		need(t, !r.m.Status()[1].Online, "blackhole online")
		routes := allRoutes(f)
		want := []string{"/", string(nc.SyncWLRoute), "/", string(nc.AtomicRoute)}
		need(t, fmt.Sprint(routes) == fmt.Sprint(want), "healthy sequence changed", routes)
	})
}

type transportDispatch struct{ f *fakeNode }

func (d transportDispatch) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "b.invalid" {
		return nil, errors.New("blackhole")
	}
	return d.f.RoundTrip(r)
}
