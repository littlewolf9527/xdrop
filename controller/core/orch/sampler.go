package orch

import (
	"encoding/json"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"strconv"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
)

func (m *Manager) sampler(n *node) {
	health, stopHealth := m.ticks("health", m.opts.HealthInterval)
	stats, stopStats := m.ticks("stats", m.opts.StatsInterval)
	defer stopHealth()
	defer stopStats()
	if n.client == nil {
		return
	}
	m.sampleHealth(n)
	m.sampleStats(n)
	for {
		if n.ctx.Err() != nil {
			return
		}
		if m.opts.statsPriority != nil {
			m.opts.statsPriority()
		}
		select {
		case <-stats:
			m.sampleStats(n)
			m.dispatch()
			continue
		default:
		}
		select {
		case <-n.ctx.Done():
			return
		case <-health:
			m.sampleHealth(n)
		case <-stats:
			m.sampleStats(n)
		}
		m.dispatch()
	}
}
func (m *Manager) sampleHealth(n *node) {
	started := time.Now()
	r, e := n.client.Health(n.ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if e != nil {
		n.healthFailures++
		if n.healthFailures >= 2 && n.status.Online {
			n.status.Online = false
			m.record(n, Event{time.Now(), n.status.Name, "online", "true", "false", "offline"})
		}
		return
	}
	n.healthFailures = 0
	n.status.HealthAt = time.Now()
	n.status.Health = r
	if !n.status.Online {
		n.status.Online = true
		m.record(n, Event{time.Now(), n.status.Name, "online", "false", "true", "reconnected"})
		if n.connected {
			for i := 0; i < 2; i++ {
				n.sides[i].full = true
				n.sides[i].fullAt = time.Time{}
				n.sides[i].due = time.Time{}
				n.sides[i].driftWrite = false
				if !n.status.Incompatible {
					m.transition(n, i, "pending", "reconnected")
				}
			}
		}
		n.connected = true
		wake(n)
	}
	restart := false
	for i, flag := range []bool{r.RulesSynced, r.WhitelistSynced} {
		s := &n.sides[i]
		if !s.fullAt.IsZero() && started.After(s.fullAt) && !flag {
			s.badHealth = true
			if s.status.State == "normal" {
				restart = true
			}
		}
	}
	if restart && !n.status.Incompatible {
		for i := 0; i < 2; i++ {
			n.sides[i].full = true
			n.sides[i].due = time.Time{}
			n.sides[i].driftWrite = false
			m.transition(n, i, "pending", "node_restarted")
		}
		wake(n)
	}
}

var counterNames = []string{"total_packets", "dropped_packets", "passed_packets", "whitelisted_packets", "rate_limited_packets", "mapped_v6_dropped", "cond_row_missing", "tailcall_fail", "total_bytes", "dropped_bytes", "passed_bytes"}

func (m *Manager) sampleStats(n *node) {
	r, e := n.client.Stats(n.ctx)
	if e != nil {
		return
	}
	now := m.now()
	current := map[string]uint64{}
	for _, key := range counterNames {
		if v, ok := r[key].(json.Number); ok {
			u, err := strconv.ParseUint(string(v), 10, 64)
			if err != nil {
				return
			}
			current[key] = u
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	reset := n.previous == nil
	for key, value := range current {
		if value < n.previous[key] {
			reset = true
		}
	}
	rates := map[string]float64(nil)
	if !reset && now.After(n.status.StatsAt) {
		rates = map[string]float64{}
		for key, value := range current {
			rates[key] = float64(value-n.previous[key]) / now.Sub(n.status.StatsAt).Seconds()
		}
	}
	for _, key := range []string{"cond_row_missing", "tailcall_fail"} {
		growing := !reset && current[key] > n.previous[key]
		if growing && !n.growing[key] {
			m.record(n, Event{now, n.status.Name, "counter", "steady", "increasing", key})
		}
		n.growing[key] = growing
	}
	n.previous = current
	n.status.Stats = r
	n.status.Rates = rates
	n.status.StatsAt = now
	n.statsSeq++
	m.addTraffic(n, now, rates)
	n.limits = rules.Values{}
	capacity, _ := r["capacity"].(map[string]any)
	for i, name := range rules.DimensionNames() {
		entry, _ := capacity[name].(map[string]any)
		if number, ok := entry["limit"].(json.Number); ok {
			value, err := strconv.Atoi(string(number))
			if err == nil && value > 0 {
				n.limits[i] = value
			}
		}
	}
	wake(n)
}

// Reference the response type here to keep sampling's protocol dependency clear.
var _ nc.Health
