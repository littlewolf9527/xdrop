package orch

import (
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"log"
	"sort"
	"time"
)

type History interface {
	WriteTraffic([]store.TrafficRow, int64, time.Time, [2]int, func(string)) (bool, error)
}
type trafficRing struct {
	points [720]store.TrafficRow
	next   int64
}

func newTrafficRing(now time.Time) trafficRing {
	start := now.Truncate(time.Minute)
	if now.After(start) {
		start = start.Add(time.Minute)
	}
	return trafficRing{next: start.Unix()}
}
func (m *Manager) addTraffic(n *node, now time.Time, rates map[string]float64) {
	if rates == nil {
		return
	}
	t := now.Unix() / 5 * 5
	i := (t / 5) % 720
	p := store.TrafficRow{T: t, N: 1, Avg: [4]float64{rates["dropped_packets"], rates["passed_packets"], rates["dropped_bytes"], rates["passed_bytes"]}}
	n.traffic.points[i] = p
	total, member := store.TrafficRow{T: t}, false
	for _, current := range m.nodes {
		member = member || current == n
		v := current.traffic.points[i]
		if v.N == 0 || v.T != t {
			continue
		}
		total.N = 1
		for k := range total.Avg {
			total.Avg[k] += v.Avg[k]
		}
	}
	if member {
		m.traffic.points[i] = total
	}
}
func (r *trafficRing) minutes(name string, now time.Time) []store.TrafficRow {
	end := now.Unix() / 60 * 60
	oldest := ((now.Unix()/5-719)*5 + 59) / 60 * 60
	rows := map[int64]store.TrafficRow{}
	for _, p := range r.points {
		t := p.T / 60 * 60
		if p.N == 0 || t < r.next || t < oldest || t >= end {
			continue
		}
		v := rows[t]
		v.Node, v.T, v.N = name, t, v.N+1
		for k, x := range p.Avg {
			v.Avg[k] += x
			if x > v.Max[k] {
				v.Max[k] = x
			}
		}
		rows[t] = v
	}
	out := []store.TrafficRow{}
	for _, v := range rows {
		for k := range v.Avg {
			v.Avg[k] /= float64(v.N)
		}
		out = append(out, v)
	}
	return out
}
func (m *Manager) flushHistory(now time.Time) {
	if m.opts.History == nil {
		return
	}
	m.mu.Lock()
	rings := []*trafficRing{&m.traffic}
	rows := m.traffic.minutes("", now)
	for _, n := range m.nodes {
		rings = append(rings, &n.traffic)
		rows = append(rows, n.traffic.minutes(n.status.Name, now)...)
	}
	hour := m.historyHour
	m.mu.Unlock()
	capped, err := m.opts.History.WriteTraffic(rows, hour, now, m.opts.historyLimits, m.opts.historyTx)
	if err != nil {
		log.Printf("traffic history write failed: %v", err)
	}
	m.mu.Lock()
	if err == nil {
		for _, r := range rings {
			if next := now.Unix() / 60 * 60; next > r.next {
				r.next = next
			}
		}
		m.historyHour = now.Unix() / 3600 * 3600
	} else {
		m.record(nil, Event{At: now, Side: "history", Reason: "local_read_failed"})
	}
	if capped {
		m.cappedAt = now
		m.record(nil, Event{At: now, Side: "history", Reason: "history_capped"})
	}
	m.mu.Unlock()
	m.dispatch()
}
func (m *Manager) TrafficMemory(name string, span time.Duration) ([]store.TrafficRow, time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, r := m.now(), &m.traffic
	if name != "" {
		r = nil
		for _, n := range m.nodes {
			if n.status.Name == name {
				r = &n.traffic
				break
			}
		}
	}
	out := []store.TrafficRow{}
	if r != nil {
		for _, p := range r.points {
			if p.N > 0 && p.T >= now.Add(-span).Unix() && p.T <= now.Unix() {
				out = append(out, p)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out, now, !m.cappedAt.IsZero() && now.Sub(m.cappedAt) < time.Hour
}
