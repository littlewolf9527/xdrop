package orch

import (
	"fmt"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"time"
)

type RuleRate struct {
	PPS, BytesPS float64
	Nodes        int
}
type hitBaseline struct {
	count, bytes, at uint64
	seen             time.Time
}
type hitState struct {
	lastNow, seq               uint64
	success, failed, truncated bool
	at                         time.Time
	base                       map[uint32]hitBaseline
	rates                      map[string]RuleRate
}
type TrafficInput struct {
	Key                            string
	At                             time.Time
	Incomplete, DenominatorMissing bool
	DroppedPPS, DroppedBytesPS     float64
	Names                          map[string]bool
	Rates                          map[string]RuleRate
}

func (m *Manager) now() time.Time {
	if m.opts.now != nil {
		return m.opts.now()
	}
	return time.Now()
}
func (m *Manager) ticks(kind string, d time.Duration) (<-chan time.Time, func()) {
	if m.opts.tick != nil {
		return m.opts.tick(kind, d), func() {}
	}
	if kind == "hits" {
		t := time.NewTimer(d)
		return t.C, func() { t.Stop() }
	}
	t := time.NewTicker(d)
	return t.C, t.Stop
}
func (m *Manager) hitter(n *node) {
	if n.client == nil {
		return
	}
	base := 5 * time.Second
	if m.opts.hitsInterval > 0 {
		base = m.opts.hitsInterval
	}
	interval, next := base, m.now().Add(base)
	for {
		ch, stop := m.ticks("hits", next.Sub(m.now()))
		select {
		case <-n.ctx.Done():
			stop()
			return
		case <-ch:
			stop()
		}
		if n.ctx.Err() != nil {
			return
		}
		started := m.now()
		r, err := n.client.Hits(n.ctx, n.hits.lastNow)
		now := m.now()
		m.mu.Lock()
		if n.hits.failed != (err != nil) {
			n.hits.seq++
		}
		n.hits.failed = err != nil
		if err == nil {
			interval = base
			m.acceptHits(n, r, now)
		} else {
			interval *= 2
			if interval > time.Minute {
				interval = time.Minute
			}
		}
		m.mu.Unlock()
		next = started.Add(interval)
		if next.Before(now) {
			next = next.Add(((now.Sub(next)-1)/interval + 1) * interval)
		}
	}
}
func (m *Manager) acceptHits(n *node, r nc.HitsResponse, now time.Time) {
	h := &n.hits
	if h.success && r.NowNS == h.lastNow {
		return
	}
	if !h.success || r.NowNS < h.lastNow {
		h.base = map[uint32]hitBaseline{}
	}
	h.rates = map[string]RuleRate{}
	for _, row := range r.Hits {
		old, exists := h.base[row.LogicalID]
		if exists && old.at == h.lastNow && r.NowNS > old.at && row.DropCount >= old.count && row.DropBytes >= old.bytes {
			seconds := float64(r.NowNS-old.at) / 1e9
			h.rates[row.RuleID] = RuleRate{PPS: float64(row.DropCount-old.count) / seconds, BytesPS: float64(row.DropBytes-old.bytes) / seconds}
		}
		h.base[row.LogicalID] = hitBaseline{row.DropCount, row.DropBytes, r.NowNS, now}
	}
	for id, row := range h.base {
		if now.Sub(row.seen) > time.Minute {
			delete(h.base, id)
		}
	}
	h.lastNow, h.at, h.success, h.truncated = r.NowNS, now, true, r.Truncated
	h.seq++
}
func (m *Manager) TrafficInput() TrafficInput {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := TrafficInput{Key: fmt.Sprintf("%d/%d", m.lastGen, m.nodeVersion), Names: map[string]bool{}, Rates: map[string]RuleRate{}}
	for _, n := range m.nodes {
		h := &n.hits
		out.Names[n.status.Name] = true
		out.Key += fmt.Sprintf("/%d/%d", h.seq, n.statsSeq)
		out.Incomplete = out.Incomplete || !h.success || h.failed || h.truncated
		if h.at.After(out.At) {
			out.At = h.at
		}
		p, pOK := n.status.Rates["dropped_packets"]
		b, bOK := n.status.Rates["dropped_bytes"]
		out.DenominatorMissing = out.DenominatorMissing || !pOK || !bOK
		out.DroppedPPS += p
		out.DroppedBytesPS += b
		for id, r := range h.rates {
			if r.PPS <= 0 {
				continue
			}
			sum := out.Rates[id]
			sum.PPS += r.PPS
			sum.BytesPS += r.BytesPS
			sum.Nodes++
			out.Rates[id] = sum
		}
	}
	out.Incomplete = out.Incomplete || out.DenominatorMissing
	return out
}
