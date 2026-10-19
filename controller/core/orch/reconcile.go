package orch

import (
	"math/rand"
	"sort"
	"strings"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
)

func (m *Manager) eligible(n *node, i int) bool {
	s := &n.sides[i]
	return n.status.Online && !n.status.Incompatible && !n.overloaded && !s.full && (s.status.State == "normal" || s.status.State == "failed" && s.status.Reason == "drift_persistent") && ((i == 0 && len(n.dirty) == 0) || (i == 1 && !n.wlDirty))
}
func readKey(r nc.Rule) string {
	c, e := rules.Canonicalize(ruleMatch(r))
	if e != nil {
		return ""
	}
	return c.GroupKey
}
func (m *Manager) reconcile(n *node, i int) {
	start := time.Now()
	m.mu.Lock()
	g0 := m.lastGen
	m.mu.Unlock()
	result := ReconcileStatus{LastAt: start, Result: "void"}
	defer func() {
		result.Duration = time.Since(start)
		m.mu.Lock()
		defer m.mu.Unlock()
		if i == 0 {
			n.status.RuleReconcile = result
		} else {
			n.status.WhitelistReconcile = result
		}
		jitter := time.Duration(rand.Float64()*0.2*float64(m.opts.ReconcileInterval)) - m.opts.ReconcileInterval/10
		n.nextReconcile[i] = time.Now().Add(m.opts.ReconcileInterval + jitter)
	}()
	if i == 1 {
		actual, e := n.client.Whitelist(n.ctx)
		if e != nil {
			return
		}
		expected, ok, local := m.svc.SnapshotWhitelist(func() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.lastGen == g0 && !n.wlDirty })
		if local != nil || !ok {
			return
		}
		result.Result = "equal"
		if !equalEntries(whitelistRows(expected), actual.Entries) {
			result.Result = "drift"
			m.mu.Lock()
			n.sides[1].full = true
			n.sides[1].due = time.Time{}
			m.transition(n, 1, "pending", "drift")
			m.mu.Unlock()
			m.syncWhitelist(n)
		}
		return
	}
	actual := map[string]nc.ReadRule{}
	total, pages := 0, 1
	consistent := true
	for page := 1; page <= pages; page++ {
		r, e := n.client.Rules(n.ctx, page, 1000)
		if e != nil {
			return
		}
		result.Pages++
		if page == 1 {
			total = r.Pagination.Total
			pages = r.Pagination.Pages
		}
		if r.Pagination.Total != total || total < 0 || pages < 0 {
			consistent = false
		}
		for _, r := range r.Rules {
			if _, exists := actual[r.ID]; exists {
				consistent = false
			}
			actual[r.ID] = r
		}
	}
	if !consistent || len(actual) != total {
		return
	}
	valid := false
	rows, local := m.svc.SnapshotEnabled(func() { m.mu.Lock(); defer m.mu.Unlock(); valid = m.lastGen == g0 && len(n.dirty) == 0 })
	if local != nil || !valid {
		return
	}
	m.mu.Lock()
	components := closures(n)
	ids := map[string]bool{}
	for id := range n.ids {
		ids[id] = true
	}
	m.mu.Unlock()
	expected := map[string]nc.ReadRule{}
	for _, r := range rows {
		if !ids[r.ID] {
			expected[r.ID] = nc.ReadRule{Rule: nodeRule(r)}
		}
	}
	diff := Diff{}
	for id, want := range expected {
		got, exists := actual[id]
		if exists && equalRule(want, got) {
			continue
		}
		wc, wheld := components[readKey(want.Rule)]
		if !exists {
			if !wheld {
				diff.MissingIDs = append(diff.MissingIDs, id)
			}
			continue
		}
		gc, gheld := components[readKey(got.Rule)]
		if !(wheld && gheld && wc == gc) {
			diff.DifferentIDs = append(diff.DifferentIDs, id)
		}
	}
	for id, got := range actual {
		if _, exists := expected[id]; !exists {
			if _, held := components[readKey(got.Rule)]; !held {
				diff.ExtraIDs = append(diff.ExtraIDs, id)
			}
		}
	}
	sort.Strings(diff.MissingIDs)
	sort.Strings(diff.DifferentIDs)
	sort.Strings(diff.ExtraIDs)
	diff.Missing, diff.Different, diff.Extra = len(diff.MissingIDs), len(diff.DifferentIDs), len(diff.ExtraIDs)
	all := append(append(append([]string{}, diff.MissingIDs...), diff.DifferentIDs...), diff.ExtraIDs...)
	sort.Strings(all)
	signature := strings.Join(all, "\x00")
	diff.MissingIDs = diff.MissingIDs[:min(20, diff.Missing)]
	diff.DifferentIDs = diff.DifferentIDs[:min(20, diff.Different)]
	diff.ExtraIDs = diff.ExtraIDs[:min(20, diff.Extra)]
	result.Diff = diff
	result.Result = "equal"
	m.mu.Lock()
	n.status.RuleStatsCount = len(actual)
	n.status.RuleStatsAt = time.Now()
	s := &n.sides[0]
	if len(all) == 0 {
		s.lastDrift = ""
		s.corrected = false
		s.persistent = false
		if s.status.State == "failed" && s.status.Reason == "drift_persistent" {
			m.transition(n, 0, "normal", "")
		}
		m.mu.Unlock()
		return
	}
	result.Result = "drift"
	if s.corrected && s.lastDrift == signature {
		s.persistent = true
	}
	s.lastDrift = signature
	s.corrected = false
	s.driftWrite = true
	s.full = true
	s.due = time.Time{}
	if s.persistent {
		m.transition(n, 0, "failed", "drift_persistent")
	} else {
		m.transition(n, 0, "pending", "drift")
	}
	m.mu.Unlock()
	m.atomic(n)
}
