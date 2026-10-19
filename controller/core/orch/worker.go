package orch

import (
	"encoding/json"
	"log"
	"sort"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
)

func (m *Manager) failure(n *node, i int, reason string, e *nc.CallError) {
	s := &n.sides[i]
	if e != nil {
		s.status.LastError = LastError{e.Route, e.HTTPStatus, e.Code, e.Message}
	}
	s.status.ConsecutiveFailures++
	delay := m.opts.CheckInterval
	state := "failed"
	if reason == "outcome_unknown" || reason == "capacity_retry" || reason == "probe_unreachable" || reason == "local_read_failed" {
		if s.status.ConsecutiveFailures < 3 {
			state = "pending"
			delay = m.opts.RetryBase * time.Duration(1<<uint(s.status.ConsecutiveFailures-1))
			delay = min(delay, m.opts.RetryMax)
		} else {
			reason = "retry_exhausted"
		}
	}
	s.due = time.Now().Add(delay)
	m.transition(n, i, state, reason)
}
func (m *Manager) success(n *node, i int, gen uint64, full bool) {
	s := &n.sides[i]
	s.status.ConfirmedGen = gen
	s.status.ConsecutiveFailures = 0
	s.status.LastError = LastError{}
	s.due = time.Time{}
	if full {
		s.full = false
		s.fullAt = time.Now()
		s.badHealth = false
	}
	if i == 0 && s.persistent && s.driftWrite {
		m.transition(n, i, "failed", "drift_persistent")
		return
	}
	s.persistent = false
	if (i == 0 && len(n.dirty) > 0) || (i == 1 && n.wlDirty) || s.full {
		m.transition(n, i, "pending", "changes")
	} else {
		m.transition(n, i, "normal", "")
	}
}
func (m *Manager) probe(n *node, i int) bool {
	result, e := n.client.Probe(n.ctx)
	var name string
	mismatch := false
	defer func() {
		if mismatch {
			log.Printf("node incompatible; node=%q reason=protocol_mismatch", name)
		}
	}()
	m.mu.Lock()
	defer m.mu.Unlock()
	if result == nc.OK {
		return true
	}
	if result == nc.Incompatible {
		if !n.status.Incompatible {
			name, mismatch = n.status.Name, true
			m.record(n, Event{time.Now(), n.status.Name, "incompatible", "false", "true", "protocol_mismatch"})
		}
		n.status.Incompatible = true
		n.probeAt = time.Now().Add(m.opts.CheckInterval)
	} else {
		m.failure(n, i, "probe_unreachable", e)
	}
	return false
}
func (m *Manager) recoverVersion(n *node) {
	result, _ := n.client.Probe(n.ctx)
	var name string
	recovered := false
	defer func() {
		if recovered {
			log.Printf("node compatible; node=%q reason=version_recovered", name)
		}
	}()
	m.mu.Lock()
	defer m.mu.Unlock()
	n.probeAt = time.Now().Add(m.opts.CheckInterval)
	if result != nc.OK {
		return
	}
	n.status.Incompatible = false
	name, recovered = n.status.Name, true
	m.record(n, Event{time.Now(), n.status.Name, "incompatible", "true", "false", "version_recovered"})
	for i := 0; i < 2; i++ {
		n.sides[i].full = true
		n.sides[i].due = time.Time{}
		m.transition(n, i, "pending", "version_recovered")
	}
}

func (m *Manager) worker(n *node) {
	for {
		m.mu.Lock()
		now := time.Now()
		next := now.Add(m.opts.CheckInterval)
		if n.status.Incompatible {
			next = n.probeAt
		} else if n.status.Online && !n.overloaded {
			for i := 0; i < 2; i++ {
				work := n.sides[i].full || (i == 0 && len(n.dirty) > 0) || (i == 1 && n.wlDirty)
				if work && n.sides[i].due.Before(next) {
					next = n.sides[i].due
				}
				if m.eligible(n, i) && n.nextReconcile[i].Before(next) {
					next = n.nextReconcile[i]
				}
			}
		}
		m.mu.Unlock()
		timer := time.NewTimer(max(0, time.Until(next)))
		woken := false
		select {
		case <-n.ctx.Done():
			timer.Stop()
			return
		case <-n.wake:
			woken = true
		case <-timer.C:
		}
		timer.Stop()
		m.mu.Lock()
		merge := woken && len(n.dirty) > 0 && !n.sides[0].full && !n.sides[1].full && !n.wlDirty
		m.mu.Unlock()
		if merge {
			timer = time.NewTimer(m.opts.MergeWindow)
			tick := timer.C
			if m.opts.mergeTick != nil {
				tick = m.opts.mergeTick(m.opts.MergeWindow)
			}
			select {
			case <-n.ctx.Done():
				timer.Stop()
				return
			case <-tick:
			}
			timer.Stop()
			// Consume coalesced notifications; any subsequent write re-wakes us.
			select {
			case <-n.wake:
			default:
			}
		}
		m.mu.Lock()
		online, incompatible := n.status.Online, n.status.Incompatible
		if !online || incompatible {
			// Offline or incompatible nodes recover through a full sync; only the worker clears queued deltas.
			n.dirty = map[string]bool{}
			n.pending = nil
		}
		probeDue := !time.Now().Before(n.probeAt)
		m.mu.Unlock()
		if incompatible && probeDue && n.client != nil {
			m.recoverVersion(n)
		}
		m.checkOverload(n)
		m.mu.Lock()
		incompatible = n.status.Incompatible
		m.mu.Unlock()
		if online && !incompatible && n.client != nil {
			for _, i := range []int{1, 0} {
				m.mu.Lock()
				ready := !time.Now().Before(n.sides[i].due) && !n.status.Incompatible && n.status.Online && !n.overloaded
				full := n.sides[i].full
				dirty := len(n.dirty) > 0
				if i == 1 {
					dirty = n.wlDirty
				}
				if i == 0 && dirty && !full && !commitReady(n) {
					n.sides[0].full = true
					n.sides[0].driftWrite = false
					full = true
					m.transition(n, 0, "pending", "node_restarted")
				}
				m.mu.Unlock()
				if ready && (full || dirty) {
					if i == 1 {
						m.syncWhitelist(n)
					} else if full {
						m.atomic(n)
					} else {
						m.commit(n)
					}
				}
			}
			for i := 0; i < 2; i++ {
				m.mu.Lock()
				due := m.eligible(n, i) && !time.Now().Before(n.nextReconcile[i])
				m.mu.Unlock()
				if due {
					m.reconcile(n, i)
				}
			}
		}
		m.dispatch()
		if m.opts.roundDone != nil {
			m.opts.roundDone(n.status.Name)
		}
	}
}

// closures maps every active-move partner of a rejected key to its component.
func closures(n *node) map[string]string {
	adj := map[string][]string{}
	for _, move := range n.moves {
		adj[move.OldKey] = append(adj[move.OldKey], move.NewKey)
		adj[move.NewKey] = append(adj[move.NewKey], move.OldKey)
	}
	out := map[string]string{}
	for key := range n.blocked {
		if _, ok := out[key]; ok {
			continue
		}
		queue := []string{key}
		out[key] = key
		for len(queue) > 0 {
			k := queue[0]
			queue = queue[1:]
			for _, p := range adj[k] {
				if _, ok := out[p]; !ok {
					out[p] = key
					queue = append(queue, p)
				}
			}
		}
	}
	return out
}
func (m *Manager) drain(n *node) []string {
	for _, move := range n.pending {
		n.moves = append(n.moves, movement{move, m.lastGen})
	}
	n.pending = nil
	n.drainGen = m.lastGen
	keys := n.dirty
	n.dirty = map[string]bool{}
	components := closures(n)
	selected := map[string]bool{}
	for key := range keys {
		if c, ok := components[key]; ok {
			selected[c] = true
		}
	}
	for key, c := range components {
		if selected[c] {
			keys[key] = true
		}
	}
	out := []string{}
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
func restore(n *node, keys []string) {
	for _, key := range keys {
		n.dirty[key] = true
	}
}

func (m *Manager) atomic(n *node) {
	if !m.probe(n, 0) {
		return
	}
	m.snapMu.Lock()
	m.mu.Lock()
	gen := m.lastGen
	keys := []string{}
	var local error
	if m.snapshot.valid && gen == m.snapshot.gen {
		keys = m.drain(n)
		m.mu.Unlock()
	} else {
		m.mu.Unlock()
		rows, e := m.svc.SnapshotEnabled(func() { m.mu.Lock(); keys = m.drain(n); gen = n.drainGen; m.mu.Unlock() })
		if e != nil {
			local = e
		} else {
			payload := struct {
				Rules []nc.Rule `json:"rules"`
			}{Rules: []nc.Rule{}}
			ids := map[string]bool{}
			for _, r := range rows {
				payload.Rules = append(payload.Rules, nodeRule(r))
				ids[r.ID] = true
			}
			body, err := json.Marshal(payload)
			local = err
			if err == nil {
				m.snapshot.valid = true
				m.snapshot.gen = gen
				m.snapshot.body = body
				m.snapshot.n = len(rows)
				m.snapshot.ids = ids
			}
		}
	}
	body, count, ids := m.snapshot.body, m.snapshot.n, m.snapshot.ids
	m.snapMu.Unlock()
	if local != nil {
		m.mu.Lock()
		restore(n, keys)
		m.failure(n, 0, "local_read_failed", nil)
		m.mu.Unlock()
		return
	}
	r, e := n.client.Atomic(n.ctx, body)
	details := make([]struct {
		group   string
		removed bool
	}, len(r.Rejected))
	if e == nil {
		for i, rejected := range r.Rejected {
			if !ids[rejected.ID] {
				continue
			}
			row, err := m.svc.Get(rejected.ID)
			if err == nil {
				details[i].removed = !row.Enabled
				if row.Enabled {
					details[i].group = row.GroupKey
				}
			} else if err.Code == "not_found" {
				details[i].removed = true
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e != nil {
		restore(n, keys)
		m.classify(n, 0, e, true)
		return
	}
	ok := r.Success && r.Added == r.Rules+r.CIDRRules && r.Failed == len(r.Rejected) && r.Added+r.Failed == count
	for _, rejected := range r.Rejected {
		ok = ok && ids[rejected.ID]
	}
	if !ok {
		m.failure(n, 0, "response_invalid", nil)
		return
	}
	n.blocked = map[string]Rejected{}
	n.ids = map[string]idRejection{}
	for i, r := range r.Rejected {
		if !details[i].removed {
			n.ids[r.ID] = idRejection{Rejected: Rejected{ID: r.ID, Error: r.Reason}, group: details[i].group}
		}
	}
	retained := n.moves[:0]
	for _, move := range n.moves {
		if move.gen > gen {
			retained = append(retained, move)
		}
	}
	n.moves = retained
	if n.sides[0].driftWrite {
		n.sides[0].corrected = true
	}
	m.success(n, 0, gen, true)
}

func (m *Manager) syncWhitelist(n *node) {
	if !m.probe(n, 1) {
		return
	}
	var gen uint64
	rows, ok, local := m.svc.SnapshotWhitelist(func() bool { m.mu.Lock(); defer m.mu.Unlock(); gen = m.lastGen; n.wlDirty = false; return true })
	if local != nil || !ok {
		m.mu.Lock()
		n.wlDirty = true
		m.failure(n, 1, "local_read_failed", nil)
		m.mu.Unlock()
		return
	}
	body, err := json.Marshal(struct {
		Entries []nc.Entry `json:"entries"`
	}{whitelistRows(rows)})
	if err != nil {
		m.mu.Lock()
		n.wlDirty = true
		m.failure(n, 1, "local_read_failed", nil)
		m.mu.Unlock()
		return
	}
	r, e := n.client.SyncWhitelist(n.ctx, body)
	m.mu.Lock()
	defer m.mu.Unlock()
	if e != nil {
		n.wlDirty = true
		m.classify(n, 1, e, true)
		return
	}
	if r.Total != len(rows) {
		n.sides[1].full = true
		m.failure(n, 1, "response_invalid", nil)
		return
	}
	m.success(n, 1, gen, true)
}

func (m *Manager) classify(n *node, i int, e *nc.CallError, full bool) {
	reason := "outcome_unknown"
	if e.HTTPStatus >= 300 && e.HTTPStatus < 500 {
		reason = "request_malformed"
	}
	if e.Kind == "status" && e.Body != nil {
		if e.HTTPStatus == 409 && e.Code == "table_full" {
			reason = "capacity_retry"
		} else if i == 1 && e.HTTPStatus == 400 {
			reason = "node_rejected_batch"
		} else if full && i == 0 && e.HTTPStatus == 409 {
			switch e.Code {
			case "duplicate_id", "duplicate_logical_id", "duplicate_key", "cidr_overlap", "condition_group_invalid":
				reason = "node_rejected_batch"
			}
		}
	}
	if reason != "capacity_retry" || full {
		n.sides[i].full = true
	}
	m.failure(n, i, reason, e)
	if !full && reason == "capacity_retry" && n.sides[i].status.ConsecutiveFailures >= 3 {
		n.sides[i].full = true
	}
}

// Caller holds Manager.mu; health observed during Probe must gate the POST too.
func commitReady(n *node) bool {
	s := &n.sides[0]
	return !s.full && !s.fullAt.IsZero() && !s.badHealth
}

func (m *Manager) commit(n *node) {
	if !m.probe(n, 0) {
		return
	}
	var gen uint64
	keys, rows, local := m.svc.SnapshotGroups(func() []string { m.mu.Lock(); defer m.mu.Unlock(); keys := m.drain(n); gen = n.drainGen; return keys })
	if local != nil {
		m.mu.Lock()
		restore(n, keys)
		m.failure(n, 0, "local_read_failed", nil)
		m.mu.Unlock()
		return
	}
	groups := map[string]nc.Group{}
	for _, key := range keys {
		groups[key] = group(key, rows[key])
	}
	m.mu.Lock()
	components := closures(n)
	changed := map[string]bool{}
	for key, g := range groups {
		if c, ok := components[key]; ok {
			if old, exists := n.blocked[key]; !exists || old.Fingerprint != fingerprint(g) {
				changed[c] = true
			}
		}
	}
	for key := range groups {
		if c, ok := components[key]; ok && !changed[c] {
			delete(groups, key)
		}
	}
	m.mu.Unlock()
	for attempt := 0; len(groups) > 0 && attempt < 8; attempt++ {
		ordered := []string{}
		for key := range groups {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		if attempt > 0 && !m.probe(n, 0) {
			m.mu.Lock()
			restore(n, ordered)
			m.mu.Unlock()
			return
		}
		payload := struct {
			Groups []nc.Group `json:"groups"`
		}{Groups: []nc.Group{}}
		for _, key := range ordered {
			payload.Groups = append(payload.Groups, groups[key])
		}
		body, err := json.Marshal(payload)
		if err != nil {
			m.mu.Lock()
			restore(n, ordered)
			m.failure(n, 0, "local_read_failed", nil)
			m.mu.Unlock()
			return
		}
		m.mu.Lock()
		ready := commitReady(n)
		if !ready {
			restore(n, keys)
			n.sides[0].full = true
			n.sides[0].driftWrite = false
			m.transition(n, 0, "pending", "node_restarted")
		}
		m.mu.Unlock()
		if !ready {
			m.atomic(n)
			return
		}
		r, e := n.client.Commit(n.ctx, body, len(ordered))
		m.mu.Lock()
		if e == nil {
			ok := (r.Code == "committed" || r.Code == "unchanged") && len(r.Groups) == len(ordered)
			for i, g := range r.Groups {
				ok = ok && g.Index == i
			}
			if !ok {
				n.sides[0].full = true
				m.failure(n, 0, "response_invalid", nil)
				m.mu.Unlock()
				return
			}
			for _, key := range ordered {
				delete(n.blocked, key)
				for _, rule := range groups[key].Rules {
					delete(n.ids, rule.ID)
				}
			}
			for id, rejection := range n.ids {
				if rejection.group != "" {
					i := sort.SearchStrings(ordered, rejection.group)
					if i < len(ordered) && ordered[i] == rejection.group {
						delete(n.ids, id)
					}
				}
			}
			retained := n.moves[:0]
			for _, move := range n.moves {
				_, old := groups[move.OldKey]
				_, new := groups[move.NewKey]
				if !old || !new {
					retained = append(retained, move)
				}
			}
			n.moves = retained
			n.sides[0].driftWrite = false
			m.success(n, 0, gen, false)
			m.mu.Unlock()
			return
		}
		if e.Kind == "status" && ((e.HTTPStatus == 400 && e.Code == "validation_rejected") || (e.HTTPStatus == 409 && e.Code == "condition_capacity")) {
			list, _ := e.Body["groups"].([]any)
			if len(list) > 0 {
				item, _ := list[0].(map[string]any)
				index, parseErr := json.Number(numberString(item["index"])).Int64()
				if parseErr == nil && index >= 0 && index < int64(len(ordered)) {
					key := ordered[index]
					g := groups[key]
					rejection := Rejected{Key: key, Fingerprint: fingerprint(g), Code: e.Code, Error: e.Message}
					if ids, ok := item["rule_ids"].([]any); ok {
						for _, id := range ids {
							if id, ok := id.(string); ok {
								rejection.RuleIDs = append(rejection.RuleIDs, id)
							}
						}
					}
					n.blocked[key] = rejection
					components := closures(n)
					component := components[key]
					for partner, c := range components {
						if c == component {
							if g, ok := groups[partner]; ok {
								r := rejection
								r.Key = partner
								r.Fingerprint = fingerprint(g)
								n.blocked[partner] = r
								delete(groups, partner)
							}
						}
					}
					m.mu.Unlock()
					continue
				}
			}
		}
		if e.Kind == "status" && e.HTTPStatus == 409 {
			switch e.Code {
			case "cidr_overlap", "group_undeclared", "content_different", "duplicate_logical_id", "duplicate_id":
				restore(n, ordered)
				n.sides[0].full = true
				n.sides[0].driftWrite = false
				m.transition(n, 0, "pending", "incremental_mismatch")
				m.mu.Unlock()
				m.atomic(n)
				return
			}
		}
		restore(n, ordered)
		m.classify(n, 0, e, false)
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(groups) > 0 {
		for key := range groups {
			n.dirty[key] = true
		}
		m.transition(n, 0, "pending", "changes")
		wake(n)
	} else {
		m.withheld(n)
	}
}

// No write succeeded: only settle scheduling state, never acknowledge or clear.
func (m *Manager) withheld(n *node) {
	if len(n.dirty) > 0 || n.sides[0].full {
		m.transition(n, 0, "pending", "changes")
	} else if n.sides[0].persistent {
		m.transition(n, 0, "failed", "drift_persistent")
	} else {
		m.transition(n, 0, "normal", "")
	}
}
func numberString(v any) string {
	if n, ok := v.(json.Number); ok {
		return string(n)
	}
	return ""
}
