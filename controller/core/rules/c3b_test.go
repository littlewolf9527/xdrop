package rules

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type c3bTimedQueryer struct {
	store.Queryer
	query time.Duration
}

func (q *c3bTimedQueryer) Query(sql string, args ...any) (*sql.Rows, error) {
	start := time.Now()
	rows, err := q.Queryer.Query(sql, args...)
	q.query += time.Since(start)
	return rows, err
}
func (q *c3bTimedQueryer) QueryRow(sql string, args ...any) *sql.Row {
	start := time.Now()
	row := q.Queryer.QueryRow(sql, args...)
	q.query += time.Since(start)
	return row
}
func TestC3BProfile(t *testing.T) {
	s, _ := setup(t)
	seedRules(t, s, 49999, 50000)
	q := &c3bTimedQueryer{Queryer: s.db}
	start := time.Now()
	rows, w, err := store.LedgerRows(q, unconditionalKey)
	read := time.Since(start)
	check(t, err == nil, err)
	start = time.Now()
	counts, errs := ledgerCandidates(rows)
	candidate := time.Since(start)
	check(t, len(errs) == 0, errs)
	start = time.Now()
	l := ledgerMaps(rows, counts, w)
	maps := time.Since(start)
	check(t, l.occupancy.Total == 99999 && l.occupancy.Used == (Values{50000, 49999, 0, 0, 0, 49999, 0, 0, 0, 99999}), l.occupancy)
	t.Logf("PROFILE_AFTER rows=%d query=%s decode_iteration=%s candidate=%s map_build=%s total=%s", len(rows), q.query, read-q.query, candidate, maps, read+candidate+maps)
}
func TestC3BStore(t *testing.T) {
	s, _ := setup(t)
	a := create(t, s, RulePatch{SrcIP: ptr("192.0.2.1"), Protocol: ptr("tcp")})
	b := create(t, s, RulePatch{SrcCIDR: ptr("2001:db8::1/128"), Protocol: ptr("tcp"), TTL: ptr("64"), PktLen: ptr("100,200,300"), TCPFlags: ptr("SYN")})
	c := create(t, s, RulePatch{SrcIP: ptr("192.0.2.2"), Protocol: ptr("tcp"), TTL: ptr("40"), Enabled: ptr(false)})
	_, e := s.CreateWhitelist(ui, WhitelistInput{SrcIP: "192.0.2.3"})
	check(t, e == nil, e)
	rows, w, err := store.LedgerRows(s.db, unconditionalKey)
	check(t, err == nil && w == 1 && len(rows) == 3, rows, w, err)
	byID := map[string]store.Rule{}
	for _, r := range rows {
		byID[r.ID] = r
	}
	check(t, reflect.DeepEqual(byID[b.ID], b), "conditional full input", byID[b.ID], b)
	for _, r := range []store.Rule{a, b, c} {
		got := byID[r.ID]
		check(t, got.ID == r.ID && got.Kind == r.Kind && got.GroupKey == r.GroupKey && got.CondKey == r.CondKey && got.SrcCIDR == r.SrcCIDR && got.DstCIDR == r.DstCIDR && got.Enabled == r.Enabled, "narrow identity", got, r)
	}
	full, err := store.List(s.db)
	check(t, err == nil, err)
	narrowLedger, ne := buildLedger(rows, w)
	fullLedger, fe := buildLedger(full, w)
	check(t, len(ne) == 0 && len(fe) == 0 && reflect.DeepEqual(narrowLedger, fullLedger), "narrow/full ledger mismatch", ne, fe)
}

func c3bAudit(t *testing.T, s *Service) {
	t.Helper()
	rows, err := store.List(s.db)
	check(t, err == nil, err)
	ws, err := store.ListWhitelist(s.db)
	check(t, err == nil, err)
	want, es := buildLedger(rows, len(ws))
	got, e := s.Occupancy()
	check(t, e == nil && len(es) == 0, e, es)
	got.LogicalReserve = 0
	check(t, got == want.occupancy, "occupancy rebuild", got, want.occupancy)
	check(t, len(s.ledger.groups) == len(want.groups), "groups")
	for key, g := range s.ledger.groups {
		w, ok := want.groups[key]
		check(t, ok && g.kind == w.kind && g.members == w.members && g.conditional == w.conditional && g.candidates == w.candidates, "group", key, g, w)
		a, b := append([]string{}, g.ids...), append([]string{}, w.ids...)
		sort.Strings(a)
		sort.Strings(b)
		check(t, reflect.DeepEqual(a, b), "group IDs", a, b)
	}
	for i, tree := range s.ledger.trees {
		check(t, len(tree) == len(want.trees[i]), "prefix count", i)
		for raw, p := range tree {
			w, ok := want.trees[i][raw]
			a, b := append([]string{}, p.ids...), append([]string{}, w.ids...)
			sort.Strings(a)
			sort.Strings(b)
			check(t, ok && p.network == w.network && reflect.DeepEqual(a, b), "prefix refs", i, raw, a, b)
		}
	}
}
func c3bDims(t *testing.T) *Service {
	s, _ := setup(t)
	for _, ttl := range []string{"10", "20", "30"} {
		create(t, s, RulePatch{SrcIP: ptr("192.0.2.1"), Protocol: ptr("tcp"), TTL: ptr(ttl)})
	}
	for _, p := range []RulePatch{
		{SrcIP: ptr("192.0.2.2"), Protocol: ptr("tcp"), TTL: ptr("40")},
		{SrcIP: ptr("192.0.2.3"), Protocol: ptr("tcp")},
		{SrcCIDR: ptr("192.0.2.16/32"), DstCIDR: ptr("198.51.100.16/32"), Protocol: ptr("tcp")},
		{SrcCIDR: ptr("2001:db8:1::1/128"), DstCIDR: ptr("2001:db8:2::1/128"), Protocol: ptr("tcp"), TTL: ptr("64")},
		{SrcIP: ptr("192.0.2.4"), Protocol: ptr("tcp"), TTL: ptr("50"), Enabled: ptr(false)},
	} {
		create(t, s, p)
	}
	for _, ip := range []string{"192.0.2.5", "192.0.2.6"} {
		_, e := s.CreateWhitelist(ui, WhitelistInput{SrcIP: ip})
		check(t, e == nil, e)
	}
	return s
}
func TestC3BRules(t *testing.T) {
	t.Run("CAP-dims", func(t *testing.T) {
		s := c3bDims(t)
		o, e := s.Occupancy()
		check(t, e == nil && o.Used == (Values{3, 2, 2, 1, 2, 1, 1, 1, 1, 7}) && o.Total == 8 && o.FullKeys == 0 && o.NearKeys == 1, o, e)
		c, e := Canonicalize(RuleInput{SrcIP: "192.0.2.3", Protocol: "tcp"})
		check(t, e == nil && c.CondKey == `["","","","","","","",""]` && c.CandidateCount == 1, "unconditional candidate premise", c, e)
		c3bAudit(t, s)
	})
	t.Run("CAP-ledger-ops", func(t *testing.T) {
		s, _ := setup(t)
		a := create(t, s, draft(1, ""))
		c3bAudit(t, s)
		duplicate, e := s.Create(ui, "", draft(1, ""))
		check(t, e == nil && duplicate.Existing, e)
		c3bAudit(t, s)
		b := create(t, s, draft(2, "30"))
		c3bAudit(t, s)
		_, e = s.Update(ui, a.ID, RulePatch{DstPort: ptr(2), TTL: ptr("20")})
		check(t, e == nil, e)
		c3bAudit(t, s)
		c := create(t, s, RulePatch{SrcCIDR: ptr("192.0.2.8/32")})
		c3bAudit(t, s)
		_, e = s.Update(ui, c.ID, RulePatch{SrcCIDR: ptr("192.0.2.9/32")})
		check(t, e == nil, e)
		c3bAudit(t, s)
		check(t, s.SetEnabled(ui, a.ID, false) == nil, "disable")
		c3bAudit(t, s)
		check(t, s.SetEnabled(ui, a.ID, true) == nil, "enable")
		c3bAudit(t, s)
		m, e := s.Create(machine, "case", draft(3, ""))
		check(t, e == nil, e)
		c3bAudit(t, s)
		check(t, s.ReleaseClaim(machine, m.Rule.ID, "case") == nil, "release")
		c3bAudit(t, s)
		beforeClaims, e := s.Occupancy()
		check(t, e == nil, e)
		first, e := s.Create(machine, "first", draft(5, ""))
		check(t, e == nil && !first.Existing, e)
		c3bAudit(t, s)
		second, e := s.Create(machine, "second", draft(5, ""))
		check(t, e == nil && second.Existing && second.Rule.ID == first.Rule.ID, "two claims on one rule", e)
		c3bAudit(t, s)
		claimed, e := s.Occupancy()
		check(t, e == nil && claimed.Used[0] == beforeClaims.Used[0]+1 && claimed.Used[9] == beforeClaims.Used[9]+1 && claimed.Total == beforeClaims.Total+1, "new claimed rule occupancy", claimed, beforeClaims, e)
		check(t, s.ReleaseClaim(machine, first.Rule.ID, "first") == nil, "release non-last claim")
		c3bAudit(t, s)
		afterFirst, e := s.Occupancy()
		check(t, e == nil && afterFirst == claimed, "non-last claim must preserve every dimension", afterFirst, claimed, e)
		remaining, e := s.Get(first.Rule.ID)
		check(t, e == nil && remaining.ID == first.Rule.ID, "rule survives non-last claim", e)
		check(t, s.ReleaseClaim(machine, first.Rule.ID, "second") == nil, "release last claim")
		c3bAudit(t, s)
		afterLast, e := s.Occupancy()
		check(t, e == nil && afterLast == beforeClaims, "last claim removes rule occupancy", afterLast, beforeClaims, e)
		_, e = s.Get(first.Rule.ID)
		code(t, e, "not_found")
		check(t, s.ForceDelete(ui, b.ID) == nil, "delete")
		c3bAudit(t, s)
		p := draft(4, "")
		p.ExpiresIn = ptr("1s")
		create(t, s, p)
		c3bAudit(t, s)
		check(t, s.ExpireDue(s.now().Add(2*time.Second)) == nil, "expire")
		c3bAudit(t, s)
		w, e := s.CreateWhitelist(ui, WhitelistInput{SrcIP: "192.0.2.10"})
		check(t, e == nil, e)
		c3bAudit(t, s)
		again, e := s.CreateWhitelist(ui, WhitelistInput{SrcIP: "192.0.2.10"})
		check(t, e == nil && again.Existing, e)
		c3bAudit(t, s)
		check(t, s.DeleteWhitelist(ui, w.Whitelist.ID) == nil, "whitelist delete")
		c3bAudit(t, s)
		check(t, s.DeleteWhitelist(ui, w.Whitelist.ID) == nil, "whitelist idempotence")
		c3bAudit(t, s)
	})
	t.Run("CAP-overlap-deterministic", func(t *testing.T) {
		row := func(id, prefix string) store.Rule {
			c, e := Canonicalize(RuleInput{SrcCIDR: prefix})
			check(t, e == nil, e)
			return store.Rule{ID: id, Kind: c.Kind, GroupKey: c.GroupKey, CondKey: c.CondKey, Match: c.RuleInput, Enabled: true}
		}
		l, errs := buildLedger([]store.Rule{row("existing_2", "192.0.2.2/32"), row("existing_1", "192.0.2.1/32")}, 0)
		check(t, len(errs) == 0, errs)
		s := &Service{ledger: l}
		candidate := row("candidate", "192.0.2.0/24")
		for i := 0; i < 1000; i++ {
			e := s.admit(candidate, store.Rule{})
			check(t, e != nil && e.Code == "cidr_overlap" && e.Message == "nested prefixes in sv4", i, e)
			check(t, reflect.DeepEqual(e.RuleIDs, []string{"existing_1", "candidate"}), "deterministic witness", i, e.RuleIDs)
		}
		t.Log("samples=1000 witness=[existing_1 candidate]")
		c, e := Canonicalize(RuleInput{DstCIDR: "198.51.100.1/32"})
		check(t, e == nil, e)
		l.change(store.Rule{ID: "existing_0", Kind: c.Kind, GroupKey: c.GroupKey, CondKey: c.CondKey, Match: c.RuleInput, Enabled: true}, 1)
		candidate.DstCIDR = "198.51.100.0/24"
		for i := 0; i < 200; i++ {
			e = s.admit(candidate, store.Rule{})
			check(t, e != nil && e.Code == "cidr_overlap" && e.Message == "nested prefixes in sv4", "source direction first", i, e)
			check(t, reflect.DeepEqual(e.RuleIDs, []string{"existing_1", "candidate"}), "source witness despite smaller destination ID", i, e.RuleIDs)
		}
		t.Log("direction=src-first samples=200 witness=[existing_1 candidate] message=nested prefixes in sv4")
	})
	t.Run("CAP-ledger-rollback", func(t *testing.T) {
		s, _ := setup(t)
		a := create(t, s, draft(1, ""))
		m, e := s.Create(machine, "case", draft(2, ""))
		check(t, e == nil, e)
		p := draft(3, "")
		p.ExpiresIn = ptr("1s")
		create(t, s, p)
		w, e := s.CreateWhitelist(ui, WhitelistInput{SrcIP: "192.0.2.4"})
		check(t, e == nil, e)
		before, e := s.Occupancy()
		check(t, e == nil, e)
		s.beforeCommit = func(*sql.Tx) error { return errors.New("injected before commit") }
		for _, op := range []func() *Error{
			func() *Error { _, e := s.Create(ui, "", draft(4, "")); return e },
			func() *Error { _, e := s.Update(ui, a.ID, RulePatch{DstPort: ptr(5)}); return e },
			func() *Error { return s.SetEnabled(ui, a.ID, false) },
			func() *Error { return s.ReleaseClaim(machine, m.Rule.ID, "case") },
			func() *Error { return s.ForceDelete(ui, a.ID) },
			func() *Error { return s.ExpireDue(s.now().Add(2 * time.Second)) },
			func() *Error { _, e := s.CreateWhitelist(ui, WhitelistInput{SrcIP: "192.0.2.5"}); return e },
			func() *Error { return s.DeleteWhitelist(ui, w.Whitelist.ID) },
		} {
			code(t, op(), "internal")
			after, e := s.Occupancy()
			check(t, e == nil && before == after, "rollback ledger", before, after, e)
			c3bAudit(t, s)
		}
	})
	t.Run("CAP-lazy", func(t *testing.T) {
		s, _ := setup(t)
		check(t, s.ledger == nil, "New built ledger")
		seedRules(t, s, 1, 1)
		create(t, s, RulePatch{SrcIP: ptr("192.0.2.99")})
		o, e := s.Occupancy()
		check(t, e == nil && o.Total == 3 && o.Used[9] == 3 && o.Used[5] == 1, o, e)
		c3bAudit(t, s)
	})
	for dim, name := range []string{"blacklist", "cidr_blacklist", "cond", "cidr_cond", "whitelist", "sv4", "dv4", "sv6", "dv6", "logical_state"} {
		dim, name := dim, name
		t.Run("CAP-admit-"+name, func(t *testing.T) {
			reserves := []int{0}
			if dim == 9 {
				reserves = append(reserves, 2)
			}
			for _, reserve := range reserves {
				c3bBoundary(t, dim, name, reserve)
			}
		})
	}
	t.Run("CAP-batch", func(t *testing.T) {
		s, _ := setup(t)
		calls := 0
		s.UseLimits(func() Limits { calls++; l := BuiltinLimits(); l.Values[0] = 3; return l })
		items := []RulePatch{draft(1, ""), draft(2, ""), draft(3, ""), draft(4, ""), draft(5, "")}
		got := s.BatchCreate(ui, "", items)
		check(t, calls == 1, "limits calls", calls)
		for i, r := range got {
			if i < 3 {
				check(t, r.Error == nil && r.Rule.ID != "", "batch accepted", i, r)
			} else {
				code(t, r.Error, "table_full")
				check(t, r.Error.Table == "blacklist", "batch table", r)
			}
		}
		o, e := s.Occupancy()
		check(t, e == nil && o.Used[0] == 3 && o.Total == 3, o, e)
		c3bAudit(t, s)
	})
	t.Run("CAP-prepare", func(t *testing.T) {
		s := c3bDims(t)
		good, err := Prepare(s.db)
		check(t, err == nil && len(good.Violations) == 0, good, err)
		for i, name := range DimensionNames() {
			lim := BuiltinLimits().Values
			lim[i] = good.ledger.occupancy.Used[i] - 1
			report, err := prepare(s.db, lim)
			check(t, err == nil && len(report.Violations) > 0, "missing dimension", name, report, err)
			if i < 5 || i == 9 {
				check(t, len(report.Violations) == 1 && report.Violations[0].ID == "capacity:"+name, "global violation ID", report)
			}
		}
		badRow := create(t, s, RulePatch{SrcCIDR: ptr("198.51.100.9/32")})
		_, err = s.db.Exec("UPDATE rules SET src_cidr=? WHERE id=?", "invalid-prefix", badRow.ID)
		check(t, err == nil, err)
		report, err := Prepare(s.db)
		found := false
		for _, v := range report.Violations {
			found = found || v.ID == badRow.ID
		}
		check(t, err == nil && found, "invalid stored prefix must remain a named violation", report, err)

	})
}
func c3bBoundary(t *testing.T, dim int, name string, reserve int) {
	t.Helper()
	s, _ := setup(t)
	limits := BuiltinLimits()
	limit := 4
	if dim == 9 {
		limit = 8
	}
	limits.Values[dim] = limit
	s.UseLimits(func() Limits { return limits })
	s.UseLogicalReserve(reserve)
	boundary := limit
	if dim == 9 {
		boundary -= reserve
	}
	rows := []store.Rule{}
	whites := []string{}
	patch := func(i int) RulePatch {
		p := RulePatch{SrcIP: ptr("203.0.113.1"), DstPort: ptr(i + 1), Protocol: ptr("tcp")}
		if dim == 1 || dim == 3 || dim >= 5 && dim <= 8 {
			p.SrcIP = nil
			raw := fmt.Sprintf("192.0.2.%d/32", i+1)
			if dim == 7 || dim == 8 {
				raw = fmt.Sprintf("2001:db8::%x/128", i+1)
			}
			if dim == 6 || dim == 8 {
				p.DstCIDR = ptr(raw)
			} else {
				p.SrcCIDR = ptr(raw)
			}
		}
		if dim == 2 || dim == 3 {
			p.TTL = ptr("64")
		}
		return p
	}
	for i := 0; i <= boundary; i++ {
		var e *Error
		if dim == 4 {
			r, err := s.CreateWhitelist(ui, WhitelistInput{SrcIP: fmt.Sprintf("192.0.2.%d", i+1)})
			e = err
			if e == nil {
				whites = append(whites, r.Whitelist.ID)
			}
		} else {
			r, err := s.Create(ui, "", patch(i))
			e = err
			if e == nil {
				check(t, !r.Existing, "fresh keys")
				rows = append(rows, r.Rule)
			}
		}
		if i < boundary {
			check(t, e == nil, "boundary acceptance", name, i+1, boundary, e)
		} else {
			code(t, e, "table_full")
			check(t, e.Table == name && len(e.RuleIDs) == 0, name, e)
		}
	}
	c3bAudit(t, s)
	limits.Values[dim] = 1
	if dim == 4 {
		rows = append(rows, create(t, s, draft(100, "")))
	}
	_, e := s.Update(ui, rows[0].ID, RulePatch{Comment: ptr("neutral")})
	check(t, e == nil, "neutral while overloaded", name, e)
	c3bAudit(t, s)
	if dim == 4 {
		check(t, s.DeleteWhitelist(ui, whites[0]) == nil, "shrink whitelist")
	} else {
		check(t, s.SetEnabled(ui, rows[0].ID, false) == nil, "shrink rule")
	}
	o, e := s.Occupancy()
	check(t, e == nil && o.Used[dim] == boundary-1 && o.Used[dim] > limits.Values[dim], "shrunk but still over", name, o, e)
	c3bAudit(t, s)
	t.Logf("dim=%s node_limit=%d reserve=%d accepted=%d rejected=%d reduced_used=%d smaller_limit=1", name, limit, reserve, boundary, boundary+1, o.Used[dim])
}

func c3bFullRows(t *testing.T) []store.Rule {
	t.Helper()
	rows := make([]store.Rule, 500000)
	for i := range rows {
		in := RuleInput{SrcIP: fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255), Protocol: "tcp", Action: "drop"}
		if i >= 400000 {
			j := i - 400000
			in.SrcIP = ""
			if j < 50000 {
				in.SrcCIDR = fmt.Sprintf("172.16.%d.%d/32", j/256, j%256)
				in.DstCIDR = fmt.Sprintf("192.168.%d.%d/32", j/256, j%256)
			} else {
				j -= 50000
				in.SrcCIDR = fmt.Sprintf("2001:db8:1::%x/128", j+1)
				in.DstCIDR = fmt.Sprintf("2001:db8:2::%x/128", j+1)
			}
		}
		c, e := Canonicalize(in)
		check(t, e == nil, e)
		rows[i] = store.Rule{ID: fmt.Sprintf("rule_%032x", i+1), LogicalID: int64(i + 1), Match: c.RuleInput, Kind: c.Kind, GroupKey: c.GroupKey, CondKey: c.CondKey, Enabled: true, CreatedAt: "2026-10-12T00:00:00Z", UpdatedAt: "2026-10-12T00:00:00Z", CreatedBy: "ui", UpdatedBy: "ui"}
	}
	return rows
}
func TestC3BPerf(t *testing.T) {
	rows := c3bFullRows(t)
	t.Run("PERF-c3b-admit", func(t *testing.T) {
		l, es := buildLedger(rows, 0)
		check(t, len(es) == 0, es)
		check(t, l.occupancy.Used == (Values{400000, 100000, 0, 0, 0, 50000, 50000, 50000, 50000, 500000}), l.occupancy)
		s := &Service{ledger: l, writeLimits: BuiltinLimits(), reserve: DefaultLogicalReserve}
		for _, kind := range []string{"exact", "cidr"} {
			kind := kind
			input := RuleInput{SrcIP: "203.0.113.254", Protocol: "tcp"}
			if kind == "cidr" {
				input.SrcIP = ""
				input.SrcCIDR = "203.0.113.254/32"
			}
			c, e := Canonicalize(input)
			check(t, e == nil, e)
			r := store.Rule{ID: "candidate", Match: c.RuleInput, Kind: c.Kind, GroupKey: c.GroupKey, CondKey: c.CondKey, Enabled: true}
			call := func() time.Duration {
				start := time.Now()
				e := s.admit(r, store.Rule{})
				elapsed := time.Since(start)
				if kind == "exact" {
					check(t, e == nil, e)
				} else {
					code(t, e, "table_full")
					check(t, e.Table == "sv4", e)
				}
				return elapsed
			}
			for i := 0; i < 20; i++ {
				call()
			}
			values := make([]time.Duration, 200)
			for i := range values {
				values[i] = call()
			}
			sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
			p99 := values[(len(values)*99+99)/100-1]
			bound := 1500 * time.Microsecond
			if kind == "cidr" {
				bound = 5 * time.Millisecond
			}
			t.Logf("PERF-c3b-admit kind=%s warmup=20 samples=%d p99=%s limit=%s", kind, len(values), p99, bound)
			check(t, len(values) == 200 && p99 <= bound, "admission overhead", kind, p99, bound)
		}
	})
	t.Run("PERF-c3b-prime", func(t *testing.T) {
		s, _ := setup(t)
		tx, err := s.db.Begin()
		check(t, err == nil, err)
		defer tx.Rollback()
		for _, r := range rows {
			check(t, store.InsertRule(tx, r) == nil, "seed")
		}
		_, err = tx.Exec("UPDATE logical_id_hw SET high_water=500000")
		check(t, err == nil, err)
		check(t, tx.Commit() == nil, "commit")
		start := time.Now()
		report, err := Prepare(s.db)
		s.Prime(report)
		elapsed := time.Since(start)
		check(t, err == nil && len(report.Violations) == 0, err, report.Violations)
		o, e := s.Occupancy()
		check(t, e == nil && o.Total == 500000 && o.Used[9] == 500000, o, e)
		t.Logf("PERF-c3b-prime rows=500000 samples=1 Prepare+Prime=%s ledger_build=%s limit=50s", elapsed, report.ledgerTime)
		check(t, elapsed <= 50*time.Second, "prepare prime time", elapsed)
	})
}
