package rules

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func c4bRows(t *testing.T, q store.Queryer, tables []string) [][]string {
	t.Helper()
	out := [][]string{}
	for _, table := range tables {
		rows, e := q.Query("SELECT * FROM " + table + " ORDER BY rowid")
		check(t, e == nil, e)
		cols, e := rows.Columns()
		check(t, e == nil, e)
		for rows.Next() {
			v := make([]sql.NullString, len(cols))
			p := make([]any, len(v))
			for i := range v {
				p[i] = &v[i]
			}
			check(t, rows.Scan(p...) == nil, "snapshot scan")
			line := []string{table}
			for _, x := range v {
				line = append(line, fmt.Sprint(x.Valid)+":"+x.String)
			}
			out = append(out, line)
		}
		check(t, rows.Err() == nil, "snapshot rows")
		rows.Close()
	}
	return out
}
func c4bAudits(t *testing.T, s *Service) []store.AuditEvent {
	t.Helper()
	rows, e := store.AuditAfter(s.db.Reader(), "", "", "", 0, 10000)
	check(t, e == nil, e)
	return rows
}
func c4bLatest(t *testing.T, s *Service, n int, action string) store.AuditEvent {
	t.Helper()
	rows := c4bAudits(t, s)
	check(t, len(rows) == n, "audit count", len(rows), n)
	e := rows[len(rows)-1]
	check(t, e.Action == action, "action", e.Action, action)
	return e
}

type c4bQueryCounter struct {
	store.Queryer
	queries int
}

func (q *c4bQueryCounter) Query(s string, args ...any) (*sql.Rows, error) {
	if strings.Contains(s, "FROM audit") {
		q.queries++
	}
	return q.Queryer.Query(s, args...)
}

func TestC4BRules(t *testing.T) {
	t.Run("C4B-noop", func(t *testing.T) {
		s, _ := setup(t)
		a := Actor{Kind: UI, Name: "alice"}
		r, e := s.Create(a, "", draft(80, ""))
		check(t, e == nil && !r.Existing, "existing rule witness")
		before, e := s.Get(r.Rule.ID)
		check(t, e == nil && before.Enabled && before.Comment == "", "initial row")
		n := len(c4bAudits(t, s))
		for _, name := range []string{"empty-patch", "same-comment", "same-enabled"} {
			name := name
			t.Run(name, func(t *testing.T) {
				if name == "same-enabled" {
					e = s.SetEnabled(a, before.ID, true)
				} else {
					patch := RulePatch{}
					if name == "same-comment" {
						patch.Comment = ptr("")
					}
					_, e = s.Update(a, before.ID, patch)
				}
				check(t, e == nil, "successful no-op", name)
				after, e := s.Get(before.ID)
				check(t, e == nil && reflect.DeepEqual(before, after), "all business fields unchanged", name)
				check(t, len(c4bAudits(t, s)) == n, "no-op update audited", name)
			})
		}
		_, e = s.Update(a, before.ID, RulePatch{Comment: ptr("changed")})
		check(t, e == nil, "changed comment")
		c4bLatest(t, s, n+1, "rule.update")
		_, e = s.Update(Actor{Kind: UI, Name: "bob"}, before.ID, RulePatch{})
		check(t, e == nil, "changed operator")
		c4bLatest(t, s, n+2, "rule.update")
	})
	t.Run("C4B-atomic", func(t *testing.T) {
		for _, name := range []string{"Create", "Update", "SetEnabled", "ReleaseClaim", "ForceDelete", "ExpireDue", "CreateWhitelist", "DeleteWhitelist"} {
			name := name
			t.Run(name, func(t *testing.T) {
				s, _ := setup(t)
				a := Actor{Kind: Machine, Name: "a", Source: "198.51.100.7"}
				p := draft(80, "")
				p.ExpiresIn = ptr("1s")
				r, e := s.Create(a, "ref", p)
				check(t, e == nil, e)
				w, e := s.CreateWhitelist(ui, WhitelistInput{DstIP: "192.0.2.4"})
				check(t, e == nil, e)
				tables := []string{"rules", "claims", "logical_id_hw", "whitelist", "audit"}
				before := c4bRows(t, s.db.Reader(), tables)
				n := len(c4bAudits(t, s))
				seen := false
				s.beforeCommit = func(tx *sql.Tx) error {
					var got int
					check(t, tx.QueryRow("SELECT COUNT(*) FROM audit").Scan(&got) == nil, "same transaction query")
					check(t, got == n+1, "audit must be visible before commit", name, got, n)
					seen = true
					return errors.New("test rollback")
				}
				var failure *Error
				switch name {
				case "Create":
					_, failure = s.Create(ui, "", draft(81, ""))
				case "Update":
					_, failure = s.Update(ui, r.Rule.ID, RulePatch{Comment: ptr("changed")})
				case "SetEnabled":
					failure = s.SetEnabled(ui, r.Rule.ID, false)
				case "ReleaseClaim":
					failure = s.ReleaseClaim(a, r.Rule.ID, "ref")
				case "ForceDelete":
					failure = s.ForceDelete(ui, r.Rule.ID)
				case "ExpireDue":
					failure = s.ExpireDue(s.now().Add(2 * time.Second))
				case "CreateWhitelist":
					_, failure = s.CreateWhitelist(ui, WhitelistInput{DstIP: "192.0.2.5"})
				case "DeleteWhitelist":
					failure = s.DeleteWhitelist(ui, w.Whitelist.ID)
				}
				code(t, failure, "internal")
				check(t, seen, "hook executed")
				check(t, reflect.DeepEqual(before, c4bRows(t, s.db.Reader(), tables)), "business and audit rollback", name)
			})
		}
	})
	t.Run("C4B-claim", func(t *testing.T) {
		for _, path := range []string{"direct-renewal", "unique-renewal"} {
			path := path
			t.Run(path, func(t *testing.T) {
				s, _ := setup(t)
				a, b := Actor{Kind: Machine, Name: "a"}, Actor{Kind: Machine, Name: "b"}
				p := draft(80, "")
				p.DstIP, p.ExpiresIn = ptr("192.0.2.10"), ptr("1h")
				var first Result
				seed := func(writer *Service) {
					var e *Error
					first, e = writer.Create(a, "ref-a", p)
					check(t, e == nil && !first.Existing, "a creates one-hour rule")
				}
				hooks := 0
				if path == "direct-renewal" {
					seed(s)
				} else {
					s.beforeInsert = func(proposed store.Rule) error {
						hooks++
						_, err := store.Identity(s.db.Reader(), proposed.GroupKey, proposed.CondKey)
						check(t, errors.Is(err, sql.ErrNoRows), "unique race begins absent")
						writer := New(s.db, &recordingSink{})
						writer.now = s.now
						seed(writer)
						return nil
					}
				}
				q := p
				q.ExpiresIn = ptr("2h")
				second, e := s.Create(b, "ref-b", q)
				check(t, e == nil && second.Existing && second.Rule.ID == first.Rule.ID, "b claims existing rule", path)
				check(t, hooks == map[string]int{"direct-renewal": 0, "unique-renewal": 1}[path], "path witness")
				oldAt, newAt := s.now().Add(time.Hour).Format(timeFormat), s.now().Add(2*time.Hour).Format(timeFormat)
				check(t, *first.Rule.ExpiresAt == oldAt && *second.Rule.ExpiresAt == newAt, "expiry extension witness")
				ev := c4bLatest(t, s, 2, "rule.claim")
				var before, after map[string]any
				check(t, json.Unmarshal(ev.Before, &before) == nil && json.Unmarshal(ev.After, &after) == nil, "claim JSON")
				claimA := map[string]any{"claimant": "cred:a", "claim_ref": "ref-a"}
				claimB := map[string]any{"claimant": "cred:b", "claim_ref": "ref-b"}
				check(t, before["expires_at"] == oldAt && reflect.DeepEqual(before["claimants"], []any{claimA}), "before must precede renewal and claim", path)
				check(t, after["expires_at"] == newAt && reflect.DeepEqual(after["claimants"], []any{claimA, claimB}), "after contains renewal and claim", path)
				check(t, ev.Actor == "cred:b" && ev.Target == "rule:"+first.Rule.ID, "claim actor and target")
			})
		}
		s, _ := setup(t)
		a, b := Actor{Kind: Machine, Name: "a"}, Actor{Kind: Machine, Name: "b"}
		p := draft(80, "")
		p.ExpiresIn = ptr("1h")
		r, e := s.Create(a, "ref", p)
		check(t, e == nil, e)
		c4bLatest(t, s, 1, "rule.create")
		_, e = s.Create(b, "ref", p)
		check(t, e == nil, e)
		c4bLatest(t, s, 2, "rule.claim")
		p.ExpiresIn = ptr("2h")
		renewed, e := s.Create(a, "ref", p)
		check(t, e == nil && *renewed.Rule.ExpiresAt > *r.Rule.ExpiresAt, "renewal witness", e)
		check(t, len(c4bAudits(t, s)) == 2, "pure renewal audited")
		check(t, s.ReleaseClaim(a, r.Rule.ID, "ref") == nil, "first release")
		ev := c4bLatest(t, s, 3, "rule.release")
		check(t, len(ev.After) > 0, "rule retained")
		check(t, s.ReleaseClaim(b, r.Rule.ID, "ref") == nil, "last release")
		ev = c4bLatest(t, s, 4, "rule.release")
		check(t, len(ev.After) == 0 && count(t, s) == 0, "last release deletion")
	})
	t.Run("C4B-cover", func(t *testing.T) {
		s, sink := setup(t)
		r := create(t, s, draft(80, ""))
		n := 1
		for _, p := range []RulePatch{{Comment: ptr("comment")}, {DstPort: ptr(81)}} {
			before := r
			var e *Error
			r, e = s.Update(Actor{Kind: UI, Name: "bob"}, r.ID, p)
			check(t, e == nil, e)
			n++
			ev := c4bLatest(t, s, n, "rule.update")
			var b, a map[string]any
			check(t, json.Unmarshal(ev.Before, &b) == nil && json.Unmarshal(ev.After, &a) == nil, "views")
			if p.Comment != nil {
				check(t, b["comment"] == before.Comment && a["comment"] == "comment", "comment view")
			} else {
				check(t, !reflect.DeepEqual(b["match"], a["match"]), "changed match")
				changes := sink.all()
				move := changes[len(changes)-1].Moves
				check(t, len(move) == 1 && move[0].OldKey == before.GroupKey && move[0].NewKey == r.GroupKey, "move preserved")
			}
		}
		for _, enabled := range []bool{false, true} {
			check(t, s.SetEnabled(ui, r.ID, enabled) == nil, "enabled")
			n++
			ev := c4bLatest(t, s, n, "rule.update")
			var a map[string]any
			check(t, json.Unmarshal(ev.After, &a) == nil && a["enabled"] == enabled, "enabled audit")
		}
		results := s.BatchCreate(ui, "", []RulePatch{draft(82, ""), draft(81, ""), {DstPort: ptr(-1)}})
		check(t, len(results) == 3 && results[0].Error == nil && results[1].Existing && results[2].Error != nil, "batch branches")
		n++
		c4bLatest(t, s, n, "rule.create")
		p := draft(83, "")
		p.ExpiresIn = ptr("1h")
		machineRule, e := s.Create(machine, "ref", p)
		check(t, e == nil, e)
		n++
		_, e = s.Create(Actor{Kind: UI, Name: "alice"}, "", p)
		check(t, e == nil, e)
		n++
		c4bLatest(t, s, n, "rule.claim")
		p.ExpiresIn = ptr("2h")
		renewed, e := s.Create(ui, "", p)
		check(t, e == nil && *renewed.Rule.ExpiresAt > *machineRule.Rule.ExpiresAt, "UI renewal witness")
		check(t, len(c4bAudits(t, s)) == n, "UI renewal audit")
	})
	t.Run("C4B-retention", func(t *testing.T) {
		t.Run("boundary-batch", func(t *testing.T) {
			s, _ := setup(t)
			now := s.now()
			boundary := now.Add(-24 * time.Hour).Format(timeFormat)
			sqlExec(t, s, "UPDATE settings SET value=1 WHERE key='audit_retention_days'")
			tx, e := s.db.Begin()
			check(t, e == nil, e)
			for i := 0; i < 5001; i++ {
				check(t, store.InsertAudit(tx, store.AuditEvent{At: now.Add(-25 * time.Hour).Format(timeFormat), Action: "node.sync"}) == nil, "expired seed")
			}
			check(t, store.InsertAudit(tx, store.AuditEvent{At: boundary, Action: "node.sync"}) == nil, "boundary seed")
			check(t, tx.Commit() == nil, "seed commit")
			check(t, s.ExpireDue(now) == nil, "purge")
			rows := c4bAudits(t, s)
			check(t, len(rows) == 2, "one batch must leave expired witness and boundary", len(rows))
			check(t, rows[1].At == boundary, "inclusive boundary must survive")
			check(t, s.ExpireDue(now) == nil, "second purge")
			rows = c4bAudits(t, s)
			check(t, len(rows) == 1 && rows[0].At == boundary, "strict boundary")
		})
		t.Run("unlocked", func(t *testing.T) {
			s, _ := setup(t)
			done := make(chan *Error, 1)
			timedOut := false
			s.beforePurge = func() {
				go func() { _, e := s.Create(ui, "", draft(90, "")); done <- e }()
				select {
				case e := <-done:
					check(t, e == nil, e)
				case <-time.After(2 * time.Second):
					timedOut = true
				}
			}
			check(t, s.ExpireDue(s.now()) == nil, "expiry")
			if timedOut {
				<-done
				t.Fatal("purge retained rule mutex")
			}
			check(t, count(t, s) == 1, "concurrent create completed")
		})
	})
	t.Run("C4B-export", func(t *testing.T) {
		s, _ := setup(t)
		from, to := "2026-10-10T00:00:00Z", "2026-10-11T00:00:00Z"
		tx, e := s.db.Begin()
		check(t, e == nil, e)
		for i := 0; i < 2500; i++ {
			check(t, store.InsertAudit(tx, store.AuditEvent{At: from, Action: "node.sync"}) == nil, "seed")
		}
		check(t, tx.Commit() == nil, "seed commit")
		q := &c4bQueryCounter{Queryer: s.db.Reader()}
		s.auditReader = q
		count := 0
		witness := false
		err := s.AuditExport(from, to, func(ev store.AuditEvent) error {
			count++
			if count == 1000 {
				at := "2026-10-10T12:00:00Z"
				check(t, at >= from && at < to && at > ev.At, "witness ordering")
				return store.InsertAudit(s.db, store.AuditEvent{At: at, Action: "node.sync", Target: "witness"})
			}
			witness = witness || ev.Target == "witness"
			return nil
		})
		check(t, err == nil && count == 2501 && witness, "page visibility", err, count, witness)
		check(t, q.queries >= 3, "actual store query count", q.queries)
		t.Logf("export_seed=2500 emitted=%d actual_read_queries=%d witness=true", count, q.queries)
	})
	t.Run("C4B-actor", func(t *testing.T) {
		s, _ := setup(t)
		p := draft(91, "")
		p.ExpiresIn = ptr("1s")
		expired, e := s.Create(machine, "expired", p)
		check(t, e == nil, e)
		keeper := create(t, s, draft(92, ""))
		before := c4bRows(t, s.db.Reader(), []string{"claims"})
		check(t, len(before) == 2, "claim seed")
		_, e = s.Create(Actor{Kind: System, Name: "cli"}, "", draft(93, ""))
		code(t, e, "forbidden")
		check(t, reflect.DeepEqual(before, c4bRows(t, s.db.Reader(), []string{"claims"})), "system entered claims")
		check(t, s.ExpireDue(s.now().Add(2*time.Second)) == nil, "expire")
		after := c4bRows(t, s.db.Reader(), []string{"claims"})
		var expected [][]string
		for _, row := range before {
			if row[1] == "true:"+keeper.ID {
				expected = append(expected, row)
			}
		}
		check(t, reflect.DeepEqual(expected, after), "unrelated claims changed")
		ev := c4bLatest(t, s, 3, "rule.expire")
		check(t, ev.Actor == "system:expiry" && ev.Source == "" && ev.Target == "rule:"+expired.Rule.ID, "expiry identity")
	})
}
