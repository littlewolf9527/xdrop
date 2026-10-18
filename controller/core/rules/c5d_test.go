package rules

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestC5DRevision(t *testing.T) {
	for _, mode := range []string{"create-renew", "batch", "withWrite", "zero-failure-audit-claims"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			s, sink := setup(t)
			seq, gen := func() (uint64, uint64) { return s.Revision() }()
			check(t, seq == 0 && gen == 0, "initial revision")
			p := draft(80, "")
			p.ExpiresIn = ptr("1h")
			r, e := s.Create(machine, "one", p)
			check(t, e == nil, "seed")
			want := uint64(1)
			switch mode {
			case "create-renew":
				p.ExpiresIn = ptr("2h")
				_, e = s.Create(machine, "one", p)
				check(t, e == nil && len(sink.all()) == 1, "renew must not notify")
				want = 2
			case "batch":
				p.ExpiresIn = ptr("2h")
				out := s.BatchCreate(machine, "one", []RulePatch{p, {DstIP: ptr("invalid")}, draft(81, "")})
				check(t, out[0].Error == nil && out[1].Error != nil && out[2].Error == nil, "partial batch")
				want = 2
			case "withWrite":
				check(t, s.SetEnabled(ui, r.Rule.ID, false) == nil, "disable")
				w, err := s.CreateWhitelist(ui, WhitelistInput{DstIP: "192.0.2.8"})
				check(t, err == nil && s.DeleteWhitelist(ui, w.Whitelist.ID) == nil, "whitelist changes")
				check(t, s.ForceDelete(ui, r.Rule.ID) == nil, "delete")
				want = 5
			case "zero-failure-audit-claims":
				check(t, s.Record(ui, "node.sync", "node:test") == nil, "pure audit")
				check(t, s.ExpireDue(s.now().Add(time.Minute)) == nil, "empty expiry")
				check(t, s.ForceDelete(ui, "absent") == nil && s.DeleteWhitelist(ui, "absent") == nil, "zero rows")
				_, e = s.Create(Actor{Kind: Machine, Name: "B"}, "two", p)
				check(t, e == nil && s.ReleaseClaim(machine, r.Rule.ID, "one") == nil, "claim-only")
				s.beforeCommit = func(*sql.Tx) error { return errors.New("TEST_ONLY_COMMIT_FAILURE") }
				_, e = s.Create(machine, "", draft(82, ""))
				check(t, e != nil && s.SetEnabled(ui, r.Rule.ID, false) != nil, "failed commits")
				out := s.BatchCreate(machine, "", []RulePatch{draft(83, "")})
				check(t, out[0].Error != nil, "failed batch")
				s.beforeCommit = nil
				seq, _ = s.Revision()
				check(t, seq == 1, "zero/failure/audit/claims advanced seq", seq)
				check(t, s.ReleaseClaim(Actor{Kind: Machine, Name: "B"}, r.Rule.ID, "two") == nil, "last release")
				want = 2
			}
			seq, gen = s.Revision()
			check(t, seq == want, "commit count", seq, want)
			if mode == "create-renew" {
				check(t, gen == 1, "renew gen")
			}
			t.Logf("commit_seq=%d gen=%d sink_calls=%d", seq, gen, len(sink.all()))
		})
	}
}
