package rules

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

// TD-164: a claim keeps its own expiry; releasing a non-final claim restores
// the latest expiry among the remaining claims (permanent wins).

func td164Patch(expires string) RulePatch {
	p := draft(80, "")
	p.DstIP = ptr("192.0.2.164")
	if expires != "" {
		p.ExpiresIn = ptr(expires)
	}
	return p
}
func td164At(s *Service, d time.Duration) *string {
	v := s.now().Add(d).UTC().Format(timeFormat)
	return &v
}
func td164Expiry(t *testing.T, s *Service, id string) (*string, bool) {
	t.Helper()
	r, err := store.Get(s.db, id)
	if err == sql.ErrNoRows {
		return nil, false
	}
	check(t, err == nil, err)
	return r.ExpiresAt, true
}
func td164Same(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}
func td164Show(v *string) string {
	if v == nil {
		return "permanent"
	}
	return *v
}
func td164Want(t *testing.T, s *Service, id string, want *string, label string) {
	t.Helper()
	got, ok := td164Expiry(t, s, id)
	check(t, ok, label, "rule missing")
	check(t, td164Same(got, want), label, "got", td164Show(got), "want", td164Show(want))
}
func td164Join(t *testing.T, s *Service, a Actor, ref, expires string) Result {
	t.Helper()
	r, e := s.Create(a, ref, td164Patch(expires))
	check(t, e == nil, e)
	return r
}

var (
	td164A = Actor{Kind: Machine, Name: "a"}
	td164B = Actor{Kind: Machine, Name: "b"}
	td164C = Actor{Kind: Machine, Name: "c"}
	td164D = Actor{Kind: Machine, Name: "d"}
)

func TestTD164Behavior(t *testing.T) {
	t.Run("B1-finite-then-permanent-release-restores", func(t *testing.T) {
		s, _ := setup(t)
		first := td164Join(t, s, td164A, "ref-a", "1h")
		check(t, !first.Existing, "a creates")
		second := td164Join(t, s, td164B, "ref-b", "")
		check(t, second.Existing && second.Rule.ID == first.Rule.ID, "b joins")
		td164Want(t, s, first.Rule.ID, nil, "joined permanent")
		check(t, s.ReleaseClaim(td164B, first.Rule.ID, "ref-b") == nil, "b releases")
		td164Want(t, s, first.Rule.ID, td164At(s, time.Hour), "B1 restored")
	})
	t.Run("B2-permanent-then-finite-release-restores", func(t *testing.T) {
		s, _ := setup(t)
		first := td164Join(t, s, td164B, "ref-b", "")
		second := td164Join(t, s, td164A, "ref-a", "1h")
		check(t, second.Existing, "a joins")
		td164Want(t, s, first.Rule.ID, nil, "still permanent")
		check(t, s.ReleaseClaim(td164B, first.Rule.ID, "ref-b") == nil, "b releases")
		td164Want(t, s, first.Rule.ID, td164At(s, time.Hour), "B2 restored")
	})
	t.Run("B3-latest-remaining-wins", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "1h").Rule.ID
		td164Join(t, s, td164C, "ref-c", "2h")
		td164Join(t, s, td164B, "ref-b", "")
		td164Want(t, s, id, nil, "permanent while b holds")
		check(t, s.ReleaseClaim(td164B, id, "ref-b") == nil, "b releases")
		td164Want(t, s, id, td164At(s, 2*time.Hour), "B3 latest remaining")
		check(t, s.ReleaseClaim(td164C, id, "ref-c") == nil, "c releases")
		td164Want(t, s, id, td164At(s, time.Hour), "B3 next remaining")
		check(t, s.ReleaseClaim(td164A, id, "ref-a") == nil, "a releases")
		_, ok := td164Expiry(t, s, id)
		check(t, !ok && count(t, s) == 0, "final release deletes")
	})
	t.Run("B5-ui-finite-machine-permanent", func(t *testing.T) {
		s, _ := setup(t)
		r, e := s.Create(Actor{Kind: UI, Name: "operator"}, "", td164Patch("1h"))
		check(t, e == nil && !r.Existing, e)
		td164Join(t, s, td164B, "xsight-ref", "")
		td164Want(t, s, r.Rule.ID, nil, "joined permanent")
		check(t, s.ReleaseClaim(td164B, r.Rule.ID, "xsight-ref") == nil, "machine releases")
		td164Want(t, s, r.Rule.ID, td164At(s, time.Hour), "B5 restored")
	})
	t.Run("B6-same-claim-renewal-keeps-later", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "3h").Rule.ID
		td164Join(t, s, td164B, "ref-b", "")
		again := td164Join(t, s, td164A, "ref-a", "1h")
		check(t, again.Existing, "same triple again")
		td164Want(t, s, id, nil, "still permanent")
		check(t, s.ReleaseClaim(td164B, id, "ref-b") == nil, "b releases")
		td164Want(t, s, id, td164At(s, 3*time.Hour), "B6 later of own claims")
	})
	t.Run("B7-seq-and-audit", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "1h").Rule.ID
		td164Join(t, s, td164B, "ref-b", "")
		n := len(c4bAudits(t, s))
		seq, gen := s.Revision()
		check(t, s.ReleaseClaim(td164B, id, "ref-b") == nil, "b releases")
		seq2, gen2 := s.Revision()
		check(t, seq2 == seq+1 && gen2 == gen, "B7 seq advances once, gen unchanged", seq, seq2, gen, gen2)
		ev := c4bLatest(t, s, n+1, "rule.release")
		var before, after map[string]any
		check(t, json.Unmarshal(ev.Before, &before) == nil && json.Unmarshal(ev.After, &after) == nil, "release JSON")
		check(t, before["expires_at"] == nil && after["expires_at"] == *td164At(s, time.Hour), "B7 audit expiry", before["expires_at"], after["expires_at"])
	})
	t.Run("B10-patch-without-expiry-keeps-claims", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "1h").Rule.ID
		td164Join(t, s, td164B, "ref-b", "")
		_, e := s.Update(Actor{Kind: UI, Name: "operator"}, id, RulePatch{Comment: ptr("note")})
		check(t, e == nil, e)
		td164Want(t, s, id, nil, "patch keeps permanent")
		check(t, s.ReleaseClaim(td164B, id, "ref-b") == nil, "b releases")
		td164Want(t, s, id, td164At(s, time.Hour), "B10 claim expiry survives comment patch")
	})
}

// td164Model is the reference: rule expiry = later over the claims.
type td164Model struct {
	exists bool
	rule   *string
	claims map[string]*string
}

func td164Later(a, b *string) *string {
	if a == nil || b == nil {
		return nil
	}
	if *b > *a {
		return b
	}
	return a
}
func (m *td164Model) recompute() {
	first := true
	for _, v := range m.claims {
		if first {
			m.rule, first = v, false
			continue
		}
		m.rule = td164Later(m.rule, v)
	}
}

func TestTD164InvariantProperty(t *testing.T) {
	s, _ := setup(t)
	rng := rand.New(rand.NewSource(164))
	machines := []Actor{td164A, td164B, td164C}
	refs := []string{"r0", "r1"}
	uis := []Actor{{Kind: UI, Name: "u0"}, {Kind: UI, Name: "u1"}}
	durations := []string{"", "1h", "2h", "3h"}
	stamp := func(d string) *string {
		if d == "" {
			return nil
		}
		v, err := time.ParseDuration(d)
		check(t, err == nil, err)
		return td164At(s, v)
	}
	m := &td164Model{claims: map[string]*string{}}
	id := ""
	for step := 0; step < 2400; step++ {
		label := ""
		switch op := rng.Intn(10); {
		case op < 4:
			var a Actor
			ref := ""
			if rng.Intn(4) == 0 {
				a = uis[rng.Intn(len(uis))]
			} else {
				a, ref = machines[rng.Intn(len(machines))], refs[rng.Intn(len(refs))]
			}
			d := durations[rng.Intn(len(durations))]
			label = fmt.Sprintf("join %s/%s %q", a, ref, d)
			r := td164Join(t, s, a, ref, d)
			key := a.String() + "\x00" + claimRefFor(a, ref)
			if !m.exists {
				m.exists, m.rule, m.claims = true, stamp(d), map[string]*string{key: stamp(d)}
				id = r.Rule.ID
			} else {
				m.rule = td164Later(m.rule, stamp(d))
				if old, ok := m.claims[key]; ok {
					m.claims[key] = td164Later(old, stamp(d))
				} else {
					m.claims[key] = stamp(d)
				}
			}
		case op < 5:
			if !m.exists {
				continue
			}
			d := durations[rng.Intn(len(durations))]
			label = fmt.Sprintf("patch expiry %q", d)
			_, e := s.Update(uis[0], id, RulePatch{ExpiresIn: ptr(d)})
			check(t, e == nil, e)
			m.rule = stamp(d)
			for k := range m.claims {
				m.claims[k] = stamp(d)
			}
		case op < 6:
			if !m.exists {
				continue
			}
			label = "patch comment"
			_, e := s.Update(uis[1], id, RulePatch{Comment: ptr(fmt.Sprint("c", step))})
			check(t, e == nil, e)
		case op < 9:
			if !m.exists {
				continue
			}
			a, ref := machines[rng.Intn(len(machines))], refs[rng.Intn(len(refs))]
			label = fmt.Sprintf("release %s/%s", a, ref)
			check(t, s.ReleaseClaim(a, id, ref) == nil, label)
			key := a.String() + "\x00" + ref
			if _, ok := m.claims[key]; ok {
				delete(m.claims, key)
				if len(m.claims) == 0 {
					m.exists, m.rule = false, nil
				} else {
					m.recompute()
				}
			}
		default:
			if !m.exists || rng.Intn(4) != 0 {
				continue
			}
			label = "force delete"
			check(t, s.ForceDelete(uis[0], id) == nil, label)
			m.exists, m.rule, m.claims = false, nil, map[string]*string{}
		}
		got, ok := td164Expiry(t, s, id)
		if id == "" {
			continue
		}
		check(t, ok == m.exists, "B8 existence", step, label)
		if ok {
			check(t, td164Same(got, m.rule), "B8 expiry", step, label, "got", td164Show(got), "model", td164Show(m.rule))
		}
	}
}

func TestTD164Guards(t *testing.T) {
	t.Run("G1-existing-matrix", func(t *testing.T) {
		olds, proposals := []string{"", "1h", "2h"}, []string{"", "1h", "2h"}
		for _, old := range olds {
			for _, proposed := range proposals {
				s, _ := setup(t)
				first := td164Join(t, s, td164A, "ref-a", old)
				seq, gen := s.Revision()
				second := td164Join(t, s, td164B, "ref-b", proposed)
				var want *string
				if old != "" && proposed != "" {
					want = td164At(s, map[string]time.Duration{"1h": time.Hour, "2h": 2 * time.Hour}[map[bool]string{true: old, false: proposed}[old > proposed]])
				}
				changed := !td164Same(first.Rule.ExpiresAt, want)
				seq2, gen2 := s.Revision()
				label := old + "×" + proposed
				check(t, second.Existing && second.Rule.ID == first.Rule.ID, label, "existing")
				check(t, td164Same(second.Rule.ExpiresAt, want), label, "reply expiry", td164Show(second.Rule.ExpiresAt), td164Show(want))
				td164Want(t, s, first.Rule.ID, want, label+" stored")
				check(t, gen2 == gen && second.Gen == gen, label, "gen", gen, gen2, second.Gen)
				check(t, (seq2 == seq+1) == changed && (seq2 == seq) == !changed, label, "seq", seq, seq2, changed)
			}
		}
	})
	t.Run("G2-patch-expiry-syncs-claims", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "1h").Rule.ID
		td164Join(t, s, td164B, "ref-b", "")
		_, e := s.Update(Actor{Kind: UI, Name: "operator"}, id, RulePatch{ExpiresIn: ptr("30m")})
		check(t, e == nil, e)
		td164Want(t, s, id, td164At(s, 30*time.Minute), "patched")
		check(t, s.ReleaseClaim(td164B, id, "ref-b") == nil, "b releases")
		td164Want(t, s, id, td164At(s, 30*time.Minute), "G2 patched expiry survives release")
	})
	t.Run("G4-validate-writes-nothing", func(t *testing.T) {
		s, _ := setup(t)
		td164Join(t, s, td164A, "ref-a", "1h")
		td164Join(t, s, td164C, "ref-c", "2h")
		tables := []string{"rules", "claims", "audit", "logical_id_hw"}
		before := td164Dump(t, s, tables)
		seq, gen := s.Revision()
		other := td164Patch("")
		other.DstPort = ptr(81)
		results := s.BatchValidate(td164B, []RulePatch{td164Patch(""), td164Patch("3h"), other, td164Patch("1h")})
		for i, r := range results {
			check(t, r.Error == nil, "validate item", i, r.Error)
		}
		check(t, results[0].Existing && results[1].Existing && !results[2].Existing, "validate projections")
		seq2, gen2 := s.Revision()
		check(t, seq2 == seq && gen2 == gen, "G4 counters")
		check(t, reflect.DeepEqual(before, td164Dump(t, s, tables)), "G4 validate wrote to the database")
	})
	t.Run("G5-expire-and-force-delete", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "1h").Rule.ID
		td164Join(t, s, td164C, "ref-c", "1h")
		td164Join(t, s, Actor{Kind: UI, Name: "operator"}, "", "1h")
		check(t, claims(t, s, id) == 3, "three claims")
		n := len(c4bAudits(t, s))
		check(t, s.ExpireDue(s.now().Add(2*time.Hour)) == nil, "expire")
		_, ok := td164Expiry(t, s, id)
		check(t, !ok && claims(t, s, id) == 0, "G5 expired with claims")
		c4bLatest(t, s, n+1, "rule.expire")
		s, _ = setup(t) // audit order is by time; the expiry record above is two hours later
		id = td164Join(t, s, td164A, "ref-a", "").Rule.ID
		td164Join(t, s, td164B, "ref-b", "1h")
		n = len(c4bAudits(t, s))
		check(t, s.ForceDelete(Actor{Kind: UI, Name: "operator"}, id) == nil, "force delete")
		_, ok = td164Expiry(t, s, id)
		check(t, !ok && claims(t, s, id) == 0, "G5 force-deleted with claims")
		c4bLatest(t, s, n+1, "rule.delete")
	})
	t.Run("G6-audit-shape", func(t *testing.T) {
		view, err := json.Marshal(ruleAuditView{Claimants: []store.ClaimRow{{}}})
		check(t, err == nil, err)
		var m map[string]any
		check(t, json.Unmarshal(view, &m) == nil, "view JSON")
		keys := []string{}
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		check(t, strings.Join(keys, ",") == "claimants,comment,created_by,enabled,expires_at,id,logical_id,match,updated_by", "G6 audit view keys", keys)
		row := m["claimants"].([]any)[0].(map[string]any)
		check(t, len(row) == 2 && row["claimant"] != nil && row["claim_ref"] != nil, "G6 claim row keys", row)
	})
	t.Run("G9-unheld-ref-release-is-a-no-op", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "1h").Rule.ID
		td164Join(t, s, td164B, "ref-b", "")
		tables := []string{"rules", "claims", "audit"}
		before := td164Dump(t, s, tables)
		seq, gen := s.Revision()
		check(t, s.ReleaseClaim(td164B, id, "never-held") == nil, "unheld ref")
		check(t, s.ReleaseClaim(td164C, id, "ref-b") == nil, "other credential's ref")
		check(t, s.ReleaseClaim(Actor{Kind: UI, Name: "operator"}, id, "") == nil, "UI release")
		check(t, s.ReleaseClaim(td164B, "rule_missing", "ref-b") == nil, "missing rule")
		seq2, gen2 := s.Revision()
		check(t, seq2 == seq && gen2 == gen, "G9 counters", seq, seq2)
		check(t, reflect.DeepEqual(before, td164Dump(t, s, tables)), "G9 unheld release changed the database")
	})
	t.Run("G10-zero-claim-rule-first-claim-keeps-rule-expiry", func(t *testing.T) {
		s, _ := setup(t)
		r, e := s.Create(Actor{Kind: UI, Name: "operator"}, "", td164Patch(""))
		check(t, e == nil, e)
		sqlExec(t, s, "DELETE FROM claims WHERE rule_id=?", r.Rule.ID)
		check(t, claims(t, s, r.Rule.ID) == 0, "zero-claim legacy rule")
		td164Join(t, s, td164A, "ref-a", "1h")
		td164Want(t, s, r.Rule.ID, nil, "join keeps permanent")
		td164Join(t, s, td164B, "ref-b", "")
		check(t, s.ReleaseClaim(td164B, r.Rule.ID, "ref-b") == nil, "b releases")
		td164Want(t, s, r.Rule.ID, nil, "G10 first claim inherited the permanent rule expiry")
	})
	t.Run("G11-release-of-shorter-claim-changes-nothing", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "2h").Rule.ID
		td164Join(t, s, td164C, "ref-c", "1h")
		n := len(c4bAudits(t, s))
		seq, gen := s.Revision()
		check(t, s.ReleaseClaim(td164C, id, "ref-c") == nil, "c releases")
		td164Want(t, s, id, td164At(s, 2*time.Hour), "G11 expiry unchanged")
		seq2, gen2 := s.Revision()
		check(t, seq2 == seq && gen2 == gen, "G11 equal finite expiry is not a change", seq, seq2)
		ev := c4bLatest(t, s, n+1, "rule.release")
		var before, after map[string]any
		check(t, json.Unmarshal(ev.Before, &before) == nil && json.Unmarshal(ev.After, &after) == nil, "release JSON")
		check(t, before["expires_at"] == after["expires_at"] && after["expires_at"] == *td164At(s, 2*time.Hour), "G11 audit expiry")
	})
	t.Run("G12-failed-release-leaves-no-pending-renewal", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "1h").Rule.ID
		td164Join(t, s, td164B, "ref-b", "")
		seq, gen := s.Revision()
		s.beforeCommit = func(*sql.Tx) error { return fmt.Errorf("injected commit failure") }
		check(t, s.ReleaseClaim(td164B, id, "ref-b") != nil, "release must fail")
		s.beforeCommit = nil
		td164Want(t, s, id, nil, "failed release rolled back")
		check(t, claims(t, s, id) == 2, "claims intact")
		check(t, s.ReleaseClaim(td164B, id, "never-held") == nil, "later no-op")
		seq2, gen2 := s.Revision()
		check(t, seq2 == seq && gen2 == gen, "G12 failure left a pending renewal", seq, seq2)
	})
	t.Run("G13-release-keeps-update-metadata", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "1h").Rule.ID
		td164Join(t, s, td164B, "ref-b", "")
		before, err := store.Get(s.db, id)
		check(t, err == nil, err)
		start := s.now()
		s.now = func() time.Time { return start.Add(5 * time.Minute) }
		n := len(c4bAudits(t, s))
		check(t, s.ReleaseClaim(td164B, id, "ref-b") == nil, "b releases")
		after, err := store.Get(s.db, id)
		check(t, err == nil, err)
		want := before
		want.ExpiresAt = ptr(start.Add(time.Hour).UTC().Format(timeFormat))
		check(t, reflect.DeepEqual(after, want), "G13 release changed more than the expiry", after, want)
		check(t, after.UpdatedAt == before.UpdatedAt && after.UpdatedBy == "cred:a", "G13 update metadata", after.UpdatedAt, after.UpdatedBy)
		ev := c4bLatest(t, s, n+1, "rule.release")
		var view map[string]any
		check(t, json.Unmarshal(ev.After, &view) == nil && view["updated_by"] == "cred:a", "G13 audit updated_by", view["updated_by"])
	})
	t.Run("G8-permanent-remaining-unchanged", func(t *testing.T) {
		s, _ := setup(t)
		id := td164Join(t, s, td164A, "ref-a", "1h").Rule.ID
		td164Join(t, s, td164B, "ref-b", "")
		td164Join(t, s, td164D, "ref-d", "")
		n := len(c4bAudits(t, s))
		seq, gen := s.Revision()
		check(t, s.ReleaseClaim(td164B, id, "ref-b") == nil, "b releases")
		td164Want(t, s, id, nil, "G8 permanent remains")
		seq2, gen2 := s.Revision()
		check(t, seq2 == seq && gen2 == gen, "G8 claim-only release keeps counters", seq, seq2)
		ev := c4bLatest(t, s, n+1, "rule.release")
		var before, after map[string]any
		check(t, json.Unmarshal(ev.Before, &before) == nil && json.Unmarshal(ev.After, &after) == nil, "release JSON")
		check(t, before["expires_at"] == nil && after["expires_at"] == nil, "G8 audit expiry stays permanent")
	})
}

func td164Dump(t *testing.T, s *Service, tables []string) []string {
	t.Helper()
	out := []string{}
	for _, table := range tables {
		rows, err := s.db.Reader().Query("SELECT * FROM " + table)
		check(t, err == nil, err)
		cols, err := rows.Columns()
		check(t, err == nil, err)
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			check(t, rows.Scan(ptrs...) == nil, "scan")
			line := table
			for i, c := range cols {
				line += fmt.Sprintf("|%s=%v", c, vals[i])
			}
			out = append(out, line)
		}
		check(t, rows.Err() == nil, rows.Err())
		rows.Close()
	}
	sort.Strings(out)
	return out
}
