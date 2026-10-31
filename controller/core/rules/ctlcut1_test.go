package rules

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func ptr[T any](v T) *T { return &v }

var ui = Actor{Kind: UI}
var machine = Actor{Kind: Machine, Name: "A"}

type recordingSink struct {
	mu      sync.Mutex
	changes []Change
}

func (r *recordingSink) Changed(c Change) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changes = append(r.changes, c)
}
func (r *recordingSink) all() []Change {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Change(nil), r.changes...)
}
func setup(t *testing.T) (*Service, *recordingSink) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	sink := &recordingSink{}
	svc := New(db, sink)
	svc.now = func() time.Time { return time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC) }
	return svc, sink
}
func draft(port int, ttl string) RulePatch {
	p := RulePatch{DstIP: ptr("10.20.0.1"), DstPort: ptr(port), Protocol: ptr("tcp")}
	if ttl != "" {
		p.TTL = ptr(ttl)
	}
	return p
}
func create(t *testing.T, s *Service, p RulePatch) store.Rule {
	t.Helper()
	r, e := s.Create(ui, "", p)
	if e != nil {
		t.Fatal(e)
	}
	if r.Existing {
		t.Fatal("unexpected existing")
	}
	return r.Rule
}
func check(t *testing.T, yes bool, args ...any) {
	t.Helper()
	if !yes {
		t.Fatal(args...)
	}
}
func code(t *testing.T, e *Error, want string) {
	t.Helper()
	if e == nil || e.Code != want {
		t.Fatalf("error=%v want=%s", e, want)
	}
}
func count(t *testing.T, s *Service) int {
	t.Helper()
	rows, e := s.List()
	if e != nil {
		t.Fatal(e)
	}
	return len(rows)
}
func claims(t *testing.T, s *Service, id string) int {
	t.Helper()
	n, e := store.ClaimCount(s.db, id)
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func sqlExec(t *testing.T, s *Service, q string, args ...any) {
	t.Helper()
	if _, err := s.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}
func capacityIDs(t *testing.T, e *Error, known []store.Rule, want int) {
	t.Helper()
	code(t, e, "condition_capacity")
	check(t, len(e.RuleIDs) == want, "occupants", e.RuleIDs)
	seen := map[string]bool{}
	for _, id := range e.RuleIDs {
		check(t, !seen[id], "duplicate occupant")
		seen[id] = true
	}
	for _, r := range known {
		check(t, seen[r.ID], "missing occupant", r.ID)
	}
}

func TestCtlCut1(t *testing.T) {
	t.Run("S-open", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new.db")
		for i := 0; i < 2; i++ {
			db, e := store.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			var version int
			e = db.QueryRow("SELECT version FROM schema_version").Scan(&version)
			check(t, e == nil && version == 7, "schema", version, e)
			var mode string
			e = db.QueryRow("PRAGMA journal_mode").Scan(&mode)
			check(t, e == nil && mode == "wal", "journal", mode, e)
			db.Close()
		}
		db, e := store.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		_, e = db.Exec("UPDATE schema_version SET version=99")
		check(t, e == nil, e)
		db.Close()
		other, e := store.Open(path)
		if other != nil {
			other.Close()
		}
		check(t, e != nil, "future schema accepted")
	})
	t.Run("B1-wild", func(t *testing.T) {
		s, _ := setup(t)
		first := create(t, s, draft(80, ""))
		for _, src := range []string{"0.0.0.0", "::"} {
			p := draft(80, "")
			p.SrcIP = ptr(src)
			r, e := s.Create(ui, "", p)
			check(t, e == nil && r.Existing && r.Rule.ID == first.ID, "wildcard identity", r, e)
		}
		check(t, count(t, s) == 1, "duplicate rows")
	})
	t.Run("B1-unique", func(t *testing.T) {
		s, _ := setup(t)
		r := create(t, s, draft(80, ""))
		r.ID = "rule_" + strings.Repeat("a", 32)
		r.LogicalID = 2
		err := store.InsertRule(s.db, r)
		check(t, store.Unique(err), "expected SQLite identity uniqueness", err)
		check(t, count(t, s) == 1, "duplicate persisted")
	})
	t.Run("B3-dup", func(t *testing.T) {
		s, sink := setup(t)
		r := create(t, s, draft(80, ""))
		check(t, s.SetEnabled(ui, r.ID, false) == nil, "disable")
		n := len(sink.all())
		result, e := s.Create(machine, "x", draft(80, ""))
		check(t, e == nil && result.Existing && result.Rule.ID == r.ID && !result.Rule.Enabled, "existing", result, e)
		check(t, len(sink.all()) == n, "claim notified")
	})
	t.Run("B3-conflict", func(t *testing.T) {
		s, _ := setup(t)
		r := create(t, s, draft(80, ""))
		p := draft(80, "")
		p.Action = ptr("rate_limit")
		p.RateLimit = ptr(int64(100))
		_, e := s.Create(ui, "", p)
		code(t, e, "rule_conflict")
		check(t, e.RuleID == r.ID, "conflict ID")
	})
	for _, field := range []string{"dst_ip", "ttl"} {
		field := field
		t.Run("B4-create-empty/"+field, func(t *testing.T) {
			s, _ := setup(t)
			p := draft(80, "")
			if field == "dst_ip" {
				p.DstIP = ptr("")
			} else {
				p.TTL = ptr("")
			}
			_, e := s.Create(ui, "", p)
			code(t, e, "empty_value")
			check(t, e.Field == field && count(t, s) == 0, "shape guard", e)
		})
	}
	t.Run("B4-update-clear", func(t *testing.T) {
		s, _ := setup(t)
		p := draft(80, "1")
		p.ExpiresIn = ptr("90m")
		r := create(t, s, p)
		updated, e := s.Update(ui, r.ID, RulePatch{TTL: ptr(""), ExpiresIn: ptr("")})
		check(t, e == nil && updated.TTL == nil && updated.ExpiresAt == nil, "clear", updated, e)
	})
	t.Run("B5-cap", func(t *testing.T) {
		s, _ := setup(t)
		rows := []store.Rule{}
		for i := 1; i <= 3; i++ {
			rows = append(rows, create(t, s, draft(80, fmt.Sprint(i))))
		}
		p := draft(80, "")
		p.PktLen = ptr("100,120,140")
		_, e := s.Create(ui, "", p)
		capacityIDs(t, e, rows, 3)
		check(t, count(t, s) == 3, "capacity wrote")
	})
	t.Run("B5-enable", func(t *testing.T) {
		s, _ := setup(t)
		rows := []store.Rule{}
		for i := 1; i <= 3; i++ {
			rows = append(rows, create(t, s, draft(80, fmt.Sprint(i))))
		}
		p := draft(80, "")
		p.PktLen = ptr("100,120,140")
		p.Enabled = ptr(false)
		r := create(t, s, p)
		rows = append(rows, r)
		capacityIDs(t, s.SetEnabled(ui, r.ID, true), rows, 4)
		got, e := s.Get(r.ID)
		check(t, e == nil && !got.Enabled, "enable leaked")
	})
	t.Run("B5-concurrent", func(t *testing.T) {
		s, _ := setup(t)
		for i := 1; i <= 3; i++ {
			create(t, s, draft(80, fmt.Sprint(i)))
		}
		start := make(chan struct{})
		results := make(chan *Error, 8)
		for i := 0; i < 8; i++ {
			i := i
			go func() { <-start; _, e := s.Create(ui, "", draft(80, fmt.Sprint(10+i))); results <- e }()
		}
		close(start)
		succeeded := 0
		rejects := []*Error{}
		for i := 0; i < 8; i++ {
			if e := <-results; e != nil {
				rejects = append(rejects, e)
			} else {
				succeeded++
			}
		}
		check(t, succeeded == 1 && len(rejects) == 7, "concurrent results", succeeded, len(rejects))
		rows, e := s.List()
		check(t, e == nil && len(rows) == 4, "final rows", rows, e)
		candidates := 0
		for _, r := range rows {
			c, e := Canonicalize(r.Match)
			check(t, e == nil && r.Enabled, "final canonical row")
			candidates += c.CandidateCount
		}
		check(t, candidates == 4, "final candidates", candidates)
		for _, e := range rejects {
			capacityIDs(t, e, rows, 4)
		}
	})
	t.Run("B5-disabled-free", func(t *testing.T) {
		s, _ := setup(t)
		rows := []store.Rule{}
		for i := 1; i <= 4; i++ {
			rows = append(rows, create(t, s, draft(80, fmt.Sprint(i))))
		}
		check(t, s.SetEnabled(ui, rows[0].ID, false) == nil, "disable")
		create(t, s, draft(80, "5"))
		enabled, e := s.ListEnabledByGroup(rows[0].GroupKey)
		check(t, e == nil && len(enabled) == 4, "enabled occupancy", e)
	})
	t.Run("B5-update-self", func(t *testing.T) {
		s, _ := setup(t)
		rows := []store.Rule{}
		for i := 1; i <= 4; i++ {
			rows = append(rows, create(t, s, draft(80, fmt.Sprint(i))))
		}
		r, e := s.Update(ui, rows[0].ID, RulePatch{TTL: ptr("8")})
		check(t, e == nil && *r.TTL == "8", "self counted twice", e)
	})
	t.Run("B6-two", func(t *testing.T) {
		s, _ := setup(t)
		p := draft(80, "")
		p.MatchAnomaly = ptr(1)
		a := create(t, s, p)
		p.MatchAnomaly = ptr(2)
		b := create(t, s, p)
		check(t, a.ID != b.ID && a.CondKey != b.CondKey && count(t, s) == 2, "anomaly identities merged")
	})
	t.Run("B8-flags-anom", func(t *testing.T) {
		s, _ := setup(t)
		p := draft(80, "")
		p.MatchAnomaly = ptr(1)
		p.TCPFlags = ptr("SYN")
		create(t, s, p)
		p.DstPort = ptr(81)
		p.Action = ptr("rate_limit")
		p.RateLimit = ptr(int64(100))
		r := create(t, s, p)
		check(t, r.Action == "rate_limit" && r.RateLimit == 100, "rate lost")
	})
	t.Run("A1-immutable", func(t *testing.T) {
		s, _ := setup(t)
		r := create(t, s, draft(80, "1"))
		original := r.LogicalID
		for _, item := range []struct {
			name  string
			patch RulePatch
		}{{"port", RulePatch{SrcPort: ptr(40)}}, {"cross-key", RulePatch{DstIP: ptr("10.20.0.2")}}, {"condition", RulePatch{TTL: ptr("2")}}} {
			item := item
			t.Run(item.name, func(t *testing.T) {
				var e *Error
				r, e = s.Update(ui, r.ID, item.patch)
				check(t, e == nil && r.LogicalID == original, "logical ID changed", r, e)
			})
		}
		t.Run("enabled", func(t *testing.T) {
			for _, v := range []bool{false, true} {
				check(t, s.SetEnabled(ui, r.ID, v) == nil, "toggle")
				got, e := s.Get(r.ID)
				check(t, e == nil && got.LogicalID == original, "logical ID changed")
			}
		})
	})
	t.Run("A8-mono", func(t *testing.T) {
		for _, which := range []int{1, 2} {
			which := which
			name := "del-middle"
			if which == 2 {
				name = "del-max"
			}
			t.Run(name, func(t *testing.T) {
				s, _ := setup(t)
				rows := []store.Rule{}
				for i := 1; i <= 3; i++ {
					r := create(t, s, draft(i, ""))
					check(t, r.LogicalID == int64(i), "initial IDs")
					rows = append(rows, r)
				}
				check(t, s.ForceDelete(ui, rows[which].ID) == nil, "delete")
				r := create(t, s, draft(4, ""))
				var high int
				e := s.db.QueryRow("SELECT high_water FROM logical_id_hw").Scan(&high)
				check(t, e == nil && high == 4 && r.LogicalID == 4, "ID reused", r.LogicalID, high, e)
			})
		}
	})
	t.Run("V1-drop", func(t *testing.T) {
		s, _ := setup(t)
		p := draft(80, "")
		p.RateLimit = ptr(int64(100))
		r := create(t, s, p)
		stored, e := store.Get(s.db, r.ID)
		check(t, e == nil && stored.Action == "drop" && stored.RateLimit == 0, "default/drop rate", stored, e)
	})
	t.Run("V2-batch", func(t *testing.T) {
		s, sink := setup(t)
		old := create(t, s, draft(81, ""))
		results := s.BatchCreate(machine, "x", []RulePatch{draft(80, ""), draft(81, ""), draft(80, ""), draft(70000, "")})
		check(t, len(results) == 4, "batch length")
		failures := 0
		for i, r := range results {
			check(t, r.Index == i, "batch index")
			if r.Error != nil {
				failures++
			}
		}
		check(t, failures == 1 && !results[0].Existing && results[1].Existing && results[1].Rule.ID == old.ID && results[2].Existing && results[2].Rule.ID == results[0].Rule.ID, "batch results", results)
		check(t, claims(t, s, results[0].Rule.ID) == 1 && len(sink.all()) == 2, "batch claim/notification")
	})
	for _, action := range []string{"drop", "rate_limit"} {
		action := action
		t.Run("V3-race/"+action, func(t *testing.T) {
			s, sink := setup(t)
			injected := "rule_" + strings.Repeat("a", 32)
			s.beforeInsert = func(r store.Rule) error {
				r.ID = injected
				r.Action = action
				if action == "rate_limit" {
					r.RateLimit = 100
				}
				return s.transaction(func(tx *sql.Tx) error {
					var err error
					r.LogicalID, err = store.NextLogicalID(tx)
					if err != nil {
						return err
					}
					return store.InsertRule(tx, r)
				})
			}
			r, e := s.Create(machine, "x", draft(80, ""))
			if action == "drop" {
				check(t, e == nil && r.Existing && r.Rule.ID == injected, "race existing", r, e)
				check(t, claims(t, s, injected) == 1, "missing claim")
			} else {
				code(t, e, "rule_conflict")
				check(t, e.RuleID == injected, "conflict ID")
			}
			check(t, len(sink.all()) == 0 && s.gen == 0 && count(t, s) == 1, "race side effects")
		})
	}
	t.Run("G4-claims", func(t *testing.T) {
		t.Run("cross-credential-same-ref", func(t *testing.T) {
			s, sink := setup(t)
			credentialB := Actor{Kind: Machine, Name: "B"}
			a, e := s.Create(machine, "same-ref", draft(80, ""))
			check(t, e == nil && !a.Existing, "credential A create", a, e)
			b, e := s.Create(credentialB, "same-ref", draft(80, ""))
			check(t, e == nil && b.Existing && b.Rule.ID == a.Rule.ID, "credential B claim", b, e)
			check(t, claims(t, s, a.Rule.ID) == 2, "credentials did not retain two claims")
			before := sink.all()
			check(t, len(before) == 1 && s.gen == 1, "claim-only create notified", before)
			check(t, s.ReleaseClaim(machine, a.Rule.ID, "same-ref") == nil, "credential A release")
			remaining, e := s.Get(a.Rule.ID)
			check(t, e == nil && remaining.ID == a.Rule.ID, "credential A removed B's rule", remaining, e)
			check(t, claims(t, s, a.Rule.ID) == 1, "remaining claim count")
			var claimant, ref string
			err := s.db.QueryRow("SELECT claimant,claim_ref FROM claims WHERE rule_id=?", a.Rule.ID).Scan(&claimant, &ref)
			check(t, err == nil && claimant == "cred:B" && ref == "same-ref", "wrong remaining claimant", claimant, ref, err)
			check(t, reflect.DeepEqual(sink.all(), before) && s.gen == 1, "partial release notified", sink.all())
			check(t, s.ReleaseClaim(credentialB, a.Rule.ID, "same-ref") == nil, "credential B release")
			_, e = s.Get(a.Rule.ID)
			code(t, e, "not_found")
			check(t, claims(t, s, a.Rule.ID) == 0, "last claim remains")
			changes := sink.all()
			check(t, len(changes) == 2 && s.gen == 2, "last release notification count", changes)
			check(t, reflect.DeepEqual(changes[1], Change{Gen: 2, RuleKeys: []string{a.Rule.GroupKey}}), "last release notification content", changes[1])
		})
		t.Run("two-refs", func(t *testing.T) {
			s, _ := setup(t)
			a, e := s.Create(machine, "x", draft(80, ""))
			check(t, e == nil, "create")
			b, e := s.Create(machine, "y", draft(80, ""))
			check(t, e == nil && b.Existing && claims(t, s, a.Rule.ID) == 2, "two refs")
			check(t, s.ReleaseClaim(machine, a.Rule.ID, "x") == nil && count(t, s) == 1, "first release")
			check(t, s.ReleaseClaim(machine, a.Rule.ID, "y") == nil && count(t, s) == 0, "last release")
		})
		t.Run("repeat", func(t *testing.T) {
			s, _ := setup(t)
			a, e := s.Create(machine, "x", draft(80, ""))
			check(t, e == nil, "create")
			_, e = s.Create(machine, "x", draft(80, ""))
			check(t, e == nil && claims(t, s, a.Rule.ID) == 1, "same triple grew")
			_, e = s.Create(machine, "y", draft(80, ""))
			check(t, e == nil, "second ref")
			for i := 0; i < 2; i++ {
				check(t, s.ReleaseClaim(machine, a.Rule.ID, "x") == nil, "release")
			}
			check(t, count(t, s) == 1 && claims(t, s, a.Rule.ID) == 1, "repeat release deleted other claim")
		})
		t.Run("ui-and-force", func(t *testing.T) {
			s, _ := setup(t)
			r := create(t, s, draft(80, ""))
			_, e := s.Create(machine, "x", draft(80, ""))
			check(t, e == nil, "claim")
			check(t, s.ReleaseClaim(machine, r.ID, "x") == nil && count(t, s) == 1 && claims(t, s, r.ID) == 1, "UI claim lost")
			check(t, s.ReleaseClaim(ui, r.ID, "") == nil && count(t, s) == 1, "external UI release")
			check(t, s.ForceDelete(ui, r.ID) == nil && claims(t, s, r.ID) == 0 && count(t, s) == 0, "cascade")
			check(t, s.ForceDelete(ui, r.ID) == nil && s.ReleaseClaim(machine, r.ID, "x") == nil, "idempotency")
		})
		t.Run("default-ref", func(t *testing.T) {
			s, _ := setup(t)
			a, e := s.Create(machine, "", draft(80, ""))
			check(t, e == nil, "create")
			_, e = s.Create(machine, "", draft(80, ""))
			check(t, e == nil && claims(t, s, a.Rule.ID) == 1, "default ref not idempotent")
		})
	})
	t.Run("G6-id", func(t *testing.T) {
		s, _ := setup(t)
		pattern := regexp.MustCompile(`^rule_[0-9a-f]{32}$`)
		seen := map[string]bool{}
		for i := 1; i <= 1000; i++ {
			r := create(t, s, draft(i, ""))
			check(t, pattern.MatchString(r.ID) && !seen[r.ID], "bad/repeated ID", r.ID)
			seen[r.ID] = true
		}
		w, e := s.CreateWhitelist(ui, WhitelistInput{DstIP: "10.20.0.1"})
		check(t, e == nil && regexp.MustCompile(`^wl_[0-9a-f]{32}$`).MatchString(w.Whitelist.ID), "whitelist ID", w, e)
	})
	for _, value := range []string{"abc", "-5m", "0", "90m"} {
		value := value
		t.Run("E8-expires/"+value, func(t *testing.T) {
			s, _ := setup(t)
			p := draft(80, "")
			p.ExpiresIn = ptr(value)
			r, e := s.Create(ui, "", p)
			if value != "90m" {
				code(t, e, "invalid_expires_in")
				check(t, count(t, s) == 0, "invalid expiry wrote")
			} else {
				check(t, e == nil && r.Rule.ExpiresAt != nil && *r.Rule.ExpiresAt == "2026-10-10T11:30:00Z", "expiry", r, e)
			}
		})
	}
	t.Run("E8-cidr-update", func(t *testing.T) {
		s, _ := setup(t)
		r := create(t, s, RulePatch{SrcCIDR: ptr("10.20.0.77/24"), PktLen: ptr("100")})
		got, e := s.Update(ui, r.ID, RulePatch{PktLen: ptr("120")})
		check(t, e == nil && got.SrcCIDR == "10.20.0.0/24" && *got.PktLen == "120", "CIDR lost", got, e)
	})
	t.Run("N-sink-rollback", func(t *testing.T) {
		s, sink := setup(t)
		s.beforeCommit = func(tx *sql.Tx) error {
			if e := tx.Rollback(); e != nil {
				return e
			}
			return tx.Commit()
		}
		_, e := s.Create(ui, "", draft(80, ""))
		code(t, e, "internal")
		var high int
		err := s.db.QueryRow("SELECT high_water FROM logical_id_hw").Scan(&high)
		check(t, err == nil && high == 0 && count(t, s) == 0 && s.gen == 0 && len(sink.all()) == 0, "rollback leaked")
	})
	t.Run("N-ovl", func(t *testing.T) {
		s, _ := setup(t)
		r := create(t, s, RulePatch{SrcCIDR: ptr("10.20.0.0/24")})
		_, e := s.Create(ui, "", RulePatch{SrcCIDR: ptr("10.20.0.0/25")})
		code(t, e, "cidr_overlap")
		check(t, len(e.RuleIDs) == 1 && e.RuleIDs[0] == r.ID, "overlap ID", e)
	})
	for _, bucket := range []string{"sv4", "dv4", "sv6", "dv6"} {
		bucket := bucket
		t.Run("N-trie/"+bucket, func(t *testing.T) {
			s, _ := setup(t)
			s.trieLimit = 2
			for i := 0; i < 3; i++ {
				prefix := fmt.Sprintf("10.20.%d.0/24", i)
				if strings.HasSuffix(bucket, "6") {
					prefix = fmt.Sprintf("2001:db8:%x::/64", i)
				}
				p := RulePatch{}
				if strings.HasPrefix(bucket, "s") {
					p.SrcCIDR = ptr(prefix)
				} else {
					p.DstCIDR = ptr(prefix)
				}
				_, e := s.Create(ui, "", p)
				if i < 2 {
					check(t, e == nil, "trie initial", e)
				} else {
					code(t, e, "table_full")
					check(t, e.Table == bucket, "wrong tree", e)
				}
			}
		})
	}
	t.Run("W-dup", func(t *testing.T) {
		s, sink := setup(t)
		a, e := s.CreateWhitelist(ui, WhitelistInput{DstIP: "2001:DB8::1"})
		check(t, e == nil, "create WL")
		b, e := s.CreateWhitelist(ui, WhitelistInput{SrcIP: "::", DstIP: "2001:db8::1", Protocol: "all"})
		rows, err := s.ListWhitelist()
		check(t, e == nil && err == nil && b.Existing && a.Whitelist.ID == b.Whitelist.ID && len(rows) == 1 && len(sink.all()) == 1, "WL duplicate", b, e)
	})
	t.Run("B2-prepare", func(t *testing.T) {
		s, _ := setup(t)
		a := create(t, s, draft(80, "1"))
		b := create(t, s, draft(81, ""))
		c := create(t, s, draft(82, ""))
		known := []store.Rule{a, b, c}
		sqlExec(t, s, "UPDATE rules SET ttl='nonsense' WHERE id=?", a.ID)
		sqlExec(t, s, "UPDATE rules SET dst_ip='::ffff:10.20.0.1' WHERE id=?", b.ID)
		sqlExec(t, s, "UPDATE rules SET cond_key='wrong' WHERE id=?", c.ID)
		for i := 1; i <= 5; i++ {
			p := draft(83, fmt.Sprint(i))
			p.Enabled = ptr(false)
			r := create(t, s, p)
			known = append(known, r)
		}
		sqlExec(t, s, "UPDATE rules SET enabled=1 WHERE dst_port=83")
		w, e := s.CreateWhitelist(ui, WhitelistInput{DstIP: "10.20.0.2"})
		check(t, e == nil, "WL")
		sqlExec(t, s, "UPDATE whitelist SET wl_key='wrong' WHERE id=?", w.Whitelist.ID)
		report, err := Prepare(s.db)
		check(t, err == nil && len(report.Violations) >= 4, "report", report, err)
		seen := map[string]bool{}
		for _, v := range report.Violations {
			check(t, v.Reason != "", "empty reason")
			seen[v.ID] = true
		}
		for _, r := range known {
			check(t, seen[r.ID], "missing violation", r.ID)
		}
		check(t, seen[w.Whitelist.ID], "missing WL violation")
	})
	t.Run("B2-dryrun", func(t *testing.T) {
		for _, kind := range []string{"clean", "bad", "empty", "missing", "future"} {
			kind := kind
			t.Run(kind, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "source.db")
				want := 0
				if kind == "empty" {
					check(t, os.WriteFile(path, nil, 0600) == nil, "empty fixture")
				} else if kind != "missing" {
					db, e := store.Open(path)
					if e != nil {
						t.Fatal(e)
					}
					s := New(db, nil)
					r := create(t, s, draft(80, ""))
					if kind == "bad" {
						sqlExec(t, s, "UPDATE rules SET cond_key='wrong' WHERE id=?", r.ID)
						want = 1
					}
					if kind == "future" {
						sqlExec(t, s, "UPDATE schema_version SET version=99")
						want = 2
					}
					db.Close()
				} else {
					want = 2
				}
				before, err := os.ReadFile(path)
				if kind != "missing" {
					check(t, err == nil, err)
				}
				entries, err := os.ReadDir(dir)
				check(t, err == nil, err)
				var output bytes.Buffer
				rc := DryRun(path, &output)
				check(t, rc == want, "dryrun exit", rc, want, output.String())
				after, err := os.ReadFile(path)
				if kind == "missing" {
					check(t, os.IsNotExist(err), "source was created")
				} else {
					check(t, err == nil && sha256.Sum256(before) == sha256.Sum256(after), "source changed")
					if kind == "empty" {
						check(t, len(after) == 0, "empty source migrated")
					}
				}
				end, err := os.ReadDir(dir)
				check(t, err == nil && len(end) == len(entries), "left new source-side files")
				if kind == "bad" {
					check(t, strings.Contains(output.String(), "\t"), "missing tab report")
				}
			})
		}
	})
	t.Run("F1-single", func(t *testing.T) {
		entries, err := os.ReadDir(".")
		check(t, err == nil, err)
		constructors := 0
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
				b, e := os.ReadFile(entry.Name())
				check(t, e == nil, e)
				constructors += strings.Count(string(b), "func groupKey(")
			}
		}
		check(t, constructors == 1, "group key constructor count", constructors)
	})
}

func TestCtlCut1Notifications(t *testing.T) {
	s, sink := setup(t)
	var r store.Rule
	var expected uint64
	witness := func(t *testing.T, keys []string, moves []Move, wl bool) {
		t.Helper()
		expected++
		changes := sink.all()
		check(t, len(changes) == int(expected), "notification count", changes)
		c := changes[len(changes)-1]
		sort.Strings(keys)
		check(t, c.Gen == expected && reflect.DeepEqual(c.RuleKeys, keys) && reflect.DeepEqual(c.Moves, moves) && c.Whitelist == wl, "notification content", c, keys, moves, wl)
	}
	t.Run("N-sink/create", func(t *testing.T) { r = create(t, s, draft(80, "")); witness(t, []string{r.GroupKey}, nil, false) })
	t.Run("N-sink/same-key", func(t *testing.T) {
		got, e := s.Update(ui, r.ID, RulePatch{TTL: ptr("1")})
		check(t, e == nil, "update", e)
		r = got
		witness(t, []string{r.GroupKey}, nil, false)
	})
	t.Run("N-sink/cross-key", func(t *testing.T) {
		old := r.GroupKey
		got, e := s.Update(ui, r.ID, RulePatch{DstPort: ptr(81)})
		check(t, e == nil, "update", e)
		r = got
		witness(t, []string{old, r.GroupKey}, []Move{{r.ID, old, r.GroupKey}}, false)
	})
	t.Run("N-sink/disable", func(t *testing.T) {
		check(t, s.SetEnabled(ui, r.ID, false) == nil, "disable")
		witness(t, []string{r.GroupKey}, nil, false)
	})
	t.Run("N-sink/enable", func(t *testing.T) {
		check(t, s.SetEnabled(ui, r.ID, true) == nil, "enable")
		witness(t, []string{r.GroupKey}, nil, false)
	})
	t.Run("N-sink/existing-claim", func(t *testing.T) {
		p := draft(81, "1")
		got, e := s.Create(machine, "x", p)
		check(t, e == nil && got.Existing, "existing", e)
		check(t, len(sink.all()) == int(expected) && s.gen == expected, "claim notified")
	})
	t.Run("N-sink/comment", func(t *testing.T) {
		_, e := s.Update(ui, r.ID, RulePatch{Comment: ptr("note")})
		check(t, e == nil, "comment", e)
		witness(t, []string{r.GroupKey}, nil, false)
	})
	t.Run("N-sink/precheck-failure", func(t *testing.T) {
		_, e := s.Create(ui, "", draft(70000, ""))
		code(t, e, "invalid_rule")
		check(t, len(sink.all()) == int(expected) && s.gen == expected, "failed write notified")
	})
	t.Run("N-sink/force", func(t *testing.T) {
		check(t, s.ForceDelete(ui, r.ID) == nil, "delete")
		witness(t, []string{r.GroupKey}, nil, false)
	})
	t.Run("N-sink/release-zero", func(t *testing.T) {
		got, e := s.Create(machine, "x", draft(82, ""))
		check(t, e == nil, "create", e)
		witness(t, []string{got.Rule.GroupKey}, nil, false)
		check(t, s.ReleaseClaim(machine, got.Rule.ID, "x") == nil, "release")
		witness(t, []string{got.Rule.GroupKey}, nil, false)
	})
	t.Run("N-sink/expire-round", func(t *testing.T) {
		keys := []string{}
		for _, port := range []int{83, 84} {
			p := draft(port, "")
			p.ExpiresIn = ptr("1m")
			r := create(t, s, p)
			keys = append(keys, r.GroupKey)
			witness(t, []string{r.GroupKey}, nil, false)
		}
		check(t, s.ExpireDue(s.now().Add(time.Minute)) == nil, "expire")
		witness(t, keys, nil, false)
		check(t, count(t, s) == 0, "expired rows remain")
	})
	t.Run("N-sink/expire-non-utc", func(t *testing.T) {
		s, sink := setup(t)
		p := draft(85, "")
		p.ExpiresIn = ptr("1h")
		r := create(t, s, p)
		stored, e := s.Get(r.ID)
		check(t, e == nil && stored.ExpiresAt != nil && *stored.ExpiresAt == "2026-10-10T11:00:00Z", "stored expiry", stored, e)
		before := sink.all()
		check(t, len(before) == 1 && s.gen == 1, "create notification", before)
		early, err := time.Parse(time.RFC3339, "2026-10-10T18:30:00+08:00")
		check(t, err == nil, err)
		check(t, s.ExpireDue(early) == nil, "early expiry call")
		remaining, e := s.Get(r.ID)
		check(t, e == nil && remaining.ID == r.ID, "rule expired before UTC deadline", remaining, e)
		check(t, reflect.DeepEqual(sink.all(), before) && s.gen == 1, "early expiry notified", sink.all())
		due, err := time.Parse(time.RFC3339, "2026-10-10T04:00:00-07:00")
		check(t, err == nil, err)
		check(t, s.ExpireDue(due) == nil, "deadline expiry call")
		_, e = s.Get(r.ID)
		code(t, e, "not_found")
		changes := sink.all()
		check(t, len(changes) == 2 && s.gen == 2, "expiry notification count", changes)
		check(t, reflect.DeepEqual(changes[1], Change{Gen: 2, RuleKeys: []string{r.GroupKey}}), "expiry notification content", changes[1])
	})
	t.Run("N-sink/whitelist", func(t *testing.T) {
		w, e := s.CreateWhitelist(ui, WhitelistInput{DstIP: "10.20.0.1"})
		check(t, e == nil, "WL", e)
		witness(t, nil, nil, true)
		check(t, s.DeleteWhitelist(ui, w.Whitelist.ID) == nil, "WL delete")
		witness(t, nil, nil, true)
		check(t, s.DeleteWhitelist(ui, w.Whitelist.ID) == nil && len(sink.all()) == int(expected), "missing WL notified")
	})
}

type blockedSink struct {
	recordingSink
	entered, release chan struct{}
}

func (s *blockedSink) Changed(c Change) {
	s.recordingSink.Changed(c)
	if c.Gen == 1 {
		close(s.entered)
		<-s.release
	}
}
func TestCtlCut1SinkOrder(t *testing.T) {
	t.Run("N-sink-order", func(t *testing.T) {
		s, _ := setup(t)
		sink := &blockedSink{entered: make(chan struct{}), release: make(chan struct{})}
		s.sink = sink
		var once sync.Once
		release := func() { once.Do(func() { close(sink.release) }) }
		defer release()
		first := make(chan *Error, 1)
		go func() { _, e := s.Create(ui, "", draft(80, "")); first <- e }()
		select {
		case <-sink.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("first notification did not enter")
		}
		calling := make(chan struct{})
		second := make(chan *Error, 1)
		go func() { close(calling); _, e := s.Create(ui, "", draft(81, "")); second <- e }()
		<-calling
		returned := false
		select {
		case e := <-second:
			returned = true
			t.Errorf("second write returned while first sink blocked: %v", e)
		case <-time.After(200 * time.Millisecond):
		}
		rows, e := s.List()
		if e != nil || len(rows) != 1 {
			t.Errorf("second write became visible while first sink blocked: %d %v", len(rows), e)
		}
		release()
		check(t, <-first == nil, "first write")
		if !returned {
			select {
			case e := <-second:
				check(t, e == nil, "second write", e)
			case <-time.After(3 * time.Second):
				t.Fatal("second write blocked after release")
			}
		}
		changes := sink.all()
		check(t, len(changes) == 2 && changes[0].Gen == 1 && changes[1].Gen == 2, "notification order", changes)
	})
}

func TestCtlCut1StoredFields(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		s, _ := setup(t)
		p := draft(80, " 5,3-4 , 1 ")
		p.Comment = ptr("a")
		p.ExpiresIn = ptr("90m")
		result, createErr := s.Create(Actor{Kind: UI, Name: "alice"}, "", p)
		check(t, createErr == nil, createErr)
		r := result.Rule
		var claimant, ref string
		err := s.db.QueryRow("SELECT claimant,claim_ref FROM claims WHERE rule_id=?", r.ID).Scan(&claimant, &ref)
		check(t, err == nil && claimant == "ui" && ref == "", "UI claim", err)
		got, e := s.Get(r.ID)
		check(t, e == nil && reflect.DeepEqual(r, got) && *got.TTL == "1,3-5" && got.CreatedBy == "user:alice" && got.UpdatedBy == "user:alice", "roundtrip", got, e)
		b, e2 := json.Marshal(got)
		check(t, e2 == nil && len(b) > 0, "marshal")
	})
}
