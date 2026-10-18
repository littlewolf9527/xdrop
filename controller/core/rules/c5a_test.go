package rules

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func c5aPatch(port int, ttl, expiry string) RulePatch {
	p := RulePatch{DstIP: ptr("192.0.2.10"), DstPort: ptr(port), Protocol: ptr("tcp")}
	if ttl != "" {
		p.TTL = ptr(ttl)
	}
	if expiry != "" {
		p.ExpiresIn = ptr(expiry)
	}
	return p
}
func c5aLedgerSnapshot(l *ledger) *ledger {
	out := &ledger{occupancy: l.occupancy, groups: map[string]ledgerGroup{}}
	for k, g := range l.groups {
		ids := make([]string, len(g.ids))
		copy(ids, g.ids)
		g.ids = ids
		out.groups[k] = g
	}
	for i, tree := range l.trees {
		out.trees[i] = map[string]ledgerPrefix{}
		for k, p := range tree {
			ids := make([]string, len(p.ids))
			copy(ids, p.ids)
			p.ids = ids
			out.trees[i][k] = p
		}
	}
	return out
}
func TestC5ARules(t *testing.T) {
	t.Run("C5A-clone", func(t *testing.T) {
		l := &ledger{groups: map[string]ledgerGroup{"g": {members: 2, ids: []string{"a", "b"}}}}
		for i := range l.trees {
			l.trees[i] = map[string]ledgerPrefix{"prefix": {network: netip.MustParsePrefix("2001:db8::/64"), ids: []string{"a", "b"}}}
		}
		before := c5aLedgerSnapshot(l)
		clone := l.clone()
		g := clone.groups["g"]
		g.ids = changeID(g.ids, "a", -1)
		g.ids[0] = "changed"
		g.members = 9
		clone.groups["g"] = g
		for i := range clone.trees {
			p := clone.trees[i]["prefix"]
			p.ids = changeID(p.ids, "a", -1)
			p.ids[0] = "changed"
			clone.trees[i]["prefix"] = p
		}
		check(t, reflect.DeepEqual(l, before), "clone shares map or member storage")
		t.Log("clone_groups=1 clone_trees=4 members_each=2")
	})
	t.Run("C5A-validate-50", func(t *testing.T) {
		s, sink := setup(t)
		s.UseLogicalReserve(0)
		seed := create(t, s, c5aPatch(100, "", "1h"))
		limits := BuiltinLimits()
		limits.Values[0] = 4
		s.UseLimits(func() Limits { return limits })
		rate := func(p RulePatch) RulePatch { p.Action = ptr("rate_limit"); p.RateLimit = ptr(int64(1)); return p }
		items := []RulePatch{
			c5aPatch(100, "", "3h"), c5aPatch(100, "", "2h"), rate(c5aPatch(100, "", "")),
			c5aPatch(200, "1", "1h"), c5aPatch(200, "1", "3h"), c5aPatch(200, "1", "2h"), c5aPatch(200, "1", ""), c5aPatch(200, "1", "2h"),
			c5aPatch(201, "1", "1h"), c5aPatch(201, "1", ""), c5aPatch(201, "1", "2h"),
			c5aPatch(200, "2", ""), c5aPatch(200, "3", ""), c5aPatch(200, "4", ""), c5aPatch(200, "5", ""), rate(c5aPatch(200, "1", "")),
			{DstCIDR: ptr("198.51.100.0/25")}, {DstCIDR: ptr("198.51.100.0/26")}, c5aPatch(202, "", ""), c5aPatch(203, "", ""), c5aPatch(100, "", ""), c5aPatch(100, "", "2h"),
		}
		for i := 22; i < 50; i++ {
			items = append(items, RulePatch{DstPort: ptr(-1)})
		}
		wantCodes := map[int]string{2: "rule_conflict", 14: "condition_capacity", 15: "rule_conflict", 17: "cidr_overlap", 19: "table_full"}
		existing := map[int]bool{0: true, 1: true, 4: true, 5: true, 6: true, 7: true, 9: true, 10: true, 20: true, 21: true}
		logical := map[int]int64{0: 1, 1: 1, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 8: 3, 9: 3, 10: 3, 11: 4, 12: 5, 13: 6, 16: 7, 18: 8, 20: 1, 21: 1}
		expiry := map[int]string{0: "3h", 1: "3h", 3: "1h", 4: "3h", 5: "3h", 8: "1h"}
		tables := []string{"rules", "claims", "audit", "logical_id_hw", "settings", "users", "sessions", "credentials", "whitelist", "user_prefs", "templates"}
		before := c4bRows(t, s.db.Reader(), tables)
		ledgerBefore := c5aLedgerSnapshot(s.ledger)
		notifications := len(sink.all())
		gen := s.gen
		start := time.Now()
		results := s.BatchValidate(Actor{Kind: Machine, Name: "preview"}, items)
		t.Logf("validate_50_elapsed=%s", time.Since(start))
		check(t, reflect.DeepEqual(before, c4bRows(t, s.db.Reader(), tables)), "preview wrote database/audit/claims/highwater before result checks")
		check(t, len(results) == 50, "batch size")
		classes := map[string]int{}
		for i, r := range results {
			check(t, r.Index == i, "index", i)
			want := wantCodes[i]
			if i >= 22 {
				want = "invalid_rule"
			}
			if want != "" {
				code(t, r.Error, want)
				if i >= 22 {
					check(t, r.Error.Field == "dst_port", "invalid field", i)
				}
				if i == 19 {
					check(t, r.Error.Table == "blacklist", "capacity table")
				}
				classes[want]++
				continue
			}
			check(t, r.Error == nil && r.Existing == existing[i] && r.Rule.LogicalID == logical[i], "independent result", i, r.Error)
			check(t, r.Rule.Enabled && r.Rule.Action == "drop" && r.Rule.RateLimit == 0, "canonical defaults", i)
			if d := expiry[i]; d != "" {
				duration, _ := time.ParseDuration(d)
				want := s.now().Add(duration).UTC().Format(timeFormat)
				check(t, r.Rule.ExpiresAt != nil && *r.Rule.ExpiresAt == want, "expiry projection", i)
			} else {
				check(t, r.Rule.ExpiresAt == nil, "permanent projection", i)
			}
			if i == 0 || i == 1 || i == 20 || i == 21 {
				check(t, r.Rule.ID == seed.ID, "stored ID")
				classes["stored_existing"]++
			} else {
				check(t, r.Rule.ID == "", "temporary success ID")
				if r.Existing {
					classes["batch_existing"]++
				} else {
					classes["new"]++
				}
			}
		}
		for name, want := range map[string]int{"stored_existing": 4, "rule_conflict": 2, "batch_existing": 6, "condition_capacity": 1, "table_full": 1, "invalid_rule": 28, "cidr_overlap": 1, "new": 7} {
			check(t, classes[name] == want, "class count", name, classes[name], want)
		}
		check(t, results[2].Error.RuleID == seed.ID && results[15].Error.RuleID == "batch:3", "conflict references")
		for i, want := range map[int][]string{14: {"batch:11", "batch:12", "batch:13", "batch:14", "batch:3"}, 17: {"batch:16", "batch:17"}} {
			check(t, reflect.DeepEqual(results[i].Error.RuleIDs, want), "batch reference indexes", i, results[i].Error.RuleIDs)
		}
		b, _ := json.Marshal(results)
		check(t, !strings.Contains(string(b), "validate_"), "temporary ID exposure")
		check(t, reflect.DeepEqual(before, c4bRows(t, s.db.Reader(), tables)), "preview wrote database/audit/claims/highwater")
		check(t, reflect.DeepEqual(ledgerBefore, s.ledger) && s.gen == gen && len(sink.all()) == notifications, "preview changed real ledger or notified")
		actual := s.BatchCreate(Actor{Kind: Machine, Name: "preview"}, "claim", items)
		for i, v := range results {
			c := actual[i]
			check(t, (v.Error == nil) == (c.Error == nil), "commit parity error", i)
			if v.Error != nil {
				check(t, v.Error.Code == c.Error.Code && v.Error.Field == c.Error.Field && v.Error.Table == c.Error.Table, "commit error fields", i)
				continue
			}
			projected, committed := v.Rule, c.Rule
			projected.ID, committed.ID = "", ""
			projected.CreatedAt, committed.CreatedAt = "", ""
			projected.UpdatedAt, committed.UpdatedAt = "", ""
			check(t, v.Existing == c.Existing && reflect.DeepEqual(projected, committed), "canonical field parity", i, projected, committed)
		}
		t.Logf("validate_items=50 classes=%v renewal_3h=2 permanent_sequences=3 positive_new=7", classes)
	})
	t.Run("C5A-highwater", func(t *testing.T) {
		for _, high := range []int64{4294967294, 4294967295} {
			s, _ := setup(t)
			sqlExec(t, s, "UPDATE logical_id_hw SET high_water=?", high)
			before := c4bRows(t, s.db.Reader(), []string{"logical_id_hw", "rules", "audit", "claims"})
			r := s.BatchValidate(ui, []RulePatch{c5aPatch(1, "", ""), c5aPatch(2, "", "")})
			if high == 4294967294 {
				check(t, r[0].Error == nil && r[0].Rule.LogicalID == 4294967295, "last free ID")
			} else {
				code(t, r[0].Error, "table_full")
				check(t, r[0].Error.Table == "logical_id", "exhausted table")
			}
			code(t, r[1].Error, "table_full")
			check(t, r[1].Error.Table == "logical_id", "second logical ID")
			check(t, reflect.DeepEqual(before, c4bRows(t, s.db.Reader(), []string{"logical_id_hw", "rules", "audit", "claims"})), "highwater changed")
		}
	})
}
