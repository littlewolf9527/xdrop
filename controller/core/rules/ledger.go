package rules

import (
	"net/netip"
	"strings"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

const unconditionalKey = `["","","","","","","",""]`

type ledgerGroup struct {
	kind, members, conditional, candidates int
	ids                                    []string
}
type ledgerPrefix struct {
	network netip.Prefix
	ids     []string
}
type ledger struct {
	occupancy Occupancy
	groups    map[string]ledgerGroup
	trees     [4]map[string]ledgerPrefix
}

func (l *ledger) clone() *ledger {
	out := &ledger{occupancy: l.occupancy, groups: make(map[string]ledgerGroup, len(l.groups))}
	for k, v := range l.groups {
		v.ids = append([]string(nil), v.ids...)
		out.groups[k] = v
	}
	for i, tree := range l.trees {
		out.trees[i] = make(map[string]ledgerPrefix, len(tree))
		for k, v := range tree {
			v.ids = append([]string(nil), v.ids...)
			out.trees[i][k] = v
		}
	}
	return out
}

func candidates(r *store.Rule) (int, *Error) {
	if !r.Enabled {
		return 0, nil
	}
	if r.CondKey == unconditionalKey {
		return 1, nil
	}
	c, e := Canonicalize(r.Match)
	return c.CandidateCount, e
}
func groupCounts(g ledgerGroup) (rows, cond int) {
	if g.members > 0 {
		rows = 1
	}
	if g.members >= 2 || g.conditional > 0 {
		cond = 1
	}
	return
}
func adjustGroup(g ledgerGroup, r *store.Rule, count, sign int) ledgerGroup {
	g.kind = 0
	if r.Kind == "cidr" {
		g.kind = 1
	}
	g.members += sign
	g.candidates += sign * count
	if r.CondKey != unconditionalKey {
		g.conditional += sign
	}
	return g
}
func treeIndex(raw string, direction int) int {
	if !strings.Contains(raw, ":") {
		return direction
	}
	return direction + 2
}
func changeID(ids []string, id string, sign int) []string {
	if sign > 0 {
		return append(ids, id)
	}
	for i, v := range ids {
		if v == id {
			return append(ids[:i], ids[i+1:]...)
		}
	}
	return ids
}
func (l *ledger) change(r store.Rule, sign int) {
	count, _ := candidates(&r)
	l.changeCount(&r, sign, count)
}
func (l *ledger) changeCount(r *store.Rule, sign, count int) {
	l.occupancy.Total += sign
	if !r.Enabled {
		return
	}
	g := l.groups[r.GroupKey]
	before, bc := groupCounts(g)
	f, n := candidateBand(g.candidates)
	g = adjustGroup(g, r, count, sign)
	g.ids = changeID(g.ids, r.ID, sign)
	after, ac := groupCounts(g)
	af, an := candidateBand(g.candidates)
	l.occupancy.Used[g.kind] += after - before
	l.occupancy.Used[g.kind+2] += ac - bc
	l.occupancy.FullKeys += af - f
	l.occupancy.NearKeys += an - n
	l.groups[r.GroupKey] = g
	if g.members == 0 {
		delete(l.groups, r.GroupKey)
	}
	l.occupancy.Used[9] += sign
	for direction, raw := range []string{r.SrcCIDR, r.DstCIDR} {
		if raw == "" {
			continue
		}
		i := treeIndex(raw, direction)
		p := l.trees[i][raw]
		if len(p.ids) == 0 {
			p.network, _ = netip.ParsePrefix(raw)
			l.occupancy.Used[i+5]++
		}
		p.ids = changeID(p.ids, r.ID, sign)
		l.trees[i][raw] = p
		if len(p.ids) == 0 {
			delete(l.trees[i], raw)
			l.occupancy.Used[i+5]--
		}
	}
}
func ledgerCandidates(rows []store.Rule) ([]int, []*Error) {
	counts, errs := make([]int, len(rows)), []*Error{}
	for i := range rows {
		var e *Error
		counts[i], e = candidates(&rows[i])
		if e != nil {
			e.RuleIDs = []string{rows[i].ID}
			errs = append(errs, e)
			counts[i] = -1
		}
	}
	return counts, errs
}
func ledgerMaps(rows []store.Rule, counts []int, whitelistCount int) *ledger {
	l := &ledger{groups: make(map[string]ledgerGroup, len(rows))}
	sizes := [4]int{}
	for i := range rows {
		r := &rows[i]
		if !r.Enabled || counts[i] < 0 {
			continue
		}
		for direction, raw := range []string{r.SrcCIDR, r.DstCIDR} {
			if raw != "" {
				sizes[treeIndex(raw, direction)]++
			}
		}
	}
	for i := range l.trees {
		l.trees[i] = make(map[string]ledgerPrefix, min(sizes[i], TrieLimit))
	}
	l.occupancy.Used[4] = whitelistCount
	for i := range rows {
		if counts[i] >= 0 {
			l.changeCount(&rows[i], 1, counts[i])
		}
	}
	return l
}
func buildLedger(rows []store.Rule, whitelistCount int) (*ledger, []*Error) {
	counts, errs := ledgerCandidates(rows)
	return ledgerMaps(rows, counts, whitelistCount), errs
}
func (s *Service) ensureLedger() *Error {
	if s.ledger != nil {
		return nil
	}
	rows, count, err := store.LedgerRows(s.db.Reader(), unconditionalKey)
	if err != nil {
		return internal(err)
	}
	l, errs := buildLedger(rows, count)
	if len(errs) > 0 {
		return errs[0]
	}
	s.ledger = l
	return nil
}
func (s *Service) Prime(report Report) { s.mu.Lock(); defer s.mu.Unlock(); s.ledger = report.ledger }

// delta projects only the touched groups and prefixes; it never changes the ledger.
func (l *ledger) delta(old, next store.Rule) Values {
	d := Values{}
	groups := map[string]ledgerGroup{}
	prefixes := [4]map[string]int{}
	for i := range prefixes {
		prefixes[i] = map[string]int{}
	}
	for i, r := range []store.Rule{old, next} {
		if r.ID == "" || !r.Enabled {
			continue
		}
		sign := 2*i - 1
		g, ok := groups[r.GroupKey]
		if !ok {
			g = l.groups[r.GroupKey]
		}
		before, bc := groupCounts(g)
		count, _ := candidates(&r)
		g = adjustGroup(g, &r, count, sign)
		after, ac := groupCounts(g)
		d[g.kind] += after - before
		d[g.kind+2] += ac - bc
		groups[r.GroupKey] = g
		d[9] += sign
		for direction, raw := range []string{r.SrcCIDR, r.DstCIDR} {
			if raw == "" {
				continue
			}
			k := treeIndex(raw, direction)
			n, ok := prefixes[k][raw]
			if !ok {
				n = len(l.trees[k][raw].ids)
			}
			if n == 0 {
				d[k+5]++
			}
			n += sign
			if n == 0 {
				d[k+5]--
			}
			prefixes[k][raw] = n
		}
	}
	return d
}
