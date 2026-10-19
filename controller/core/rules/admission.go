package rules

import (
	"bytes"
	"fmt"
	"net"
	"sort"

	"github.com/littlewolf9527/xdrop/controller/core/condexpr"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"net/netip"
)

type prefixEntry struct {
	id, raw string
	network *net.IPNet
}

// constraints uses the stored canonical identities, and only enabled members.
func constraints(rows []store.Rule, limit int) []*Error {
	l, errs := buildLedger(rows, 0)
	limits := BuiltinLimits().Values
	for i := TrieDimensionStart; i < TrieDimensionStart+TrieDimensionCount; i++ {
		limits[i] = limit
	}
	return append(errs, ledgerConstraints(l, limits)...)
}
func ledgerConstraints(l *ledger, limits Values) []*Error {
	errs := []*Error{}
	keys := []string{}
	for k := range l.groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := l.groups[k]
		if g.candidates > condexpr.MaxCandidates {
			ids := append([]string{}, g.ids...)
			sort.Strings(ids)
			errs = append(errs, &Error{Code: "condition_capacity", RuleIDs: ids, Message: fmt.Sprintf("physical candidates %d exceed %d", g.candidates, condexpr.MaxCandidates)})
		}
	}
	for i, tree := range l.trees {
		entries := []prefixEntry{}
		ids := []string{}
		for raw, p := range tree {
			_, n, _ := net.ParseCIDR(raw)
			if n == nil {
				continue
			}
			for _, id := range p.ids {
				entries = append(entries, prefixEntry{id, raw, n})
				ids = append(ids, id)
			}
		}
		bucket := trieBucketNames[i]
		errs = append(errs, overlaps(entries, bucket)...)
		if l.occupancy.Used[i+TrieDimensionStart] > limits[i+TrieDimensionStart] {
			sort.Strings(ids)
			errs = append(errs, &Error{Code: "table_full", Table: bucket, RuleIDs: ids, Message: "prefix tree capacity exceeded"})
		}
	}
	for i, used := range l.occupancy.Used {
		if (i < TrieDimensionStart || i == LogicalDimension) && used > limits[i] {
			errs = append(errs, &Error{Code: "table_full", Table: DimensionNames()[i], Message: "capacity exceeded"})
		}
	}
	return errs
}

// overlaps sorts each direction/family bucket, then keeps only containing
// ancestors on the stack. Equal prefixes share a frame. Each child is paired
// with its nearest outer prefix; duplicate outer IDs are reported once, keeping
// both the output and the traversal linear after sorting.
func overlaps(entries []prefixEntry, bucket string) []*Error {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i].network, entries[j].network
		if cmp := bytes.Compare(a.IP, b.IP); cmp != 0 {
			return cmp < 0
		}
		x, _ := a.Mask.Size()
		y, _ := b.Mask.Size()
		if x != y {
			return x < y
		}
		return entries[i].id < entries[j].id
	})
	type frame struct {
		members  []prefixEntry
		reported bool
	}
	stack := []*frame{}
	errs := []*Error{}
	pair := func(a, b string) {
		errs = append(errs, &Error{Code: "cidr_overlap", RuleIDs: []string{a, b}, Message: "nested prefixes in " + bucket})
	}
	for i := 0; i < len(entries); {
		end := i + 1
		for end < len(entries) && entries[end].raw == entries[i].raw {
			end++
		}
		current := &frame{members: entries[i:end]}
		for len(stack) > 0 && !stack[len(stack)-1].members[0].network.Contains(entries[i].network.IP) {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 {
			outer := stack[len(stack)-1]
			for _, p := range current.members {
				pair(outer.members[0].id, p.id)
			}
			if !outer.reported {
				for _, p := range outer.members[1:] {
					pair(p.id, current.members[0].id)
				}
				outer.reported = true
			}
			current.reported = true
		}
		stack = append(stack, current)
		i = end
	}
	return errs
}

func (s *Service) admit(candidate, old store.Rule) *Error {
	return s.admitWith(s.ledger, candidate, old)
}
func (s *Service) admitWith(l *ledger, candidate, old store.Rule) *Error {
	if !candidate.Enabled {
		return nil
	}
	g := l.groups[candidate.GroupKey]
	if old.Enabled && old.GroupKey == candidate.GroupKey {
		n, _ := candidates(&old)
		g.candidates -= n
	}
	n, e := candidates(&candidate)
	if e != nil {
		return e
	}
	if g.candidates+n > condexpr.MaxCandidates {
		ids := []string{candidate.ID}
		for _, id := range g.ids {
			if id != candidate.ID {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		return &Error{Code: "condition_capacity", RuleIDs: ids, Message: fmt.Sprintf("physical candidates %d exceed %d", g.candidates+n, condexpr.MaxCandidates)}
	}
	for direction, raw := range []string{candidate.SrcCIDR, candidate.DstCIDR} {
		if raw == "" {
			continue
		}
		network, err := netip.ParsePrefix(raw)
		if err != nil {
			return bad("cidr", err.Error())
		}
		k := treeIndex(raw, direction)
		witness := ""
		tree := l.trees[k]
		// A host prefix can only overlap a strict ancestor.
		if network.Bits() == network.Addr().BitLen() {
			tree = map[string]ledgerPrefix{}
			for bits := 0; bits < network.Bits(); bits++ {
				raw := netip.PrefixFrom(network.Addr(), bits).Masked().String()
				if p, ok := l.trees[k][raw]; ok {
					tree[raw] = p
				}
			}
		}
		for other, p := range tree {
			if other == raw {
				continue
			}
			if network.Contains(p.network.Addr()) || p.network.Contains(network.Addr()) {
				for _, id := range p.ids {
					if id != candidate.ID && (witness == "" || id < witness) {
						witness = id
					}
				}
			}
		}
		if witness != "" {
			return &Error{Code: "cidr_overlap", RuleIDs: []string{witness, candidate.ID}, Message: "nested prefixes in " + trieBucketNames[k]}
		}
	}
	return s.checkCapacityWith(l, l.delta(old, candidate))
}
