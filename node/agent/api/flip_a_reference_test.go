package api

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"testing"
)

// Frozen reference bodies from 021db2d: only function names and the overlap
// callee are renamed. They must never call the optimized overlap/count paths.
func (h *Handlers) flipAReferencePrefixes(p *commitPlan) *commitError {
	if !p.HasCIDR {
		return nil
	}
	if h.cidrMgr == nil {
		return &commitError{Status: 500, Code: "commit_failed", Message: "CIDR manager unavailable"}
	}
	old := [2][]string{h.cidrMgr.ListSrcCIDRs(), h.cidrMgr.ListDstCIDRs()}
	union := [2][]string{append([]string(nil), old[0]...), append([]string(nil), old[1]...)}
	for _, g := range p.Groups {
		if len(g.Members) == 0 {
			continue
		}
		for direction, prefix := range []string{g.Key.SrcCIDR, g.Key.DstCIDR} {
			if prefix == "" {
				continue
			}
			if conflict, err := flipAReferenceOverlap(prefix, union[direction]); err != nil || conflict != "" {
				return commitReject(g.Index, 409, "cidr_overlap", fmt.Sprintf("prefix %s overlaps %s", prefix, conflict))
			}
			found := false
			for _, existing := range union[direction] {
				if prefix == existing {
					found = true
					break
				}
			}
			if !found {
				union[direction] = append(union[direction], prefix)
			}
		}
	}
	// Count the complete resulting policy; overlap still uses the live union above.
	next := [2]map[string]int{{}, {}}
	h.rulesMu.RLock()
	for d, prefixes := range prefixReferences(h.cidrRules) {
		for _, prefix := range prefixes {
			next[d][prefix]++
		}
	}
	h.rulesMu.RUnlock()
	for _, g := range p.Groups {
		for _, r := range g.Old {
			for d, prefix := range []string{r.SrcCIDR, r.DstCIDR} {
				next[d][prefix]--
			}
		}
		for _, member := range g.Members {
			for d, prefix := range []string{member.Rule.SrcCIDR, member.Rule.DstCIDR} {
				next[d][prefix]++
			}
		}
	}
	var count [4]int
	for d := range next {
		for prefix, refs := range next[d] {
			if prefix == "" || refs <= 0 {
				continue
			}
			ip, _, _ := net.ParseCIDR(prefix)
			k := d
			if ip.To4() == nil {
				k += 2
			}
			count[k]++
		}
	}
	capacities := h.cidrMgr.TrieCapacities()
	names := [4]string{"sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie"}
	for k, used := range count {
		capacity := h.commitTrieCapacity[k]
		if capacity == 0 {
			capacity = int(capacities[k])
		}
		if used > capacity {
			return commitCapacityError(0, names[k], used-capacity)
		}
	}
	return nil
}

func flipAReferenceOverlap(newCIDR string, existingCIDRs []string) (string, error) {
	_, newNet, err := net.ParseCIDR(newCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %s", newCIDR)
	}

	for _, existing := range existingCIDRs {
		_, existNet, err := net.ParseCIDR(existing)
		if err != nil {
			continue
		}

		// Same CIDR → not a conflict
		if newNet.String() == existNet.String() {
			continue
		}

		// Strict containment: one contains the other
		if existNet.Contains(newNet.IP) || newNet.Contains(existNet.IP) {
			return existing, nil
		}
	}
	return "", nil
}

func (h *Handlers) flipAReferenceUnion(next map[uint32]bool) int {
	ids := make(map[uint32]bool, len(h.logicalOwners)+len(next)+len(h.pendingLogicalIDs))
	for id := range h.logicalOwners {
		ids[id] = true
	}
	for id := range next {
		ids[id] = true
	}
	for id := range h.pendingLogicalIDs {
		ids[id] = true
	}
	return len(ids)
}

// 甲-3: ordered overlap diagnostics, retiring prefixes and all four capacity axes.
func TestFlipAPreflightEquivalent(t *testing.T) {
	rng := rand.New(rand.NewSource(93))
	for trial := 0; trial < 160; trial++ {
		f := cut55Memory(t)
		old := []Rule{{ID: "v4", LogicalID: 1, SrcCIDR: "192.0.2.0/24", DstCIDR: "198.51.100.0/24", Action: "drop"}, {ID: "v6", LogicalID: 2, SrcCIDR: "2001:db8:1::/64", DstCIDR: "2001:db8:2::/64", Action: "drop"}}
		cut55Commit(t, f.h, cut55Group(t, f.h, old[0], old[0]), cut55Group(t, f.h, old[1], old[1]))
		p := &commitPlan{HasCIDR: true}
		for _, r := range old {
			p.Groups = append(p.Groups, &commitPreparedGroup{Index: len(p.Groups), Old: map[string]Rule{r.ID: r}})
		}
		prefixes := []string{"192.0.2.0/25", "203.0.113.0/25", "203.0.113.128/25", "203.0.113.0/24", "2001:db8:1::/65", "2001:db8:3::/64", "2001:db8:4::/64", "2001:db8:3::/63"}
		for i := 0; i < 4; i++ {
			j := rng.Intn(len(prefixes))
			if trial == 0 {
				j = []int{1, 2, 3, 0}[i]
			}
			r := Rule{ID: fmt.Sprint(i), LogicalID: uint32(i + 3), SrcCIDR: prefixes[j], Action: "drop"}
			if trial%2 == 1 {
				r.DstCIDR, r.SrcCIDR = r.SrcCIDR, ""
			}
			prepared, err := f.h.prepareAtomicRule(r)
			if err != nil {
				t.Fatal(err)
			}
			key, err := f.h.classifyRuleKey(r)
			if err != nil {
				t.Fatal(err)
			}
			p.Groups = append(p.Groups, &commitPreparedGroup{Index: len(p.Groups), Key: key, Members: []atomicPreparedRule{prepared}})
		}
		for k := range f.h.commitTrieCapacity {
			f.h.commitTrieCapacity[k] = 1 + rng.Intn(3)
		}
		want, got := f.h.flipAReferencePrefixes(p), f.h.preflightCommitPrefixes(p)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("preflight diagnostics trial=%d got=%+v want=%+v", trial, got, want)
		}
	}
}

// 甲-3: Used/Excess count owners ∪ pending ∪ requested IDs, including overlaps.
func TestFlipALogicalUnion(t *testing.T) {
	rng := rand.New(rand.NewSource(94))
	for trial := 0; trial < 128; trial++ {
		h := &Handlers{logicalOwners: map[uint32]string{}, pendingLogicalIDs: map[uint32]bool{}, logicalStateCapacity: 1 + trial%16}
		h.quiescer = cut5ReceiptFunc(func() error { return fmt.Errorf("retain pending witness") })
		next := map[uint32]bool{}
		for id := uint32(1); id <= 16; id++ {
			if rng.Intn(2) == 0 {
				h.logicalOwners[id] = "owner"
			}
			if rng.Intn(2) == 0 {
				h.pendingLogicalIDs[id] = true
			}
			if rng.Intn(2) == 0 {
				next[id] = true
			}
		}
		used := h.flipAReferenceUnion(next)
		a := h.newLogicalAdmissionLocked()
		for id := range next {
			a.reserve(id)
		}
		if a.used != used {
			t.Fatalf("union Used=%d want=%d", a.used, used)
		}
		got := h.admitCommitLogicalLocked(&commitPlan{LogicalIDs: next})
		var want *commitError
		if used > h.logicalCapacity() {
			want = commitCapacityError(0, "logical_state", used-h.logicalCapacity())
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("union diagnostics got=%+v want=%+v", got, want)
		}
		var rules []Rule
		for id := range next {
			rules = append(rules, cut55Rule(fmt.Sprint(id), id, "192.0.2.1"))
		}
		var wantAtomic error
		if used > h.logicalCapacity() {
			wantAtomic = &logicalTableFullError{used, h.logicalCapacity()}
		}
		if gotAtomic := h.admitAtomicLogicalIDs(rules); !reflect.DeepEqual(gotAtomic, wantAtomic) || fmt.Sprint(gotAtomic) != fmt.Sprint(wantAtomic) {
			t.Fatalf("atomic union Used/diagnostic got=%v want=%v", gotAtomic, wantAtomic)
		}
	}
}
