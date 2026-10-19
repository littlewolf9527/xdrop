package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"github.com/littlewolf9527/xdrop/node/agent/condexpr"
)

type CommitGroup struct {
	Key   json.RawMessage `json:"key"`
	Rules []Rule          `json:"rules"`
}

type CommitGroupResult struct {
	Index         int            `json:"index"`
	Result        string         `json:"result,omitempty"`
	Code          string         `json:"code,omitempty"`
	Error         string         `json:"error,omitempty"`
	RuleID        string         `json:"rule_id,omitempty"`
	UndeclaredKey *groupIdentity `json:"undeclared_key,omitempty"`
	RuleIDs       []string       `json:"rule_ids,omitempty"`
	Table         string         `json:"table,omitempty"`
	Excess        int            `json:"excess,omitempty"`
}

type CommitResult struct {
	Code    string              `json:"code"`
	Groups  []CommitGroupResult `json:"groups"`
	Receipt string              `json:"receipt,omitempty"`
}

type commitError struct {
	Status  int
	Code    string
	Message string
	Groups  []CommitGroupResult
}

func (e *commitError) Error() string { return e.Message }

func commitReject(index int, status int, code, message string) *commitError {
	return &commitError{status, code, message, []CommitGroupResult{{Index: index, Code: code, Error: message}}}
}

type commitPreparedGroup struct {
	Index            int
	Key              groupIdentity
	Members          []atomicPreparedRule
	Old              map[string]Rule
	Value, Condition []byte
	Physical         []byte
	Known            bool
	Changed          bool
}
type commitPlan struct {
	Groups             []*commitPreparedGroup
	Result             CommitResult
	Changed            bool
	HasCIDR            bool
	Rows               [4]int
	Combos, CIDRCombos [64]int
	LogicalIDs         map[uint32]bool
}

func (h *Handlers) canonicalCommitKey(raw json.RawMessage) (groupIdentity, error) {
	var supplied groupIdentity
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&supplied); err != nil {
		return groupIdentity{}, err
	}
	if supplied.Kind != "exact" && supplied.Kind != "cidr" {
		return groupIdentity{}, fmt.Errorf("key.kind must be exact or cidr")
	}
	if supplied.Kind == "cidr" && supplied.SrcCIDR == "" && supplied.DstCIDR == "" {
		return groupIdentity{}, fmt.Errorf("CIDR key requires a prefix")
	}
	r := Rule{SrcIP: supplied.SrcIP, DstIP: supplied.DstIP, SrcCIDR: supplied.SrcCIDR, DstCIDR: supplied.DstCIDR, SrcPort: supplied.SrcPort, DstPort: supplied.DstPort, Protocol: supplied.Protocol}
	canonical, err := h.classifyRuleKey(r)
	if err != nil {
		return groupIdentity{}, err
	}
	b, err := json.Marshal(canonical)
	if err != nil {
		return groupIdentity{}, err
	}
	var got, want map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		return groupIdentity{}, err
	}
	if err := json.Unmarshal(b, &want); err != nil {
		return groupIdentity{}, err
	}
	if !reflect.DeepEqual(got, want) {
		return groupIdentity{}, fmt.Errorf("key must use its canonical form")
	}
	if _, err := h.prepareAtomicRule(Rule{SrcIP: canonical.SrcIP, DstIP: canonical.DstIP, SrcCIDR: canonical.SrcCIDR, DstCIDR: canonical.DstCIDR, SrcPort: canonical.SrcPort, DstPort: canonical.DstPort, Protocol: canonical.Protocol, LogicalID: 1}); err != nil {
		return groupIdentity{}, err
	}
	return canonical, nil
}

// P5 preserves the typed compiler error, including its occupying rule IDs.
func encodeCommitGroup(rules []Rule) ([]byte, error) {
	row, err := EncodeConditionValue(rules)
	if err != nil {
		return nil, err
	}
	return conditionValueToBytes(row), nil
}

func commitEncodingError(index int, err error) *commitError {
	var capacity *condexpr.CapacityError
	if errors.As(err, &capacity) {
		e := commitReject(index, http.StatusConflict, "condition_capacity", err.Error())
		e.Groups[0].RuleIDs = append([]string(nil), capacity.RuleIDs...)
		return e
	}
	return commitReject(index, http.StatusBadRequest, mutationInvalid, err.Error())
}

func (h *Handlers) commitPhysicalKey(g groupIdentity) ([]byte, bool, error) {
	if g.Kind == "exact" {
		return ruleKeyToBytes(g.exactKey), true, nil
	}
	if h.cidrMgr == nil {
		return nil, false, nil
	}
	var src, dst uint32
	var ok bool
	if g.SrcCIDR != "" {
		src, ok = h.cidrMgr.GetSrcID(g.SrcCIDR)
		if !ok {
			return nil, false, nil
		}
	}
	if g.DstCIDR != "" {
		dst, ok = h.cidrMgr.GetDstID(g.DstCIDR)
		if !ok {
			return nil, false, nil
		}
	}
	// Protocol has already passed classifyRuleKey's strict parser.
	p, err := h.prepareAtomicRule(Rule{SrcCIDR: g.SrcCIDR, DstCIDR: g.DstCIDR, SrcPort: g.SrcPort, DstPort: g.DstPort, Protocol: g.Protocol, LogicalID: 1})
	if err != nil {
		return nil, false, err
	}
	k := p.CIDR
	k.SrcID, k.DstID = src, dst
	return cidrRuleKeyToBytes(k), true, nil
}

func readCommitRow(m ruleMirrorMap, key []byte, known bool) ([]byte, error) {
	if !known {
		return nil, nil
	}
	if m == nil {
		return nil, fmt.Errorf("map unavailable")
	}
	v := make([]byte, m.ValueSize())
	if err := m.Lookup(key, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}

func (h *Handlers) sameCommitMembers(g *commitPreparedGroup) bool {
	if len(g.Old) != len(g.Members) {
		return false
	}
	for _, p := range g.Members {
		if _, exists := g.Old[p.Rule.ID]; !exists {
			return false
		}
		if p.IsCIDR {
			old := h.cidrRules[p.Rule.ID]
			if !sameCIDRContent(old, p.Rule.SrcCIDR, p.Rule.DstCIDR, p.CIDR.SrcPort, p.CIDR.DstPort, p.CIDR.Protocol, p.Rule) {
				return false
			}
		} else if !sameExactContent(h.rules[p.Rule.ID], p.Exact, p.Rule) {
			return false
		}
	}
	return true
}

// S+P serialize writers; r protects index reads. P1-P7 do no writes, receipt,
// reservation or bookkeeping mutation. Capacity payment is a separate phase.
func (h *Handlers) preflightCommit(groups []CommitGroup) (*commitPlan, *commitError) {
	p := &commitPlan{Result: CommitResult{Code: "unchanged", Groups: make([]CommitGroupResult, len(groups))}, LogicalIDs: make(map[uint32]bool)}
	declared := make(map[groupIdentity]int, len(groups))
	ids := make(map[string]int)
	logical := make(map[uint32]string)
	for i, group := range groups {
		key, err := h.canonicalCommitKey(group.Key)
		if err != nil {
			return nil, commitReject(i, 400, mutationInvalid, err.Error())
		}
		if _, duplicate := declared[key]; duplicate {
			return nil, commitReject(i, 400, mutationInvalid, "key occurs in more than one group")
		}
		declared[key] = i
		g := &commitPreparedGroup{Index: i, Key: key}
		var normalized []Rule
		for _, r := range group.Rules {
			if r.ID == "" {
				return nil, commitReject(i, 400, mutationInvalid, "rule id must be nonempty")
			}
			prepared, err := h.prepareAtomicRule(r)
			if err != nil {
				return nil, commitReject(i, 400, mutationInvalid, err.Error())
			}
			if err := validateLogicalID(r.LogicalID); err != nil {
				return nil, commitReject(i, 400, mutationInvalid, err.Error())
			}
			actual, err := h.classifyRuleKey(prepared.Rule)
			if err != nil || actual != key {
				return nil, commitReject(i, 400, mutationInvalid, "rule key differs from declared group key")
			}
			if first, duplicate := ids[r.ID]; duplicate {
				e := commitReject(first, 409, "duplicate_id", "rule ID occurs more than once in request")
				e.Groups[0].RuleID = r.ID
				if first != i {
					e.Groups = append(e.Groups, CommitGroupResult{Index: i, Code: e.Code, Error: e.Message, RuleID: r.ID})
				}
				return nil, e
			}
			ids[r.ID] = i
			if owner, duplicate := logical[r.LogicalID]; duplicate {
				return nil, commitReject(i, 409, "duplicate_logical_id", fmt.Sprintf("logical ID is held by rule %q", owner))
			}
			logical[r.LogicalID], p.LogicalIDs[r.LogicalID] = r.ID, true
			g.Members = append(g.Members, prepared)
			normalized = append(normalized, prepared.Rule)
		}
		if len(g.Members) > 0 {
			value := g.Members[0].Value
			if conditionGroup(normalized) {
				g.Condition, err = encodeCommitGroup(normalized)
				if err != nil {
					return nil, commitEncodingError(i, err)
				}
				// The deterministic first candidate supplies the unused row action.
				value.Pad2[0] = RuleHasConditions
				value.Action = g.Condition[conditionActionOffset]
				value.RateLimit = commitUint32(g.Condition[conditionRateOffset : conditionRateOffset+4])
				value.LogicalID = commitUint32(g.Condition[conditionRuleIDOffset : conditionRuleIDOffset+4])
			}
			g.Value = ruleValueToBytes(value)
		}
		p.Groups = append(p.Groups, g)
		p.HasCIDR = p.HasCIDR || key.Kind == "cidr"
	}
	if err := h.preflightCommitMemory(p, declared); err != nil {
		return nil, err
	}
	if err := h.preflightCommitPrefixes(p); err != nil {
		return nil, err
	}
	active := int(h.activeRuleSlot.Load())
	p.Rows = h.ruleRowCounts
	if !h.ruleRowCountsKnown && len(groups) > 0 {
		for kind := range p.Rows {
			keys, err := mirrorKeys(h.mirrorTable(active, kind))
			if err != nil {
				return nil, &commitError{Status: 500, Code: "commit_failed", Message: err.Error()}
			}
			p.Rows[kind] = len(keys)
		}
	}
	for _, g := range p.Groups {
		var err error
		g.Physical, g.Known, err = h.commitPhysicalKey(g.Key)
		if err != nil {
			return nil, commitReject(g.Index, 400, mutationInvalid, err.Error())
		}
		kind, cond := mirrorExact, mirrorCondition
		if g.Key.Kind == "cidr" {
			kind, cond = mirrorCIDR, mirrorCIDRCondition
		}
		oldRule, err := readCommitRow(h.mirrorTable(active, kind), g.Physical, g.Known)
		if err != nil {
			return nil, &commitError{Status: 500, Code: "commit_failed", Message: err.Error()}
		}
		oldCond, err := readCommitRow(h.mirrorTable(active, cond), g.Physical, g.Known)
		if err != nil {
			return nil, &commitError{Status: 500, Code: "commit_failed", Message: err.Error()}
		}
		g.Changed = g.Changed || !bytes.Equal(oldRule, g.Value) || !bytes.Equal(oldCond, g.Condition)
		result := "unchanged"
		if g.Changed {
			p.Changed = true
			result = "replaced"
			if len(g.Members) == 0 {
				result = "deleted"
			} else if len(g.Old) == 0 {
				result = "created"
			}
		}
		p.Result.Groups[g.Index] = CommitGroupResult{Index: g.Index, Result: result}
		for _, row := range []struct {
			kind      int
			old, next []byte
		}{{kind, oldRule, g.Value}, {cond, oldCond, g.Condition}} {
			if row.old != nil {
				p.Rows[row.kind]--
			}
			if row.next != nil {
				p.Rows[row.kind]++
			}
		}
		refs := &p.Combos
		combo := getComboType(g.Key.exactKey)
		if g.Key.Kind == "cidr" {
			refs = &p.CIDRCombos
			probe, err := h.prepareAtomicRule(Rule{SrcCIDR: g.Key.SrcCIDR, DstCIDR: g.Key.DstCIDR, SrcPort: g.Key.SrcPort, DstPort: g.Key.DstPort, Protocol: g.Key.Protocol, LogicalID: 1})
			if err != nil {
				return nil, commitReject(g.Index, 400, mutationInvalid, err.Error())
			}
			combo = getCIDRComboType(probe.CIDR)
		}
		if combo >= 0 && combo < 64 {
			if len(g.Old) > 0 {
				refs[combo]--
			}
			if len(g.Members) > 0 {
				refs[combo]++
			}
		}
	}
	for kind, count := range p.Rows {
		capacity := h.commitTableCapacity[kind]
		if capacity == 0 {
			m := h.mirrorTable(1-active, kind)
			if m == nil && len(groups) == 0 {
				continue
			}
			if m == nil {
				return nil, &commitError{Status: 500, Code: "commit_failed", Message: "shadow map unavailable"}
			}
			capacity = int(m.MaxEntries())
		}
		if count > capacity {
			return nil, commitCapacityError(0, mirrorNames[kind], count-capacity)
		}
	}
	return p, nil
}

func commitCapacityError(index int, table string, excess int) *commitError {
	e := commitReject(index, 409, "table_full", fmt.Sprintf("%s capacity exceeded by %d rows", table, excess))
	e.Groups[0].Table, e.Groups[0].Excess = table, excess
	return e
}

func (h *Handlers) preflightCommitPrefixes(p *commitPlan) *commitError {
	if !p.HasCIDR {
		return nil
	}
	if h.cidrMgr == nil {
		return &commitError{Status: 500, Code: "commit_failed", Message: "CIDR manager unavailable"}
	}
	old := [2][]string{h.cidrMgr.ListSrcCIDRs(), h.cidrMgr.ListDstCIDRs()}
	union := [2][]string{append([]string(nil), old[0]...), append([]string(nil), old[1]...)}
	seen := [2]map[string]bool{{}, {}}
	parsed := make(map[string]*net.IPNet)
	for d, prefixes := range old {
		for _, prefix := range prefixes {
			seen[d][prefix] = true
		}
	}
	for _, g := range p.Groups {
		if len(g.Members) == 0 {
			continue
		}
		for direction, prefix := range []string{g.Key.SrcCIDR, g.Key.DstCIDR} {
			if prefix == "" || seen[direction][prefix] {
				continue
			}
			if conflict, err := cidr.CheckOverlap(prefix, union[direction], parsed); err != nil || conflict != "" {
				return commitReject(g.Index, 409, "cidr_overlap", fmt.Sprintf("prefix %s overlaps %s", prefix, conflict))
			}
			seen[direction][prefix] = true
			union[direction] = append(union[direction], prefix)
		}
	}
	// Count the complete resulting policy; overlap still uses the live union above.
	next := [2]map[string]int{{}, {}}

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
	count := h.cidrMgr.CountsAfter(next)
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

// Snapshot only the touched groups under r; no map I/O or prefix scan holds r.
func (h *Handlers) preflightCommitMemory(p *commitPlan, declared map[groupIdentity]int) *commitError {
	h.rulesMu.RLock()
	defer h.rulesMu.RUnlock()
	p.Combos, p.CIDRCombos = h.comboRefCount, h.cidrComboRefCount
	for _, g := range p.Groups {
		g.Old = h.currentGroupLocked(g.Key)
		g.Changed = !h.sameCommitMembers(g)
		for _, member := range g.Members {
			r := member.Rule
			if old, exists := h.storedGroupRule(r.ID); exists {
				oldKey, _ := h.classifyRuleKey(old)
				if _, declaredOld := declared[oldKey]; !declaredOld {
					e := commitReject(g.Index, 409, "group_undeclared", "rule ID belongs to an undeclared group")
					e.Groups[0].UndeclaredKey, e.Groups[0].RuleID = &oldKey, r.ID
					return e
				}
				if old.LogicalID != r.LogicalID {
					return commitReject(g.Index, 409, mutationDifferent, "logical identity can only change through full sync")
				}
			}
			if owner := h.logicalIDOwnerLocked(r.ID, r.LogicalID); owner != "" {
				old, exists := h.storedGroupRule(owner)
				oldKey, _ := h.classifyRuleKey(old)
				_, replacing := declared[oldKey]
				if !exists || !replacing {
					return commitReject(g.Index, 409, "duplicate_logical_id", fmt.Sprintf("logical ID is held by rule %q", owner))
				}
			}
		}
	}
	return nil
}
