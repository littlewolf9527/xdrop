package api

import (
	"fmt"

	"github.com/google/uuid"
)

type atomicPreparedRule struct {
	Rule   Rule
	Exact  RuleKey
	CIDR   CIDRRuleKey
	Value  RuleValue
	IsCIDR bool
}

// prepareAtomicRule is shared by the pure preflight and construction stage.
// Existing checks and their diagnostics retain the Step 2 ordering.
func (h *Handlers) prepareAtomicRule(r Rule, memos ...*atomicMemo) (atomicPreparedRule, error) {
	p := atomicPreparedRule{Rule: r, IsCIDR: r.SrcCIDR != "" || r.DstCIDR != ""}
	fail := func(e error) (atomicPreparedRule, error) { return p, e }
	if p.IsCIDR && (r.SrcIP != "" || r.DstIP != "") {
		return fail(fmt.Errorf("exact IP and CIDR cannot be combined"))
	}
	action, err := parseAction(r.Action)
	if err != nil {
		return fail(err)
	}
	if action == ActionRateLimit && r.RateLimit <= 0 {
		return fail(fmt.Errorf("rate_limit must be > 0 for rate_limit action"))
	}
	var fm, fv uint8
	if p.IsCIDR {
		if err := checkAddressFamily(r.SrcCIDR, r.DstCIDR, true); err != nil {
			return fail(err)
		}
		if r.SrcCIDR != "" {
			r.SrcCIDR, err = firstMemo(memos).normalize(r.SrcCIDR)
			if err != nil {
				return fail(fmt.Errorf("invalid src_cidr: %v", err))
			}
		}
		if r.DstCIDR != "" {
			r.DstCIDR, err = firstMemo(memos).normalize(r.DstCIDR)
			if err != nil {
				return fail(fmt.Errorf("invalid dst_cidr: %v", err))
			}
		}
		fm, fv, err = parseTcpFlags(r.TcpFlags)
		if err != nil {
			return fail(err)
		}
		if fm != 0 && parseProtocolLenient(r.Protocol) != ProtoTCP {
			return fail(fmt.Errorf("tcp_flags requires protocol=tcp"))
		}
		if err = validateNodeAnomalyFields(r.MatchAnomaly, r.Action, r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR, firstMemo(memos)); err != nil {
			return fail(err)
		}
		if err = validatePortProtocolCompatNode(r.Protocol, r.SrcPort, r.DstPort); err != nil {
			return fail(err)
		}
		proto, e := parseProtocolStrict(r.Protocol)
		if e != nil {
			return fail(e)
		}
		p.CIDR = CIDRRuleKey{SrcPort: htons(r.SrcPort), DstPort: htons(r.DstPort), Protocol: proto}
		if r.SrcCIDR != "" {
			p.CIDR.SrcID = 1
		}
		if r.DstCIDR != "" {
			p.CIDR.DstID = 1
		}
		if err = validateComboType(getCIDRComboType(p.CIDR)); err != nil {
			return fail(err)
		}
		p.Value = RuleValue{LogicalID: r.LogicalID, Action: action, TcpFlagsMask: fm, TcpFlagsValue: fv, MatchAnomaly: r.MatchAnomaly, RateLimit: r.RateLimit, PktLenMin: r.PktLenMin, PktLenMax: r.PktLenMax}
	} else {
		if err = validateRule(r.SrcIP, r.DstIP, r.Protocol, r.SrcPort, r.DstPort, r.PktLenMin, r.PktLenMax); err != nil {
			return fail(err)
		}
		if err = validateNodeAnomalyFields(r.MatchAnomaly, r.Action, r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR, firstMemo(memos)); err != nil {
			return fail(err)
		}
		p.Exact, err = h.ruleToKey(r)
		if err != nil {
			return fail(err)
		}
		if err = validateComboType(getComboType(p.Exact)); err != nil {
			return fail(err)
		}
		fm, fv, err = parseTcpFlags(r.TcpFlags)
		if err != nil {
			return fail(err)
		}
		if fm != 0 && parseProtocolLenient(r.Protocol) != ProtoTCP {
			return fail(fmt.Errorf("tcp_flags requires protocol=tcp"))
		}
		p.Value = RuleValue{LogicalID: r.LogicalID, Action: action, TcpFlagsMask: fm, TcpFlagsValue: fv, MatchAnomaly: r.MatchAnomaly, RateLimit: r.RateLimit, PktLenMin: r.PktLenMin, PktLenMax: r.PktLenMax}
	}
	r.TcpFlags = tcpFlagsToString(fm, fv)
	if err = normalizeConditionRule(&r); err != nil {
		return fail(err)
	}
	p.Rule = r
	p.Value = markConditionValue(r, p.Value)
	return p, nil
}

type atomicConditionGroup struct {
	Key       groupIdentity
	Indexes   []int
	Members   []atomicPreparedRule
	Condition bool
	Row       ConditionValue
}

type atomicConditionConflict struct {
	ID     string `json:"id"`
	Index  *int   `json:"index,omitempty"`
	Reason string `json:"reason"`
}
type atomicConditionGroupError struct {
	Key       groupIdentity
	Conflicts []atomicConditionConflict
}

func (e *atomicConditionGroupError) Error() string {
	return "condition group invalid; batch not published"
}
func conditionGroupFailure(g *atomicConditionGroup, rules []Rule, reason string) *atomicConditionGroupError {
	e := &atomicConditionGroupError{Key: g.Key, Conflicts: make([]atomicConditionConflict, 0, len(g.Indexes))}
	for _, i := range g.Indexes {
		c := atomicConditionConflict{ID: rules[i].ID, Reason: reason}
		if c.ID == "" {
			index := i
			c.Index = &index
		}
		e.Conflicts = append(e.Conflicts, c)
	}
	return e
}

// preflightAtomicConditions does no BPF, Manager, receipt or ledger mutation.
// Classification uses the original request before any invalid member is removed.
func (h *Handlers) preflightAtomicConditions(rules []Rule, memos ...*atomicMemo) (map[int]*atomicConditionGroup, error) {
	byKey := make(map[groupIdentity]*atomicConditionGroup)
	byIndex := make(map[int]*atomicConditionGroup)
	var ordered []*atomicConditionGroup
	for i, r := range rules {
		key, err := h.classifyRuleKey(r, firstMemo(memos))
		if err != nil {
			continue
		}
		g := byKey[key]
		if g == nil {
			g = &atomicConditionGroup{Key: key}
			byKey[key] = g
			ordered = append(ordered, g)
		}
		g.Indexes = append(g.Indexes, i)
		byIndex[i] = g
	}
	for _, g := range ordered {
		raw := make([]Rule, 0, len(g.Indexes))
		for _, i := range g.Indexes {
			raw = append(raw, rules[i])
		}
		g.Condition = conditionGroup(raw)
		if !g.Condition {
			continue
		}
		var normalized []Rule
		var failures []error
		for _, i := range g.Indexes {
			p, err := h.prepareAtomicAt(rules[i], i, firstMemo(memos))
			failures = append(failures, err)
			if err == nil {
				if p.Rule.ID == "" {
					p.Rule.ID = uuid.NewString()
				}
				g.Members = append(g.Members, p)
				normalized = append(normalized, p.Rule)
			}
		}
		for _, err := range failures {
			if err != nil {
				e := conditionGroupFailure(g, rules, err.Error())
				for j, own := range failures {
					if own != nil {
						e.Conflicts[j].Reason = own.Error()
					}
				}
				return nil, e
			}
		}
		row, err := EncodeConditionValue(normalized)
		if err != nil {
			return nil, conditionGroupFailure(g, rules, err.Error())
		}
		g.Row = row
	}
	return byIndex, nil
}
