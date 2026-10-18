package api

import (
	"fmt"

	"github.com/littlewolf9527/xdrop/node/agent/condexpr"
)

func conditionInput(r Rule) condexpr.Input {
	return condexpr.Input{Tuple: condexpr.Tuple{SrcIP: r.SrcIP, DstIP: r.DstIP, SrcCIDR: r.SrcCIDR, DstCIDR: r.DstCIDR, SrcPort: int(r.SrcPort), DstPort: int(r.DstPort), Protocol: r.Protocol}, Fields: condexpr.Fields{TTL: r.TTL, DSCP: r.DSCP, ICMPType: r.ICMPType, ICMPCode: r.ICMPCode, Fragment: r.Fragment, PktLen: r.PktLen}, TCPFlags: r.TcpFlags, MatchAnomaly: int(r.MatchAnomaly), PktLenMin: int(r.PktLenMin), PktLenMax: int(r.PktLenMax)}
}

// ValidateCanonicalConditionRule is deliberately unreachable from existing
// handlers, replay, storage and startup until knife five enables conditions.
func ValidateCanonicalConditionRule(r Rule) error {
	in := conditionInput(r)
	n, e := condexpr.Compile(in)
	if e != nil {
		return e
	}
	for i, v := range in.Fields.Values() {
		if v != nil && *v != n.Canonical[i] {
			return fmt.Errorf("%s is not canonical", condexpr.Registry()[i].Key)
		}
	}
	if r.TcpFlags != n.TCPFlags {
		return fmt.Errorf("tcp_flags is not canonical")
	}
	return nil
}

// EncodeConditionValue encodes every logical candidate for one five-tuple.
// It builds a complete value locally, so an error never returns a partial row.
func EncodeConditionValue(rules []Rule) (ConditionValue, error) {
	var zero ConditionValue
	if len(rules) == 0 {
		return zero, fmt.Errorf("condition row requires at least one candidate")
	}
	logical := make([]condexpr.Rule, 0, len(rules))
	for _, r := range rules {
		if e := ValidateCanonicalConditionRule(r); e != nil {
			return zero, fmt.Errorf("rule %s: %w", r.ID, e)
		}
		logical = append(logical, condexpr.Rule{Input: conditionInput(r), ID: r.ID, LogicalID: r.LogicalID, Action: r.Action, Rate: r.RateLimit})
	}
	candidates, e := condexpr.Candidates(logical)
	if e != nil {
		return zero, e
	}
	var row ConditionValue
	for k, c := range candidates {
		bit := uint8(1 << k)
		row.Active |= bit
		for i, a := range condexpr.Registry() {
			if a.Kind == condexpr.Interval16 {
				continue
			}
			for v := 0; v <= a.Max; v++ {
				if !condexpr.Allows(c.Sets[i], v) {
					continue
				}
				shift := uint((v & 1) * 4)
				if a.Table >= 0 {
					row.Tab[a.Table][v>>1] |= bit << shift
				} else {
					row.Frag[v>>1] |= bit << shift
				}
			}
		}
		for j, s := range c.Lengths {
			row.Len[k][j] = ConditionSpan{Lo: s.Lo, Hi: s.Hi}
		}
		row.Action[k] = ActionDrop
		if c.Action == "rate_limit" {
			row.Action[k] = ActionRateLimit
		}
		row.Rate[k], row.RuleID[k] = c.Rate, c.LogicalID
		if c.Sets[2] != nil {
			row.TCPReq |= bit
		}
		if c.Sets[3] != nil || c.Sets[4] != nil {
			row.ICMPReq |= bit
		}
	}
	return row, nil
}
