package api

// ruleIntent is independent of the BPF wire representation. In particular,
// legacy predicates remain significant when a future writer zeros wire fields.
type optionalIntent struct {
	present bool
	value   string
}
type ruleIntent struct {
	exact     RuleKey
	cidr      CIDRRuleKey
	isCIDR    bool
	src, dst  string
	action    uint8
	rate      uint32
	min, max  uint16
	flags     string
	anomaly   uint8
	logicalID uint32
	fields    [6]optionalIntent
	valid     bool
}

func exactIntent(s StoredRule) ruleIntent {
	action, ae := parseAction(s.Action)
	fm, fv, fe := parseTcpFlags(s.TcpFlags)
	i := ruleIntent{exact: s.Key, action: action, rate: s.RateLimit, min: s.PktLenMin, max: s.PktLenMax,
		flags: tcpFlagsToString(fm, fv), anomaly: s.MatchAnomaly, logicalID: s.LogicalID, valid: ae == nil && fe == nil}
	for n, p := range []*string{s.TTL, s.DSCP, s.ICMPType, s.ICMPCode, s.Fragment, s.PktLen} {
		if p != nil {
			i.fields[n] = optionalIntent{true, *p}
		}
	}
	return i
}

func cidrIntent(s StoredCIDRRule) ruleIntent {
	i := exactIntent(StoredRule{Action: s.Action, RateLimit: s.RateLimit, PktLenMin: s.PktLenMin, PktLenMax: s.PktLenMax,
		TcpFlags: s.TcpFlags, MatchAnomaly: s.MatchAnomaly, LogicalID: s.LogicalID,
		TTL: s.TTL, DSCP: s.DSCP, ICMPType: s.ICMPType, ICMPCode: s.ICMPCode, Fragment: s.Fragment, PktLen: s.PktLen})
	i.isCIDR, i.cidr, i.src, i.dst = true, s.Key, s.SrcCIDR, s.DstCIDR
	return i
}

func (h *Handlers) logicalIDOwnerLocked(id string, logicalID uint32) string {
	if logicalID == 0 {
		return ""
	}
	if owner := h.logicalOwners[logicalID]; owner != id {
		return owner
	}
	return ""
}
