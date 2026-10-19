package api

func ruleToStored(key RuleKey, r Rule) StoredRule {
	return StoredRule{
		Key:          key,
		LogicalID:    r.LogicalID,
		TTL:          r.TTL,
		DSCP:         r.DSCP,
		ICMPType:     r.ICMPType,
		ICMPCode:     r.ICMPCode,
		Fragment:     r.Fragment,
		PktLen:       r.PktLen,
		Action:       r.Action,
		RateLimit:    r.RateLimit,
		PktLenMin:    r.PktLenMin,
		PktLenMax:    r.PktLenMax,
		TcpFlags:     r.TcpFlags,
		MatchAnomaly: r.MatchAnomaly,
	}
}

func ruleToStoredCIDR(key CIDRRuleKey, src, dst string, r Rule) StoredCIDRRule {
	return StoredCIDRRule{
		Key: key, SrcCIDR: src, DstCIDR: dst,
		LogicalID:    r.LogicalID,
		TTL:          r.TTL,
		DSCP:         r.DSCP,
		ICMPType:     r.ICMPType,
		ICMPCode:     r.ICMPCode,
		Fragment:     r.Fragment,
		PktLen:       r.PktLen,
		Action:       r.Action,
		RateLimit:    r.RateLimit,
		PktLenMin:    r.PktLenMin,
		PktLenMax:    r.PktLenMax,
		TcpFlags:     r.TcpFlags,
		MatchAnomaly: r.MatchAnomaly,
	}
}

// preparedRule is the exact-batch intermediate, including all stored metadata.
