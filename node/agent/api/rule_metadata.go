package api

import "fmt"

// Condition fields are opaque metadata until knife five. Reject presence, not
// truthiness: an empty expression is still explicitly provided.
func rejectConditionFields(ttl, dscp, icmpType, icmpCode, fragment, pktLen *string) error {
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"ttl", ttl}, {"dscp", dscp}, {"icmp_type", icmpType},
		{"icmp_code", icmpCode}, {"fragment", fragment}, {"pkt_len", pktLen},
	} {
		if field.value != nil {
			return fmt.Errorf("condition field %s is not supported yet", field.name)
		}
	}
	return nil
}

func (r Rule) rejectConditions() error {
	return rejectConditionFields(r.TTL, r.DSCP, r.ICMPType, r.ICMPCode, r.Fragment, r.PktLen)
}
func (r SyncRule) rejectConditions() error {
	return rejectConditionFields(r.TTL, r.DSCP, r.ICMPType, r.ICMPCode, r.Fragment, r.PktLen)
}

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
