// XDrop Agent - API <-> BPF internal type conversions
package api

import (
	"fmt"
	"log/slog"
	"net"
)

func (h *Handlers) ruleToKey(r Rule) (RuleKey, error) {
	key := RuleKey{}

	if r.SrcIP != "" && r.SrcIP != "0.0.0.0" && r.SrcIP != "::" {
		ip := net.ParseIP(r.SrcIP)
		if ip == nil {
			return key, fmt.Errorf("invalid src_ip: %s", r.SrcIP)
		}
		key.SrcIP = ipToIPAddr(ip)
	}

	if r.DstIP != "" && r.DstIP != "0.0.0.0" && r.DstIP != "::" {
		ip := net.ParseIP(r.DstIP)
		if ip == nil {
			return key, fmt.Errorf("invalid dst_ip: %s", r.DstIP)
		}
		key.DstIP = ipToIPAddr(ip)
	}

	key.SrcPort = htons(r.SrcPort)
	key.DstPort = htons(r.DstPort)
	key.Protocol = parseProtocol(r.Protocol)

	return key, nil
}

func (h *Handlers) whitelistToKey(w WhitelistEntry) (RuleKey, error) {
	key := RuleKey{}

	if w.SrcIP != "" && w.SrcIP != "0.0.0.0" && w.SrcIP != "::" {
		ip := net.ParseIP(w.SrcIP)
		if ip == nil {
			return key, fmt.Errorf("invalid src_ip: %s", w.SrcIP)
		}
		key.SrcIP = ipToIPAddr(ip)
	}

	if w.DstIP != "" && w.DstIP != "0.0.0.0" && w.DstIP != "::" {
		ip := net.ParseIP(w.DstIP)
		if ip == nil {
			return key, fmt.Errorf("invalid dst_ip: %s", w.DstIP)
		}
		key.DstIP = ipToIPAddr(ip)
	}

	key.SrcPort = htons(w.SrcPort)
	key.DstPort = htons(w.DstPort)
	key.Protocol = parseProtocol(w.Protocol)

	return key, nil
}

func (h *Handlers) storedRuleToRule(id string, s StoredRule) Rule {
	action := s.Action
	if action == "" {
		action = "drop"
	}
	return Rule{
		ID:           id,
		SrcIP:        ipAddrToString(s.Key.SrcIP),
		DstIP:        ipAddrToString(s.Key.DstIP),
		SrcPort:      ntohs(s.Key.SrcPort),
		DstPort:      ntohs(s.Key.DstPort),
		Protocol:     protocolToString(s.Key.Protocol),
		Action:       action,
		RateLimit:    s.RateLimit,
		PktLenMin:    s.PktLenMin,
		PktLenMax:    s.PktLenMax,
		TcpFlags:     s.TcpFlags,
		MatchAnomaly: s.MatchAnomaly, // AUD-004
	}
}

func (h *Handlers) storedCIDRRuleToRule(id string, s StoredCIDRRule) Rule {
	action := s.Action
	if action == "" {
		action = "drop"
	}
	return Rule{
		ID:           id,
		SrcCIDR:      s.SrcCIDR,
		DstCIDR:      s.DstCIDR,
		SrcPort:      ntohs(s.Key.SrcPort),
		DstPort:      ntohs(s.Key.DstPort),
		Protocol:     protocolToString(s.Key.Protocol),
		Action:       action,
		RateLimit:    s.RateLimit,
		PktLenMin:    s.PktLenMin,
		PktLenMax:    s.PktLenMax,
		TcpFlags:     s.TcpFlags,
		MatchAnomaly: s.MatchAnomaly, // AUD-004
	}
}

func (h *Handlers) keyToWhitelist(id string, k RuleKey) WhitelistEntry {
	return WhitelistEntry{
		ID:       id,
		SrcIP:    ipAddrToString(k.SrcIP),
		DstIP:    ipAddrToString(k.DstIP),
		SrcPort:  ntohs(k.SrcPort),
		DstPort:  ntohs(k.DstPort),
		Protocol: protocolToString(k.Protocol),
	}
}

// validateNodeAnomalyFields is a defence-in-depth anomaly semantic guard for
// the Node direct HTTP API. The Controller enforces the same constraints; this
// protects against direct access that bypasses the Controller.
func validateNodeAnomalyFields(matchAnomaly uint8, action, srcIP, dstIP, srcCIDR, dstCIDR string) error {
	if matchAnomaly == 0 {
		return nil
	}
	const validBits = AnomalyBadFragment | AnomalyInvalid
	if matchAnomaly&^validBits != 0 {
		return fmt.Errorf("invalid match_anomaly bits: 0x%x (valid: 0x%x)", matchAnomaly, validBits)
	}
	if action == "rate_limit" {
		return fmt.Errorf("anomaly rules are drop-only (match_anomaly != 0 requires action=drop)")
	}
	// Must have a real key constraint (0.0.0.0/:: are treated as unset by ruleToKey)
	hasBounded := false
	for _, s := range []string{srcIP, dstIP} {
		if s != "" && s != "0.0.0.0" && s != "::" {
			ip := net.ParseIP(s)
			if ip != nil && !ip.IsUnspecified() {
				hasBounded = true
			}
		}
	}
	for _, s := range []string{srcCIDR, dstCIDR} {
		if s != "" {
			_, n, err := net.ParseCIDR(s)
			if err == nil {
				ones, _ := n.Mask.Size()
				if ones > 0 {
					hasBounded = true
				}
			}
		}
	}
	if !hasBounded {
		return fmt.Errorf("anomaly rule requires a bounded target (src/dst IP must not be empty/wildcard, CIDR must not be /0)")
	}
	if matchAnomaly&AnomalyBadFragment != 0 {
		for _, s := range []string{srcIP, dstIP} {
			if s != "" {
				ip := net.ParseIP(s)
				if ip != nil && ip.To4() == nil && !ip.IsUnspecified() {
					return fmt.Errorf("bad_fragment not supported for IPv6 target")
				}
			}
		}
		for _, s := range []string{srcCIDR, dstCIDR} {
			if s != "" {
				ip, _, err := net.ParseCIDR(s)
				if err == nil && ip.To4() == nil {
					return fmt.Errorf("bad_fragment not supported for IPv6 target")
				}
			}
		}
	}
	return nil
}

// ruleValueFromStored rebuilds a BPF RuleValue from a StoredRule.
// Used exclusively in rollback paths — does NOT return error so rollback
// callers stay on a single code path. On parse failure, falls back to
// ActionDrop + zero flags and logs a warning.
func ruleValueFromStored(s StoredRule) RuleValue {
	action, err := parseAction(s.Action)
	if err != nil {
		slog.Warn("ruleValueFromStored: parseAction failed, falling back to drop",
			"stored_action", s.Action, "error", err)
		action = ActionDrop
	}
	fm, fv, err := parseTcpFlags(s.TcpFlags)
	if err != nil {
		slog.Warn("ruleValueFromStored: parseTcpFlags failed, dropping flags",
			"stored_flags", s.TcpFlags, "error", err)
		fm, fv = 0, 0
	}
	return RuleValue{
		Action:        action,
		TcpFlagsMask:  fm,
		TcpFlagsValue: fv,
		MatchAnomaly:  s.MatchAnomaly,
		RateLimit:     s.RateLimit,
		PktLenMin:     s.PktLenMin,
		PktLenMax:     s.PktLenMax,
	}
}

// ruleValueFromStoredCIDR is the CIDR-rule variant of ruleValueFromStored.
func ruleValueFromStoredCIDR(s StoredCIDRRule) RuleValue {
	action, err := parseAction(s.Action)
	if err != nil {
		slog.Warn("ruleValueFromStoredCIDR: parseAction failed, falling back to drop",
			"stored_action", s.Action, "error", err)
		action = ActionDrop
	}
	fm, fv, err := parseTcpFlags(s.TcpFlags)
	if err != nil {
		slog.Warn("ruleValueFromStoredCIDR: parseTcpFlags failed, dropping flags",
			"stored_flags", s.TcpFlags, "error", err)
		fm, fv = 0, 0
	}
	return RuleValue{
		Action:        action,
		TcpFlagsMask:  fm,
		TcpFlagsValue: fv,
		MatchAnomaly:  s.MatchAnomaly,
		RateLimit:     s.RateLimit,
		PktLenMin:     s.PktLenMin,
		PktLenMax:     s.PktLenMax,
	}
}
