// XDrop Agent - API <-> BPF internal type conversions
package api

import (
	"fmt"
	"net"
	"strings"
)

// checkAddressFamily reads literal addresses before normalization erases their spelling.
// Invalid syntax remains the responsibility of the existing entry-point parser.
func checkAddressFamily(src, dst string, prefix bool) error {
	var ips [2]net.IP
	var networks [2]*net.IPNet
	for i, raw := range []string{src, dst} {
		if raw == "" || (!prefix && (raw == "0.0.0.0" || raw == "::")) {
			continue
		}
		ip := net.ParseIP(raw)
		if prefix {
			var err error
			ip, networks[i], err = net.ParseCIDR(raw)
			if err != nil {
				return nil
			}
		}
		if ip == nil {
			return nil
		}
		ips[i] = ip
	}
	for i, raw := range []string{src, dst} {
		ip, network := ips[i], networks[i]
		if ip == nil {
			continue
		}
		address, field, kind := raw, []string{"src_ip", "dst_ip"}[i], "address"
		if prefix {
			address = raw[:strings.LastIndexByte(raw, '/')]
			field, kind = []string{"src_cidr", "dst_cidr"}[i], "prefix"
		}
		if strings.Contains(address, ":") && ip.To4() != nil {
			suggestion := "; write the IPv4 address " + ip.String()
			if prefix {
				suggestion = ""
				if ones, _ := network.Mask.Size(); ones >= 96 {
					suggestion = "; write the IPv4 prefix " + network.String()
				}
			}
			return fmt.Errorf("invalid %s: IPv4-mapped IPv6 %s %s%s", field, kind, raw, suggestion)
		}
	}
	if ips[0] != nil && ips[1] != nil && (ips[0].To4() != nil) != (ips[1].To4() != nil) {
		srcFamily, dstFamily := "IPv4", "IPv6"
		if ips[0].To4() == nil {
			srcFamily, dstFamily = dstFamily, srcFamily
		}
		return fmt.Errorf("address family mismatch: src is %s, dst is %s", srcFamily, dstFamily)
	}
	return nil
}

func (h *Handlers) ruleToKey(r Rule) (RuleKey, error) {
	key := RuleKey{}
	if err := checkAddressFamily(r.SrcIP, r.DstIP, false); err != nil {
		return key, err
	}

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

	// S0-6 (2026-09-14, external audit D-09, owner decision 2026-09-05).
	// This used to take the lenient parse, which maps anything it does not
	// recognise to ProtoAll. A typo'd protocol therefore turned a rule aimed at
	// ONE protocol into a rule matching ALL of them — a silently wider drop,
	// with no error returned anywhere. The whitelist conversion in this same
	// file already used the strict parser; the rule path did not.
	proto, err := parseProtocolStrict(r.Protocol)
	if err != nil {
		return key, err
	}
	key.Protocol = proto

	return key, nil
}

func (h *Handlers) whitelistToKey(w WhitelistEntry) (RuleKey, error) {
	key := RuleKey{}
	if err := checkAddressFamily(w.SrcIP, w.DstIP, false); err != nil {
		return key, err
	}

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
	proto, err := parseProtocolStrict(w.Protocol)
	if err != nil {
		return key, fmt.Errorf("whitelist protocol: %w", err)
	}
	key.Protocol = proto

	return key, nil
}

func (h *Handlers) storedRuleToRule(id string, s StoredRule) Rule {
	action := s.Action
	if action == "" {
		action = "drop"
	}
	return Rule{
		LogicalID: s.LogicalID,
		TTL:       s.TTL,
		DSCP:      s.DSCP,
		ICMPType:  s.ICMPType,
		ICMPCode:  s.ICMPCode,
		Fragment:  s.Fragment,
		PktLen:    s.PktLen,

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
		LogicalID: s.LogicalID,
		TTL:       s.TTL,
		DSCP:      s.DSCP,
		ICMPType:  s.ICMPType,
		ICMPCode:  s.ICMPCode,
		Fragment:  s.Fragment,
		PktLen:    s.PktLen,

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
// the Node direct HTTP API. Both drop and rate_limit actions may use anomaly
// conditions; bounded-target, bit-mask and IPv6 constraints remain mandatory.
func validateNodeAnomalyFields(matchAnomaly uint8, action, srcIP, dstIP, srcCIDR, dstCIDR string, memos ...*atomicMemo) error {
	if matchAnomaly == 0 {
		return nil
	}
	const validBits = uint8(0x0F)
	if matchAnomaly&^validBits != 0 {
		return fmt.Errorf("invalid match_anomaly bits: 0x%x (valid: 0x%x)", matchAnomaly, validBits)
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
			parsed := firstMemo(memos).parse(s)
			n, err := parsed.network, parsed.err
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
	if matchAnomaly&(AnomalyBadFragment|0x08) != 0 {
		for _, s := range []string{srcIP, dstIP} {
			if s != "" {
				ip := net.ParseIP(s)
				if ip != nil && ip.To4() == nil && !ip.IsUnspecified() {
					if matchAnomaly&AnomalyBadFragment != 0 {
						return fmt.Errorf("bad_fragment not supported for IPv6 target")
					}
					return fmt.Errorf("match_anomaly 0x08 not supported for IPv6 target")
				}
			}
		}
		for _, s := range []string{srcCIDR, dstCIDR} {
			if s != "" {
				parsed := firstMemo(memos).parse(s)
				ip, err := parsed.ip, parsed.err
				if err == nil && ip.To4() == nil {
					if matchAnomaly&AnomalyBadFragment != 0 {
						return fmt.Errorf("bad_fragment not supported for IPv6 target")
					}
					return fmt.Errorf("match_anomaly 0x08 not supported for IPv6 target")
				}
			}
		}
	}
	return nil
}
