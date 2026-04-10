// XDrop Agent - API <-> BPF internal type conversions
package api

import (
	"fmt"
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
		ID:        id,
		SrcIP:     ipAddrToString(s.Key.SrcIP),
		DstIP:     ipAddrToString(s.Key.DstIP),
		SrcPort:   ntohs(s.Key.SrcPort),
		DstPort:   ntohs(s.Key.DstPort),
		Protocol:  protocolToString(s.Key.Protocol),
		Action:    action,
		RateLimit: s.RateLimit,
		PktLenMin: s.PktLenMin,
		PktLenMax: s.PktLenMax,
		TcpFlags:  s.TcpFlags,
	}
}

func (h *Handlers) storedCIDRRuleToRule(id string, s StoredCIDRRule) Rule {
	action := s.Action
	if action == "" {
		action = "drop"
	}
	return Rule{
		ID:        id,
		SrcCIDR:   s.SrcCIDR,
		DstCIDR:   s.DstCIDR,
		SrcPort:   ntohs(s.Key.SrcPort),
		DstPort:   ntohs(s.Key.DstPort),
		Protocol:  protocolToString(s.Key.Protocol),
		Action:    action,
		RateLimit: s.RateLimit,
		PktLenMin: s.PktLenMin,
		PktLenMax: s.PktLenMax,
		TcpFlags:  s.TcpFlags,
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
