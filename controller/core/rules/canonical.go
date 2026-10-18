// Package rules owns admission, identity and serialized writes.
package rules

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/littlewolf9527/xdrop/controller/core/condexpr"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type Error struct {
	Code, Message, Field, RuleID, Table string
	RuleIDs                             []string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }
func bad(field, message string) *Error {
	return &Error{Code: "invalid_rule", Field: field, Message: message}
}
func internal(err error) *Error { return &Error{Code: "internal", Message: err.Error()} }

type RuleInput = store.Match
type Canon struct {
	RuleInput
	Kind, GroupKey, CondKey string
	CandidateCount          int
}

// groupKey is the sole constructor of rule group identity.
func groupKey(c Canon) string {
	g := struct {
		Kind     string `json:"kind"`
		SrcIP    string `json:"src_ip,omitempty"`
		DstIP    string `json:"dst_ip,omitempty"`
		SrcCIDR  string `json:"src_cidr,omitempty"`
		DstCIDR  string `json:"dst_cidr,omitempty"`
		SrcPort  int    `json:"src_port"`
		DstPort  int    `json:"dst_port"`
		Protocol string `json:"protocol"`
	}{c.Kind, c.SrcIP, c.DstIP, c.SrcCIDR, c.DstCIDR, c.SrcPort, c.DstPort, c.Protocol}
	b, _ := json.Marshal(g)
	return string(b)
}

func addressFamily(src, dst string, prefix bool) *Error {
	var ips [2]net.IP
	for i, raw := range []string{src, dst} {
		if raw == "" || (!prefix && (raw == "0.0.0.0" || raw == "::")) {
			continue
		}
		ip := net.ParseIP(raw)
		var network *net.IPNet
		address := raw
		if prefix {
			var err error
			ip, network, err = net.ParseCIDR(raw)
			if err != nil {
				return nil
			}
			address = strings.Split(raw, "/")[0]
		}
		if ip == nil {
			return nil
		}
		if strings.Contains(address, ":") && ip.To4() != nil {
			message := "IPv4-mapped IPv6 is not supported; use IPv4 " + ip.String()
			if prefix {
				bits, _ := network.Mask.Size()
				message = "IPv4-mapped IPv6 prefix is not supported"
				if bits >= 96 {
					message += "; use IPv4 " + network.String()
				}
			}
			return &Error{Code: "mapped_ipv6", Message: message}
		}
		ips[i] = ip
	}
	if ips[0] != nil && ips[1] != nil && (ips[0].To4() != nil) != (ips[1].To4() != nil) {
		return &Error{Code: "address_family_mismatch", Message: "source and destination address families differ"}
	}
	return nil
}

func canonicalIP(raw string) (string, *Error) {
	if raw == "" {
		return "", nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", bad("ip", "invalid IP address")
	}
	s := ip.String()
	if s == "0.0.0.0" || s == "::" {
		s = ""
	}
	return s, nil
}

func canonicalPrefix(raw string) (string, *Error) {
	if raw == "" {
		return "", nil
	}
	_, network, err := net.ParseCIDR(raw)
	if err != nil {
		return "", bad("cidr", err.Error())
	}
	return network.String(), nil
}

func protocolName(raw string, src, dst int) (string, *Error) {
	if raw == "" {
		raw = "all"
	}
	switch raw {
	case "all", "tcp", "udp":
	case "icmp", "icmpv6", "igmp", "gre", "esp":
		if src != 0 || dst != 0 {
			return "", bad("protocol", "protocol does not support ports")
		}
	default:
		return "", bad("protocol", "unknown protocol")
	}
	return raw, nil
}

func inputConditions(in RuleInput) condexpr.Input {
	return condexpr.Input{
		Tuple:    condexpr.Tuple{SrcIP: in.SrcIP, DstIP: in.DstIP, SrcCIDR: in.SrcCIDR, DstCIDR: in.DstCIDR, SrcPort: in.SrcPort, DstPort: in.DstPort, Protocol: in.Protocol},
		Fields:   condexpr.Fields{TTL: in.TTL, DSCP: in.DSCP, ICMPType: in.ICMPType, ICMPCode: in.ICMPCode, Fragment: in.Fragment, PktLen: in.PktLen},
		TCPFlags: in.TCPFlags, MatchAnomaly: in.MatchAnomaly,
	}
}

func Canonicalize(in RuleInput) (Canon, *Error) {
	c := Canon{RuleInput: in, Kind: "exact"}
	if in.SrcPort < 0 || in.SrcPort > 65535 {
		return c, bad("src_port", "port out of range")
	}
	if in.DstPort < 0 || in.DstPort > 65535 {
		return c, bad("dst_port", "port out of range")
	}
	if in.RateLimit < 0 || in.RateLimit > 4294967295 {
		return c, bad("rate_limit", "rate out of range")
	}
	if in.MatchAnomaly < 0 || in.MatchAnomaly > 255 {
		return c, bad("match_anomaly", "anomaly out of range")
	}
	if c.Action == "" {
		c.Action = "drop"
	}
	switch c.Action {
	case "drop":
		c.RateLimit = 0
	case "rate_limit":
		if c.RateLimit == 0 {
			return c, bad("rate_limit", "rate must be positive")
		}
	default:
		return c, bad("action", "unknown action")
	}
	isCIDR := in.SrcCIDR != "" || in.DstCIDR != ""
	src, dst := in.SrcIP, in.DstIP
	if isCIDR {
		src, dst = in.SrcCIDR, in.DstCIDR
		c.Kind = "cidr"
	}
	if err := addressFamily(src, dst, isCIDR); err != nil {
		return c, err
	}
	if isCIDR && (in.SrcIP != "" || in.DstIP != "") {
		return c, bad("ip", "exact IP and CIDR cannot be combined")
	}
	for _, v := range []struct {
		raw    string
		target *string
	}{{in.SrcIP, &c.SrcIP}, {in.DstIP, &c.DstIP}} {
		s, e := canonicalIP(v.raw)
		if e != nil {
			return c, e
		}
		*v.target = s
	}
	for _, v := range []struct {
		raw    string
		target *string
	}{{in.SrcCIDR, &c.SrcCIDR}, {in.DstCIDR, &c.DstCIDR}} {
		s, e := canonicalPrefix(v.raw)
		if e != nil {
			return c, e
		}
		*v.target = s
	}
	var err *Error
	c.Protocol, err = protocolName(in.Protocol, in.SrcPort, in.DstPort)
	if err != nil {
		return c, err
	}
	if !isCIDR && c.SrcIP == "" && c.DstIP == "" && c.SrcPort == 0 && c.DstPort == 0 && c.Protocol == "all" {
		return c, bad("tuple", "rule field combination is not recognized")
	}
	if in.MatchAnomaly != 0 {
		if in.MatchAnomaly & ^0x0F != 0 {
			return c, bad("match_anomaly", "unknown anomaly bits")
		}
		bounded, v6 := false, false
		for _, ip := range []string{c.SrcIP, c.DstIP} {
			if ip != "" {
				bounded = true
				v6 = v6 || net.ParseIP(ip).To4() == nil
			}
		}
		for _, prefix := range []string{c.SrcCIDR, c.DstCIDR} {
			if prefix != "" {
				ip, n, _ := net.ParseCIDR(prefix)
				ones, _ := n.Mask.Size()
				bounded = bounded || ones > 0
				v6 = v6 || ip.To4() == nil
			}
		}
		if !bounded {
			return c, bad("match_anomaly", "anomaly requires a bounded target")
		}
		if v6 && in.MatchAnomaly&0x09 != 0 {
			return c, bad("match_anomaly", "anomaly is not supported for IPv6")
		}
	}
	mask, _, flags, e := condexpr.ParseTCPFlags(in.TCPFlags)
	if e != nil {
		return c, bad("tcp_flags", e.Error())
	}
	if mask != 0 && c.Protocol != "tcp" {
		return c, bad("tcp_flags", "flags require tcp")
	}
	c.TCPFlags = flags
	n, e := condexpr.Compile(inputConditions(c.RuleInput))
	if e != nil {
		return c, bad("conditions", e.Error())
	}
	c.TTL, c.DSCP, c.ICMPType, c.ICMPCode, c.Fragment, c.PktLen = n.TTL, n.DSCP, n.ICMPType, n.ICMPCode, n.Fragment, n.PktLen
	c.CandidateCount = n.CandidateCount
	c.CondKey = n.CondKey()
	// Preserve the tuple produced by the address normalization stage above.
	c.GroupKey = groupKey(c)
	return c, nil
}

type WhitelistInput struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  int    `json:"src_port"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"`
	Comment  string `json:"comment"`
}
type WLCanon struct {
	WhitelistInput
	Key string
}

func CanonicalizeWhitelist(in WhitelistInput) (WLCanon, *Error) {
	c := WLCanon{WhitelistInput: in}
	if in.SrcPort < 0 || in.SrcPort > 65535 || in.DstPort < 0 || in.DstPort > 65535 {
		return c, bad("port", "port out of range")
	}
	if e := addressFamily(in.SrcIP, in.DstIP, false); e != nil {
		return c, e
	}
	var e *Error
	if c.SrcIP, e = canonicalIP(in.SrcIP); e != nil {
		return c, e
	}
	if c.DstIP, e = canonicalIP(in.DstIP); e != nil {
		return c, e
	}
	if c.Protocol, e = protocolName(in.Protocol, in.SrcPort, in.DstPort); e != nil {
		return c, e
	}
	if c.SrcIP == "" && c.DstIP == "" && c.SrcPort == 0 && c.DstPort == 0 && c.Protocol == "all" {
		return c, bad("tuple", "rule field combination is not recognized")
	}
	c.Key = fmt.Sprintf("%s|%s|%d|%d|%s", c.SrcIP, c.DstIP, c.SrcPort, c.DstPort, c.Protocol)
	return c, nil
}
