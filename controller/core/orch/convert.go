package orch

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"sort"

	"github.com/littlewolf9527/xdrop/controller/core/condexpr"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func nodeRule(r store.NodeRow) nc.Rule {
	return nc.Rule{ID: r.ID, LogicalID: uint32(r.LogicalID), SrcIP: r.SrcIP, DstIP: r.DstIP, SrcCIDR: r.SrcCIDR, DstCIDR: r.DstCIDR,
		SrcPort: r.SrcPort, DstPort: r.DstPort, Protocol: r.Protocol, Action: r.Action, RateLimit: r.RateLimit,
		TCPFlags: r.TCPFlags, MatchAnomaly: r.MatchAnomaly, TTL: r.TTL, DSCP: r.DSCP, ICMPType: r.ICMPType, ICMPCode: r.ICMPCode, Fragment: r.Fragment, PktLen: r.PktLen}
}
func group(key string, rows []store.Rule) nc.Group {
	g := nc.Group{Key: json.RawMessage(key), Rules: []nc.Rule{}}
	for _, r := range rows {
		g.Rules = append(g.Rules, nodeRule(store.NodeRow{ID: r.ID, LogicalID: r.LogicalID, Match: r.Match}))
	}
	sort.Slice(g.Rules, func(i, j int) bool { return g.Rules[i].ID < g.Rules[j].ID })
	return g
}
func fingerprint(g nc.Group) string {
	b, _ := json.Marshal(g.Rules)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func whitelistRows(rows []store.Whitelist) []nc.Entry {
	out := []nc.Entry{}
	for _, r := range rows {
		out = append(out, nc.Entry{ID: r.ID, SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: r.SrcPort, DstPort: r.DstPort, Protocol: r.Protocol})
	}
	return out
}
func ruleMatch(r nc.Rule) store.Match {
	return store.Match{SrcIP: r.SrcIP, DstIP: r.DstIP, SrcCIDR: r.SrcCIDR, DstCIDR: r.DstCIDR, SrcPort: r.SrcPort, DstPort: r.DstPort,
		Protocol: r.Protocol, Action: r.Action, RateLimit: r.RateLimit, TCPFlags: r.TCPFlags, MatchAnomaly: r.MatchAnomaly,
		TTL: r.TTL, DSCP: r.DSCP, ICMPType: r.ICMPType, ICMPCode: r.ICMPCode, Fragment: r.Fragment, PktLen: r.PktLen}
}
func normalized(r nc.ReadRule) nc.ReadRule {
	r.Stats = nil
	if r.Protocol == "" {
		r.Protocol = "all"
	}
	if r.Action == "" {
		r.Action = "drop"
	}
	for _, p := range []*string{&r.SrcIP, &r.DstIP} {
		if ip, err := netip.ParseAddr(*p); err == nil {
			*p = ip.String()
		}
	}
	for _, p := range []*string{&r.SrcCIDR, &r.DstCIDR} {
		if ip, err := netip.ParsePrefix(*p); err == nil {
			*p = ip.Masked().String()
		}
	}
	if mask, value, _, err := condexpr.ParseTCPFlags(r.TCPFlags); err == nil {
		r.TCPFlags = fmt.Sprintf("%d:%d", mask, value)
	}
	return r
}
func equalRule(a, b nc.ReadRule) bool { return reflect.DeepEqual(normalized(a), normalized(b)) }
func equalEntries(a, b []nc.Entry) bool {
	convert := func(entries []nc.Entry) map[string]nc.ReadRule {
		m := map[string]nc.ReadRule{}
		for _, e := range entries {
			m[e.ID] = normalized(nc.ReadRule{Rule: nc.Rule{ID: e.ID, SrcIP: e.SrcIP, DstIP: e.DstIP, SrcPort: e.SrcPort, DstPort: e.DstPort, Protocol: e.Protocol}})
		}
		return m
	}
	return len(a) == len(b) && reflect.DeepEqual(convert(a), convert(b))
}
