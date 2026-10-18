package api

import (
	"encoding/binary"

	"github.com/littlewolf9527/xdrop/node/agent/condexpr"
)

// conditionGroup is the single definition of PLAN ③-0. Classify raw inputs
// before validation; a present but invalid expression still makes a group.
func conditionGroup(rules []Rule) bool {
	if len(rules) > 1 {
		return true
	}
	for _, r := range rules {
		if r.TTL != nil || r.DSCP != nil || r.ICMPType != nil || r.ICMPCode != nil || r.Fragment != nil || r.PktLen != nil || r.TcpFlags != "" || r.PktLenMin > 0 || (r.PktLenMax != 0 && r.PktLenMax != 65535) || r.MatchAnomaly != 0 {
			return true
		}
	}
	return false
}

// normalizeConditionRule runs only after the entry point's existing validators.
// Keep tuple identity under the node's key builders, independent of the compiler.
func normalizeConditionRule(r *Rule) error {
	n, err := condexpr.Compile(conditionInput(*r))
	if err != nil {
		return err
	}
	r.TTL, r.DSCP, r.ICMPType, r.ICMPCode, r.Fragment, r.PktLen = n.TTL, n.DSCP, n.ICMPType, n.ICMPCode, n.Fragment, n.PktLen
	r.TcpFlags = n.TCPFlags
	if r.Action == "" {
		r.Action = "drop"
	}
	return ValidateCanonicalConditionRule(*r)
}

// groupIdentity contains the public canonical identity, never allocated trie IDs.
type groupIdentity struct {
	exactKey RuleKey
	Kind     string `json:"kind"`
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcCIDR  string `json:"src_cidr,omitempty"`
	DstCIDR  string `json:"dst_cidr,omitempty"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Protocol string `json:"protocol"`
}

// classifyRuleKey checks only fields needed to identify a key. Other invalid
// fields remain in the group until its entry point's existing validation runs.
func (h *Handlers) classifyRuleKey(r Rule, memos ...*atomicMemo) (groupIdentity, error) {
	g := groupIdentity{Kind: "exact", SrcPort: r.SrcPort, DstPort: r.DstPort}
	if r.SrcCIDR != "" || r.DstCIDR != "" {
		g.Kind = "cidr"
		if err := checkAddressFamily(r.SrcCIDR, r.DstCIDR, true); err != nil {
			return g, err
		}
		var err error
		if r.SrcCIDR != "" {
			g.SrcCIDR, err = firstMemo(memos).normalize(r.SrcCIDR)
			if err != nil {
				return g, err
			}
		}
		if r.DstCIDR != "" {
			g.DstCIDR, err = firstMemo(memos).normalize(r.DstCIDR)
			if err != nil {
				return g, err
			}
		}
		proto, err := parseProtocolStrict(r.Protocol)
		if err != nil {
			return g, err
		}
		g.Protocol = protocolToString(proto)
		return g, nil
	}
	k, err := h.ruleToKey(r)
	if err != nil {
		return g, err
	}
	g.exactKey = k
	g.SrcIP, g.DstIP, g.Protocol = ipAddrToString(k.SrcIP), ipAddrToString(k.DstIP), protocolToString(k.Protocol)
	return g, nil
}

func (h *Handlers) storedGroupRule(id string) (Rule, bool) {
	if r, ok := h.rules[id]; ok {
		return h.storedRuleToRule(id, r), true
	}
	if r, ok := h.cidrRules[id]; ok {
		return h.storedCIDRRuleToRule(id, r), true
	}
	return Rule{}, false
}

// currentGroupLocked reads a reverse index without reserving prefixes. The
// nil-index fallback supports intentionally minimal test fixtures, without
// mutating them during a zero-write rejection.
func (h *Handlers) currentGroupLocked(g groupIdentity) map[string]Rule {
	out := make(map[string]Rule)
	if g.Kind == "exact" && h.ruleKeyIndex != nil {
		for id := range h.ruleKeyIndex[g.exactKey] {
			if r, ok := h.rules[id]; ok {
				out[id] = h.storedRuleToRule(id, r)
			}
		}
		return out
	}
	if g.Kind == "cidr" && h.cidrMgr != nil && h.cidrRuleKeyIndex != nil {
		var src, dst uint32
		var ok bool
		if g.SrcCIDR != "" {
			src, ok = h.cidrMgr.GetSrcID(g.SrcCIDR)
			if !ok {
				return out
			}
		}
		if g.DstCIDR != "" {
			dst, ok = h.cidrMgr.GetDstID(g.DstCIDR)
			if !ok {
				return out
			}
		}
		proto, _ := parseProtocolStrict(g.Protocol)
		key := CIDRRuleKey{SrcID: src, DstID: dst, SrcPort: htons(g.SrcPort), DstPort: htons(g.DstPort), Protocol: proto}
		for id := range h.cidrRuleKeyIndex[key] {
			if r, ok := h.cidrRules[id]; ok {
				out[id] = h.storedCIDRRuleToRule(id, r)
			}
		}
		return out
	}
	if g.Kind == "exact" {
		for id, r := range h.rules {
			value := h.storedRuleToRule(id, r)
			key, err := h.classifyRuleKey(value)
			key.exactKey = r.Key
			if err == nil && key == g {
				out[id] = value
			}
		}
	} else {
		for id, r := range h.cidrRules {
			value := h.storedCIDRRuleToRule(id, r)
			key, err := h.classifyRuleKey(value)
			if err == nil && key == g {
				out[id] = value
			}
		}
	}
	return out
}

// Anonymous request members have a separate identity domain from stored/user
// IDs. No string prefix is reserved by the API, including strings with NULs.
type incrementalMemberIdentity struct {
	ID           string
	RequestIndex int
	Anonymous    bool
}

func markConditionValue(r Rule, v RuleValue) RuleValue {
	if conditionGroup([]Rule{r}) {
		v.Pad2[0] = RuleHasConditions
	}
	return v
}

// conditionValueToBytes is explicit little-endian ABI serialization. No cilium
// struct marshalling or host struct padding participates in production writes.
func conditionValueToBytes(v ConditionValue) []byte {
	b := make([]byte, 844)
	for i := range v.Tab {
		copy(b[i*128:(i+1)*128], v.Tab[i][:])
	}
	copy(b[768:772], v.Frag[:])
	for i := range v.Len {
		for j, s := range v.Len[i] {
			off := 772 + i*8 + j*4
			binary.LittleEndian.PutUint16(b[off:], s.Lo)
			binary.LittleEndian.PutUint16(b[off+2:], s.Hi)
		}
	}
	copy(b[804:808], v.Action[:])
	for i := range v.Rate {
		binary.LittleEndian.PutUint32(b[808+i*4:], v.Rate[i])
		binary.LittleEndian.PutUint32(b[824+i*4:], v.RuleID[i])
	}
	b[840], b[841], b[842], b[843] = v.Active, v.ICMPReq, v.TCPReq, v.Pad[0]
	return b
}

type ruleIDSet map[string]struct{}

func addRuleID[K comparable](index map[K]ruleIDSet, key K, id string) {
	if index[key] == nil {
		index[key] = make(ruleIDSet)
	}
	index[key][id] = struct{}{}
}
func removeRuleID[K comparable](index map[K]ruleIDSet, key K, id string) {
	delete(index[key], id)
	if len(index[key]) == 0 {
		delete(index, key)
	}
}
