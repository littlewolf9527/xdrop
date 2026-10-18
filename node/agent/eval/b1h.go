package eval

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// B1Packet adds extracted attributes without changing the historical Packet.
// IPv6PayloadLength, when supplied, is the declared header payload length;
// Length remains the historical uint16 L3 length for IPv4 and other callers.
type B1Packet struct {
	Packet
	TTL, DSCP, ICMPType, ICMPCode, FragClass uint8
	ICMPValid                                bool
	NonFirst                                 bool
	IPv6PayloadLength                        *uint16
}

// B1Rule describes logical intent, never an encoded H row or physical slice.
// Historical Conditions carries legacy mask/value, length bounds and anomaly.
type B1Rule struct {
	Rule
	LogicalID                                       uint32
	HasConditions                                   bool
	TTL, DSCP, ICMPType, ICMPCode, Fragment, PktLen *string
}

type B1RuleSet struct {
	Whitelist                                []Rule
	Exact, CIDR                              []B1Rule
	SrcPrefixes, DstPrefixes                 []Prefix
	WhitelistBitmap, ExactBitmap, CIDRBitmap uint64
}

type B1Decision struct {
	Decision
	LogicalID, Rate uint32
	ActionCode      uint8 // 0 pass, 1 drop, 2 rate limit
	HasConditions   bool
}

type b1Intent struct {
	rule           B1Rule
	allowed        [8][]bool
	strict, pieces int
}

// This oracle intentionally uses enumerated membership arrays instead of the
// compiler's interval algebra. Do not import condexpr here.
func b1Expression(raw string, max int, fragment bool) ([]bool, error) {
	for _, r := range raw {
		if r > 127 || r == '\n' || r == '\r' {
			return nil, fmt.Errorf("illegal expression character")
		}
	}
	s := strings.Trim(raw, " \t")
	invert := strings.HasPrefix(s, "!")
	if invert {
		s = strings.Trim(s[1:], " \t")
	}
	if s == "" {
		return nil, fmt.Errorf("empty expression")
	}
	set := make([]bool, max+1)
	number := func(s string) (int, error) {
		s = strings.Trim(s, " \t")
		if s == "" || len(s) > 1 && s[0] == '0' {
			return 0, fmt.Errorf("invalid decimal")
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("invalid decimal")
			}
		}
		v, e := strconv.Atoi(s)
		if e != nil || v > max {
			return 0, fmt.Errorf("value outside domain")
		}
		return v, nil
	}
	for _, item := range strings.Split(s, ",") {
		item = strings.Trim(item, " \t")
		if item == "" {
			return nil, fmt.Errorf("empty item")
		}
		if fragment {
			var vals []int
			switch strings.ToLower(item) {
			case "nofrag":
				vals = []int{0, 4}
			case "first":
				vals = []int{2, 6}
			case "middle":
				vals = []int{3, 7}
			case "last":
				vals = []int{1, 5}
			case "frag":
				vals = []int{1, 2, 3, 5, 6, 7}
			case "nonfirst":
				vals = []int{1, 3, 5, 7}
			default:
				return nil, fmt.Errorf("invalid fragment name")
			}
			for _, v := range vals {
				set[v] = true
			}
			continue
		}
		loText, hiText, rangeItem := strings.Cut(item, "-")
		lo, e := number(loText)
		if e != nil {
			return nil, e
		}
		hi := lo
		if rangeItem {
			hi, e = number(hiText)
			if e != nil {
				return nil, e
			}
		}
		if lo > hi {
			return nil, fmt.Errorf("reversed interval")
		}
		for v := lo; v <= hi; v++ {
			set[v] = true
		}
	}
	count := 0
	for i := range set {
		if invert {
			set[i] = !set[i]
		}
		if set[i] {
			count++
		}
	}
	if count == 0 || count == len(set) {
		return nil, fmt.Errorf("empty or full expression set")
	}
	return set, nil
}

func b1CompileIntent(r B1Rule) (b1Intent, error) {
	n := b1Intent{rule: r, pieces: 1}
	if !r.HasConditions {
		if r.TTL != nil || r.DSCP != nil || r.ICMPType != nil || r.ICMPCode != nil || r.Fragment != nil || r.PktLen != nil {
			return n, fmt.Errorf("expression on flag-zero rule")
		}
		return n, nil
	}
	values := [8]*string{r.TTL, r.DSCP, nil, r.ICMPType, r.ICMPCode, nil, r.Fragment, r.PktLen}
	maxima := [8]int{255, 63, 255, 255, 255, 15, 7, 65535}
	for i, p := range values {
		if p == nil {
			continue
		}
		s, e := b1Expression(*p, maxima[i], i == 6)
		if e != nil {
			return n, fmt.Errorf("attribute %d: %w", i, e)
		}
		n.allowed[i] = s
	}
	proto := r.Key.Proto
	if r.CIDRKey != (CIDRTuple{}) {
		proto = r.CIDRKey.Proto
	}
	if (r.ICMPType != nil || r.ICMPCode != nil) && proto != 1 && proto != 58 {
		return n, fmt.Errorf("ICMP expression requires ICMP protocol")
	}
	if r.FlagsValue&^r.FlagsMask != 0 {
		return n, fmt.Errorf("flags value outside mask")
	}
	if r.FlagsMask != 0 {
		if proto != 6 {
			return n, fmt.Errorf("flags require TCP")
		}
		n.allowed[2] = make([]bool, 256)
		for v := range n.allowed[2] {
			n.allowed[2][v] = uint8(v)&r.FlagsMask == r.FlagsValue
		}
	}
	if r.Anomaly > 15 {
		return n, fmt.Errorf("anomaly outside domain")
	}
	if r.Anomaly != 0 {
		n.allowed[5] = make([]bool, 16)
		for v := range n.allowed[5] {
			n.allowed[5][v] = uint8(v)&r.Anomaly != 0
		}
	}
	legacy := r.MinLength != 0 || r.MaxLength != 0 && r.MaxLength != 65535
	if legacy {
		if r.PktLen != nil {
			return n, fmt.Errorf("new and legacy lengths coexist")
		}
		hi := int(r.MaxLength)
		if hi == 0 {
			hi = 65535
		}
		if int(r.MinLength) > hi {
			return n, fmt.Errorf("reversed legacy length")
		}
		n.allowed[7] = make([]bool, 65536)
		for i := int(r.MinLength); i <= hi; i++ {
			n.allowed[7][i] = true
		}
	}
	for _, s := range n.allowed {
		if s != nil {
			n.strict++
		}
	}
	if lengths := n.allowed[7]; lengths != nil {
		runs := 0
		for i, yes := range lengths {
			if yes && (i == 0 || !lengths[i-1]) {
				runs++
			}
		}
		n.pieces = (runs + 1) / 2
	}
	return n, nil
}

func (rs B1RuleSet) validateB1(t Tables) error {
	if t.contract != B1 {
		return fmt.Errorf("H evaluator requires B1 contract")
	}
	if e := t.Validate(); e != nil {
		return e
	}
	base := RuleSet{Whitelist: rs.Whitelist, SrcPrefixes: rs.SrcPrefixes, DstPrefixes: rs.DstPrefixes, WhitelistBitmap: rs.WhitelistBitmap, ExactBitmap: rs.ExactBitmap, CIDRBitmap: rs.CIDRBitmap}
	if e := base.validate(t); e != nil {
		return e
	}
	ids := map[string]bool{}
	logical := map[uint32]bool{}
	for _, r := range rs.Whitelist {
		ids[r.ID] = true
	}
	for gi, group := range [][]B1Rule{rs.Exact, rs.CIDR} {
		counts := map[any]int{}
		flags := map[any]bool{}
		for _, r := range group {
			if r.ID == "" || ids[r.ID] {
				return fmt.Errorf("missing/duplicate RuleID %q", r.ID)
			}
			ids[r.ID] = true
			if r.LogicalID == 0 || logical[r.LogicalID] {
				return fmt.Errorf("missing/duplicate logical_id %d", r.LogicalID)
			}
			logical[r.LogicalID] = true
			n, e := b1CompileIntent(r)
			if e != nil {
				return e
			}
			var key any = r.Key
			if gi == 1 {
				key = r.CIDRKey
			}
			if old, seen := flags[key]; seen && (old != r.HasConditions || !old) {
				return fmt.Errorf("mixed flag-zero/flag-one or duplicate flag-zero tuple")
			}
			flags[key] = r.HasConditions
			counts[key] += n.pieces
			if counts[key] > 4 {
				return fmt.Errorf("physical candidates exceed four")
			}
			if r.HasConditions {
				addresses := []netip.Addr{r.Key.Src, r.Key.Dst}
				v4, v6 := false, false
				anchor := r.Key.Proto != 0 || r.Key.Sport != 0 || r.Key.Dport != 0
				if gi == 1 {
					anchor = r.CIDRKey.Proto != 0 || r.CIDRKey.Sport != 0 || r.CIDRKey.Dport != 0
					for side, prefixes := range [][]Prefix{rs.SrcPrefixes, rs.DstPrefixes} {
						id := r.CIDRKey.SrcID
						if side == 1 {
							id = r.CIDRKey.DstID
						}
						for _, p := range prefixes {
							if id != 0 && id == p.ID {
								addresses = append(addresses, p.Network.Addr())
								anchor = true
								if p.Network.Addr().Unmap().Is4() {
									v4 = true
								} else {
									v6 = true
								}
							}
						}
					}
				}
				for _, a := range addresses {
					if !a.IsValid() || a.IsUnspecified() {
						continue
					}
					anchor = true
					if a.Unmap().Is4() {
						v4 = true
					} else {
						v6 = true
					}
				}
				if r.Fragment != nil && (!v4 || v6) {
					return fmt.Errorf("fragment requires IPv4 anchor")
				}
				if r.Anomaly&9 != 0 && v6 {
					return fmt.Errorf("IPv6 anomaly bit unreachable")
				}
				if n.strict > 0 && !anchor {
					return fmt.Errorf("condition rule requires anchor")
				}
			}
		}
	}
	return nil
}

func b1Matches(n b1Intent, p B1Packet) bool {
	// Both flag paths consume the same extracted uint16 L3 length.
	if p.Src.Is6() && p.IPv6PayloadLength != nil {
		p.Length = uint16(uint32(*p.IPv6PayloadLength) + 40)
	}
	if p.NonFirst && ((!n.rule.HasConditions && p.Proto == 6 && n.rule.FlagsMask != 0) || n.allowed[2] != nil) {
		return false
	}
	if !n.rule.HasConditions {
		return matches(n.rule.Rule, p.Packet, false)
	}
	values := [8]int{int(p.TTL), int(p.DSCP), int(p.Flags), int(p.ICMPType), int(p.ICMPCode), int(p.Anomaly), int(p.FragClass), int(p.Length)}
	if p.Proto != 6 {
		values[2] = 0
	}
	if p.Src.Is6() {
		values[6] = 0
	}
	if !p.ICMPValid {
		if n.allowed[3] != nil || n.allowed[4] != nil {
			return false
		}
		values[3], values[4] = 0, 0
	}
	maxima := [8]int{255, 63, 255, 255, 255, 15, 7, 65535}
	for i, v := range values {
		if v > maxima[i] {
			return false
		}
		if n.allowed[i] != nil && (v >= len(n.allowed[i]) || !n.allowed[i][v]) {
			return false
		}
	}
	return true
}

func b1Result(stage Stage, combo int, r B1Rule) B1Decision {
	code := uint8(1)
	if r.Rate > 0 {
		code = 2
	}
	return B1Decision{Decision: result(stage, combo, r.Rule), LogicalID: r.LogicalID, Rate: r.Rate, ActionCode: code, HasConditions: r.HasConditions}
}

// EvaluateB1 preserves the existing combination order, including D8 fallback
// and fixed longest-prefix IDs. All exact combinations precede any CIDR search.
func EvaluateB1(t Tables, rs B1RuleSet, p B1Packet) (B1Decision, error) {
	if e := rs.validateB1(t); e != nil {
		return B1Decision{}, e
	}
	if !p.Src.IsValid() || !p.Dst.IsValid() {
		return B1Decision{}, fmt.Errorf("packet addresses required")
	}
	if p.NonFirst {
		p.Sport, p.Dport = 0, 0
	}
	if d, ok := lookupExact(t, RuleSet{Whitelist: rs.Whitelist, WhitelistBitmap: rs.WhitelistBitmap}, p.Packet, Whitelist); ok {
		return B1Decision{Decision: d}, nil
	}
	src, dst := longest(rs.SrcPrefixes, p.Src), longest(rs.DstPrefixes, p.Dst)
	for gi, group := range [][]B1Rule{rs.Exact, rs.CIDR} {
		if gi == 1 && src == 0 && dst == 0 {
			continue
		}
		bitmap, stage := rs.ExactBitmap, Exact
		if gi == 1 {
			bitmap, stage = rs.CIDRBitmap, CIDR
		}
		for _, combo := range t.Order {
			if bitmap&t.Valid&(uint64(1)<<combo) == 0 {
				continue
			}
			var hits []b1Intent
			for _, r := range group {
				match := r.Key == maskTuple(p.Tuple, t.Masks[combo])
				if gi == 1 {
					match = r.CIDRKey == maskCIDR(CIDRTuple{src, dst, p.Sport, p.Dport, p.Proto}, t.Masks[combo])
				}
				if match {
					n, e := b1CompileIntent(r)
					if e != nil {
						return B1Decision{}, e
					}
					hits = append(hits, n)
				}
			}
			sort.Slice(hits, func(i, j int) bool {
				if hits[i].strict != hits[j].strict {
					return hits[i].strict > hits[j].strict
				}
				return hits[i].rule.LogicalID < hits[j].rule.LogicalID
			})
			for _, n := range hits {
				if b1Matches(n, p) {
					return b1Result(stage, combo, n.rule), nil
				}
			}
		}
	}
	return B1Decision{Decision: noMatch()}, nil
}

// Cut 5-4 has an explicit entry point. EvaluateB1 and lookupCIDR retain the
// previously registered semantics for replay of all historical generations.
func EvaluateB1Cut54(t Tables, rs B1RuleSet, p B1Packet) (B1Decision, error) {
	if e := rs.validateB1(t); e != nil {
		return B1Decision{}, e
	}
	if !p.Src.IsValid() || !p.Dst.IsValid() {
		return B1Decision{}, fmt.Errorf("packet addresses required")
	}
	if p.NonFirst {
		p.Sport, p.Dport = 0, 0
	}
	if d, ok := lookupExact(t, RuleSet{Whitelist: rs.Whitelist, WhitelistBitmap: rs.WhitelistBitmap}, p.Packet, Whitelist); ok {
		return B1Decision{Decision: d}, nil
	}
	src, dst := longest(rs.SrcPrefixes, p.Src), longest(rs.DstPrefixes, p.Dst)
	for gi, group := range [][]B1Rule{rs.Exact, rs.CIDR} {
		if gi == 1 && src == 0 && dst == 0 {
			continue
		}
		bitmap, stage := rs.ExactBitmap, Exact
		if gi == 1 {
			bitmap, stage = rs.CIDRBitmap, CIDR
		}
		for _, combo := range t.Order {
			if bitmap&t.Valid&(uint64(1)<<combo) == 0 {
				continue
			}
			if gi == 1 && ((t.Masks[combo]&SrcIP != 0 && src == 0) || (t.Masks[combo]&DstIP != 0 && dst == 0)) {
				continue
			}
			var hits []b1Intent
			for _, r := range group {
				match := r.Key == maskTuple(p.Tuple, t.Masks[combo])
				if gi == 1 {
					match = r.CIDRKey == maskCIDR(CIDRTuple{src, dst, p.Sport, p.Dport, p.Proto}, t.Masks[combo])
				}
				if match {
					n, e := b1CompileIntent(r)
					if e != nil {
						return B1Decision{}, e
					}
					hits = append(hits, n)
				}
			}
			sort.Slice(hits, func(i, j int) bool {
				if hits[i].strict != hits[j].strict {
					return hits[i].strict > hits[j].strict
				}
				return hits[i].rule.LogicalID < hits[j].rule.LogicalID
			})
			for _, n := range hits {
				if b1Matches(n, p) {
					return b1Result(stage, combo, n.rule), nil
				}
			}
		}
	}
	return B1Decision{Decision: noMatch()}, nil
}

func lookupCIDRCut54(t Tables, rs RuleSet, p Packet, stage Stage) (Decision, bool) {
	src, dst := longest(rs.SrcPrefixes, p.Src), longest(rs.DstPrefixes, p.Dst)
	if src == 0 && dst == 0 {
		return noMatch(), false
	}
	key := CIDRTuple{src, dst, p.Sport, p.Dport, p.Proto}
	bitmap := rs.CIDRBitmap & t.Valid
	for _, combo := range t.Order {
		if bitmap&(uint64(1)<<combo) == 0 {
			continue
		}
		if (t.Masks[combo]&SrcIP != 0 && src == 0) || (t.Masks[combo]&DstIP != 0 && dst == 0) {
			continue
		}
		candidate := maskCIDR(key, t.Masks[combo])
		for _, r := range rs.CIDR {
			if candidate == r.CIDRKey && matches(r, p, stage == AnomalyCIDR) {
				return result(stage, combo, r), true
			}
		}
	}
	// The selected LPM IDs stay fixed through the whole search: no shorter retry.
	return noMatch(), false
}

// EvaluateCut54 is the explicit 5-4 entry for the legacy RuleSet model.
func EvaluateCut54(t Tables, rs RuleSet, p Packet) (Decision, error) {
	if err := t.Validate(); err != nil {
		return Decision{}, err
	}
	if !p.Src.IsValid() || !p.Dst.IsValid() {
		return Decision{}, fmt.Errorf("packet addresses are required")
	}
	if err := rs.validate(t); err != nil {
		return Decision{}, err
	}
	cidrLookup := lookupCIDR
	if t.contract == B1 {
		cidrLookup = lookupCIDRCut54
	}
	if d, ok := lookupExact(t, rs, p, Whitelist); ok {
		return d, nil
	}
	if d, ok := lookupExact(t, rs, p, Exact); ok {
		return d, nil
	}
	if d, ok := cidrLookup(t, rs, p, CIDR); ok {
		return d, nil
	}
	if p.Anomaly != 0 {
		if d, ok := lookupExact(t, rs, p, AnomalyExact); ok {
			return d, nil
		}
		if d, ok := cidrLookup(t, rs, p, AnomalyCIDR); ok {
			return d, nil
		}
	}
	return noMatch(), nil
}
