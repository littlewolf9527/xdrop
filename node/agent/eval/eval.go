package eval

import (
	"fmt"
	"net/netip"
)

type Stage string

const (
	Whitelist    Stage = "whitelist"
	Exact        Stage = "exact"
	CIDR         Stage = "cidr"
	AnomalyExact Stage = "anomaly_exact"
	AnomalyCIDR  Stage = "anomaly_cidr"
	None         Stage = "none"
)

type Decision struct {
	Stage  Stage
	Combo  int
	RuleID string
	Action string
}

type Tuple struct {
	Src, Dst     netip.Addr
	Sport, Dport uint16
	Proto        uint8
}
type CIDRTuple struct {
	SrcID, DstID uint32
	Sport, Dport uint16
	Proto        uint8
}
type Packet struct {
	Tuple
	Length         uint16
	Flags, Anomaly uint8
}
type Conditions struct {
	MinLength, MaxLength           uint16
	FlagsMask, FlagsValue, Anomaly uint8
}

// The instrument's blacklist action domain is DROP or positive-rate limiting,
// the two blacklist actions represented by the PLAN's output vocabulary.
type Rule struct {
	ID      string
	Key     Tuple
	CIDRKey CIDRTuple
	Conditions
	Rate uint32 // zero = DROP; positive = RATE_LIMIT, no token-bucket simulation
}
type Prefix struct {
	Network netip.Prefix
	ID      uint32
}
type RuleSet struct {
	Whitelist, Exact, CIDR                   []Rule
	SrcPrefixes, DstPrefixes                 []Prefix
	WhitelistBitmap, ExactBitmap, CIDRBitmap uint64 // explicit, including zero
}

func noMatch() Decision { return Decision{Stage: None, Combo: -1, Action: "pass_no_match"} }
func result(stage Stage, combo int, r Rule) Decision {
	action := "drop"
	if stage == Whitelist {
		action = "pass_whitelist"
	} else if r.Rate > 0 && stage != AnomalyExact && stage != AnomalyCIDR {
		action = fmt.Sprintf("rate_limit@%d", r.Rate)
	}
	return Decision{stage, combo, r.ID, action}
}
func maskTuple(k Tuple, m Mask) Tuple {
	if m&SrcIP == 0 {
		k.Src = netip.Addr{}
	}
	if m&DstIP == 0 {
		k.Dst = netip.Addr{}
	}
	if m&SrcPort == 0 {
		k.Sport = 0
	}
	if m&DstPort == 0 {
		k.Dport = 0
	}
	if m&Protocol == 0 {
		k.Proto = 0
	}
	return k
}
func maskCIDR(k CIDRTuple, m Mask) CIDRTuple {
	if m&SrcIP == 0 {
		k.SrcID = 0
	}
	if m&DstIP == 0 {
		k.DstID = 0
	}
	if m&SrcPort == 0 {
		k.Sport = 0
	}
	if m&DstPort == 0 {
		k.Dport = 0
	}
	if m&Protocol == 0 {
		k.Proto = 0
	}
	return k
}
func matches(r Rule, p Packet, anomaly bool) bool {
	if r.MinLength > 0 && p.Length < r.MinLength || r.MaxLength > 0 && p.Length > r.MaxLength {
		return false
	}
	if p.Proto == 6 && r.FlagsMask != 0 && p.Flags&r.FlagsMask != r.FlagsValue {
		return false
	}
	if anomaly {
		return r.Anomaly != 0 && r.Anomaly&p.Anomaly != 0
	}
	return r.Anomaly == 0
}
func longest(prefixes []Prefix, ip netip.Addr) uint32 {
	best, id := -1, uint32(0)
	for _, p := range prefixes {
		if p.Network.Contains(ip) && p.Network.Bits() > best {
			best, id = p.Network.Bits(), p.ID
		}
	}
	return id
}

func lookupExact(t Tables, rs RuleSet, p Packet, stage Stage) (Decision, bool) {
	rules, bitmap, order := rs.Exact, rs.ExactBitmap, t.Order
	if stage == Whitelist {
		rules, bitmap, order = rs.Whitelist, rs.WhitelistBitmap, t.WhitelistOrder
	}
	bitmap &= t.Valid
	for _, combo := range order {
		if bitmap&(uint64(1)<<combo) == 0 {
			continue
		}
		key := maskTuple(p.Tuple, t.Masks[combo])
		for _, r := range rules {
			if key == r.Key && (stage == Whitelist || matches(r, p, stage == AnomalyExact)) {
				return result(stage, combo, r), true
			}
		}
	}
	return noMatch(), false
}
func lookupCIDR(t Tables, rs RuleSet, p Packet, stage Stage) (Decision, bool) {
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

// Evaluate follows gate -> main exact -> main CIDR -> anomaly exact -> anomaly
// CIDR. All comparisons use the map keys, not a rule's declared combo label.
func Evaluate(t Tables, rs RuleSet, p Packet) (Decision, error) {
	if err := t.Validate(); err != nil {
		return Decision{}, err
	}
	if !p.Src.IsValid() || !p.Dst.IsValid() {
		return Decision{}, fmt.Errorf("packet addresses are required")
	}
	if err := rs.validate(t); err != nil {
		return Decision{}, err
	}
	if d, ok := lookupExact(t, rs, p, Whitelist); ok {
		return d, nil
	}
	if d, ok := lookupExact(t, rs, p, Exact); ok {
		return d, nil
	}
	if d, ok := lookupCIDR(t, rs, p, CIDR); ok {
		return d, nil
	}
	if p.Anomaly != 0 {
		if d, ok := lookupExact(t, rs, p, AnomalyExact); ok {
			return d, nil
		}
		if d, ok := lookupCIDR(t, rs, p, AnomalyCIDR); ok {
			return d, nil
		}
	}
	return noMatch(), nil
}
func (rs RuleSet) validate(t Tables) error {
	if (rs.ExactBitmap|rs.CIDRBitmap|rs.WhitelistBitmap)&^t.Valid != 0 {
		return fmt.Errorf("bitmap contains absent combo")
	}
	if rs.WhitelistBitmap&((1<<20)|(1<<32)) != 0 {
		return fmt.Errorf("whitelist bitmap contains an unexpanded alias")
	}
	ids := map[string]bool{}
	for _, group := range [][]Rule{rs.Whitelist, rs.Exact, rs.CIDR} {
		for _, r := range group {
			if r.ID == "" || ids[r.ID] {
				return fmt.Errorf("missing/duplicate RuleID %q", r.ID)
			}
			ids[r.ID] = true
		}
	}
	for _, group := range [][]Rule{rs.Whitelist, rs.Exact} {
		seen := map[Tuple]bool{}
		for _, r := range group {
			if seen[r.Key] {
				return fmt.Errorf("duplicate exact map key")
			}
			seen[r.Key] = true
		}
	}
	seen := map[CIDRTuple]bool{}
	for _, r := range rs.CIDR {
		if seen[r.CIDRKey] {
			return fmt.Errorf("duplicate CIDR map key")
		}
		seen[r.CIDRKey] = true
	}
	for _, group := range [][]Prefix{rs.SrcPrefixes, rs.DstPrefixes} {
		prefixes := map[netip.Prefix]bool{}
		for _, p := range group {
			if !p.Network.IsValid() || p.ID == 0 || prefixes[p.Network.Masked()] {
				return fmt.Errorf("invalid/duplicate LPM prefix")
			}
			prefixes[p.Network.Masked()] = true
		}
	}
	return nil
}
