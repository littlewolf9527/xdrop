// 权威在 shared/condexpr/，controller 与 node 各有一份逐字节拷贝，⛔ 手改拷贝。
package condexpr

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
)

type Tuple struct {
	SrcIP, DstIP, SrcCIDR, DstCIDR string
	SrcPort, DstPort               int
	Protocol                       string
}

// NormalizeTuple follows the node's input aliases, preserving exact/CIDR keys.
func NormalizeTuple(t Tuple) (Tuple, error) {
	if t.Protocol == "" {
		t.Protocol = "all"
	}
	switch t.Protocol {
	case "all", "tcp", "udp", "icmp", "icmpv6", "igmp", "gre", "esp":
	default:
		return t, fmt.Errorf("invalid protocol %q", t.Protocol)
	}
	if t.SrcPort < 0 || t.SrcPort > 65535 || t.DstPort < 0 || t.DstPort > 65535 {
		return t, fmt.Errorf("port outside 0-65535")
	}
	if t.Protocol != "all" && t.Protocol != "tcp" && t.Protocol != "udp" && (t.SrcPort != 0 || t.DstPort != 0) {
		return t, fmt.Errorf("protocol %s does not carry ports", t.Protocol)
	}
	if (t.SrcCIDR != "" || t.DstCIDR != "") && (t.SrcIP != "" || t.DstIP != "") {
		return t, fmt.Errorf("cannot mix exact IP and CIDR")
	}
	for _, p := range []*string{&t.SrcIP, &t.DstIP} {
		if *p == "" {
			continue
		}
		ip := net.ParseIP(*p)
		if ip == nil {
			return t, fmt.Errorf("invalid IP %q", *p)
		}
		*p = ip.String()
		if *p == "0.0.0.0" || *p == "::" {
			*p = ""
		}
	}
	for _, p := range []*string{&t.SrcCIDR, &t.DstCIDR} {
		if *p == "" {
			continue
		}
		_, n, e := net.ParseCIDR(*p)
		if e != nil {
			return t, fmt.Errorf("invalid CIDR %q", *p)
		}
		*p = n.String()
	}
	return t, nil
}

type Input struct {
	Tuple
	Fields
	TCPFlags                           string
	MatchAnomaly, PktLenMin, PktLenMax int
}

type Normalized struct {
	Tuple
	Fields
	Canonical                  [8]string
	Sets                       [8][]Span // nil means unconstrained, never an empty allowed set
	TCPFlags                   string
	Strictness, CandidateCount int
}

func (n Normalized) CondKey() string { b, _ := json.Marshal(n.Canonical); return string(b) }

func truthSet(max int, predicate func(int) bool) []Span {
	var spans []Span
	for v := 0; v <= max; v++ {
		if predicate(v) {
			spans = append(spans, Span{uint16(v), uint16(v)})
		}
	}
	return merge(spans)
}

func Compile(in Input) (Normalized, error) {
	var n Normalized
	t, e := NormalizeTuple(in.Tuple)
	if e != nil {
		return n, e
	}
	n.Tuple = t
	values := in.Fields.Values()
	for i, a := range Registry() {
		if values[i] == nil {
			continue
		}
		if a.Protocols != "*" && !strings.Contains(","+a.Protocols+",", ","+t.Protocol+",") {
			return n, fmt.Errorf("%s requires protocol %s", a.Key, a.Protocols)
		}
		n.Canonical[i], n.Sets[i], e = Parse(a.Key, *values[i])
		if e != nil {
			return n, e
		}
	}
	mask, value, flags, e := ParseTCPFlags(in.TCPFlags)
	if e != nil {
		return n, e
	}
	n.TCPFlags = flags
	if mask != 0 {
		if t.Protocol != "tcp" {
			return n, fmt.Errorf("tcp_flags requires protocol tcp")
		}
		n.Sets[2] = truthSet(255, func(v int) bool { return uint8(v)&mask == value })
		n.Canonical[2] = format(n.Sets[2])
	}
	if in.MatchAnomaly < 0 || in.MatchAnomaly > 15 {
		return n, fmt.Errorf("match_anomaly outside 0x0F")
	}
	if in.MatchAnomaly != 0 {
		n.Sets[5] = truthSet(15, func(v int) bool { return v&in.MatchAnomaly != 0 })
		n.Canonical[5] = format(n.Sets[5])
	}
	if in.PktLenMin < 0 || in.PktLenMin > 65535 || in.PktLenMax < 0 || in.PktLenMax > 65535 {
		return n, fmt.Errorf("legacy packet length outside 0-65535")
	}
	legacy := in.PktLenMin > 0 || (in.PktLenMax != 0 && in.PktLenMax != 65535)
	if legacy {
		if in.PktLen != nil {
			return n, fmt.Errorf("new and legacy packet length coexist")
		}
		hi := in.PktLenMax
		if hi == 0 {
			hi = 65535
		}
		if in.PktLenMin > hi {
			return n, fmt.Errorf("legacy packet length reversed interval")
		}
		n.Sets[7] = []Span{{uint16(in.PktLenMin), uint16(hi)}}
		n.Canonical[7] = format(n.Sets[7])
	}
	v4, v6, anchor := false, false, t.Protocol != "all" || t.SrcPort != 0 || t.DstPort != 0
	for _, s := range []string{t.SrcIP, t.DstIP, t.SrcCIDR, t.DstCIDR} {
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if strings.Contains(s, "/") {
			ip, _, _ = net.ParseCIDR(s)
			// A /0 is still an explicit family-specific trie key, matching
			// validatePktLenRule's existing nonempty-CIDR anchor convention.
		}
		anchor = true
		if ip.To4() != nil {
			v4 = true
		} else {
			v6 = true
		}
	}
	if in.Fragment != nil && (!v4 || v6) {
		return n, fmt.Errorf("fragment requires IPv4 address or CIDR anchor")
	}
	if in.MatchAnomaly&9 != 0 && v6 {
		return n, fmt.Errorf("match_anomaly 0x01/0x08 unsupported for IPv6 target")
	}
	// D2 uses the allowed set, not the spelling of the fragment expression.
	l4Constrained := t.SrcPort != 0 || t.DstPort != 0 || n.Sets[2] != nil || n.Sets[3] != nil || n.Sets[4] != nil
	nonfirstOnly := len(n.Sets[6]) != 0
	for _, span := range n.Sets[6] {
		if span.Lo != span.Hi || span.Lo > 7 || span.Lo&1 == 0 {
			nonfirstOnly = false
		}
	}
	if l4Constrained && (nonfirstOnly || in.MatchAnomaly == 0x08) {
		return n, fmt.Errorf("D2: nonfirst fragment or anomaly 0x08 cannot satisfy a port, TCP flags, or ICMP constraint")
	}
	for _, s := range n.Sets {
		if s != nil {
			n.Strictness++
		}
	}
	if n.Strictness > 0 && !anchor {
		return n, fmt.Errorf("condition rule requires a five-tuple anchor")
	}
	n.Fields = fieldsFrom(n.Canonical, values)
	n.CandidateCount = (len(n.Sets[7]) + SpansPerCandidate - 1) / SpansPerCandidate
	if n.CandidateCount == 0 {
		n.CandidateCount = 1
	}
	return n, nil
}

type Rule struct {
	Input
	ID        string
	LogicalID uint32
	Action    string
	Rate      uint32
}

type Candidate struct {
	Normalized
	ID        string
	LogicalID uint32
	Action    string
	Rate      uint32
	Piece     int
	Lengths   [SpansPerCandidate]Span
}

type CapacityError struct {
	Count   int
	RuleIDs []string
}

func (e *CapacityError) Error() string {
	return fmt.Sprintf("physical candidates %d exceed %d; occupying rule IDs: %s", e.Count, MaxCandidates, strings.Join(e.RuleIDs, ","))
}

// Candidates consumes logical rules for exactly one normalized tuple.
func Candidates(rules []Rule) ([]Candidate, error) {
	var out []Candidate
	var tuple Tuple
	ids := map[string]bool{}
	logical := map[uint32]bool{}
	var occupied []string
	for i, r := range rules {
		n, e := Compile(r.Input)
		if e != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, e)
		}
		if i == 0 {
			tuple = n.Tuple
		} else if tuple != n.Tuple {
			return nil, fmt.Errorf("candidates have different five-tuples")
		}
		if r.ID == "" || ids[r.ID] {
			return nil, fmt.Errorf("missing/duplicate rule ID %q", r.ID)
		}
		ids[r.ID] = true
		if r.LogicalID == 0 || logical[r.LogicalID] {
			return nil, fmt.Errorf("missing/duplicate logical_id %d", r.LogicalID)
		}
		logical[r.LogicalID] = true
		if r.Action != "drop" && r.Action != "rate_limit" {
			return nil, fmt.Errorf("action must be drop or rate_limit")
		}
		if r.Action == "rate_limit" && r.Rate == 0 {
			return nil, fmt.Errorf("rate_limit requires positive rate")
		}
		rate := r.Rate
		if r.Action == "drop" {
			rate = 0
		}
		occupied = append(occupied, r.ID)
		lengths := n.Sets[7]
		if lengths == nil {
			lengths = []Span{{0, 65535}}
		}
		for start := 0; start < len(lengths); start += SpansPerCandidate {
			c := Candidate{Normalized: n, ID: r.ID, LogicalID: r.LogicalID, Action: r.Action, Rate: rate, Piece: start / SpansPerCandidate, Lengths: [SpansPerCandidate]Span{{1, 0}, {1, 0}}}
			end := start + SpansPerCandidate
			if end > len(lengths) {
				end = len(lengths)
			}
			copy(c.Lengths[:], lengths[start:end])
			out = append(out, c)
		}
	}
	if len(out) > MaxCandidates {
		sort.Strings(occupied)
		return nil, &CapacityError{len(out), occupied}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Strictness != out[j].Strictness {
			return out[i].Strictness > out[j].Strictness
		}
		if out[i].LogicalID != out[j].LogicalID {
			return out[i].LogicalID < out[j].LogicalID
		}
		return out[i].Piece < out[j].Piece
	})
	return out, nil
}

// Allows interprets nil as the reachable domain, for deterministic H encoding.
func Allows(spans []Span, value int) bool { return spans == nil || contains(spans, value) }
