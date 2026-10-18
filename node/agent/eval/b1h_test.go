package eval

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func b1HString(s string) *string { return &s }
func b1HTables(t *testing.T) Tables {
	t.Helper()
	v, e := LoadTables(instrumentRoot(t), B1)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func b1HRule(id string, n uint32) B1Rule {
	return B1Rule{Rule: Rule{ID: id, Key: Tuple{Proto: 6}}, LogicalID: n, HasConditions: true}
}
func b1HPacket() B1Packet {
	return B1Packet{Packet: Packet{Tuple: Tuple{Src: ip("192.0.2.1"), Dst: ip("198.51.100.1"), Proto: 6}, Length: 100}, TTL: 64, DSCP: 3}
}

func TestB1HValidation(t *testing.T) {
	tables := b1HTables(t)
	for _, kind := range []string{"physical", "mixed", "zero-id", "duplicate-rule"} {
		t.Run(kind, func(t *testing.T) {
			a, b := b1HRule("a", 1), b1HRule("b", 2)
			switch kind {
			case "physical":
				a.PktLen = b1HString("1,3,5,7,9,11,13,15,17")
			case "mixed":
				b.HasConditions = false
			case "zero-id":
				a.LogicalID = 0
			case "duplicate-rule":
				b.ID = "a"
			}
			rs := B1RuleSet{Exact: []B1Rule{a, b}, ExactBitmap: 1 << 5}
			if _, e := EvaluateB1(tables, rs, b1HPacket()); e == nil {
				t.Fatal("invalid B1 rules accepted")
			}
		})
	}
	a := b1HRule("split", 1)
	a.PktLen = b1HString("100,200,300")
	rs := B1RuleSet{Exact: []B1Rule{a}, ExactBitmap: 1 << 5}
	if _, e := EvaluateB1(tables, rs, b1HPacket()); e != nil {
		t.Fatalf("split slices share RuleID: %v", e)
	}
	for _, contract := range []Contract{PreS2a, S2a, S2b, Contract("unknown")} {
		other := tables
		other.contract = contract
		if _, e := EvaluateB1(other, rs, b1HPacket()); e == nil || !strings.Contains(e.Error(), "B1 contract") {
			t.Fatalf("contract %s accepted: %v", contract, e)
		}
	}
}

func TestB1HD1D8AndFlagZero(t *testing.T) {
	tables := b1HTables(t)
	p := b1HPacket()
	a, b, c := b1HRule("broad", 1), b1HRule("specific", 9), b1HRule("tie", 10)
	b.TTL = b1HString("64")
	c.DSCP = b1HString("3")
	rs := B1RuleSet{Exact: []B1Rule{c, a, b}, ExactBitmap: 1 << 5}
	d, e := EvaluateB1(tables, rs, p)
	if e != nil || d.RuleID != "specific" {
		t.Fatalf("D1/tie=%+v %v", d, e)
	}
	b.Key = p.Tuple
	b.TTL = b1HString("65")
	rs.Exact = []B1Rule{b, a}
	rs.ExactBitmap |= 1
	d, e = EvaluateB1(tables, rs, p)
	if e != nil || d.RuleID != "broad" || d.Combo != 5 {
		t.Fatalf("D8=%+v %v", d, e)
	}
	a.HasConditions = false
	a.FlagsMask = 2
	a.FlagsValue = 2
	p.Proto = 17
	a.Key.Proto = 17
	rs.Exact = []B1Rule{a}
	d, e = EvaluateB1(tables, rs, p)
	if e != nil || d.RuleID != "broad" {
		t.Fatalf("flag zero original non-TCP predicate=%+v %v", d, e)
	}
}

func TestB1HD5Fixture(t *testing.T) {
	tables := b1HTables(t)
	seen := 0
	for _, f := range fixtures() {
		if f.Name != "5-cidr-before-anomaly-exact" {
			continue
		}
		seen++
		rs := B1RuleSet{SrcPrefixes: f.Rules.SrcPrefixes, DstPrefixes: f.Rules.DstPrefixes, ExactBitmap: f.Rules.ExactBitmap, CIDRBitmap: f.Rules.CIDRBitmap}
		for _, r := range f.Rules.Exact {
			rs.Exact = append(rs.Exact, B1Rule{Rule: r, LogicalID: 1, HasConditions: true})
		}
		for _, r := range f.Rules.CIDR {
			rs.CIDR = append(rs.CIDR, B1Rule{Rule: r, LogicalID: 2, HasConditions: true})
		}
		d, e := EvaluateB1(tables, rs, B1Packet{Packet: f.Packet})
		if e != nil || d.RuleID != "anomaly-after-cidr" || d.Stage != Exact || d.LogicalID != 1 {
			t.Fatalf("B1 D5=%+v %v", d, e)
		}
		old, e := Evaluate(tables, f.Rules, f.Packet)
		if e != nil || old != f.Want {
			t.Fatalf("old entry changed: %+v %v", old, e)
		}
	}
	if seen != 1 {
		t.Fatalf("fixture matches=%d", seen)
	}
}

func TestB1HIndependentExpressions(t *testing.T) {
	for _, c := range []struct {
		raw     string
		max     int
		frag    bool
		yes, no int
	}{{"!0-63,65-255", 255, false, 64, 63}, {"3, 1-2", 255, false, 2, 4}, {"nonfirst", 7, true, 7, 6}, {"0,65535", 65535, false, 65535, 1}} {
		s, e := b1Expression(c.raw, c.max, c.frag)
		if e != nil || !s[c.yes] || s[c.no] {
			t.Fatalf("%s membership wrong: %v", c.raw, e)
		}
	}
	for _, s := range []string{"", "064", "+64", "64,", ",64", "64,,65", "!", "0x40", "2-1", "0-255", "!0-255", "256"} {
		if _, e := b1Expression(s, 255, false); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	tables := b1HTables(t)
	p := b1HPacket()
	r := b1HRule("split-rate", 17)
	r.Rate = 1000
	r.PktLen = b1HString("100,200,300")
	for _, length := range []uint16{99, 100, 200, 300, 301} {
		p.Length = length
		d, e := EvaluateB1(tables, B1RuleSet{Exact: []B1Rule{r}, ExactBitmap: 1 << 5}, p)
		hit := length == 100 || length == 200 || length == 300
		if e != nil || (d.RuleID == r.ID) != hit || hit && (d.Rate != 1000 || d.ActionCode != 2) {
			t.Fatalf("length=%d result=%+v %v", length, d, e)
		}
	}
	p.Src, p.Dst = ip("2001:db8::1"), ip("2001:db8::2")
	length := uint16(65535)
	p.IPv6PayloadLength = &length
	r.PktLen = b1HString("39")
	d, e := EvaluateB1(tables, B1RuleSet{Exact: []B1Rule{r}, ExactBitmap: 1 << 5}, p)
	if e != nil || d.RuleID != r.ID {
		t.Fatalf("IPv6 wrap=%+v %v", d, e)
	}
	r.Key.Proto = 58
	p.Proto = 58
	r.PktLen = nil
	r.ICMPCode = b1HString("0")
	rs := B1RuleSet{Exact: []B1Rule{r}, ExactBitmap: 1 << 5}
	for _, valid := range []bool{false, true} {
		p.ICMPValid = valid
		d, e = EvaluateB1(tables, rs, p)
		if e != nil || (d.RuleID == r.ID) != valid {
			t.Fatalf("ICMP valid=%v decision=%+v %v", valid, d, e)
		}
	}
	t.Log(fmt.Sprintf("B1_H independent_parser=1 split_shared_identity=1 ipv6_wrap=39"))
}

func TestB1HDefaultCIDRAnchor(t *testing.T) {
	tables := b1HTables(t)
	p := b1HPacket()
	r := b1HRule("default-cidr", 1)
	r.Key = Tuple{}
	r.CIDRKey = CIDRTuple{DstID: 9}
	r.Fragment = b1HString("nofrag")
	rs := B1RuleSet{CIDR: []B1Rule{r}, DstPrefixes: []Prefix{{Network: netip.MustParsePrefix("0.0.0.0/0"), ID: 9}}, CIDRBitmap: 1 << 4}
	d, e := EvaluateB1(tables, rs, p)
	if e != nil || d.RuleID != r.ID {
		t.Fatalf("IPv4 default CIDR anchor=%+v %v", d, e)
	}
}

func TestB1HIPv6LengthBothFlags(t *testing.T) {
	tables := b1HTables(t)
	for _, c := range []struct {
		name              string
		v6                bool
		payload, min, max uint16
		hit               bool
	}{
		{"wrap-39-hit", true, 65535, 39, 39, true},
		{"wrap-39-miss", true, 65535, 40, 40, false},
		{"last-before-wrap", true, 65495, 65535, 65535, true},
		{"first-wrap-zero", true, 65496, 0, 1, true},
		{"empty-payload", true, 0, 40, 40, true},
		{"ipv4-ignores-v6-payload", false, 65535, 1234, 1234, true},
	} {
		for _, flag := range []bool{false, true} {
			for _, cidr := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/flag=%v/cidr=%v", c.name, flag, cidr), func(t *testing.T) {
					p := b1HPacket()
					p.Length = 1234 // Deliberately differs from every declared IPv6 L3 length.
					p.IPv6PayloadLength = &c.payload
					if c.v6 {
						p.Src, p.Dst = ip("2001:db8::1"), ip("2001:db8::2")
					}
					r := b1HRule("length-both-flags", 77)
					r.HasConditions, r.MinLength, r.MaxLength = flag, c.min, c.max
					rs := B1RuleSet{Exact: []B1Rule{r}, ExactBitmap: 1 << 5}
					if cidr {
						bits := 32
						if c.v6 {
							bits = 128
						}
						r.Key = Tuple{}
						r.CIDRKey = CIDRTuple{DstID: 9, Proto: 6}
						rs = B1RuleSet{CIDR: []B1Rule{r}, CIDRBitmap: 1 << 3,
							DstPrefixes: []Prefix{{Network: netip.PrefixFrom(p.Dst, bits), ID: 9}}}
					}
					d, e := EvaluateB1(tables, rs, p)
					if e != nil || (d.RuleID == r.ID) != c.hit {
						t.Fatalf("decision=%+v error=%v hit=%v", d, e, c.hit)
					}
					if p.Length != 1234 || *p.IPv6PayloadLength != c.payload {
						t.Fatal("evaluator mutated caller packet")
					}
				})
			}
		}
	}
}
