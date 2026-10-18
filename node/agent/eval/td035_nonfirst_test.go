package eval

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestTD035NonFirstOracle(t *testing.T) {
	tables := b1HTables(t)
	cells := 0
	for _, v6 := range []bool{false, true} {
		for _, nonfirst := range []bool{false, true} {
			for _, kind := range []string{"ip", "port", "cidr-port", "whitelist-port", "whitelist-ip", "legacy-syn", "legacy-not-syn", "condition-syn", "condition-not-syn", "non-tcp-legacy-flags"} {
				t.Run(fmt.Sprintf("v6=%t/nonfirst=%t/%s", v6, nonfirst, kind), func(t *testing.T) {
					p := b1HPacket()
					p.Sport, p.Dport, p.Flags, p.NonFirst = 1234, 53, 2, nonfirst
					prefix := netip.MustParsePrefix("198.51.100.0/24")
					if v6 {
						p.Src, p.Dst = ip("2001:db8:1::1"), ip("2001:db8:2::1")
						prefix = netip.MustParsePrefix("2001:db8:2::/64")
					}
					r := B1Rule{Rule: Rule{ID: "target", Key: Tuple{Dst: p.Dst, Proto: 6}}, LogicalID: 1}
					combo := 3
					wantHit := true
					switch kind {
					case "port", "whitelist-port":
						r.Key.Dport = 53
						combo = 2
						wantHit = !nonfirst
					case "legacy-syn", "condition-syn":
						r.FlagsMask, r.FlagsValue = 2, 2
						wantHit = !nonfirst
					case "legacy-not-syn", "condition-not-syn":
						r.FlagsMask = 2
						p.Flags = 0x10
						wantHit = !nonfirst
					case "non-tcp-legacy-flags":
						p.Proto, r.Key.Proto = 17, 17
						r.FlagsMask, r.FlagsValue = 2, 2
					}
					if kind == "condition-syn" || kind == "condition-not-syn" {
						r.HasConditions = true
					}
					rs := B1RuleSet{Exact: []B1Rule{r}, ExactBitmap: 1 << combo}
					if kind == "cidr-port" {
						r.Key = Tuple{}
						r.CIDRKey = CIDRTuple{DstID: 9, Dport: 53, Proto: 6}
						rs = B1RuleSet{CIDR: []B1Rule{r}, CIDRBitmap: 1 << 2, DstPrefixes: []Prefix{{Network: prefix, ID: 9}}}
						wantHit = !nonfirst
					}
					if kind == "whitelist-port" || kind == "whitelist-ip" {
						rs = B1RuleSet{Whitelist: []Rule{r.Rule}, WhitelistBitmap: 1 << combo}
					}
					d, err := EvaluateB1(tables, rs, p)
					if err != nil {
						t.Fatal(err)
					}
					if (d.RuleID == "target") != wantHit {
						t.Fatalf("TD035_ORACLE kind=%s NonFirst=%t got=%+v wantHit=%t", kind, nonfirst, d, wantHit)
					}
					cells++
				})
			}
		}
	}
	if cells != 40 {
		t.Fatalf("TD035_ORACLE cells=%d want=40", cells)
	}
	t.Logf("TD035_ORACLE cells=%d", cells)
}

// Source-only port keys keep a destination-port miss from masking an uncleared
// source port. Complete/first hits and two-byte source-port twins are controls.
func TestTD035SourcePortOracle(t *testing.T) {
	td035SourcePortOracle(t, 17)
}

func TestTD035TCPSourcePortOracle(t *testing.T) {
	td035SourcePortOracle(t, 6)
}

func td035SourcePortOracle(t *testing.T, proto uint8) {
	tables := b1HTables(t)
	cells := 0
	for _, v := range []int{4, 6} {
		for _, kind := range []string{"complete", "first", "last", "middle"} {
			for _, path := range []string{"whitelist", "exact", "cidr"} {
				for _, sport := range []uint16{1234, 5678} {
					t.Run(fmt.Sprintf("v%d/%s-sport%d/%s", v, kind, sport, path), func(t *testing.T) {
						p := b1HPacket()
						p.Proto, p.Sport, p.Dport = proto, sport, 53
						p.NonFirst = kind == "last" || kind == "middle"
						prefix := netip.MustParsePrefix("198.51.100.0/24")
						if v == 6 {
							p.Src, p.Dst = ip("2001:db8:1::1"), ip("2001:db8:2::1")
							prefix = netip.MustParsePrefix("2001:db8:2::/64")
						} else {
							p.FragClass = map[string]uint8{"complete": 0, "first": 2, "last": 1, "middle": 3}[kind]
						}
						// 守卫格: complete/first sport 1234 hits; sport 5678 always misses.
						// 行为格: nonfirst sport 1234 must miss despite the forged bytes.
						wantHit := !p.NonFirst && sport == 1234
						r := B1Rule{Rule: Rule{ID: "src-port-target", Key: Tuple{Dst: p.Dst, Sport: 1234, Proto: proto}}, LogicalID: 1}
						rs := B1RuleSet{Exact: []B1Rule{r}, ExactBitmap: 1 << 26}
						switch path {
						case "whitelist":
							rs = B1RuleSet{Whitelist: []Rule{r.Rule}, WhitelistBitmap: 1 << 26}
						case "cidr":
							r.Key = Tuple{}
							r.CIDRKey = CIDRTuple{DstID: 9, Sport: 1234, Proto: proto}
							rs = B1RuleSet{CIDR: []B1Rule{r}, CIDRBitmap: 1 << 26, DstPrefixes: []Prefix{{Network: prefix, ID: 9}}}
						}
						d, err := EvaluateB1(tables, rs, p)
						if err != nil {
							t.Fatal(err)
						}
						if (d.RuleID == "src-port-target") != wantHit {
							t.Fatalf("TD035_SRC_ORACLE v=%d pkt=%s-sport%d rule=%s NonFirst=%t got=%+v wantHit=%t", v, kind, sport, path, p.NonFirst, d, wantHit)
						}
						cells++
					})
				}
			}
		}
	}
	if cells != 48 {
		t.Fatalf("TD035_SRC_ORACLE cells=%d want=48", cells)
	}
	t.Logf("TD035_SRC_ORACLE cells=%d", cells)
}
