package eval

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

// All fixtures are untagged Ethernet / complete, unfragmented IPv4; VLAN is
// outside S1. Anomaly fixtures use TCP doff=4 with a full TCP buffer and IHL=5.
// /16 is expressed using an RFC5737 address; it intentionally contains /24.
// Expectations below are literal, never obtained by calling Evaluate.
type fixture struct {
	Name     string
	Packet   Packet
	Rules    RuleSet
	Want     Decision
	Combos   map[string]int // independently fixed identity -> expected key combo
	Evidence [4]string      // Stage / Combo / RuleID / Action calibration channels
}

func fixtures() []fixture {
	tcp := Packet{Tuple: Tuple{Src: ip("192.0.2.10"), Dst: ip("198.51.100.20"), Sport: 1234, Dport: 443, Proto: 6}, Length: 60, Flags: 16}
	udp := tcp
	udp.Proto = 17
	udp.Flags = 0
	invalid := tcp
	invalid.Anomaly = 2
	nested := []Prefix{{netip.MustParsePrefix("192.0.2.0/16"), 16}, {netip.MustParsePrefix("192.0.2.0/24"), 24}}
	blEvidence := [4]string{"candidate match_count and stage map", "unique map key with canonical bitmap", "candidate match_count -> RuleID", "independent encoded action/rate; XDP code when deterministic"}
	out := []fixture{
		{Name: "1-priority", Packet: udp, Rules: RuleSet{Exact: []Rule{
			{ID: "coarse-drop", Key: Tuple{Proto: 17}},
			{ID: "fine-rate", Key: Tuple{Src: udp.Src, Sport: 1234, Dport: 443, Proto: 17}, Rate: 1000},
		}, ExactBitmap: 1<<5 | 1<<24}, Want: Decision{Exact, 5, "coarse-drop", "drop"}, Combos: map[string]int{"coarse-drop": 5, "fine-rate": 24}},
		{Name: "2-flags", Packet: tcp, Rules: RuleSet{Exact: []Rule{
			{ID: "syn-only", Key: tcp.Tuple, Conditions: Conditions{FlagsMask: 2, FlagsValue: 2}},
			{ID: "after-flags", Key: Tuple{Proto: 6}, Rate: 1000},
		}, ExactBitmap: 1<<0 | 1<<5}, Want: Decision{Exact, 5, "after-flags", "rate_limit@1000"}, Combos: map[string]int{"syn-only": 0, "after-flags": 5}},
		{Name: "2-length-min", Packet: tcp, Rules: RuleSet{Exact: []Rule{
			{ID: "too-short", Key: tcp.Tuple, Conditions: Conditions{MinLength: 61}},
			{ID: "after-min", Key: Tuple{Proto: 6}},
		}, ExactBitmap: 1<<0 | 1<<5}, Want: Decision{Exact, 5, "after-min", "drop"}, Combos: map[string]int{"too-short": 0, "after-min": 5}},
		{Name: "2-length-max", Packet: tcp, Rules: RuleSet{Exact: []Rule{
			{ID: "too-long", Key: tcp.Tuple, Conditions: Conditions{MaxLength: 59}},
			{ID: "after-max", Key: Tuple{Proto: 6}},
		}, ExactBitmap: 1<<0 | 1<<5}, Want: Decision{Exact, 5, "after-max", "drop"}, Combos: map[string]int{"too-long": 0, "after-max": 5}},
		{Name: "2-length-boundary", Packet: tcp, Rules: RuleSet{Exact: []Rule{
			{ID: "inclusive", Key: tcp.Tuple, Conditions: Conditions{MinLength: 60, MaxLength: 60}},
			{ID: "later", Key: Tuple{Proto: 6}, Rate: 1000},
		}, ExactBitmap: 1<<0 | 1<<5}, Want: Decision{Exact, 0, "inclusive", "drop"}, Combos: map[string]int{"inclusive": 0, "later": 5}},
		{Name: "2-non-tcp-flags", Packet: udp, Rules: RuleSet{Exact: []Rule{
			{ID: "udp-flags-ignored", Key: Tuple{Proto: 17}, Conditions: Conditions{FlagsMask: 2, FlagsValue: 2}},
		}, ExactBitmap: 1 << 5}, Want: Decision{Exact, 5, "udp-flags-ignored", "drop"}, Combos: map[string]int{"udp-flags-ignored": 5}},
		{Name: "3-rate-first", Packet: udp, Rules: RuleSet{Exact: []Rule{
			{ID: "coarse-rate", Key: Tuple{Proto: 17}, Rate: 1000},
			{ID: "fine-drop", Key: Tuple{Src: udp.Src, Sport: 1234, Dport: 443, Proto: 17}},
		}, ExactBitmap: 1<<5 | 1<<24}, Want: Decision{Exact, 5, "coarse-rate", "rate_limit@1000"}, Combos: map[string]int{"coarse-rate": 5, "fine-drop": 24}},
		{Name: "4-a", Packet: tcp, Rules: RuleSet{SrcPrefixes: nested, CIDR: []Rule{
			{ID: "short-drop", CIDRKey: CIDRTuple{SrcID: 16}},
			{ID: "long-drop", CIDRKey: CIDRTuple{SrcID: 24}},
		}, CIDRBitmap: 1 << 8}, Want: Decision{CIDR, 8, "long-drop", "drop"}, Combos: map[string]int{"short-drop": 8, "long-drop": 8}},
		{Name: "4-b", Packet: tcp, Rules: RuleSet{SrcPrefixes: nested, CIDR: []Rule{
			{ID: "short-must-not-win", CIDRKey: CIDRTuple{SrcID: 16}},
			{ID: "long-syn", CIDRKey: CIDRTuple{SrcID: 24}, Conditions: Conditions{FlagsMask: 2, FlagsValue: 2}},
		}, CIDRBitmap: 1 << 8}, Want: Decision{None, -1, "", "pass_no_match"}, Combos: map[string]int{"short-must-not-win": 8, "long-syn": 8}},
		{Name: "4-c", Packet: tcp, Rules: RuleSet{SrcPrefixes: nested, CIDR: []Rule{
			{ID: "clear-selected-id", CIDRKey: CIDRTuple{Proto: 6}},
			{ID: "keep-selected-id", CIDRKey: CIDRTuple{SrcID: 24}},
		}, CIDRBitmap: 1<<5 | 1<<8}, Want: Decision{CIDR, 5, "clear-selected-id", "drop"}, Combos: map[string]int{"clear-selected-id": 5, "keep-selected-id": 8}},
		{Name: "5-whitelist", Packet: tcp, Rules: RuleSet{
			Whitelist: []Rule{{ID: "only-whitelist", Key: Tuple{Src: tcp.Src}}}, WhitelistBitmap: 1 << 8,
			Exact: []Rule{{ID: "blacklist-behind-wl", Key: tcp.Tuple}}, ExactBitmap: 1 << 0,
		}, Want: Decision{Whitelist, 8, "only-whitelist", "pass_whitelist"}, Combos: map[string]int{"only-whitelist": 8, "blacklist-behind-wl": 0}},
		{Name: "5-exact-before-cidr", Packet: tcp, Rules: RuleSet{
			Exact: []Rule{{ID: "exact-first", Key: Tuple{Proto: 6}}}, ExactBitmap: 1 << 5,
			SrcPrefixes: nested, CIDR: []Rule{{ID: "cidr-after-exact", CIDRKey: CIDRTuple{SrcID: 24}}}, CIDRBitmap: 1 << 8,
		}, Want: Decision{Exact, 5, "exact-first", "drop"}, Combos: map[string]int{"exact-first": 5, "cidr-after-exact": 8}},
		{Name: "5-cidr-before-anomaly-exact", Packet: invalid, Rules: RuleSet{
			Exact: []Rule{{ID: "anomaly-after-cidr", Key: tcp.Tuple, Conditions: Conditions{Anomaly: 2}}}, ExactBitmap: 1 << 0,
			SrcPrefixes: nested, CIDR: []Rule{{ID: "ordinary-cidr-first", CIDRKey: CIDRTuple{SrcID: 24}}}, CIDRBitmap: 1 << 8,
		}, Want: Decision{CIDR, 8, "ordinary-cidr-first", "drop"}, Combos: map[string]int{"anomaly-after-cidr": 0, "ordinary-cidr-first": 8}},
		{Name: "5-anomaly-exact", Packet: invalid, Rules: RuleSet{
			Exact: []Rule{{ID: "anomaly-exact-first", Key: tcp.Tuple, Conditions: Conditions{Anomaly: 2}}}, ExactBitmap: 1 << 0,
			SrcPrefixes: nested, CIDR: []Rule{{ID: "anomaly-cidr-second", CIDRKey: CIDRTuple{SrcID: 24}, Conditions: Conditions{Anomaly: 2}}}, CIDRBitmap: 1 << 8,
		}, Want: Decision{AnomalyExact, 0, "anomaly-exact-first", "drop"}, Combos: map[string]int{"anomaly-exact-first": 0, "anomaly-cidr-second": 8}},
		{Name: "5-anomaly-cidr", Packet: invalid, Rules: RuleSet{
			Exact: []Rule{{ID: "wrong-anomaly-bit", Key: tcp.Tuple, Conditions: Conditions{Anomaly: 1}}}, ExactBitmap: 1 << 0,
			SrcPrefixes: nested, CIDR: []Rule{{ID: "anomaly-cidr", CIDRKey: CIDRTuple{SrcID: 24}, Conditions: Conditions{Anomaly: 2}}}, CIDRBitmap: 1 << 8,
		}, Want: Decision{AnomalyCIDR, 8, "anomaly-cidr", "drop"}, Combos: map[string]int{"wrong-anomaly-bit": 0, "anomaly-cidr": 8}},
		{Name: "5-none", Packet: tcp, Rules: RuleSet{
			Exact: []Rule{{ID: "udp-miss", Key: Tuple{Proto: 17}}}, ExactBitmap: 1 << 5,
		}, Want: Decision{None, -1, "", "pass_no_match"}, Combos: map[string]int{"udp-miss": 5}},
	}
	for i := range out {
		out[i].Evidence = blEvidence
		if out[i].Want.Stage == Whitelist {
			out[i].Evidence = [4]string{"whitelist stats delta; all blacklist deltas zero", "sole possible whitelist key; canonical bitmap", "sole possible whitelist rule", "whitelist stats and XDP_PASS"}
		}
		if out[i].Want.Stage == None {
			out[i].Evidence = [4]string{"all candidate/whitelist deltas zero", "no winning combo", "no winning rule", "XDP_PASS with FF off"}
		}
	}
	return out
}

func checkDecision(t *testing.T, got, want Decision) {
	t.Helper()
	for _, f := range []struct {
		name      string
		got, want any
	}{{"Stage", got.Stage, want.Stage}, {"Combo", got.Combo, want.Combo}, {"RuleID", got.RuleID, want.RuleID}, {"Action", got.Action, want.Action}} {
		t.Run(f.name, func(t *testing.T) {
			if f.got != f.want {
				t.Errorf("%s got=%v want=%v", f.name, f.got, f.want)
			}
		})
	}
}
func TestFixtures(t *testing.T) {
	tables := testTables(t)
	for _, original := range fixtures() {
		f := privateModelFixture(original)
		t.Run(f.Name, func(t *testing.T) {
			got, err := Evaluate(tables, f.Rules, f.Packet)
			if err != nil {
				t.Fatal(err)
			}
			checkDecision(t, got, f.Want)
		})
	}
}
func TestFixtureContract(t *testing.T) {
	tables := testTables(t)
	expectedNames := []string{"1-priority", "2-flags", "2-length-min", "2-length-max", "2-length-boundary", "2-non-tcp-flags", "3-rate-first", "4-a", "4-b", "4-c", "5-whitelist", "5-exact-before-cidr", "5-cidr-before-anomaly-exact", "5-anomaly-exact", "5-anomaly-cidr", "5-none"}
	var names []string
	documentation := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	checkIP := func(ip netip.Addr) {
		if !ip.IsValid() {
			return
		}
		for _, p := range documentation {
			if p.Contains(ip) {
				return
			}
		}
		t.Fatalf("non-RFC5737 fixture address: %s", ip)
	}
	paths := map[Stage]bool{}
	for _, f := range fixtures() {
		for _, rules := range [][]Rule{f.Rules.Whitelist, f.Rules.Exact, f.Rules.CIDR} {
			if len(rules) > 256 {
				t.Fatal("fixture exceeds private rule capacity before loading")
			}
		}
		if len(f.Rules.SrcPrefixes) > 256 || len(f.Rules.DstPrefixes) > 256 {
			t.Fatal("fixture exceeds private LPM capacity before loading")
		}
		names = append(names, f.Name)
		paths[f.Want.Stage] = true
		if err := f.Rules.validate(tables); err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		if (f.Rules.WhitelistBitmap|f.Rules.ExactBitmap|f.Rules.CIDRBitmap)&((1<<19)|(1<<20)|(1<<32)) != 0 {
			t.Fatal("noncanonical fixture bitmap")
		}
		for _, channel := range f.Evidence {
			if channel == "" {
				t.Fatal("unlabeled output evidence")
			}
		}
		checkIP(f.Packet.Src)
		checkIP(f.Packet.Dst)
		for _, ps := range [][]Prefix{f.Rules.SrcPrefixes, f.Rules.DstPrefixes} {
			for _, p := range ps {
				checkIP(p.Network.Addr())
			}
		}
		n := 0
		for stage, rs := range map[Stage][]Rule{Whitelist: f.Rules.Whitelist, Exact: f.Rules.Exact, CIDR: f.Rules.CIDR} {
			for _, r := range rs {
				n++
				combo, ok := f.Combos[r.ID]
				if !ok {
					t.Fatalf("missing combo identity %s", r.ID)
				}
				var mask Mask
				if stage == CIDR {
					if r.CIDRKey.SrcID != 0 {
						mask |= SrcIP
					}
					if r.CIDRKey.DstID != 0 {
						mask |= DstIP
					}
					if r.CIDRKey.Sport != 0 {
						mask |= SrcPort
					}
					if r.CIDRKey.Dport != 0 {
						mask |= DstPort
					}
					if r.CIDRKey.Proto != 0 {
						mask |= Protocol
					}
				} else {
					checkIP(r.Key.Src)
					checkIP(r.Key.Dst)
					if r.Key.Src.IsValid() {
						mask |= SrcIP
					}
					if r.Key.Dst.IsValid() {
						mask |= DstIP
					}
					if r.Key.Sport != 0 {
						mask |= SrcPort
					}
					if r.Key.Dport != 0 {
						mask |= DstPort
					}
					if r.Key.Proto != 0 {
						mask |= Protocol
					}
				}
				bitmap := f.Rules.ExactBitmap
				if stage == Whitelist {
					bitmap = f.Rules.WhitelistBitmap
				}
				if stage == CIDR {
					bitmap = f.Rules.CIDRBitmap
				}
				var enabled []int
				for _, b := range tables.Order {
					if bitmap&(1<<b) != 0 && tables.Masks[b] == mask {
						enabled = append(enabled, b)
					}
				}
				if !reflect.DeepEqual(enabled, []int{combo}) {
					t.Fatalf("%s key/combo ambiguity for %s: %v want [%d]", f.Name, r.ID, enabled, combo)
				}
			}
		}
		if n == 0 || n != len(f.Combos) {
			t.Fatalf("%s candidate inventory=%d bindings=%d", f.Name, n, len(f.Combos))
		}
	}
	if !reflect.DeepEqual(names, expectedNames) {
		t.Fatalf("fixture inventory got=%v want=%v", names, expectedNames)
	}
	for _, stage := range []Stage{Whitelist, Exact, CIDR, AnomalyExact, AnomalyCIDR, None} {
		if !paths[stage] {
			t.Fatalf("missing stage %s", stage)
		}
	}
	t.Logf("fixtures=%d fields_per_fixture=%d observable_paths=%d", len(names), len(fixtures()[0].Evidence), len(paths))
}

func TestPostConditions(t *testing.T) {
	// Small truth table independently covers zero/unset and inclusive boundaries.
	r := Rule{Conditions: Conditions{MinLength: 40, MaxLength: 60, FlagsMask: 2, FlagsValue: 2}}
	for _, c := range []struct {
		length       uint16
		proto, flags uint8
		want         bool
	}{{39, 6, 2, false}, {40, 6, 2, true}, {60, 6, 2, true}, {61, 6, 2, false}, {50, 6, 16, false}, {50, 17, 0, true}} {
		t.Run(fmt.Sprintf("%d-%d-%d", c.length, c.proto, c.flags), func(t *testing.T) {
			if got := matches(r, Packet{Tuple: Tuple{Proto: c.proto}, Length: c.length, Flags: c.flags}, false); got != c.want {
				t.Fatalf("got=%v want=%v", got, c.want)
			}
		})
	}
}
