// 权威在 shared/condexpr/，controller 与 node 各有一份逐字节拷贝，⛔ 手改拷贝。
package condexpr

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func ptr(s string) *string { return &s }

func TestB1ExpressionMatrix(t *testing.T) {
	for _, a := range ExpressionAttributes() {
		cases := []struct{ name, raw, want, reason string }{
			{"single", "1", "1", ""}, {"interval", "1-3", "1-3", ""}, {"list", "3,1", "1,3", ""},
			{"not", "!1", "0,2-" + fmt.Sprint(a.Max), ""}, {"whitespace", " \t1 - 3\t ", "1-3", ""},
			{"reversed", "3-1", "", "reversed"}, {"outside", fmt.Sprint(a.Max + 1), "", "outside"},
			{"empty-set", "!0-" + fmt.Sprint(a.Max), "", "empty set"}, {"full-set", "0-" + fmt.Sprint(a.Max), "", "full set"},
			{"empty-string", "", "", "empty expression"}, {"illegal", "1;2", "", "invalid decimal"},
		}
		if a.Key == "fragment" {
			cases = []struct{ name, raw, want, reason string }{
				{"single", "FIRST", "first", ""}, {"interval", "first-last", "", "invalid name"}, {"list", "last,FIRST", "first,last", ""},
				{"not", "!frag", "nofrag", ""}, {"whitespace", " \tfirst , middle ", "first,middle", ""},
				{"reversed", "last-first", "", "invalid name"}, {"outside", "8", "", "invalid name"},
				{"empty-set", "!nofrag,frag", "", "empty set"}, {"full-set", "nofrag,frag", "", "full set"},
				{"empty-string", "", "", "empty expression"}, {"illegal", "first;last", "", "invalid name"},
			}
		}
		for _, c := range cases {
			t.Run(a.Key+"/"+c.name, func(t *testing.T) {
				got, _, e := Parse(a.Key, c.raw)
				if c.reason != "" {
					if e == nil || !strings.Contains(e.Error(), c.reason) {
						t.Fatalf("got=%q err=%v want rejection %s", got, e, c.reason)
					}
					return
				}
				if e != nil || got != c.want {
					t.Fatalf("got=%q err=%v want=%q", got, e, c.want)
				}
				again, _, e := Parse(a.Key, got)
				if e != nil || again != got {
					t.Fatalf("idempotence %q %v", again, e)
				}
			})
		}
	}
}

func TestB1ExplicitLexicalExpectations(t *testing.T) {
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"064", "", false}, {"+64", "", false}, {" 64 - 128 ", "64-128", true}, {"! 64", "0-63,65-255", true},
		{",64", "", false}, {"64,", "", false}, {"64,,65", "", false}, {"!", "", false}, {"0x40", "", false},
		{"64,128", "64,128", true}, {"128,64", "64,128", true}, {"128, 64", "64,128", true}, {"!0-63,65-255", "64", true},
		{"3,2,1,4-6,6-8", "1-8", true}, {"64\n", "", false}, {"64\r", "", false}, {"64\v", "", false},
		{"64\u00a0", "", false}, {"6 4", "", false}, {"-1", "", false}, {"1,!2", "", false}, {"!!1", "", false},
	} {
		t.Run(fmt.Sprintf("%q", c.in), func(t *testing.T) {
			got, _, e := Parse("ttl", c.in)
			if (e == nil) != c.ok || c.ok && got != c.want {
				t.Fatalf("got=%q error=%v want=%q accepted=%v", got, e, c.want, c.ok)
			}
		})
	}
}

func TestB1FragmentMapping(t *testing.T) {
	for _, c := range []struct {
		in, canonical string
		values        []int
	}{
		{"nofrag", "nofrag", []int{0, 4}}, {"first", "first", []int{2, 6}}, {"middle", "middle", []int{3, 7}}, {"last", "last", []int{1, 5}},
		{"frag", "first,middle,last", []int{1, 2, 3, 5, 6, 7}}, {"nonfirst", "middle,last", []int{1, 3, 5, 7}},
	} {
		t.Run(c.in, func(t *testing.T) {
			got, s, e := Parse("fragment", c.in)
			var values []int
			for i := 0; i < 8; i++ {
				if contains(s, i) {
					values = append(values, i)
				}
			}
			if e != nil || got != c.canonical || !reflect.DeepEqual(values, c.values) {
				t.Fatalf("got=%s %v %v want=%s %v", got, values, e, c.canonical, c.values)
			}
		})
	}
}

func TestB1ConstraintsAndLegacy(t *testing.T) {
	for _, c := range []struct {
		name string
		in   Input
		bad  string
	}{
		{"icmp-on-tcp", Input{Tuple: Tuple{Protocol: "tcp"}, Fields: Fields{ICMPType: ptr("8")}}, "requires"},
		{"icmp-on-all", Input{Tuple: Tuple{DstIP: "192.0.2.1"}, Fields: Fields{ICMPCode: ptr("0")}}, "requires"},
		{"icmp-code-alone", Input{Tuple: Tuple{Protocol: "icmp"}, Fields: Fields{ICMPCode: ptr("0")}}, ""},
		{"icmp-with-port", Input{Tuple: Tuple{Protocol: "icmp", DstPort: 80}, Fields: Fields{ICMPType: ptr("8")}}, "ports"},
		{"fragment-v6", Input{Tuple: Tuple{DstIP: "2001:db8::1"}, Fields: Fields{Fragment: ptr("first")}}, "IPv4"},
		{"fragment-no-address", Input{Tuple: Tuple{Protocol: "udp"}, Fields: Fields{Fragment: ptr("first")}}, "IPv4"},
		{"fragment-zero-v4", Input{Tuple: Tuple{DstIP: "0.0.0.0"}, Fields: Fields{Fragment: ptr("first")}}, "IPv4"},
		{"fragment-zero-v6", Input{Tuple: Tuple{DstIP: "::"}, Fields: Fields{Fragment: ptr("first")}}, "IPv4"},
		{"fragment-v4", Input{Tuple: Tuple{DstIP: "192.0.2.1"}, Fields: Fields{Fragment: ptr("first")}}, ""},
		{"fragment-cidr", Input{Tuple: Tuple{DstCIDR: "192.0.2.0/24"}, Fields: Fields{Fragment: ptr("first")}}, ""},
		{"fragment-v4-default-cidr", Input{Tuple: Tuple{DstCIDR: "0.0.0.0/0"}, Fields: Fields{Fragment: ptr("nofrag")}}, ""},
		{"ttl-default-cidr", Input{Tuple: Tuple{DstCIDR: "::/0"}, Fields: Fields{TTL: ptr("64")}}, ""},
		{"fragment-mapped", Input{Tuple: Tuple{DstIP: "::ffff:192.0.2.1"}, Fields: Fields{Fragment: ptr("first")}}, ""},
		{"anomaly-v6-01", Input{Tuple: Tuple{DstIP: "2001:db8::1"}, MatchAnomaly: 1}, "IPv6"},
		{"anomaly-v6-08", Input{Tuple: Tuple{DstCIDR: "2001:db8::/64"}, MatchAnomaly: 8}, "IPv6"},
		{"anomaly-new-04", Input{Tuple: Tuple{Protocol: "tcp"}, MatchAnomaly: 4}, ""},
		{"anomaly-new-08", Input{Tuple: Tuple{Protocol: "tcp"}, MatchAnomaly: 8}, ""},
		{"anomaly-outside", Input{Tuple: Tuple{Protocol: "tcp"}, MatchAnomaly: 16}, "0x0F"},
		{"anomaly-negative", Input{Tuple: Tuple{Protocol: "tcp"}, MatchAnomaly: -1}, "0x0F"},
		{"no-anchor", Input{Fields: Fields{TTL: ptr("64")}}, "anchor"},
		{"new-old-length", Input{Tuple: Tuple{Protocol: "tcp"}, Fields: Fields{PktLen: ptr("100-200")}, PktLenMin: 100, PktLenMax: 200}, "coexist"},
		{"new-unconstrained-old", Input{Tuple: Tuple{Protocol: "tcp"}, Fields: Fields{PktLen: ptr("100-200")}, PktLenMax: 65535}, ""},
		{"flags-nontcp", Input{Tuple: Tuple{Protocol: "udp"}, TCPFlags: "SYN"}, "tcp"},
		{"old-reversed", Input{Tuple: Tuple{Protocol: "tcp"}, PktLenMin: 200, PktLenMax: 100}, "reversed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, e := Compile(c.in)
			if c.bad == "" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil || !strings.Contains(e.Error(), c.bad) {
				t.Fatalf("error=%v want=%s", e, c.bad)
			}
		})
	}
	for _, in := range []Input{{}, {PktLenMax: 65535}, {TCPFlags: ",, \t"}, {MatchAnomaly: 0}} {
		n, e := Compile(in)
		if e != nil || n.Strictness != 0 || n.CondKey() != `["","","","","","","",""]` {
			t.Fatalf("unconstrained=%+v error=%v", n, e)
		}
	}
	a, e := Compile(Input{Tuple: Tuple{Protocol: "tcp"}, PktLenMin: 100, PktLenMax: 200})
	if e != nil {
		t.Fatal(e)
	}
	b, e := Compile(Input{Tuple: Tuple{Protocol: "tcp"}, Fields: Fields{PktLen: ptr("100-200")}})
	if e != nil || a.CondKey() != b.CondKey() {
		t.Fatalf("legacy key %s new key %s err=%v", a.CondKey(), b.CondKey(), e)
	}
}

func TestB1SplitCapacityAndOrder(t *testing.T) {
	for _, c := range []struct{ segments, pieces int }{{1, 1}, {2, 1}, {3, 2}, {4, 2}, {8, 4}, {9, 5}} {
		parts := []string{}
		for i := 0; i < c.segments; i++ {
			parts = append(parts, fmt.Sprint(100+2*i))
		}
		r := Rule{Input: Input{Tuple: Tuple{Protocol: "tcp"}, Fields: Fields{PktLen: ptr(strings.Join(parts, ","))}}, ID: "split", LogicalID: 7, Action: "drop"}
		n, e := Compile(r.Input)
		if e != nil || n.CandidateCount != c.pieces {
			t.Fatalf("segments=%d count=%d err=%v", c.segments, n.CandidateCount, e)
		}
		got, e := Candidates([]Rule{r})
		if c.pieces > 4 {
			var cap *CapacityError
			if !errors.As(e, &cap) || cap.Count != 5 || !reflect.DeepEqual(cap.RuleIDs, []string{"split"}) {
				t.Fatalf("capacity=%v", e)
			}
			continue
		}
		if e != nil || len(got) != c.pieces {
			t.Fatalf("split=%v %v", got, e)
		}
		for i, v := range got {
			second := Span{1, 0}
			if i*2+1 < c.segments {
				second = Span{uint16(102 + 4*i), uint16(102 + 4*i)}
			}
			if v.Lengths[1] != second {
				t.Fatalf("second span=%v want=%v", v.Lengths[1], second)
			}
			if v.LogicalID != 7 || v.Piece != i || v.Lengths[0].Lo != uint16(100+4*i) {
				t.Fatalf("adjacent split=%+v", v)
			}
		}
	}
	rules := []Rule{
		{Input: Input{Tuple: Tuple{Protocol: "tcp"}, Fields: Fields{PktLen: ptr("100,200,300")}}, ID: "split", LogicalID: 1, Action: "drop"},
		{Input: Input{Tuple: Tuple{Protocol: "tcp"}, Fields: Fields{TTL: ptr("64")}}, ID: "later", LogicalID: 9, Action: "drop"},
		{Input: Input{Tuple: Tuple{Protocol: "tcp"}, Fields: Fields{TTL: ptr("64"), DSCP: ptr("3")}}, ID: "strict", LogicalID: 10, Action: "drop"},
	}
	want, e := Candidates(rules)
	if e != nil {
		t.Fatal(e)
	}
	gotIDs := []string{}
	for _, v := range want {
		gotIDs = append(gotIDs, fmt.Sprintf("%s/%d", v.ID, v.Piece))
	}
	if !reflect.DeepEqual(gotIDs, []string{"strict/0", "split/0", "split/1", "later/0"}) {
		t.Fatalf("order=%v", gotIDs)
	}
	rng := rand.New(rand.NewSource(173))
	for i := 0; i < 100; i++ {
		rng.Shuffle(len(rules), func(i, j int) { rules[i], rules[j] = rules[j], rules[i] })
		got, e := Candidates(rules)
		if e != nil || !reflect.DeepEqual(want, got) {
			t.Fatalf("shuffle %d differs: %v", i, e)
		}
	}
	var five []Rule
	for i := 1; i <= 5; i++ {
		five = append(five, Rule{Input: Input{Tuple: Tuple{Protocol: "udp"}}, ID: fmt.Sprint(i), LogicalID: uint32(i), Action: "drop"})
	}
	_, e = Candidates(five)
	var cap *CapacityError
	if !errors.As(e, &cap) || cap.Count != 5 || !reflect.DeepEqual(cap.RuleIDs, []string{"1", "2", "3", "4", "5"}) {
		t.Fatalf("capacity IDs=%v", e)
	}
}

func TestB1RegistryContract(t *testing.T) {
	wantKeys := []string{"ttl", "dscp", "tcp_flags", "icmp_type", "icmp_code", "anomaly", "fragment", "pkt_len"}
	wantTables := []int{0, 1, 2, 3, 4, 5, -1, -2}
	wantMax := []int{255, 63, 255, 255, 255, 15, 7, 65535}
	r := Registry()
	if len(r) != 8 {
		t.Fatalf("registry=%d", len(r))
	}
	for i, a := range r {
		if a.Key != wantKeys[i] || a.Table != wantTables[i] || a.Max != wantMax[i] {
			t.Fatalf("slot %d=%+v", i, a)
		}
	}
	if r[5].LegacyKey != "match_anomaly" {
		t.Fatal("anomaly legacy mapping")
	}
	var keys []string
	for _, a := range ExpressionAttributes() {
		keys = append(keys, a.Key)
	}
	if !reflect.DeepEqual(keys, []string{"ttl", "dscp", "icmp_type", "icmp_code", "fragment", "pkt_len"}) {
		t.Fatalf("expression keys=%v", keys)
	}
}

func TestB1CondexprCopy(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	here := filepath.Dir(file)
	source := filepath.Clean(filepath.Join(here, "../../..", "shared/condexpr"))
	read := func(dir string) map[string][]byte {
		out := map[string][]byte{}
		entries, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".go") {
				b, e := os.ReadFile(filepath.Join(dir, entry.Name()))
				if e != nil {
					t.Fatal(e)
				}
				out[entry.Name()] = b
			}
		}
		return out
	}
	a, b := read(source), read(here)
	if len(a) != len(b) {
		t.Fatal("condexpr file set differs; run bash scripts/sync-condexpr.sh")
	}
	for name, raw := range a {
		if !bytes.Equal(raw, b[name]) {
			t.Fatalf("condexpr %s differs; run bash scripts/sync-condexpr.sh", name)
		}
	}
}

// Each spelling reaches Compile; parser normalization is part of this contract.
func TestB1Cut5AD2(t *testing.T) {
	for _, frag := range []string{"nonfirst", "middle,last", "!first,nofrag"} {
		for _, axis := range []string{"src_port", "dst_port", "flags", "icmp_type", "icmp_code"} {
			t.Run(frag+"/"+axis, func(t *testing.T) {
				in := Input{Tuple: Tuple{SrcIP: "192.0.2.1", Protocol: "tcp"}, Fields: Fields{Fragment: ptr(frag)}}
				switch axis {
				case "src_port":
					in.SrcPort = 1234
				case "dst_port":
					in.DstPort = 80
				case "flags":
					in.TCPFlags = "SYN"
				case "icmp_type":
					in.Protocol = "icmp"
					in.ICMPType = ptr("8")
				case "icmp_code":
					in.Protocol = "icmp"
					in.ICMPCode = ptr("0")
				}
				if _, err := Compile(in); err == nil || !strings.Contains(err.Error(), "D2:") {
					t.Fatalf("D2 %s/%s got %v", frag, axis, err)
				}
			})
		}
	}
	for _, frag := range []string{"frag", "first"} {
		t.Run("allow/"+frag, func(t *testing.T) {
			if _, err := Compile(Input{Tuple: Tuple{SrcIP: "192.0.2.1", Protocol: "tcp", DstPort: 80}, Fields: Fields{Fragment: ptr(frag)}}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, axis := range []string{"port", "flags", "icmp_type", "icmp_code"} {
		t.Run("anomaly08/"+axis, func(t *testing.T) {
			in := Input{Tuple: Tuple{SrcIP: "192.0.2.1", Protocol: "tcp"}, MatchAnomaly: 8}
			switch axis {
			case "port":
				in.DstPort = 80
			case "flags":
				in.TCPFlags = "SYN"
			case "icmp_type":
				in.Protocol = "icmp"
				in.ICMPType = ptr("8")
			case "icmp_code":
				in.Protocol = "icmp"
				in.ICMPCode = ptr("0")
			}
			if _, err := Compile(in); err == nil || !strings.Contains(err.Error(), "D2:") {
				t.Fatalf("D2 anomaly08/%s got %v", axis, err)
			}
		})
	}
	for name, in := range map[string]Input{
		"anomaly0A-port":          {Tuple: Tuple{SrcIP: "192.0.2.1", Protocol: "tcp", DstPort: 80}, MatchAnomaly: 10},
		"nonfirst-portless":       {Tuple: Tuple{SrcIP: "192.0.2.1", Protocol: "tcp"}, Fields: Fields{Fragment: ptr("nonfirst")}},
		"anomaly08-portless":      {Tuple: Tuple{SrcIP: "192.0.2.1", Protocol: "tcp"}, MatchAnomaly: 8},
		"TD080-08-nonTCP":         {Tuple: Tuple{SrcIP: "192.0.2.1", Protocol: "udp"}, MatchAnomaly: 8},
		"TD080-08-noIntersection": {Tuple: Tuple{SrcIP: "192.0.2.1", Protocol: "tcp"}, Fields: Fields{Fragment: ptr("first")}, MatchAnomaly: 8},
		"TD080-02-first-port":     {Tuple: Tuple{SrcIP: "192.0.2.1", Protocol: "tcp", DstPort: 80}, Fields: Fields{Fragment: ptr("first")}, MatchAnomaly: 2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile(in); err != nil {
				t.Fatal(err)
			}
		})
	}
}
