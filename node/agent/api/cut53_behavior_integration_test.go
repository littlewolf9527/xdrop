//go:build linux && integration

package api

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/eval"
)

func cut53EvalTables(t *testing.T) eval.Tables {
	t.Helper()
	root := os.Getenv("XDROP_B1_ROOT")
	if root == "" {
		var err error
		root, err = filepath.Abs("../../..")
		if err != nil {
			t.Fatal(err)
		}
	}
	tables, err := eval.LoadTables(root, eval.B1)
	if err != nil {
		t.Fatal(err)
	}
	return tables
}

// Independent intent conversion: no compiler, row encoder, key builder or
// condition-group helper participates in the prediction.
func cut53Oracle(t *testing.T, tables eval.Tables, rules []Rule) eval.B1RuleSet {
	t.Helper()
	rs := eval.B1RuleSet{}
	srcs, dsts := map[string]uint32{}, map[string]uint32{}
	proto := map[string]uint8{"": 0, "all": 0, "tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}
	counts := map[string]int{}
	identity := func(r Rule) string {
		return fmt.Sprintf("%s/%s/%s/%s/%d/%d/%d", r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR, r.SrcPort, r.DstPort, proto[r.Protocol])
	}
	for _, r := range rules {
		counts[identity(r)]++
	}
	for _, r := range rules {
		v := eval.B1Rule{Rule: eval.Rule{ID: r.ID, Conditions: eval.Conditions{MinLength: r.PktLenMin, MaxLength: r.PktLenMax, Anomaly: r.MatchAnomaly}}, LogicalID: r.LogicalID, TTL: r.TTL, DSCP: r.DSCP, ICMPType: r.ICMPType, ICMPCode: r.ICMPCode, Fragment: r.Fragment, PktLen: r.PktLen}
		v.HasConditions = counts[identity(r)] > 1 || r.TTL != nil || r.DSCP != nil || r.ICMPType != nil || r.ICMPCode != nil || r.Fragment != nil || r.PktLen != nil || r.TcpFlags != "" || r.PktLenMin > 0 || (r.PktLenMax != 0 && r.PktLenMax != 65535) || r.MatchAnomaly != 0
		if r.Action == "rate_limit" {
			v.Rate = r.RateLimit
		}
		for _, word := range strings.Split(r.TcpFlags, ",") {
			word = strings.TrimSpace(word)
			if word == "" {
				continue
			}
			negative := strings.HasPrefix(word, "!")
			word = strings.TrimPrefix(word, "!")
			for bit, name := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
				if word == name {
					v.FlagsMask |= 1 << bit
					if !negative {
						v.FlagsValue |= 1 << bit
					}
				}
			}
		}
		mask := eval.Mask(0)
		if r.SrcIP != "" || r.SrcCIDR != "" {
			mask |= eval.SrcIP
		}
		if r.DstIP != "" || r.DstCIDR != "" {
			mask |= eval.DstIP
		}
		if r.SrcPort != 0 {
			mask |= eval.SrcPort
		}
		if r.DstPort != 0 {
			mask |= eval.DstPort
		}
		if proto[r.Protocol] != 0 {
			mask |= eval.Protocol
		}
		combo := -1
		for _, n := range tables.Order {
			if tables.Masks[n] == mask {
				combo = n
				break
			}
		}
		if combo < 0 {
			t.Fatal("oracle intent has no valid combo")
		}
		if r.SrcCIDR != "" || r.DstCIDR != "" {
			if r.SrcCIDR != "" {
				if srcs[r.SrcCIDR] == 0 {
					srcs[r.SrcCIDR] = uint32(len(srcs) + 1)
					rs.SrcPrefixes = append(rs.SrcPrefixes, eval.Prefix{Network: netip.MustParsePrefix(r.SrcCIDR), ID: srcs[r.SrcCIDR]})
				}
				v.CIDRKey.SrcID = srcs[r.SrcCIDR]
			}
			if r.DstCIDR != "" {
				if dsts[r.DstCIDR] == 0 {
					dsts[r.DstCIDR] = uint32(len(dsts) + 1)
					rs.DstPrefixes = append(rs.DstPrefixes, eval.Prefix{Network: netip.MustParsePrefix(r.DstCIDR), ID: dsts[r.DstCIDR]})
				}
				v.CIDRKey.DstID = dsts[r.DstCIDR]
			}
			v.CIDRKey.Sport, v.CIDRKey.Dport, v.CIDRKey.Proto = r.SrcPort, r.DstPort, proto[r.Protocol]
			rs.CIDR = append(rs.CIDR, v)
			rs.CIDRBitmap |= 1 << combo
		} else {
			if r.SrcIP != "" {
				v.Key.Src = netip.MustParseAddr(r.SrcIP)
			}
			if r.DstIP != "" {
				v.Key.Dst = netip.MustParseAddr(r.DstIP)
			}
			v.Key.Sport, v.Key.Dport, v.Key.Proto = r.SrcPort, r.DstPort, proto[r.Protocol]
			rs.Exact = append(rs.Exact, v)
			rs.ExactBitmap |= 1 << combo
		}
	}
	return rs
}
func cut53IntentCounts(t *testing.T, h *Handlers, r Rule) LogicalRuleCounters {
	t.Helper()
	var m *ebpf.Map
	var key []byte
	if r.SrcCIDR != "" || r.DstCIDR != "" {
		m = p7ActiveCIDR(h)
		key = cidrRuleKeyToBytes(h.cidrRules[r.ID].Key)
	} else {
		m = p7ActiveBlacklist(h)
		key = ruleKeyToBytes(h.rules[r.ID].Key)
	}
	if _, err := m.LookupBytes(key); err != nil {
		t.Fatal(err)
	}
	c, err := ReadLogicalRuleCounters(h.idCounts, r.LogicalID)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func cut53JudgeIntent(t *testing.T, h *Handlers, p *ebpf.Program, rules []Rule, packet []byte, attrs eval.B1Packet, wantID string) {
	t.Helper()
	tables := cut53EvalTables(t)
	prediction, err := eval.EvaluateB1Cut54(tables, cut53Oracle(t, tables, rules), attrs)
	if err != nil || prediction.RuleID != wantID {
		t.Fatalf("independent prediction=%+v wantID=%s err=%v", prediction, wantID, err)
	}
	before := map[string]LogicalRuleCounters{}
	for _, r := range rules {
		before[r.ID] = cut53IntentCounts(t, h, r)
	}
	want := uint32(2)
	if prediction.ActionCode == ActionDrop {
		want = 1
	}
	cut53Verdict(t, p, packet, want)
	for _, r := range rules {
		after := cut53IntentCounts(t, h, r)
		match, drop := uint64(0), uint64(0)
		if r.ID == prediction.RuleID {
			match = 1
			if want == 1 {
				drop = 1
			}
		}
		if after.Match-before[r.ID].Match != match || after.Drop-before[r.ID].Drop != drop {
			t.Fatalf("candidate accounting ID=%s before=%+v after=%+v prediction=%+v", r.ID, before[r.ID], after, prediction)
		}
	}
}

func TestCut53PriorityAndFallback(t *testing.T) {
	for _, kind := range []string{"candidate_tie", "candidate_strict", "fallback", "S5", "S7"} {
		t.Run(kind, func(t *testing.T) {
			h, _, p := b7ELF(t)
			packet := cut53Packet([4]byte{192, 0, 2, 1}, 64)
			attrs := eval.B1Packet{Packet: eval.Packet{Tuple: eval.Tuple{Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("10.1.0.1"), Sport: 12345, Dport: 80, Proto: 6}, Length: 40, Flags: 2}, TTL: 64}
			a := cut53Pure(false, "winner", 17)
			a.TTL = cut4BString("64")
			b := cut53Pure(false, "other", 18)
			b.DSCP = cut4BString("0")
			rules := []Rule{b, a}
			want := "winner"
			switch kind {
			case "candidate_strict":
				b.LogicalID = 1
				a.DSCP = cut4BString("0")
			case "fallback":
				a.SrcPort = 12345
				a.TTL = cut4BString("65")
				b.DSCP = nil
				rules = []Rule{a, b}
				want = "other"
			case "S5":
				b = Rule{ID: "other", LogicalID: 18, DstIP: "10.1.0.1", Action: "rate_limit", RateLimit: 1000000}
				a = Rule{ID: "winner", LogicalID: 17, DstIP: "10.1.0.1", DstPort: 443, Protocol: "tcp", Action: "drop", MatchAnomaly: 1}
				binary.BigEndian.PutUint16(packet[36:], 443)
				binary.BigEndian.PutUint16(packet[20:], 0x2000)
				// Declared payload 19 is a tiny first fragment. Keep the actual
				// TCP bytes available; the trailing byte is permitted L2 padding.
				binary.BigEndian.PutUint16(packet[16:], 39)
				var err error
				attrs, err = cut53IPv4Attributes(packet)
				if err != nil || attrs.Anomaly != 1 || attrs.Length != 39 || attrs.FragClass != 2 || attrs.NonFirst {
					t.Fatalf("S5 must be a real tiny first fragment: attrs=%+v err=%v", attrs, err)
				}
				rules = []Rule{b, a}
			case "S7":
				a.TTL = nil
				a.MatchAnomaly = 2
				b = cut53Pure(true, "other", 18)
				b.Action = "rate_limit"
				b.RateLimit = 1000000
				packet[46] = 0x40
				attrs.Anomaly = 2
				rules = []Rule{b, a}
			}
			if kind == "candidate_strict" {
				rules = []Rule{b, a}
			}
			if _, err := h.DoAtomicSync(rules); err != nil {
				t.Fatal(err)
			}
			cut53JudgeIntent(t, h, p, rules, packet, attrs, want)
			if kind == "candidate_tie" || kind == "candidate_strict" {
				for _, raw := range b7Snapshot(t, h.activeCond()) {
					if binary.LittleEndian.Uint32([]byte(raw)[824:]) != 17 {
						t.Fatal("lowest candidate bit does not hold the winning strict/logical order")
					}
				}
			}
			t.Logf("CUT53_PRIORITY case=%s independent_winner=%s packet_cells=1", kind, want)
		})
	}
}

func TestCut53CanonicalFullReplay(t *testing.T) {
	cells := 0
	for _, isCIDR := range []bool{false, true} {
		for _, tc := range []struct{ name, input, want string }{
			{"TTL", "128, 64", "64,128"}, {"DSCP", "3,2,1", "1-3"}, {"ICMPType", "8, 0", "0,8"}, {"ICMPCode", "3, 0", "0,3"}, {"Fragment", "nonfirst", "middle,last"}, {"PktLen", "200, 100-199", "100-200"}, {"TcpFlags", "SYN,!ACK", "!ACK,SYN"},
		} {
			t.Run(fmt.Sprintf("cidr=%v/%s", isCIDR, tc.name), func(t *testing.T) {
				h, router, _ := b7Handler(t)
				r := cut53Pure(isCIDR, "canonical", 17)
				r.Action = ""
				if strings.HasPrefix(tc.name, "ICMP") {
					r.Protocol = "icmp"
				}
				set := func(text string) {
					f := reflect.ValueOf(&r).Elem().FieldByName(tc.name)
					if tc.name == "TcpFlags" {
						f.SetString(text)
					} else {
						f.Set(reflect.ValueOf(cut4BString(text)))
					}
				}
				set(tc.input)
				w := yiAtomicCall(t, router, []Rule{r})
				if w.Code != 200 {
					t.Fatalf("I19 raw accepted=%d %s", w.Code, w.Body.String())
				}
				stored, ok := h.storedGroupRule(r.ID)
				if !ok || stored.Action != "drop" {
					t.Fatal("I19 normalized rule missing/default action not drop")
				}
				field := reflect.ValueOf(stored).FieldByName(tc.name)
				value := field.String()
				if tc.name != "TcpFlags" {
					value = field.Elem().String()
				}
				if value != tc.want {
					t.Fatalf("I19 stored %s=%q want=%q", tc.name, value, tc.want)
				}
				ruleMap, conditionMap := p7ActiveBlacklist(h), h.activeCond()
				if isCIDR {
					ruleMap, conditionMap = p7ActiveCIDR(h), h.activeCidrCond()
				}
				beforeRule, beforeCond := b7Snapshot(t, ruleMap), b7Snapshot(t, conditionMap)
				set(tc.want)
				r.Action = "drop"
				w = yiAtomicCall(t, router, []Rule{r})
				if w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				ruleMap, conditionMap = p7ActiveBlacklist(h), h.activeCond()
				if isCIDR {
					ruleMap, conditionMap = p7ActiveCIDR(h), h.activeCidrCond()
				}
				if !reflect.DeepEqual(beforeRule, b7Snapshot(t, ruleMap)) || !reflect.DeepEqual(beforeCond, b7Snapshot(t, conditionMap)) {
					t.Fatal("I19 canonical/noncanonical full replay differs in wire bytes")
				}
				cells++
			})
		}
	}
	t.Logf("CUT53_CANONICAL_FULL cells=%d six_keys=12 tcp_flags=2 canonical_bytes_equal=14", cells)
}

func TestCut53XSightAPIContract(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("XDROP_B1_XSIGHT_FIXTURES"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Fixtures []cut53XSightFixture
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures.Fixtures) != 33 {
		t.Fatalf("xsight fixtures=%d want=33", len(fixtures.Fixtures))
	}
	// Classify all original bytes before loading/running any program. The names
	// are an assertion on the computed set, never an input to the classifier.
	aborts, err := cut53XSightAbortNames(fixtures.Fixtures)
	wantAborts := []string{"invalid_tot_len_equal", "invalid_tot_len_short", "tiny_first_frag_udp_7"}
	if err != nil || !reflect.DeepEqual(aborts, wantAborts) {
		t.Fatalf("xsight main-entry abort set=%v want=%v err=%v", aborts, wantAborts, err)
	}
	evaluated, aborted := 0, 0
	for _, isCIDR := range []bool{false, true} {
		h, _, p, coll := b7ELFCollection(t)
		for _, f := range fixtures.Fixtures {
			t.Run(fmt.Sprintf("cidr=%v/%s", isCIDR, f.Name), func(t *testing.T) {
				ip, err := hex.DecodeString(f.Hex)
				if err != nil {
					t.Fatal(err)
				}
				v6 := ip[0]>>4 == 6
				ether := uint16(0x0800)
				src, dst := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
				proto := ip[9]
				length := binary.BigEndian.Uint16(ip[2:4])
				ttl := ip[8]
				if v6 {
					ether = 0x86dd
					src = netip.AddrFrom16([16]byte(ip[8:24]))
					dst = netip.AddrFrom16([16]byte(ip[24:40]))
					proto = ip[6]
					length = binary.BigEndian.Uint16(ip[4:6]) + 40
					ttl = ip[7]
				}
				packet := make([]byte, 14)
				binary.BigEndian.PutUint16(packet[12:], ether)
				packet = append(packet, ip...)
				r := Rule{ID: "invalid", LogicalID: 17, SrcIP: src.String(), Action: "drop", MatchAnomaly: 2}
				if isCIDR {
					r.SrcIP = ""
					r.SrcCIDR = netip.PrefixFrom(src, src.BitLen()).String()
				}
				rules := []Rule{r}
				if !v6 {
					bad := r
					bad.ID = "bad_fragment"
					bad.LogicalID = 18
					bad.MatchAnomaly = 1
					rules = append(rules, bad)
				}
				if _, err := h.DoAtomicSync(rules); err != nil {
					t.Fatal(err)
				}
				abort, err := cut53MainEntryAborts(ip)
				if err != nil {
					t.Fatal(err)
				}
				if abort {
					before := map[string]map[string]string{}
					// Snapshot actual main-ELF maps, including every per-CPU slot.
					for _, name := range []string{"blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b", "id_counts", "stats"} {
						before[name] = cut53KernelMapBytes(t, coll.Maps[name])
					}
					cut53Verdict(t, p, packet, 0) // XDP_ABORTED, before rule evaluation.
					for name, snapshot := range before {
						if !reflect.DeepEqual(snapshot, cut53KernelMapBytes(t, coll.Maps[name])) {
							t.Fatalf("xsight early abort changed counters/map %s", name)
						}
					}
					aborted++
					return
				}
				attrs := eval.B1Packet{Packet: eval.Packet{Tuple: eval.Tuple{Src: src, Dst: dst, Proto: proto}, Length: length}, TTL: ttl}
				want := ""
				if f.Bad {
					attrs.Anomaly |= 1
					want = "bad_fragment"
				}
				if f.Invalid {
					attrs.Anomaly |= 2
					want = "invalid"
				}
				cut53JudgeIntent(t, h, p, rules, packet, attrs, want)
				evaluated++
			})
		}
	}
	if aborted != 6 || evaluated != 60 {
		t.Fatalf("xsight packet coverage aborted=%d evaluated=%d want=6/60", aborted, evaluated)
	}
	t.Log("CUT53_XSIGHT_API fixtures=33 kinds=2 packet_cells=66 raw_abort_names=3 aborted_zero_counts=6 evaluator_packets=60 tiny_first_frag_tcp_19=evaluator ipv6_ext_hbh_tcp_doff_4=PASS")
}

func TestCut53PureWireUnchanged(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprintf("cidr=%v", isCIDR), func(t *testing.T) {
			h, router, _ := b7Handler(t)
			r := cut53Pure(isCIDR, "pure", 17)
			r.Action = "rate_limit"
			r.RateLimit = 123
			b7Code(t, cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, r, r)}), 200, "committed")
			m := p7ActiveBlacklist(h)
			if isCIDR {
				m = p7ActiveCIDR(h)
			}
			before := b7Snapshot(t, m)
			w := yiAtomicCall(t, router, []Rule{r})
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			m = p7ActiveBlacklist(h)
			if isCIDR {
				m = p7ActiveCIDR(h)
			}
			if !reflect.DeepEqual(before, b7Snapshot(t, m)) {
				t.Fatal("pure five-tuple wire differs between commit and full")
			}
			for _, v := range before {
				want := make([]byte, 32)
				want[0] = ActionRateLimit
				binary.LittleEndian.PutUint32(want[4:], 123)
				binary.LittleEndian.PutUint32(want[8:], 17)
				if !bytes.Equal([]byte(v), want) {
					t.Fatalf("pure legacy wire changed=%x want=%x", v, want)
				}
			}
		})
	}
	t.Log("CUT53_PURE_WIRE kinds=2 bytes_per_row=32 historical_layout_equal=2")
}
