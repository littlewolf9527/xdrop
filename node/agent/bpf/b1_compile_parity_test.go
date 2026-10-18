//go:build linux && integration

package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/eval"
	"golang.org/x/sys/unix"
)

type b1ParityCase struct {
	name      string
	rules     []api.Rule
	packet    []byte
	attrs     eval.B1Packet
	d2Reject  bool // authorized D2 rejection; sibling preserves parity coverage
	probeOnly bool // synthetic attribute values unreachable by packet extraction
}

func b1ParityText(s string) *string { return &s }
func b1ParityBase(name string, v6 bool, proto byte) b1ParityCase {
	payload := make([]byte, 20)
	payload[12] = 0x50
	payload[13] = 0x12
	binary.BigEndian.PutUint16(payload, 1234)
	binary.BigEndian.PutUint16(payload[2:], 80)
	protocol := "tcp"
	if proto == 1 {
		protocol = "icmp"
		payload = []byte{8, 0, 0, 0, 0, 0, 0, 0}
	}
	if proto == 58 {
		protocol = "icmpv6"
		payload = []byte{128, 0, 0, 0, 0, 0, 0, 0}
	}
	src, dst := "192.0.2.10", "198.51.100.20"
	if v6 {
		src, dst = "2001:db8:1::10", "2001:db8:2::20"
	}
	p := b1Frame(v6, proto, payload, 0)
	l4 := 34
	if v6 {
		copy(p[22:38], net.ParseIP(src).To16())
		copy(p[38:54], net.ParseIP(dst).To16())
		l4 = 54
	} else {
		copy(p[26:30], net.ParseIP(src).To4())
		copy(p[30:34], net.ParseIP(dst).To4())
	}
	r := api.Rule{ID: "first", LogicalID: 101, SrcIP: src, DstIP: dst, Protocol: protocol, Action: "drop"}
	a := eval.B1Packet{Packet: eval.Packet{Tuple: eval.Tuple{Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), Proto: proto}, Length: uint16(len(p) - 14)}, TTL: 64}
	if proto == 6 {
		r.SrcPort, r.DstPort = 1234, 80
		a.Sport, a.Dport = 1234, 80
		a.Flags = 0x12
	} else {
		a.ICMPValid = true
		a.ICMPType = p[l4]
		a.ICMPCode = p[l4+1]
	}
	return b1ParityCase{name: name, rules: []api.Rule{r}, packet: p, attrs: a}
}

func b1ParityGrid() []b1ParityCase {
	var out []b1ParityCase
	for _, v6 := range []bool{false, true} {
		for _, axis := range []string{"ttl", "dscp", "tcp_flags", "icmp_type", "icmp_code", "pkt_len"} {
			max := 255
			if axis == "dscp" {
				max = 63
			}
			if axis == "pkt_len" {
				max = 65535
			}
			for _, value := range []int{0, max} {
				proto := byte(6)
				if strings.HasPrefix(axis, "icmp_") {
					proto = 1
					if v6 {
						proto = 58
					}
				}
				if v6 && axis == "pkt_len" {
					continue
				} // IPv6 declared length has its own wrap witness below.
				c := b1ParityBase(fmt.Sprintf("%s/%d/v6=%v", axis, value, v6), v6, proto)
				expr := fmt.Sprint(value)
				l4 := 34
				if v6 {
					l4 = 54
				}
				switch axis {
				case "ttl":
					c.rules[0].TTL = &expr
					c.attrs.TTL = byte(value)
					at := 22
					if v6 {
						at = 21
					}
					c.packet[at] = byte(value)
				case "dscp":
					c.rules[0].DSCP = &expr
					c.attrs.DSCP = byte(value)
					if v6 {
						c.packet[14] = 0x60 | byte(value>>2)
						c.packet[15] = byte(value << 6)
					} else {
						c.packet[15] = byte(value << 2)
					}
				case "tcp_flags":
					flags := []string{"CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"}
					if value == 0 {
						for i := range flags {
							flags[i] = "!" + flags[i]
						}
					}
					c.rules[0].TcpFlags = strings.Join(flags, ",")
					c.packet[l4+13] = byte(value)
					c.attrs.Flags = byte(value)
				case "icmp_type":
					c.rules[0].ICMPType = &expr
					c.packet[l4] = byte(value)
					c.attrs.ICMPType = byte(value)
				case "icmp_code":
					c.rules[0].ICMPCode = &expr
					c.packet[l4+1] = byte(value)
					c.attrs.ICMPCode = byte(value)
				case "pkt_len":
					c.rules[0].PktLen = &expr
					binary.BigEndian.PutUint16(c.packet[16:], uint16(value))
					c.attrs.Length = uint16(value)
					if value == 0 {
						c.attrs.Anomaly = 2
					} else {
						c.attrs.Anomaly = 4
					}
				}
				out = append(out, c)
				// A neighboring condition, with the exact same packet, must miss.
				miss := c
				miss.name += "/miss"
				miss.rules = append([]api.Rule(nil), c.rules...)
				neighbor := "1"
				if value != 0 {
					neighbor = fmt.Sprint(value - 1)
				}
				switch axis {
				case "ttl":
					miss.rules[0].TTL = &neighbor
				case "dscp":
					miss.rules[0].DSCP = &neighbor
				case "icmp_type":
					miss.rules[0].ICMPType = &neighbor
				case "icmp_code":
					miss.rules[0].ICMPCode = &neighbor
				case "pkt_len":
					miss.rules[0].PktLen = &neighbor
				case "tcp_flags":
					if value == 0 {
						miss.rules[0].TcpFlags = "SYN"
					} else {
						miss.rules[0].TcpFlags = "!SYN"
					}
				}
				out = append(out, miss)
			}
		}
	}
	for class := 0; class < 8; class++ {
		c := b1ParityBase(fmt.Sprintf("fragment/%d", class), false, 6)
		name := []string{"nofrag", "last", "first", "middle"}[class&3]
		c.rules[0].Fragment = &name
		c.attrs.FragClass = byte(class)
		c.attrs.NonFirst = class&1 != 0
		bits := uint16(0)
		if class&4 != 0 {
			bits |= 0x4000
		}
		if class&2 != 0 {
			bits |= 0x2000
		}
		if class&1 != 0 {
			bits |= 2
		}
		binary.BigEndian.PutUint16(c.packet[20:], bits)
		if class&1 != 0 {
			c.d2Reject = true
		}
		out = append(out, c)
		if c.d2Reject {
			c.name += "/portless"
			c.d2Reject = false
			c.rules = append([]api.Rule(nil), c.rules...)
			c.rules[0].SrcPort, c.rules[0].DstPort = 0, 0
			c.attrs.Sport, c.attrs.Dport = 0, 0
			out = append(out, c)
		}
	}
	for _, length := range []int{40, 60, 80, 81} {
		c := b1ParityBase(fmt.Sprintf("three-spans/%d", length), false, 6)
		c.rules[0].PktLen = b1ParityText("40,60,80")
		c.packet = append(c.packet, make([]byte, length-40)...)
		binary.BigEndian.PutUint16(c.packet[16:], uint16(length))
		c.attrs.Length = uint16(length)
		out = append(out, c)
	}
	for _, mask := range []uint8{4, 8} {
		c := b1ParityBase(fmt.Sprintf("anomaly/%02x", mask), false, 6)
		c.rules[0].MatchAnomaly = mask
		c.attrs.Anomaly = mask
		if mask == 4 {
			binary.BigEndian.PutUint16(c.packet[16:], 41)
			c.attrs.Length = 41
		} else {
			binary.BigEndian.PutUint16(c.packet[20:], 1)
			c.attrs.FragClass = 1
			c.attrs.NonFirst = true
		}
		c.d2Reject = mask == 8
		out = append(out, c)
		if c.d2Reject {
			portless := c
			portless.name += "/portless"
			portless.d2Reject = false
			portless.rules = append([]api.Rule(nil), c.rules...)
			portless.rules[0].SrcPort, portless.rules[0].DstPort = 0, 0
			portless.attrs.Sport, portless.attrs.Dport = 0, 0
			out = append(out, portless)
		}
		miss := b1ParityBase(fmt.Sprintf("anomaly/%02x/clean", mask), false, 6)
		miss.rules[0].MatchAnomaly = mask
		miss.d2Reject = mask == 8
		out = append(out, miss)
		if miss.d2Reject {
			miss.name += "/portless"
			miss.d2Reject = false
			miss.rules = append([]api.Rule(nil), miss.rules...)
			miss.rules[0].SrcPort, miss.rules[0].DstPort = 0, 0
			miss.attrs.Sport, miss.attrs.Dport = 0, 0
			out = append(out, miss)
		}
	}
	for _, v := range []uint8{0, 15, 16} {
		c := b1ParityBase(fmt.Sprintf("anomaly-domain/%d", v), false, 6)
		c.rules[0].MatchAnomaly = 15
		c.attrs.Anomaly = v
		c.probeOnly = v != 0
		out = append(out, c)
	}
	// DSCP's first unreachable table cell must be zero even on an unconstrained rule.
	c := b1ParityBase("dscp-domain/64", false, 6)
	c.attrs.DSCP = 64
	c.probeOnly = true
	out = append(out, c)
	c = b1ParityBase("rate-tie", false, 6)
	c.rules[0].TTL = b1ParityText("64")
	c.rules[0].Action = "rate_limit"
	c.rules[0].RateLimit = 1000
	other := c.rules[0]
	other.ID = "second"
	other.LogicalID = 102
	other.Action = "drop"
	other.RateLimit = 0
	c.rules = []api.Rule{other, c.rules[0]}
	out = append(out, c)
	c = b1ParityBase("ipv6-wrap", true, 6)
	c.rules[0].PktLen = b1ParityText("39")
	payload := uint16(65535)
	c.attrs.IPv6PayloadLength = &payload
	c.attrs.Length = 39
	c.attrs.Anomaly = 4
	binary.BigEndian.PutUint16(c.packet[18:], payload)
	out = append(out, c)
	c = b1ParityBase("icmp-invalid", false, 1)
	c.rules[0].ICMPType = b1ParityText("8")
	binary.BigEndian.PutUint16(c.packet[20:], 2)
	c.attrs.FragClass = 1
	c.attrs.NonFirst = true
	c.attrs.ICMPValid = false
	c.attrs.ICMPType = 0
	out = append(out, c)
	c = b1ParityBase("ipv6-fragment-zero-icmp-invalid", true, 58)
	c.rules[0].ICMPCode = b1ParityText("0")
	fragment := []byte{58, 0, 0, 8, 0, 0, 0, 1}
	c.packet = append(c.packet[:54], append(fragment, c.packet[54:]...)...)
	c.packet[20] = 44
	binary.BigEndian.PutUint16(c.packet[18:], 16)
	c.attrs.Length = 56
	c.attrs.NonFirst = true
	c.attrs.ICMPValid = false
	c.attrs.ICMPType = 0
	c.attrs.FragClass = 0
	out = append(out, c)
	return out
}

// Convert rule intent directly; this function never reads an encoded row.
func b1ParityOracle(c b1ParityCase, cidr bool, tables eval.Tables) (eval.B1RuleSet, []byte, int) {
	rs := eval.B1RuleSet{}
	if cidr {
		src, dst := "192.0.2.0/24", "198.51.100.0/24"
		if c.attrs.Src.Is6() {
			src, dst = "2001:db8:1::/64", "2001:db8:2::/64"
		}
		rs.SrcPrefixes = []eval.Prefix{{Network: netip.MustParsePrefix(src), ID: 7}}
		rs.DstPrefixes = []eval.Prefix{{Network: netip.MustParsePrefix(dst), ID: 9}}
	}
	for _, r := range c.rules {
		v := eval.B1Rule{Rule: eval.Rule{ID: r.ID, Key: c.attrs.Tuple, Rate: r.RateLimit, Conditions: eval.Conditions{MinLength: r.PktLenMin, MaxLength: r.PktLenMax, Anomaly: r.MatchAnomaly}}, LogicalID: r.LogicalID, HasConditions: true, TTL: r.TTL, DSCP: r.DSCP, ICMPType: r.ICMPType, ICMPCode: r.ICMPCode, Fragment: r.Fragment, PktLen: r.PktLen}
		for _, word := range strings.Split(r.TcpFlags, ",") {
			if word == "" {
				continue
			}
			negative := strings.HasPrefix(word, "!")
			name := strings.TrimPrefix(word, "!")
			for i, n := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
				if n == name {
					v.FlagsMask |= 1 << i
					if !negative {
						v.FlagsValue |= 1 << i
					}
				}
			}
		}
		if cidr {
			v.Key = eval.Tuple{}
			v.CIDRKey = eval.CIDRTuple{SrcID: 7, DstID: 9, Sport: c.attrs.Sport, Dport: c.attrs.Dport, Proto: c.attrs.Proto}
			rs.CIDR = append(rs.CIDR, v)
		} else {
			rs.Exact = append(rs.Exact, v)
		}
	}
	mask := eval.SrcIP | eval.DstIP | eval.Protocol
	if c.attrs.Sport != 0 {
		mask |= eval.SrcPort
	}
	if c.attrs.Dport != 0 {
		mask |= eval.DstPort
	}
	combo := -1
	for _, i := range tables.Order {
		if tables.Masks[i] == mask {
			combo = i
			break
		}
	}
	if cidr {
		rs.CIDRBitmap = 1 << combo
	} else {
		rs.ExactBitmap = 1 << combo
	}
	key := make([]byte, 40)
	po, pr := 32, 36
	if cidr {
		key = make([]byte, 16)
		binary.LittleEndian.PutUint32(key, 7)
		binary.LittleEndian.PutUint32(key[4:], 9)
		po, pr = 8, 12
	} else {
		copy(key, net.ParseIP(c.attrs.Src.String()).To16())
		copy(key[16:], net.ParseIP(c.attrs.Dst.String()).To16())
	}
	binary.BigEndian.PutUint16(key[po:], c.attrs.Sport)
	binary.BigEndian.PutUint16(key[po+2:], c.attrs.Dport)
	key[pr] = c.attrs.Proto
	return rs, key, combo
}

func TestB1CompileParityELF(t *testing.T) {
	root := os.Getenv("XDROP_B1_ROOT")
	if root == "" {
		root = filepath.Clean("../../..")
	}
	tables, e := eval.LoadTables(root, eval.B1)
	if e != nil {
		t.Fatal(e)
	}
	probePath, productionPath, extractPath := os.Getenv("XDROP_B1_CONDITION_ELF"), os.Getenv("XDROP_BPF_ELF"), os.Getenv("XDROP_B1_PROBE_ELF")
	if probePath == "" || productionPath == "" || extractPath == "" {
		t.Fatal("condition, production and extraction ELF paths required")
	}
	packets, productionPackets, extractionPackets, layer1, layer2 := 0, 0, 0, 0, 0
	for _, cidr := range []bool{false, true} {
		kind := "exact"
		if cidr {
			kind = "cidr"
		}
		t.Run(kind, func(t *testing.T) {
			probe, production, extraction := b1Load(t, probePath), b1Load(t, productionPath), b1Load(t, extractPath)
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var before unix.CPUSet
			if e := unix.SchedGetaffinity(0, &before); e != nil {
				t.Fatal(e)
			}
			cpu := 0
			for !before.IsSet(cpu) {
				cpu++
			}
			var one unix.CPUSet
			one.Set(cpu)
			if e := unix.SchedSetaffinity(0, &one); e != nil {
				t.Fatal(e)
			}
			defer func() {
				if e := unix.SchedSetaffinity(0, &before); e != nil {
					t.Error(e)
				}
			}()
			for _, name := range []string{"sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "sv4_cidr_trie_b", "dv4_cidr_trie_b", "sv6_cidr_trie_b", "dv6_cidr_trie_b"} {
				size := 8
				if strings.Contains(name, "v6") {
					size = 20
				}
				id := uint32(7)
				if strings.HasPrefix(name, "d") {
					id = 9
				}
				b1Put(t, production, name, make([]byte, size), id)
			}
			var previous []byte
			for _, c := range b1ParityGrid() {
				t.Run(c.name, func(t *testing.T) {
					// t.Run executes on a separate goroutine: pin that execution too.
					runtime.LockOSThread()
					defer runtime.UnlockOSThread()
					var old unix.CPUSet
					if e := unix.SchedGetaffinity(0, &old); e != nil {
						t.Fatal(e)
					}
					if e := unix.SchedSetaffinity(0, &one); e != nil {
						t.Fatal(e)
					}
					defer func() {
						if e := unix.SchedSetaffinity(0, &old); e != nil {
							t.Error(e)
						}
					}()
					intent := c.rules
					if cidr {
						intent = append([]api.Rule(nil), intent...)
						for i := range intent {
							intent[i].SrcIP, intent[i].DstIP = "", ""
							intent[i].SrcCIDR, intent[i].DstCIDR = "192.0.2.0/24", "198.51.100.0/24"
							if c.attrs.Src.Is6() {
								intent[i].SrcCIDR, intent[i].DstCIDR = "2001:db8:1::/64", "2001:db8:2::/64"
							}
						}
					}
					row, e := api.EncodeConditionValue(intent)
					if c.d2Reject {
						if e == nil || !strings.Contains(e.Error(), "D2:") {
							t.Fatalf("D2 encoding rejection missing: %v", e)
						}
						t.Logf("D2 encoding rejected: %v", e)
						return
					}
					if e != nil {
						t.Fatal(e)
					}
					rs, key, combo := b1ParityOracle(c, cidr, tables)
					prediction, e := eval.EvaluateB1Cut54(tables, rs, c.attrs)
					if e != nil {
						t.Fatal(e)
					}
					b1Config(t, probe, cidr, 0, 0)
					b1SetRow(t, probe, cidr, 0, 6, row)
					if c.attrs.NonFirst && c.attrs.Proto == 6 && c.rules[0].SrcPort == 0 && c.rules[0].DstPort == 0 {
						// The probe zeroes ports when l4_valid=0. Install these
						// portless siblings under protocol-only combo 5, already
						// enabled by b1Config, preserving the opposite-slot poison.
						fine, portless := b1Key(cidr, 6, true), b1Key(cidr, 6, false)
						r, m, ro, mo := b1Maps(cidr, 0)
						for _, name := range []string{r, m, ro, mo} {
							value, err := probe.Maps[name].LookupBytes(fine)
							if err != nil || len(value) == 0 {
								t.Fatalf("portless probe source %s: bytes=%d error=%v", name, len(value), err)
							}
							b1Put(t, probe, name, portless, value)
							t.Cleanup(func() { b1Erase(t, probe, name, portless) })
						}
					}
					data := make([]byte, 64)
					binary.LittleEndian.PutUint16(data, c.attrs.Length)
					data[2], data[3], data[4], data[5] = c.attrs.Flags, c.attrs.Anomaly, c.attrs.TTL, c.attrs.DSCP
					data[6], data[7], data[8] = c.attrs.ICMPType, c.attrs.ICMPCode, c.attrs.FragClass
					if c.attrs.ICMPValid {
						data[9] = 1
					}
					if !c.attrs.NonFirst {
						data[10] = 1
					}
					output := make([]byte, len(data))
					ret, e := probe.Programs["b1_condition_"+kind].Run(&ebpf.RunOptions{Data: data, DataOut: output, Repeat: 1})
					if e != nil {
						t.Fatal(e)
					}
					packets++
					wantRet := uint32(0xb3)
					if prediction.LogicalID != 0 {
						wantRet = 0xb2
					}
					if ret != wantRet || output[13] != prediction.ActionCode || binary.LittleEndian.Uint32(output[16:]) != prediction.Rate || binary.LittleEndian.Uint32(output[20:]) != prediction.LogicalID {
						layer1++
						t.Errorf("B1_LAYER1 got=%x/%d/%d/%d want=%x/%d/%d/%d", ret, output[13], binary.LittleEndian.Uint32(output[16:]), binary.LittleEndian.Uint32(output[20:]), wantRet, prediction.ActionCode, prediction.Rate, prediction.LogicalID)
					}
					if c.probeOnly {
						return
					}
					// No legal IPv6 rule may constrain fragment. Observe the existing
					// extraction probe directly so a zero fragment class is asserted,
					// rather than hidden by an unconstrained fragment lookup.
					if c.name == "ipv6-fragment-zero-icmp-invalid" {
						name := "b1_extract_attrs"
						if cidr {
							name = "b1_extract_cidr_attrs"
						}
						out := make([]byte, len(c.packet))
						ret, e := extraction.Programs[name].Run(&ebpf.RunOptions{Data: c.packet, DataOut: out, Repeat: 1})
						extractionPackets++
						if e != nil || ret != 0xb1 || out[8] != 0 || out[9] != 0 {
							t.Fatalf("IPv6 fragment extraction ret=%x fragment=%d icmp_valid=%d error=%v", ret, out[8], out[9], e)
						}
					}
					b1Config(t, production, cidr, 0, 0)
					bitmap := uint32(2)
					if cidr {
						bitmap = 7
					}
					b1Put(t, production, "config_a", bitmap, uint64(1)<<combo)
					rules, conditions, _, _ := b1Maps(cidr, 0)
					if previous != nil {
						b1Erase(t, production, rules, previous)
						b1Erase(t, production, conditions, previous)
					}
					previous = append([]byte(nil), key...)
					value := api.RuleValue{Pad2: [4]byte{api.RuleHasConditions}}
					b1Put(t, production, rules, key, b1Wire(t, value))
					b1Put(t, production, conditions, key, b1Wire(t, row))
					counts := map[uint32]api.LogicalRuleCounters{}
					for _, r := range c.rules {
						counts[r.LogicalID] = b1LogicalCounts(t, production, r.LogicalID)
						b1Erase(t, production, "id_rl_states", r.LogicalID)
					}
					verdict, e := production.Programs["xdp_firewall_main"].Run(&ebpf.RunOptions{Data: c.packet, Repeat: 1})
					if e != nil {
						t.Fatal(e)
					}
					productionPackets++
					want := uint32(srcXDPPass)
					if prediction.ActionCode == 1 {
						want = srcXDPDrop
					}
					if verdict != want {
						layer2++
						t.Errorf("B1_LAYER2 verdict=%d want=%d", verdict, want)
					}
					for _, r := range c.rules {
						after := b1LogicalCounts(t, production, r.LogicalID)
						old := counts[r.LogicalID]
						match, drop := uint64(0), uint64(0)
						if r.LogicalID == prediction.LogicalID {
							match = 1
							if prediction.ActionCode == 1 {
								drop = 1
							}
						}
						if after.Match-old.Match != match || after.Drop-old.Drop != drop {
							layer2++
							t.Errorf("B1_LAYER2 ID=%d delta=%d/%d want=%d/%d", r.LogicalID, after.Match-old.Match, after.Drop-old.Drop, match, drop)
						}
					}
				})
			}
		})
	}
	t.Logf("B1_COMPILE_PARITY probe_packets=%d production_packets=%d layer1_mismatches=%d layer2_mismatches=%d", packets, productionPackets, layer1, layer2)
	t.Logf("B1_COMPILE_EXTRACTION ipv6_fragment_packets=%d", extractionPackets)
	if packets == 0 || productionPackets == 0 || layer1 != 0 || layer2 != 0 {
		t.Fatalf("bounded parity incomplete or unequal")
	}
}
