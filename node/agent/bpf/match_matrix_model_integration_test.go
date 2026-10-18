//go:build linux && integration

package bpf

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/eval"
)

var matrixV4Bits = []int{22, 24, 26, 28}
var matrixV6Bits = []int{52, 56, 64}

type matrixProbe struct {
	Name, Class string
	P           eval.B1Packet
	Frame       []byte
	Want        eval.B1Decision
}
type matrixCell struct {
	Name, Kind, Family, Direction, Axis string
	Rule                                api.Rule
	Blocks                              [2]netip.Prefix
	Probes                              []matrixProbe
}

func matrixText(s string) *string { return &s }
func matrixTables(t *testing.T) eval.Tables {
	t.Helper()
	root := os.Getenv("XDROP_B1_ROOT")
	if root == "" {
		root, _ = filepath.Abs("../../..")
	}
	tables, e := eval.LoadTables(root, eval.B1)
	if e != nil {
		t.Fatal(e)
	}
	return tables
}
func matrixBlock(i int, v6 bool) netip.Prefix {
	if v6 {
		return netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/48", i))
	}
	return netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/20", i>>4, (i&15)<<4))
}
func matrixPrefix(b netip.Prefix, bits int) netip.Prefix {
	a := b.Addr().As16()
	bit := bits - 1
	if b.Addr().Is4() {
		bit += 96
	}
	a[bit/8] |= 1 << uint(7-bit%8)
	p := netip.AddrFrom16(a)
	if b.Addr().Is4() {
		p = p.Unmap()
	}
	return netip.PrefixFrom(p, bits)
}
func matrixLast(p netip.Prefix) netip.Addr {
	a := p.Addr().As16()
	bit := p.Bits()
	if p.Addr().Is4() {
		bit += 96
	}
	for i := bit; i < 128; i++ {
		a[i/8] |= 1 << uint(7-i%8)
	}
	x := netip.AddrFrom16(a)
	if p.Addr().Is4() {
		x = x.Unmap()
	}
	return x
}
func matrixPacket(src, dst netip.Addr, proto byte) eval.B1Packet {
	p := eval.B1Packet{Packet: eval.Packet{Tuple: eval.Tuple{Src: src, Dst: dst, Sport: 12345, Dport: 31000, Proto: proto}, Length: 96}, TTL: 64, DSCP: 10}
	if proto == 6 {
		p.Flags = 2
	}
	if proto == 1 || proto == 58 {
		p.Sport, p.Dport = 0, 0
		p.ICMPValid = true
		p.ICMPType = 8
	}
	return p
}

// Frame generation and decoding are independent. The oracle receives P, never
// decoded bytes, production serializers, or a kernel result.
func matrixFrame(p eval.B1Packet) []byte {
	b := make([]byte, 14+int(p.Length))
	off := 34
	if p.Src.Is4() {
		binary.BigEndian.PutUint16(b[12:], 0x800)
		b[14] = 0x45
		b[15] = p.DSCP << 2
		binary.BigEndian.PutUint16(b[16:], p.Length)
		b[22], b[23] = p.TTL, p.Proto
		a, d := p.Src.As4(), p.Dst.As4()
		copy(b[26:], a[:])
		copy(b[30:], d[:])
		binary.BigEndian.PutUint16(b[20:], uint16(p.FragClass&6)<<12)
	} else {
		off = 54
		binary.BigEndian.PutUint16(b[12:], 0x86dd)
		b[14], b[15] = 0x60|p.DSCP>>2, p.DSCP<<6
		binary.BigEndian.PutUint16(b[18:], p.Length-40)
		b[20], b[21] = p.Proto, p.TTL
		a, d := p.Src.As16(), p.Dst.As16()
		copy(b[22:], a[:])
		copy(b[38:], d[:])
	}
	if p.Proto == 6 || p.Proto == 17 {
		binary.BigEndian.PutUint16(b[off:], p.Sport)
		binary.BigEndian.PutUint16(b[off+2:], p.Dport)
		if p.Proto == 6 {
			b[off+12], b[off+13] = 0x50, p.Flags
		} else {
			binary.BigEndian.PutUint16(b[off+4:], uint16(len(b)-off))
		}
	}
	if p.ICMPValid {
		b[off], b[off+1] = p.ICMPType, p.ICMPCode
	}
	return b
}
func matrixDecode(b []byte) eval.B1Packet {
	var p eval.B1Packet
	off := 34
	if binary.BigEndian.Uint16(b[12:]) == 0x800 {
		p.Src = netip.AddrFrom4([4]byte(b[26:30]))
		p.Dst = netip.AddrFrom4([4]byte(b[30:34]))
		p.Length = binary.BigEndian.Uint16(b[16:])
		p.TTL, p.DSCP, p.Proto = b[22], b[15]>>2, b[23]
		p.FragClass = uint8(binary.BigEndian.Uint16(b[20:])>>12) & 6
	} else {
		off = 54
		p.Src = netip.AddrFrom16([16]byte(b[22:38]))
		p.Dst = netip.AddrFrom16([16]byte(b[38:54]))
		p.Length = binary.BigEndian.Uint16(b[18:]) + 40
		p.TTL, p.DSCP, p.Proto = b[21], ((b[14]&15)<<2)|(b[15]>>6), b[20]
	}
	if p.Proto == 6 || p.Proto == 17 {
		p.Sport, p.Dport = binary.BigEndian.Uint16(b[off:]), binary.BigEndian.Uint16(b[off+2:])
		if p.Proto == 6 {
			p.Flags = b[off+13]
		}
	}
	if p.Proto == 1 || p.Proto == 58 {
		p.ICMPValid = true
		p.ICMPType, p.ICMPCode = b[off], b[off+1]
	}
	return p
}
func matrixProto(s string) byte {
	return map[string]byte{"all": 0, "tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}[s]
}
func matrixRuleset(t *testing.T, tables eval.Tables, rules []api.Rule) eval.B1RuleSet {
	t.Helper()
	var rs eval.B1RuleSet
	ids := [2]map[string]uint32{{}, {}}
	prefix := func(s string, side int) uint32 {
		if s == "" {
			return 0
		}
		if id := ids[side][s]; id != 0 {
			return id
		}
		id := uint32(len(ids[side]) + 1)
		ids[side][s] = id
		p := eval.Prefix{Network: netip.MustParsePrefix(s), ID: id}
		if side == 0 {
			rs.SrcPrefixes = append(rs.SrcPrefixes, p)
		} else {
			rs.DstPrefixes = append(rs.DstPrefixes, p)
		}
		return id
	}
	for _, r := range rules {
		v := eval.B1Rule{Rule: eval.Rule{ID: r.ID}, LogicalID: r.LogicalID, TTL: r.TTL, DSCP: r.DSCP, ICMPType: r.ICMPType, ICMPCode: r.ICMPCode, Fragment: r.Fragment, PktLen: r.PktLen}
		v.HasConditions = r.TTL != nil || r.DSCP != nil || r.ICMPType != nil || r.ICMPCode != nil || r.Fragment != nil || r.PktLen != nil || r.TcpFlags != ""
		if r.Action == "rate_limit" {
			v.Rate = r.RateLimit
		}
		for _, w := range strings.Split(r.TcpFlags, ",") {
			for i, n := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
				if strings.TrimPrefix(w, "!") == n {
					v.FlagsMask |= 1 << i
					if !strings.HasPrefix(w, "!") {
						v.FlagsValue |= 1 << i
					}
				}
			}
		}
		var mask eval.Mask
		cidr := r.SrcCIDR != "" || r.DstCIDR != ""
		proto := matrixProto(r.Protocol)
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
		if proto != 0 {
			mask |= eval.Protocol
		}
		combo := -1
		for _, i := range tables.Order {
			if tables.Masks[i] == mask {
				combo = i
				break
			}
		}
		if combo < 0 {
			t.Fatalf("MATRIX_MODEL no combo for %s", r.ID)
		}
		if cidr {
			v.CIDRKey = eval.CIDRTuple{SrcID: prefix(r.SrcCIDR, 0), DstID: prefix(r.DstCIDR, 1), Sport: r.SrcPort, Dport: r.DstPort, Proto: proto}
			rs.CIDR = append(rs.CIDR, v)
			rs.CIDRBitmap |= 1 << combo
		} else {
			v.Key = eval.Tuple{Sport: r.SrcPort, Dport: r.DstPort, Proto: proto}
			if r.SrcIP != "" {
				v.Key.Src = netip.MustParseAddr(r.SrcIP)
			}
			if r.DstIP != "" {
				v.Key.Dst = netip.MustParseAddr(r.DstIP)
			}
			rs.Exact = append(rs.Exact, v)
			rs.ExactBitmap |= 1 << combo
		}
	}
	return rs
}
func matrixKey(r api.Rule) json.RawMessage {
	k := map[string]any{"kind": "exact", "src_port": r.SrcPort, "dst_port": r.DstPort, "protocol": r.Protocol}
	if r.SrcCIDR != "" || r.DstCIDR != "" {
		k["kind"] = "cidr"
	}
	for key, v := range map[string]string{"src_ip": r.SrcIP, "dst_ip": r.DstIP, "src_cidr": r.SrcCIDR, "dst_cidr": r.DstCIDR} {
		if v != "" && !(k["kind"] == "cidr" && (key == "src_ip" || key == "dst_ip")) {
			k[key] = v
		}
	}
	b, e := json.Marshal(k)
	if e != nil {
		panic(e)
	}
	return b
}
func matrixGenerate() []matrixCell {
	var cells []matrixCell
	axisCount := map[string]int{}
	for _, kind := range []string{"exact", "cidr"} {
		for _, direction := range []string{"src", "dst", "both"} {
			for _, v6 := range []bool{false, true} {
				for _, proto := range []string{"tcp", "udp", "icmp", "all"} {
					ports := []int{0, 1, 2, 3}
					if proto == "icmp" {
						ports = []int{0}
					}
					for _, port := range ports {
						for _, action := range []string{"drop", "rate_limit"} {
							for _, conditional := range []bool{false, true} {
								i := len(cells)
								family := "v4"
								rp := proto
								if v6 {
									family = "v6"
									if rp == "icmp" {
										rp = "icmpv6"
									}
								}
								c := matrixCell{Kind: kind, Family: family, Direction: direction, Name: fmt.Sprintf("%s/%s/%s/%s/p%d/%s/cond=%v", kind, direction, family, rp, port, action, conditional), Blocks: [2]netip.Prefix{matrixBlock(2*i+1, v6), matrixBlock(2*i+2, v6)}}
								bits := matrixV4Bits[i%len(matrixV4Bits)]
								if v6 {
									bits = matrixV6Bits[i%len(matrixV6Bits)]
								}
								pr := [2]netip.Prefix{matrixPrefix(c.Blocks[0], bits), matrixPrefix(c.Blocks[1], bits)}
								src, dst := pr[0].Addr().Next(), pr[1].Addr().Next()
								if kind == "cidr" {
									src, dst = pr[0].Addr(), pr[1].Addr()
								}
								wireproto := matrixProto(rp)
								if wireproto == 0 {
									wireproto = 6
								}
								p := matrixPacket(src, dst, wireproto)
								if wireproto == 6 || wireproto == 17 {
									p.Sport, p.Dport = uint16(10000+i), uint16(30000+i)
								}
								r := api.Rule{ID: fmt.Sprintf("matrix-%03d", i), LogicalID: uint32(i + 1), Protocol: rp, Action: action}
								if action == "rate_limit" {
									r.RateLimit = 1000000
								}
								if port&1 != 0 {
									r.SrcPort = p.Sport
								}
								if port&2 != 0 {
									r.DstPort = p.Dport
								}
								for side := 0; side < 2; side++ {
									if direction == "src" && side == 1 || direction == "dst" && side == 0 {
										continue
									}
									if kind == "cidr" {
										if side == 0 {
											r.SrcCIDR = pr[side].String()
										} else {
											r.DstCIDR = pr[side].String()
										}
									} else {
										if side == 0 {
											r.SrcIP = src.String()
										} else {
											r.DstIP = dst.String()
										}
									}
								}
								if conditional {
									axes := []string{"ttl", "dscp", "pkt_len"}
									if proto == "tcp" {
										axes = append(axes, "tcp_flags")
									}
									if !v6 {
										axes = append(axes, "fragment")
									}
									if proto == "icmp" {
										axes = []string{"icmp_type", "icmp_code"}
									}
									key := kind + family + proto
									c.Axis = axes[axisCount[key]%len(axes)]
									axisCount[key]++
									switch c.Axis {
									case "ttl":
										r.TTL = matrixText("64")
									case "dscp":
										r.DSCP = matrixText("10")
									case "pkt_len":
										r.PktLen = matrixText("96")
									case "tcp_flags":
										r.TcpFlags = "SYN"
									case "icmp_type":
										r.ICMPType = matrixText("8")
									case "icmp_code":
										r.ICMPCode = matrixText("0")
									case "fragment":
										r.Fragment = matrixText("nofrag")
									}
								}
								c.Rule = r
								add := func(class, name string, q eval.B1Packet) {
									c.Probes = append(c.Probes, matrixProbe{Name: name, Class: class, P: q})
								}
								add("H", "first", p)
								if kind == "cidr" {
									q := p
									if direction != "dst" {
										q.Src = matrixLast(pr[0])
									}
									if direction != "src" {
										q.Dst = matrixLast(pr[1])
									}
									add("H", "last", q)
								}
								q := p
								switch {
								case direction == "src":
									q.Dst = matrixBlock(4095, v6).Addr().Next()
								case direction == "dst":
									q.Src = matrixBlock(4095, v6).Addr().Next()
								case r.SrcPort == 0 && (wireproto == 6 || wireproto == 17):
									q.Sport++
								case r.DstPort == 0 && (wireproto == 6 || wireproto == 17):
									q.Dport++
								case proto == "all":
									q.Proto = 17
									q.Flags = 0
								case c.Axis != "ttl":
									q.TTL++
								default:
									q.DSCP++
								}
								add("W", "wildcard", q)
								for side := 0; side < 2; side++ {
									if direction == "src" && side == 1 || direction == "dst" && side == 0 {
										continue
									}
									addresses := []netip.Addr{p.Src.Next()}
									if side == 1 {
										addresses = []netip.Addr{p.Dst.Next()}
									}
									if kind == "cidr" {
										addresses = []netip.Addr{pr[side].Addr().Prev(), matrixLast(pr[side]).Next()}
									}
									for j, a := range addresses {
										q := p
										if side == 0 {
											q.Src = a
										} else {
											q.Dst = a
										}
										add("N", fmt.Sprintf("addr%d-%d", side, j), q)
									}
								}
								if r.SrcPort != 0 {
									q := p
									q.Sport++
									add("N", "sport", q)
								}
								if r.DstPort != 0 {
									q := p
									q.Dport++
									add("N", "dport", q)
								}
								if proto != "all" {
									q := matrixPacket(p.Src, p.Dst, 6)
									if wireproto == 6 {
										q = matrixPacket(p.Src, p.Dst, 17)
									}
									if p.Sport != 0 {
										q.Sport, q.Dport = p.Sport, p.Dport
									}
									add("N", "protocol", q)
								}
								if conditional {
									q := p
									switch c.Axis {
									case "ttl":
										q.TTL = 63
									case "dscp":
										q.DSCP = 9
									case "pkt_len":
										q.Length = 95
									case "tcp_flags":
										q.Flags = 0
									case "icmp_type":
										q.ICMPType = 7
									case "icmp_code":
										q.ICMPCode = 1
									case "fragment":
										q.FragClass = 2
									}
									add("N", "condition", q)
								}
								cells = append(cells, c)
							}
						}
					}
				}
			}
		}
	}
	return cells
}
func matrixModel(t *testing.T) ([]matrixCell, []api.Rule) {
	t.Helper()
	cells := matrixGenerate()
	// Independent PLAN §4-2 literals; do not reuse generator enumerations.
	expected, seen := map[string]bool{}, map[string]string{}
	for _, kind := range []string{"cidr", "exact"} {
		for _, direction := range []string{"both", "dst", "src"} {
			for _, family := range []string{"v6", "v4"} {
				for _, transport := range []string{"tcp/p0", "tcp/p1", "tcp/p2", "tcp/p3", "udp/p0", "udp/p1", "udp/p2", "udp/p3", "icmp/p0", "icmpv6/p0", "all/p0", "all/p1", "all/p2", "all/p3"} {
					if family == "v4" && transport == "icmpv6/p0" || family == "v6" && transport == "icmp/p0" {
						continue
					}
					for _, action := range []string{"rate_limit", "drop"} {
						for _, conditional := range []bool{true, false} {
							expected[fmt.Sprintf("%s/%s/%s/%s/%s/cond=%v", kind, direction, family, transport, action, conditional)] = true
						}
					}
				}
			}
		}
	}
	axisNegatives := 0
	rules := make([]api.Rule, len(cells))
	for i := range cells {
		rules[i] = cells[i].Rule
	}
	tables := matrixTables(t)
	rs := matrixRuleset(t, tables, rules)
	blocks := map[netip.Prefix]bool{}
	dims := map[string]int{}
	coverage := map[string]int{}
	counts := map[string]int{}
	drop, rate, miss, frames := 0, 0, 0, 0
	maxIDPackets := 0
	for i := range cells {
		c := &cells[i]
		dims[c.Kind+"/"+c.Family]++
		dims["direction/"+c.Direction]++
		dims["action/"+c.Rule.Action]++
		dims[fmt.Sprint("conditions/", c.Axis != "")]++
		proto := c.Rule.Protocol
		if proto == "icmpv6" {
			proto = "icmp"
		}
		dims["protocol/"+proto]++
		ports := 0
		if c.Rule.SrcPort != 0 {
			ports |= 1
		}
		if c.Rule.DstPort != 0 {
			ports |= 2
		}
		dims[fmt.Sprint("ports/", ports)]++
		dims[fmt.Sprintf("protocol_ports/%s/%d", proto, ports)]++
		r := c.Rule
		required := map[string]bool{"src_ip": r.SrcIP != "" || r.SrcCIDR != "", "dst_ip": r.DstIP != "" || r.DstCIDR != "", "src_port": r.SrcPort != 0, "dst_port": r.DstPort != 0, "protocol": r.Protocol != "all", "ttl": r.TTL != nil, "dscp": r.DSCP != nil, "pkt_len": r.PktLen != nil, "tcp_flags": r.TcpFlags != "", "icmp_type": r.ICMPType != nil, "icmp_code": r.ICMPCode != nil, "fragment": r.Fragment != nil}
		conditional := r.TTL != nil || r.DSCP != nil || r.PktLen != nil || r.TcpFlags != "" || r.ICMPType != nil || r.ICMPCode != nil || r.Fragment != nil
		kind, direction, family := "exact", "", ""
		if r.SrcCIDR != "" || r.DstCIDR != "" {
			kind = "cidr"
		}
		if required["src_ip"] {
			direction = "src"
		}
		if required["dst_ip"] {
			direction = "dst"
			if required["src_ip"] {
				direction = "both"
			}
		}
		for _, address := range []string{r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR} {
			if address == "" {
				continue
			}
			a := netip.MustParseAddr(strings.Split(address, "/")[0])
			f := "v4"
			if a.Is6() {
				f = "v6"
			}
			if family != "" && family != f {
				t.Fatalf("MATRIX_AXES wrong family cell=%s", c.Name)
			}
			family = f
		}
		tuple := fmt.Sprintf("%s/%s/%s/%s/p%d/%s/cond=%v", kind, direction, family, r.Protocol, ports, r.Action, conditional)
		if !expected[tuple] || tuple != c.Name || kind != c.Kind || direction != c.Direction || family != c.Family || conditional != (c.Axis != "") {
			t.Fatalf("MATRIX_AXES unexpected tuple cell=%s actual=%s", c.Name, tuple)
		}
		if previous, exists := seen[tuple]; exists {
			t.Fatalf("MATRIX_AXES duplicate cell=%s previous=%s", tuple, previous)
		}
		seen[tuple] = r.ID
		var hit eval.B1Packet
		foundHit := false
		for _, probe := range c.Probes {
			if probe.Class == "H" {
				hit, foundHit = probe.P, true
				break
			}
		}
		if !foundHit {
			t.Fatalf("MATRIX_AXES missing H cell=%s", c.Name)
		}
		axisNames := []string{"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "ttl", "dscp", "pkt_len", "tcp_flags", "icmp_type", "icmp_code", "fragment"}
		values := func(p eval.B1Packet) []any {
			return []any{p.Src, p.Dst, p.Sport, p.Dport, p.Proto, p.TTL, p.DSCP, p.Length, p.Flags, p.ICMPType, p.ICMPCode, p.FragClass}
		}
		base, covered := values(hit), map[string]int{}
		for _, probe := range c.Probes {
			if probe.Class != "N" {
				continue
			}
			changed, value := []string{}, values(probe.P)
			for j, axis := range axisNames {
				// Protocol-dependent fields are not independent across a wire-layout change.
				if (axis == "tcp_flags" && (hit.Proto != 6 || probe.P.Proto != 6)) || ((axis == "icmp_type" || axis == "icmp_code") && (!hit.ICMPValid || !probe.P.ICMPValid)) || ((axis == "src_port" || axis == "dst_port") && ((hit.Proto != 6 && hit.Proto != 17) || (probe.P.Proto != 6 && probe.P.Proto != 17))) {
					continue
				}
				if !reflect.DeepEqual(base[j], value[j]) {
					changed = append(changed, axis)
				}
			}
			declared := map[string]string{"sport": "src_port", "dport": "dst_port", "protocol": "protocol", "condition": c.Axis, "addr0-0": "src_ip", "addr0-1": "src_ip", "addr1-0": "dst_ip", "addr1-1": "dst_ip"}[probe.Name]
			if len(changed) != 1 || !required[changed[0]] || declared != changed[0] {
				t.Fatalf("MATRIX_AXES wrong_axis cell=%s probe=%s changed=%v declared=%s", c.Name, probe.Name, changed, declared)
			}
			covered[changed[0]]++
			axisNegatives++
		}
		for _, axis := range axisNames {
			if required[axis] && covered[axis] == 0 {
				t.Fatalf("MATRIX_AXES missing cell=%s axis=%s", c.Name, axis)
			}
		}
		if c.Axis != "" {
			coverage[c.Kind+"/"+c.Family+"/"+c.Axis]++
		}
		for _, b := range c.Blocks {
			if blocks[b] {
				t.Fatalf("MATRIX_MODEL duplicate block %s", b)
			}
			blocks[b] = true
		}
		h, w, n, dc, rc, mc := 0, 0, 0, 0, 0, 0
		for j := range c.Probes {
			p := &c.Probes[j]
			p.Frame = matrixFrame(p.P)
			decoded := matrixDecode(p.Frame)
			if !reflect.DeepEqual(decoded, p.P) {
				t.Fatalf("MATRIX_MODEL frame roundtrip %s/%s got=%+v want=%+v", c.Name, p.Name, decoded, p.P)
			}
			frames++
			if (p.P.Proto == 6 || p.P.Proto == 17) && p.P.Sport == p.P.Dport {
				t.Fatal("MATRIX_MODEL equal transport ports")
			}
			if p.Class == "N" && (!c.Blocks[0].Contains(p.P.Src) || !c.Blocks[1].Contains(p.P.Dst)) {
				t.Fatal("MATRIX_MODEL N left its blocks")
			}
			var e error
			p.Want, e = eval.EvaluateB1Cut54(tables, rs, p.P)
			if e != nil {
				t.Fatal(e)
			}
			counts[p.Class]++
			switch p.Class {
			case "H", "W":
				if p.Want.LogicalID != c.Rule.LogicalID {
					t.Fatalf("MATRIX_MODEL %s/%s winner=%d want=%d", c.Name, p.Name, p.Want.LogicalID, c.Rule.LogicalID)
				}
				if p.Class == "H" {
					h++
					if p.Want.ActionCode == api.ActionDrop {
						dc++
					} else if p.Want.ActionCode == api.ActionRateLimit {
						rc++
					}
				} else {
					w++
				}
			case "N":
				n++
				if p.Want.LogicalID == c.Rule.LogicalID {
					t.Fatalf("MATRIX_MODEL N wins %s/%s", c.Name, p.Name)
				}
				if p.Want.LogicalID == 0 && p.Want.ActionCode == 0 {
					mc++
				}
			}
		}
		if h < 1 || w < 1 || n < 1 || mc < 1 {
			t.Fatalf("MATRIX_MODEL per-cell quota %s H=%d W=%d N=%d miss=%d", c.Name, h, w, n, mc)
		}
		if c.Rule.Action == "drop" {
			if dc < 1 {
				t.Fatal("MATRIX_MODEL missing drop H")
			}
			drop++
		} else {
			if rc < 1 {
				t.Fatal("MATRIX_MODEL missing rate H")
			}
			rate++
		}
		miss++
		maxIDPackets = max(maxIDPackets, 4*len(c.Probes))
	}
	for _, kind := range []string{"exact", "cidr"} {
		for _, family := range []string{"v4", "v6"} {
			fields := []string{"ttl", "dscp", "pkt_len", "tcp_flags", "icmp_type", "icmp_code"}
			if family == "v4" {
				fields = append(fields, "fragment")
			}
			for _, field := range fields {
				key := kind + "/" + family + "/" + field
				if coverage[key] < 1 {
					t.Fatalf("MATRIX_FIELD %s count=0", key)
				}
			}
		}
	}
	for tuple := range expected {
		if _, ok := seen[tuple]; !ok {
			t.Fatalf("MATRIX_AXES missing cell=%s", tuple)
		}
	}
	if len(expected) != 624 || len(seen) != 624 {
		t.Fatalf("MATRIX_AXES cardinality expected=%d unique=%d", len(expected), len(seen))
	}
	if len(cells) != 624 || len(blocks) != 1248 || drop != 312 || rate != 312 || miss != 624 || maxIDPackets > 128 {
		t.Fatal("MATRIX_MODEL size/quota/rate budget")
	}
	t.Logf("MATRIX_AXES cells=%d unique=%d expected=%d axis_negatives=%d missing=0 wrong_axis=0", len(cells), len(seen), len(expected), axisNegatives)
	keys := make([]string, 0, len(dims))
	for k := range dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("MATRIX_DIM %s cells=%d", k, dims[k])
	}
	keys = nil
	for k := range coverage {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("MATRIX_FIELD %s cells=%d", k, coverage[k])
	}
	t.Logf("MATRIX_GENERATOR cells=%d rules=%d blocks=%d overlap=0 frames=%d roundtrip_mismatch=0 transport_equal=0 N_outside=0", len(cells), len(rules), len(blocks), frames)
	t.Logf("MATRIX_PROBES H=%d W=%d N=%d per_cell_quota=624 drop_H_cells=%d rate_H_cells=%d pass_no_winner_N_cells=%d", counts["H"], counts["W"], counts["N"], drop, rate, miss)
	t.Logf("MATRIX_RATE max_packets_per_id=%d capacity_min=489 pass=1", maxIDPackets)
	return cells, rules
}
func TestMatchMatrixGenerator(t *testing.T) { matrixModel(t) }
