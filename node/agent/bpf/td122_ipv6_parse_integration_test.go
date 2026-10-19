//go:build linux && integration

package bpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/condexpr"
)

// Frames stay in process memory and enter only BPF_PROG_TEST_RUN via Test.
// P* is IPv4 destination octets 100,53 at IP offsets 18,19: 0x6435 = 25653.
const td122Port = 25653

type td122Cell struct {
	shape, rule, gate, class, name string
	head                           byte
	packet                         []byte
	drop, white                    bool
}

func td122Source(v4 bool) netip.Addr {
	if v4 {
		return netip.MustParseAddr("192.0.2.1")
	}
	return td114Src
}

func td122Packet(shape string, head byte) []byte {
	v4 := shape == "A6" || strings.HasPrefix(shape, "D")
	proto := byte(58)
	payload := []byte{128, 0, 0, 0, 0, 0, 0, 0}
	switch shape {
	case "A1", "A2", "A3", "A4":
		frag := []byte{58, 0, 0, 0, 0, 0, 0, 1}
		if shape == "A2" {
			frag[3] = 1 // M=1, offset zero
		}
		if shape == "A4" {
			frag[3] = 8 // offset one; payload still begins with 128,0
		}
		proto, payload = 44, append(frag, payload...)
		if shape == "A3" {
			proto, payload = 60, append([]byte{44, 0, 0, 0, 0, 0, 0, 0}, payload...)
		}
	case "A5":
	case "A6":
		proto, payload[0] = 1, 8
	case "B6u", "B6t", "B7":
		proto, payload = 17, make([]byte, 8)
		binary.BigEndian.PutUint16(payload[2:4], 53)
		binary.BigEndian.PutUint16(payload[4:6], 8)
		if shape == "B6t" {
			proto, payload = 6, make([]byte, 20)
			payload[12], payload[13] = 0x50, 2
		}
		if shape == "B7" {
			payload = append([]byte{17, 0, 0, 0, 0, 0, 0, 0}, payload...)
			proto = head // AH length=0 and fragment offset=0 both occupy 8 bytes.
		}
		for i := 0; i < 6; i++ {
			payload = append([]byte{proto, 0, 0, 0, 0, 0, 0, 0}, payload...)
			proto = 60
		}
	case "C1":
		proto, payload = 59, nil
	case "C2":
		proto, payload = 60, []byte{59, 0, 0, 0, 0, 0, 0, 0}
	case "D4s":
		proto, payload = 6, nil // Fixed IPv4 header complete; pseudo TCP has only 4 bytes.
	case "D4l", "D5":
		proto, payload = 17, make([]byte, 8)
		binary.BigEndian.PutUint16(payload[2:4], td122Port)
		binary.BigEndian.PutUint16(payload[4:6], 8)
	default:
		panic("unknown TD122 packet shape")
	}
	p := b1Frame(!v4, proto, payload, 0)
	if v4 {
		src, dst := td122Source(true).As4(), netip.MustParseAddr("198.51.100.53").As4()
		copy(p[26:30], src[:])
		copy(p[30:34], dst[:])
		if shape == "A6" {
			binary.BigEndian.PutUint16(p[20:22], 0x2000)
		}
		if shape == "D4s" || shape == "D4l" {
			p[14] = 0x44
		}
	} else {
		src, dst := td114Src.As16(), td114Dst.As16()
		copy(p[22:38], src[:])
		copy(p[38:54], dst[:])
	}
	return p
}

func td122Cells() []td122Cell {
	var cells []td122Cell
	add := func(shape string, head byte, rule, gate string, drop, white, behavior bool) {
		label := shape
		if shape == "B7" {
			label = fmt.Sprintf("B7-H%d", head)
		}
		class := "guard"
		if behavior {
			class = "behavior"
		}
		cells = append(cells, td122Cell{shape: shape, head: head, rule: rule, gate: gate, class: class,
			name: label + "/" + rule + "/" + gate, packet: td122Packet(shape, head), drop: drop, white: white})
	}
	for _, shape := range []string{"A1", "A2", "A3", "A4", "A5"} {
		for _, rule := range []string{"I0", "I1", "I2", "I3", "I4"} {
			drop := shape != "A4" && (rule == "I1" || rule == "I2" || rule == "I4")
			add(shape, 0, rule, "G0", drop, false, drop && shape != "A5")
		}
	}
	for _, rule := range []string{"I0", "I1", "I3"} {
		add("A6", 0, rule, "G0", rule == "I1", false, false)
	}
	for _, rule := range []string{"R1", "R3", "R5"} {
		add("B6u", 0, rule, "G0", true, false, false)
	}
	for _, rule := range []string{"R4", "Rt"} {
		add("B6t", 0, rule, "G0", true, false, false)
	}
	for _, head := range []byte{0, 43, 60, 44, 51} {
		for _, rule := range []string{"R1", "R3", "R5", "R7"} {
			add("B7", head, rule, "G0", rule == "R1" || rule == "R7", false, rule == "R5")
		}
	}
	add("B6u", 0, "R1", "Wudp", false, true, false)
	add("B7", 60, "R1", "W60", false, true, false)
	add("B7", 60, "R1", "Wudp", true, false, false)
	for _, shape := range []string{"C1", "C2"} {
		for _, rule := range []string{"R59", "R1", "R0p"} {
			add(shape, 0, rule, "G0", rule != "R0p", false, rule != "R1")
		}
	}
	add("C1", 0, "R1", "W59", false, true, false)
	for _, rule := range []string{"R0", "R1", "Rinv"} {
		add("D4s", 0, rule, "G0", rule != "R0", false, true)
	}
	for _, rule := range []string{"Rp", "R1", "Rinv"} {
		add("D4l", 0, rule, "G0", rule != "Rp", false, rule == "Rp")
	}
	add("D5", 0, "Rp", "G0", true, false, false)
	add("D4l", 0, "R1", "Wp", true, false, true)
	add("D4s", 0, "R1", "Wother", true, false, true)
	add("D5", 0, "R1", "Wp", false, true, false)
	return cells
}

func td122RunCell(t *testing.T, main, gate *ebpf.Collection, c td122Cell, index int) {
	t.Helper()
	v4 := c.shape == "A6" || strings.HasPrefix(c.shape, "D")
	src := td122Source(v4)
	cfg := [12]uint64{}
	cfg[api.ConfigRLCPUDivisor] = 1
	if c.shape == "B7" {
		td149LegacyPass(t, main)
	}
	var key []byte
	value := api.RuleValue{LogicalID: uint32(122000 + index), Action: api.ActionDrop}
	name, condName := "blacklist", "cond_a"
	hasRule := c.rule != "R0" && c.rule != "I0"
	if hasRule {
		proto, port, combo := byte(0), uint16(0), uint64(1<<8)
		intent := api.Rule{ID: "td122", LogicalID: value.LogicalID, SrcIP: src.String(), Protocol: "all", Action: "drop"}
		condition := false
		switch c.rule {
		case "R1":
		case "R3", "Rp":
			proto, port, combo = 17, 53, 1<<14
			if c.rule == "Rp" {
				port = td122Port
			}
		case "R4", "Rt":
			proto, combo = 6, 1<<9
			if c.rule == "Rt" {
				intent.Protocol, intent.TcpFlags, condition = "tcp", "SYN", true
			}
		case "R5":
			// Kernel-only wildcard protocol + TCP condition, as in TD114 R5.
			intent.Protocol, intent.TcpFlags, condition = "tcp", "!SYN", true
		case "R7":
			proto, combo = c.head, 1<<9
		case "R59":
			proto, combo = 59, 1<<9
		case "R0p":
			combo = 1 << 9 // Protocol zero deliberately remains in a protocol combo.
		case "Rinv":
			intent.MatchAnomaly, condition = 2, true
			cfg[api.ConfigAnomalyRuleCount] = 1
		case "I1", "I2", "I3", "I4":
			proto, combo, intent.Protocol, condition = 58, 1<<9, "icmpv6", true
			expr, field := "128", "icmp_type"
			if v4 {
				proto, intent.Protocol, expr = 1, "icmp", "8"
			}
			if c.rule == "I3" {
				expr = "!" + expr
			}
			if c.rule == "I2" {
				expr, field = "0", "icmp_code"
			}
			canonical, _, err := condexpr.Parse(field, expr)
			if err != nil {
				t.Fatal(err)
			}
			intent.ICMPType = &canonical
			if field == "icmp_code" {
				intent.ICMPType, intent.ICMPCode = nil, &canonical
			}
		default:
			t.Fatal("unknown TD122 rule")
		}
		key = td114Exact(src, netip.Addr{}, proto, port)
		cfg[api.ConfigBlacklistCount], cfg[api.ConfigRuleBitmap] = 1, combo
		if c.rule == "I4" {
			name, condName = "cidr_blacklist", "cidr_cond_a"
			intent.SrcIP, intent.SrcCIDR = "", "2001:db8:1::/64"
			cfg[api.ConfigBlacklistCount], cfg[api.ConfigRuleBitmap] = 0, 0
			cfg[api.ConfigCIDRRuleCount], cfg[api.ConfigCIDRBitmap] = 1, 1<<9
			key = make([]byte, 16)
			binary.LittleEndian.PutUint32(key[:4], 9)
			key[12] = proto
			lpm := make([]byte, 20)
			binary.LittleEndian.PutUint32(lpm[:4], 64)
			prefix := netip.MustParseAddr("2001:db8:1::").As16()
			copy(lpm[4:], prefix[:])
			td035Put(t, main.Maps["sv6_cidr_trie"], lpm, uint32(9))
			t.Cleanup(func() { td035Delete(t, main.Maps["sv6_cidr_trie"], lpm) })
		}
		if condition {
			row, err := api.EncodeConditionValue([]api.Rule{intent})
			if err != nil {
				t.Fatal(err)
			}
			if row.Active != 1 || strings.HasPrefix(c.rule, "I") && row.ICMPReq != 1 ||
				(c.rule == "R5" || c.rule == "Rt") && row.TCPReq != 1 {
				t.Fatal("TD122 compiled condition witness")
			}
			value.Pad2[0] = api.RuleHasConditions
			td035Put(t, main.Maps[condName], key, row)
			t.Cleanup(func() { td035Delete(t, main.Maps[condName], key) })
		}
		td035Put(t, main.Maps[name], key, value)
		t.Cleanup(func() {
			td035Delete(t, main.Maps[name], key)
			td035Delete(t, main.Maps["id_counts"], value.LogicalID)
		})
	}
	if c.gate != "G0" {
		whiteSrc, proto, port, combo := src, byte(0), uint16(0), uint64(1<<8)
		switch c.gate {
		case "Wudp", "Wp":
			proto, port, combo = 17, 53, 1<<14
			if c.gate == "Wp" {
				port = td122Port
			}
		case "W60":
			proto, combo = 60, 1<<9
		case "W59":
			proto, combo = 59, 1<<9
		case "Wother":
			whiteSrc = netip.MustParseAddr("192.0.2.99")
		default:
			t.Fatal("unknown TD122 gate")
		}
		whiteKey := td114Exact(whiteSrc, netip.Addr{}, proto, port)
		cfg[api.ConfigWhitelistCount], cfg[api.ConfigWLBitmap] = 1, combo
		td035Put(t, main.Maps["whitelist"], whiteKey, uint8(1))
		t.Cleanup(func() { td035Delete(t, main.Maps["whitelist"], whiteKey) })
	}
	for i, v := range cfg {
		td035Put(t, main.Maps["config_a"], uint32(i), v)
	}
	before := td035Stats(t, main)
	tailBefore := td035Sum(t, gate.Maps["tailcall_fail_stats"], 0)
	rule := td035Rule{name: c.rule, cidr: c.rule == "I4", value: value}
	var countBefore td035Counters
	if hasRule {
		countBefore = td035Counts(t, main, rule, key)
	}
	ret, _, err := gate.Programs["xdp_whitelist_gate"].Test(c.packet)
	got := td035Observation{Ret: ret, Stats: td035Stats(t, main), Rules: []td035Counters{},
		TailFail: td035Sum(t, gate.Maps["tailcall_fail_stats"], 0) - tailBefore}
	if err != nil {
		got.Error = err.Error()
	}
	for i := range got.Stats {
		got.Stats[i] -= before[i]
	}
	want := td035Observation{Ret: srcXDPPass, Stats: [5]uint64{1, 0, 1, 0, 0}, Rules: []td035Counters{}}
	if c.drop {
		want.Ret, want.Stats[1], want.Stats[2] = srcXDPDrop, 1, 0
	}
	if c.white {
		want.Stats[3] = 1
	}
	if hasRule {
		count := td035Counts(t, main, rule, key)
		count.Match -= countBefore.Match
		count.Drop -= countBefore.Drop
		got.Rules = append(got.Rules, count)
		expected := td035Counters{Name: c.rule}
		if c.drop {
			expected.Match, expected.Drop = 1, 1
		}
		want.Rules = append(want.Rules, expected)
	}
	verdict := "PASS"
	if !reflect.DeepEqual(got, want) {
		verdict = "FAIL"
		t.Errorf("TD122 observation got=%s want=%s", td035JSON(got), td035JSON(want))
	}
	t.Logf("TD122_CELL class=%s verdict=%s name=%s", c.class, verdict, c.name)
}

func TestTD122Matrix(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("TD122 root required")
	}
	cells := td122Cells()
	// A=5*5+3=28; B=3+2+5*4+3=28; C=2*3+1=7; D=3+3+1+3=10.
	if len(cells) != 73 {
		t.Fatalf("TD122 cells=%d want=73", len(cells))
	}
	seen, behavior := map[string]bool{}, 0
	for _, c := range cells {
		if seen[c.name] {
			t.Fatalf("TD122 duplicate cell name=%s", c.name)
		}
		seen[c.name] = true
		if c.class == "behavior" {
			behavior++
		}
	}
	if behavior != 24 {
		t.Fatalf("TD122 behavior=%d want=24", behavior)
	}
	main := td035Load(t, "XDROP_BPF_ELF", nil)
	replacements := map[string]*ebpf.Map{}
	for _, name := range []string{"whitelist", "stats", "config_a", "config_b", "active_config", "prog_tail_map", "devmap"} {
		if main.Maps[name] == nil {
			t.Fatal("missing shared map " + name)
		}
		replacements[name] = main.Maps[name]
	}
	gate := td035Load(t, "XDROP_GATE_ELF", replacements)
	if err := ClearRetiredTailSlot(main.Maps["prog_tail_map"]); err != nil {
		t.Fatal(err)
	}
	td035Put(t, main.Maps["prog_tail_map"], uint32(1), main.Programs["xdp_firewall_main"])
	td035Put(t, main.Maps["active_config"], uint32(0), uint64(0))
	for i, c := range cells {
		t.Run(c.name, func(t *testing.T) { td122RunCell(t, main, gate, c, i) })
	}
}

func TestTD122Verifier(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("TD122 root required")
	}
	type reading struct {
		insns  int
		frames []int
	}
	read := func(env, name string) reading {
		c := td035Load(t, env, nil)
		if len(c.Programs) != 1 || c.Programs[name] == nil {
			t.Fatalf("TD122 entry mismatch env=%s name=%s", env, name)
		}
		log := c.Programs[name].VerifierLog
		t.Logf("TD122_VERIFIER_RAW env=%s program=%s\n%s", env, name, log)
		ins := regexp.MustCompile(`processed ([0-9]+) insns`).FindAllStringSubmatch(log, -1)
		stack := regexp.MustCompile(`(?m)^stack depth ([0-9]+(?:\+[0-9]+)*)\s*$`).FindAllStringSubmatch(log, -1)
		if len(ins) != 1 || len(stack) != 1 {
			t.Fatalf("TD122 verifier summaries env=%s ins=%d stack=%d", env, len(ins), len(stack))
		}
		n, err := strconv.Atoi(ins[0][1])
		if err != nil || n <= 0 {
			t.Fatal("bad TD122 insns")
		}
		r := reading{insns: n}
		for _, f := range strings.Split(stack[0][1], "+") {
			v, err := strconv.Atoi(f)
			if err != nil {
				t.Fatal(err)
			}
			r.frames = append(r.frames, v)
		}
		return r
	}
	for _, p := range []struct{ name, base, after string }{
		{"xdp_firewall_main", "XDROP_BASE_BPF_ELF", "XDROP_BPF_ELF"},
		{"xdp_whitelist_gate", "XDROP_BASE_GATE_ELF", "XDROP_GATE_ELF"},
	} {
		b, a := read(p.base, p.name), read(p.after, p.name)
		bs, as := 0, 0
		for _, v := range b.frames {
			bs += v
		}
		for _, v := range a.frames {
			as += v
		}
		limit := 3000
		if p.name == "xdp_firewall_main" {
			limit = 10000
		}
		pass := a.insns <= 500000 && a.insns-b.insns <= limit && as-bs <= 64 && len(a.frames) > 0 && len(b.frames) > 0
		if p.name == "xdp_firewall_main" && len(a.frames) > 0 && len(b.frames) > 0 {
			pass = pass && a.frames[0]-b.frames[0] <= 32
		}
		verdict := "PASS"
		if !pass {
			verdict = "FAIL"
			t.Errorf("TD122 verifier budget exceeded: %s", p.name)
		}
		t.Logf("TD122_VERIFIER prog=%s base=%d after=%d delta=%d frames_base=%v frames_after=%v verdict=%s", p.name, b.insns, a.insns, a.insns-b.insns, b.frames, a.frames, verdict)
	}
}

// TestTD122IHLBelow4 guards K5 below the IHL=4 boundary (blind review r1 P2):
// an IPv4 header length of 2 must leave the packet without L4 in main and gate.
func TestTD122IHLBelow4(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("TD122 IHL witness root required")
	}
	main := td035Load(t, "XDROP_BPF_ELF", nil)
	replacements := map[string]*ebpf.Map{}
	for _, name := range []string{"whitelist", "stats", "config_a", "config_b", "active_config", "prog_tail_map", "devmap"} {
		if main.Maps[name] == nil {
			t.Fatal("missing shared map " + name)
		}
		replacements[name] = main.Maps[name]
	}
	gate := td035Load(t, "XDROP_GATE_ELF", replacements)
	if err := ClearRetiredTailSlot(main.Maps["prog_tail_map"]); err != nil {
		t.Fatal(err)
	}
	td035Put(t, main.Maps["prog_tail_map"], uint32(1), main.Programs["xdp_firewall_main"])
	td035Put(t, main.Maps["active_config"], uint32(0), uint64(0))
	packet := td122Packet("D4l", 0)
	packet[14] = (packet[14] & 0xf0) | 2
	// IHL=2 points at TTL/protocol/checksum. Its pseudo destination port is
	// the IPv4 checksum, deliberately equal to the existing rule's P*.
	binary.BigEndian.PutUint16(packet[24:26], td122Port)
	cells := []td122Cell{
		{shape: "D2l", rule: "Rp", gate: "G0", class: "guard", name: "D2l/Rp/G0", packet: packet},
		{shape: "D2l", rule: "R1", gate: "Wp", class: "guard", name: "D2l/R1/Wp", packet: packet, drop: true},
	}
	for i, c := range cells {
		t.Run(c.name, func(t *testing.T) { td122RunCell(t, main, gate, c, 100+i) })
	}
}
