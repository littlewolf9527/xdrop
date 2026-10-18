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
)

// TD-114 frames exist only in this test process and enter only Program.Test.
// Expectations come from the sealed matrix, never from either tested ELF.
var td114Src = netip.MustParseAddr("2001:db8:1::1")
var td114Dst = netip.MustParseAddr("2001:db8:2::1")

type td114Shape struct {
	head     byte
	form     string
	position int
	mismatch bool
	control  string
}

type td114Cell struct {
	shape  td114Shape
	rule   string
	gate   string
	class  string
	name   string
	packet []byte
	want   td035Observation
}

func td114Packet(s td114Shape) []byte {
	var payload []byte
	first := s.head
	if s.position == 2 {
		first = 60
		payload = []byte{s.head, 0, 0, 0, 0, 0, 0, 0}
	}
	if s.control == "udp" {
		first = 60
		payload = []byte{17, 0, 0, 0, 0, 0, 0, 0}
		udp := make([]byte, 8)
		binary.BigEndian.PutUint16(udp[2:4], 53)
		binary.BigEndian.PutUint16(udp[4:6], 8)
		payload = append(payload, udp...)
	} else if s.control == "depth" {
		first = 60
		for i := 0; i < 7; i++ {
			next := byte(60)
			if i == 6 {
				next = 17
			}
			payload = append(payload, next, 0, 0, 0, 0, 0, 0, 0)
		}
		payload = append(payload, make([]byte, 8)...)
	} else {
		switch s.form {
		case "S1":
			payload = append(payload, 17) // fewer than two header bytes
		case "S2":
			payload = append(payload, 17, 1, 0) // declared length exceeds frame
		case "S3":
			payload = append(payload, 17, 0, 0, 0, 0, 0, 0) // <8 fragment bytes
		default:
			panic("unknown TD114 shape")
		}
	}
	p := b1Frame(true, first, payload, 0)
	src, dst := td114Src.As16(), td114Dst.As16()
	copy(p[22:38], src[:])
	copy(p[38:54], dst[:])
	if s.mismatch {
		binary.BigEndian.PutUint16(p[18:20], uint16(len(payload)+20))
	}
	return p
}

func td114Exact(src, dst netip.Addr, proto byte, port uint16) []byte {
	k := make([]byte, 40)
	if src.IsValid() {
		a := src.As16()
		copy(k[:16], a[:])
	}
	if dst.IsValid() {
		a := dst.As16()
		copy(k[16:32], a[:])
	}
	binary.BigEndian.PutUint16(k[34:36], port)
	k[36] = proto
	return k
}

func td114Cells() []td114Cell {
	var shapes []td114Shape
	for _, h := range []byte{0, 43, 60, 51, 44} {
		forms := []string{"S1", "S2"}
		if h == 44 {
			forms = []string{"S3"}
		}
		for _, form := range forms {
			for _, pos := range []int{1, 2} {
				shapes = append(shapes, td114Shape{head: h, form: form, position: pos})
			}
		}
	}
	var cells []td114Cell
	add := func(s td114Shape, rule, gate string) {
		c := td114Cell{shape: s, rule: rule, gate: gate, class: "guard", packet: td114Packet(s)}
		c.name = fmt.Sprintf("H%d-%s-P%d%s/%s/%s", s.head, s.form, s.position, map[bool]string{true: "-mismatch"}[s.mismatch], rule, gate)
		if s.control != "" {
			c.name = s.control + "/" + c.name
		}
		c.want = td035Observation{Ret: srcXDPPass, Rules: []td035Counters{}}
		c.want.Stats[0], c.want.Stats[2] = 1, 1
		drop := rule == "R1" || rule == "R2" || rule == "R6" || gate == "W2" || (s.control == "udp" && rule == "R3")
		if gate == "W1" {
			c.want.Stats[3] = 1
		} else if drop {
			c.want.Ret = srcXDPDrop
			c.want.Stats[1], c.want.Stats[2] = 1, 0
		}
		if rule != "R0" {
			count := td035Counters{Name: rule}
			if drop && gate != "W1" {
				count.Match, count.Drop = 1, 1
			}
			c.want.Rules = append(c.want.Rules, count)
		}
		if rule == "R1" || rule == "R2" || rule == "R6" || gate == "W1" || gate == "W2" {
			c.class = "behavior"
		}
		if s.control != "" {
			c.class = "control"
		}
		cells = append(cells, c)
	}
	for _, s := range shapes {
		for _, gate := range []string{"G0", "G1"} {
			for _, rule := range []string{"R0", "R1", "R2", "R3", "R4", "R5"} {
				add(s, rule, gate)
			}
		}
		add(s, "R1", "W1")
		add(s, "R1", "W2")
	}
	for _, pos := range []int{1, 2} {
		s := td114Shape{head: 60, form: "S2", position: pos, mismatch: true}
		for _, gate := range []string{"G0", "G1"} {
			add(s, "R6", gate)
		}
	}
	for _, rule := range []string{"R1", "R3"} {
		add(td114Shape{control: "udp", head: 60, position: 1}, rule, "G0")
	}
	add(td114Shape{control: "depth", head: 60, position: 1}, "R1", "G0")
	return cells
}

func td114RunCell(t *testing.T, main, gate *ebpf.Collection, c td114Cell, index int) {
	t.Helper()
	cfg := [12]uint64{}
	cfg[api.ConfigRLCPUDivisor] = 1
	var key []byte
	var ruleValue api.RuleValue
	mapName := "blacklist"
	if c.rule != "R0" {
		cfg[api.ConfigBlacklistCount] = 1
		ruleValue = api.RuleValue{LogicalID: uint32(114000 + index), Action: api.ActionDrop}
		switch c.rule {
		case "R1":
			key, cfg[api.ConfigRuleBitmap] = td114Exact(td114Src, netip.Addr{}, 0, 0), 1<<8
		case "R2":
			mapName, cfg[api.ConfigBlacklistCount] = "cidr_blacklist", 0
			cfg[api.ConfigCIDRRuleCount], cfg[api.ConfigCIDRBitmap] = 1, 1<<4
			key = make([]byte, 16)
			binary.LittleEndian.PutUint32(key[4:8], 9)
			lpm := make([]byte, 20)
			binary.LittleEndian.PutUint32(lpm, 128)
			a := td114Dst.As16()
			copy(lpm[4:], a[:])
			td035Put(t, main.Maps["dv6_cidr_trie"], lpm, uint32(9))
			t.Cleanup(func() { td035Delete(t, main.Maps["dv6_cidr_trie"], lpm) })
		case "R3":
			key, cfg[api.ConfigRuleBitmap] = td114Exact(td114Src, netip.Addr{}, 0, 53), 1<<11
		case "R4":
			key, cfg[api.ConfigRuleBitmap] = td114Exact(td114Src, netip.Addr{}, 6, 0), 1<<9
		case "R5":
			key, cfg[api.ConfigRuleBitmap] = td114Exact(td114Src, netip.Addr{}, 0, 0), 1<<8
			intent := api.Rule{ID: "td114-r5", LogicalID: ruleValue.LogicalID, SrcIP: td114Src.String(), Protocol: "tcp", Action: "drop", TcpFlags: "!SYN"}
			row, err := api.EncodeConditionValue([]api.Rule{intent})
			if err != nil {
				t.Fatal(err)
			}
			if row.Active != 1 || row.TCPReq == 0 {
				t.Fatal("TD114 R5 condition witness")
			}
			ruleValue.Pad2[0] = api.RuleHasConditions
			td035Put(t, main.Maps["cond_a"], key, row)
			t.Cleanup(func() { td035Delete(t, main.Maps["cond_a"], key) })
		case "R6":
			key, cfg[api.ConfigRuleBitmap] = td114Exact(td114Src, netip.Addr{}, 0, 0), 1<<8
			cfg[api.ConfigAnomalyRuleCount] = 1
			row := b1AnomalyRow(ruleValue.LogicalID, 0x04)
			ruleValue.Pad2[0] = api.RuleHasConditions
			td035Put(t, main.Maps["cond_a"], key, row)
			t.Cleanup(func() { td035Delete(t, main.Maps["cond_a"], key) })
		default:
			t.Fatal("unknown TD114 rule")
		}
		td035Put(t, main.Maps[mapName], key, ruleValue)
		t.Cleanup(func() {
			td035Delete(t, main.Maps[mapName], key)
			td035Delete(t, main.Maps["id_counts"], ruleValue.LogicalID)
		})
	}
	if c.gate != "G0" {
		whiteSrc, whitePort := td114Src, uint16(0)
		if c.gate == "G1" {
			whiteSrc = netip.MustParseAddr("2001:db8:1::99")
		}
		if c.gate == "W2" {
			whitePort = 53
		}
		whiteKey := td114Exact(whiteSrc, netip.Addr{}, 0, whitePort)
		cfg[api.ConfigWhitelistCount] = 1
		cfg[api.ConfigWLBitmap] = 1 << 8
		if whitePort != 0 {
			cfg[api.ConfigWLBitmap] = 1 << 11
		}
		td035Put(t, main.Maps["whitelist"], whiteKey, uint8(1))
		t.Cleanup(func() { td035Delete(t, main.Maps["whitelist"], whiteKey) })
	}
	for i, v := range cfg {
		td035Put(t, main.Maps["config_a"], uint32(i), v)
	}
	before := td035Stats(t, main)
	tailBefore := td035Sum(t, gate.Maps["tailcall_fail_stats"], 0)
	var countBefore td035Counters
	if c.rule != "R0" {
		countBefore = td035Counts(t, main, td035Rule{name: c.rule, cidr: c.rule == "R2", value: ruleValue}, key)
	}
	ret, _, err := gate.Programs["xdp_whitelist_gate"].Test(c.packet)
	got := td035Observation{Ret: ret, Stats: td035Stats(t, main), TailFail: td035Sum(t, gate.Maps["tailcall_fail_stats"], 0) - tailBefore, Rules: []td035Counters{}}
	if err != nil {
		got.Error = err.Error()
	}
	for i := range got.Stats {
		got.Stats[i] -= before[i]
	}
	if c.rule != "R0" {
		count := td035Counts(t, main, td035Rule{name: c.rule, cidr: c.rule == "R2", value: ruleValue}, key)
		count.Match -= countBefore.Match
		count.Drop -= countBefore.Drop
		got.Rules = append(got.Rules, count)
	}
	verdict := "PASS"
	if !reflect.DeepEqual(got, c.want) {
		verdict = "FAIL"
	}
	t.Logf("TD114_CELL class=%s verdict=%s name=%s got=%s want=%s", c.class, verdict, c.name, td035JSON(got), td035JSON(c.want))
	if got.Stats[0] != 1 || got.TailFail != 0 {
		t.Errorf("TD114 prerequisite total=%d tailfail=%d", got.Stats[0], got.TailFail)
	}
	if verdict != "PASS" {
		t.Error("TD114_CELL mismatch")
	}
}

func TestTD114Matrix(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("TD114 root required")
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
	cells := td114Cells()
	if len(cells) != 259 {
		t.Fatalf("TD114 cells=%d want=259", len(cells))
	}
	for i, c := range cells {
		t.Run(c.name, func(t *testing.T) { td114RunCell(t, main, gate, c, i) })
	}
}

func TestTD114Verifier(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("TD114 root required")
	}
	type reading struct {
		insns  int
		frames []int
	}
	read := func(env, name string) reading {
		c := td035Load(t, env, nil)
		if len(c.Programs) != 1 || c.Programs[name] == nil {
			t.Fatalf("TD114 entry mismatch env=%s name=%s", env, name)
		}
		log := c.Programs[name].VerifierLog
		t.Logf("TD114_VERIFIER_RAW env=%s program=%s\n%s", env, name, log)
		ins := regexp.MustCompile(`processed ([0-9]+) insns`).FindAllStringSubmatch(log, -1)
		stack := regexp.MustCompile(`(?m)^stack depth ([0-9]+(?:\+[0-9]+)*)\s*$`).FindAllStringSubmatch(log, -1)
		if len(ins) != 1 || len(stack) != 1 {
			t.Fatalf("TD114 verifier summaries env=%s ins=%d stack=%d", env, len(ins), len(stack))
		}
		n, err := strconv.Atoi(ins[0][1])
		if err != nil || n <= 0 {
			t.Fatal("bad TD114 insns")
		}
		r := reading{insns: n}
		for _, f := range strings.Split(stack[0][1], "+") {
			v, e := strconv.Atoi(f)
			if e != nil {
				t.Fatal(e)
			}
			r.frames = append(r.frames, v)
		}
		return r
	}
	for _, p := range []struct{ name, base, after string }{{"xdp_firewall_main", "XDROP_BASE_BPF_ELF", "XDROP_BPF_ELF"}, {"xdp_whitelist_gate", "XDROP_BASE_GATE_ELF", "XDROP_GATE_ELF"}} {
		b, a := read(p.base, p.name), read(p.after, p.name)
		bs, as := 0, 0
		for _, v := range b.frames {
			bs += v
		}
		for _, v := range a.frames {
			as += v
		}
		limit := 5000
		if p.name == "xdp_firewall_main" {
			limit = 31000 // owner-approved after lab measured +30,347 (PLAN G3 was 30,000)
		}
		pass := a.insns <= 500000 && a.insns-b.insns <= limit && as-bs <= 64 && len(a.frames) > 0 && len(b.frames) > 0
		if p.name == "xdp_firewall_main" && len(a.frames) > 0 && len(b.frames) > 0 {
			pass = pass && a.frames[0]-b.frames[0] <= 32
		}
		verdict := "PASS"
		if !pass {
			verdict = "FAIL"
		}
		t.Logf("TD114_VERIFIER prog=%s base=%d after=%d delta=%d frames_base=%v frames_after=%v verdict=%s", p.name, b.insns, a.insns, a.insns-b.insns, b.frames, a.frames, verdict)
		if !pass {
			t.Errorf("TD114 verifier budget exceeded: %s", p.name)
		}
	}
}
