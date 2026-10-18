//go:build linux && integration

package bpf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
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
	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
)

// All behavior expectations are TD-035 expectations, including when the same
// binary is run against baseline ELFs. 行为格 must fail baseline; 守卫格 must pass
// both. There is no baseline switch which could rewrite a verdict expectation.
type td035Rule struct {
	name        string
	cidr        bool
	proto       byte
	port        uint16
	srcPort     uint16
	value       api.RuleValue
	condition   bool
	match, drop uint64
}
type td035Cell struct {
	v                int
	pkt, rule, class string
	packet           []byte
	rules            []td035Rule
	white            bool
	whiteProto       byte
	whitePort        uint16
	whiteSrcPort     uint16
	ret              uint32
	whitelisted      uint64
	bucket           bool
	seedBucket       bool
	bucketExists     bool
}
type td035Counters struct {
	Name          string `json:"name"`
	Match         uint64 `json:"match"`
	Drop          uint64 `json:"drop"`
	PhysicalMatch uint64 `json:"physical_match"`
	PhysicalDrop  uint64 `json:"physical_drop"`
}
type td035Observation struct {
	Ret             uint32          `json:"ret"`
	Stats           [5]uint64       `json:"stats_total_drop_pass_wl_rl"`
	TailFail        uint64          `json:"tailcall_fail"`
	Rules           []td035Counters `json:"rules"`
	BucketExists    bool            `json:"bucket_exists"`
	BucketUnchanged bool            `json:"bucket_unchanged"`
	BucketTokens    uint64          `json:"bucket_tokens"`
	Error           string          `json:"error"`
}

func td035JSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func td035Dst(v int) netip.Addr {
	if v == 6 {
		return netip.MustParseAddr("2001:db8:2::1")
	}
	return netip.MustParseAddr("198.51.100.1")
}
func td035Packet(v int, kind string, proto byte, port uint16, flags byte) []byte {
	payload := make([]byte, 20)
	binary.BigEndian.PutUint16(payload[0:2], 1234)
	binary.BigEndian.PutUint16(payload[2:4], port)
	payload[12], payload[13] = 0x50, flags
	if proto == 17 {
		binary.BigEndian.PutUint16(payload[4:6], 20)
	}
	first, nonfirst := kind == "first", kind == "last" || kind == "middle"
	if v == 6 && (first || nonfirst) {
		field := uint16(0)
		if nonfirst {
			field = 16
		}
		if first || kind == "middle" {
			field |= 1
		}
		ext := make([]byte, 8)
		ext[0] = proto
		binary.BigEndian.PutUint16(ext[2:4], field)
		payload, proto = append(ext, payload...), 44
	}
	p := b1Frame(v == 6, proto, payload, 0)
	if v == 4 {
		copy(p[26:30], []byte{192, 0, 2, 1})
		copy(p[30:34], []byte{198, 51, 100, 1})
		field := uint16(0)
		if nonfirst {
			field = 2
		}
		if first || kind == "middle" {
			field |= 0x2000
		}
		binary.BigEndian.PutUint16(p[20:22], field)
	} else {
		src, dst := netip.MustParseAddr("2001:db8:1::1").As16(), td035Dst(v).As16()
		copy(p[22:38], src[:])
		copy(p[38:54], dst[:])
	}
	if len(p) < 60 {
		p = append(p, make([]byte, 60-len(p))...)
	}
	return p
}
func td035Key(v int, cidr bool, proto byte, sport, port uint16) []byte {
	key := make([]byte, 40)
	po, pr := 34, 36
	if cidr {
		key = make([]byte, 16)
		po, pr = 10, 12
		binary.LittleEndian.PutUint32(key[4:8], 9)
	} else {
		dst := td035Dst(v).As16()
		copy(key[16:32], dst[:])
	}
	binary.BigEndian.PutUint16(key[po-2:po], sport)
	binary.BigEndian.PutUint16(key[po:po+2], port)
	key[pr] = proto
	return key
}
func td035Combo(proto byte, sport, port uint16) uint64 {
	if sport != 0 {
		return 1 << 26 // destination IP/ID + source port + protocol; no destination port
	}
	if port != 0 {
		return 1 << 2
	}
	if proto != 0 {
		return 1 << 3
	}
	return 1 << 4
}
func td035Cells() []td035Cell {
	var cells []td035Cell
	for _, v := range []int{4, 6} {
		for _, kind := range []string{"complete", "first", "last", "middle"} {
			for _, port := range []uint16{53, 54} {
				for _, rule := range []string{"ip-drop", "port-whitelist-ip-drop", "port-blacklist", "cidr-port-drop", "port-rate", "flags-syn", "flags-not-syn", "ip-whitelist"} {
					nf := kind == "last" || kind == "middle"
					proto, flags := byte(17), byte(2)
					if strings.HasPrefix(rule, "flags-") {
						proto = 6
					}
					if rule == "flags-not-syn" {
						flags = 0x10
					}
					// 守卫格: full/first packets, L3-only rules and payload-port misses.
					c := td035Cell{v: v, pkt: fmt.Sprintf("%s-dport%d", kind, port), rule: rule, class: "guard", packet: td035Packet(v, kind, proto, port, flags), ret: srcXDPPass}
					r := td035Rule{name: "target", proto: proto, value: api.RuleValue{Action: api.ActionDrop}}
					switch rule {
					case "ip-drop":
						r.proto, r.match, r.drop = 0, 1, 1
						c.ret = srcXDPDrop
					case "port-whitelist-ip-drop":
						c.white, c.whiteProto, c.whitePort = true, proto, 53
						r.proto = 0
						if !nf && port == 53 {
							c.whitelisted = 1
						} else {
							c.ret, r.match, r.drop = srcXDPDrop, 1, 1
						}
					case "port-blacklist", "cidr-port-drop", "port-rate":
						r.port = 53
						r.cidr = rule == "cidr-port-drop"
						if !nf && port == 53 {
							c.ret, r.match, r.drop = srcXDPDrop, 1, 1
						}
						if rule == "port-rate" {
							r.value.Action, r.value.RateLimit = api.ActionRateLimit, 17
							c.ret, r.drop, c.bucket = srcXDPPass, 0, true
							c.bucketExists = r.match == 1
						}
					case "flags-syn", "flags-not-syn":
						r.value.TcpFlagsMask = 2
						if rule == "flags-syn" {
							r.value.TcpFlagsValue = 2
						}
						if !nf {
							c.ret, r.match, r.drop = srcXDPDrop, 1, 1
						}
					case "ip-whitelist":
						c.white, c.whitelisted = true, 1
					}
					if rule != "ip-whitelist" {
						c.rules = []td035Rule{r}
					}
					// 行为格: nonfirst spoofed port hits or either flags predicate.
					if nf && ((port == 53 && (rule == "port-whitelist-ip-drop" || rule == "port-blacklist" || rule == "cidr-port-drop" || rule == "port-rate")) || strings.HasPrefix(rule, "flags-")) {
						c.class = "behavior"
					}
					cells = append(cells, c)
					if rule == "port-rate" && nf {
						c.rule, c.seedBucket, c.bucketExists = "port-rate-existing", true, true
						cells = append(cells, c)
					}
				}
			}
		}
		for _, cidr := range []bool{false, true} {
			for _, kind := range []string{"complete-ack", "complete-syn", "last-ack"} {
				pktKind, flags := "complete", byte(0x10)
				if kind == "complete-syn" {
					flags = 2
				}
				if kind == "last-ack" {
					pktKind = "last"
				}
				r := td035Rule{name: "condition", proto: 6, cidr: cidr, condition: true, value: api.RuleValue{Action: api.ActionDrop}}
				// 守卫格: full ACK hits, full SYN misses; 行为格: nonfirst ACK misses.
				c := td035Cell{v: v, pkt: kind, rule: fmt.Sprintf("condition-not-syn-cidr%t", cidr), class: "guard", packet: td035Packet(v, pktKind, 6, 53, flags), ret: srcXDPPass}
				if kind == "complete-ack" {
					c.ret, r.match, r.drop = srcXDPDrop, 1, 1
				}
				if kind == "last-ack" {
					c.class = "behavior"
				}
				c.rules = []td035Rule{r}
				cells = append(cells, c)
			}
		}
		for _, proto := range []byte{6, 17} {
			for _, gate := range []bool{false, true} {
				p := td035Packet(v, "last", proto, 53, 2)
				l4 := 34
				if v == 6 {
					l4 = 62
					binary.BigEndian.PutUint16(p[18:20], 12)
				} else {
					binary.BigEndian.PutUint16(p[16:18], 24)
				}
				p = p[:l4+4] // 行为格: do not pad; baseline aborts before its IP rule.
				c := td035Cell{v: v, pkt: fmt.Sprintf("short-last-proto%d", proto), rule: fmt.Sprintf("short-ip-drop-gate%t", gate), class: "behavior", packet: p, ret: srcXDPDrop, rules: []td035Rule{{name: "ip", value: api.RuleValue{Action: api.ActionDrop}, match: 1, drop: 1}}}
				if gate {
					c.white, c.whiteProto, c.whitePort = true, proto, 53
				}
				cells = append(cells, c)
			}
		}
	}
	// IPv4 anomaly witnesses: no-port rule must reach the anomaly tail call.
	for _, kind := range []string{"last", "middle"} {
		for _, port := range []uint16{53, 54} {
			for _, portRule := range []bool{false, true} {
				p := td035Packet(4, kind, 17, port, 0)
				off := uint16(8191)
				if kind == "middle" {
					off |= 0x2000
				}
				binary.BigEndian.PutUint16(p[20:22], off)
				r := td035Rule{name: "bad-fragment", proto: 17, value: api.RuleValue{Action: api.ActionDrop, MatchAnomaly: api.AnomalyBadFragment}, match: 1, drop: 1}
				c := td035Cell{v: 4, pkt: fmt.Sprintf("bad-%s-dport%d", kind, port), rule: fmt.Sprintf("anomaly-port%t", portRule), class: "guard", packet: p, ret: srcXDPDrop}
				if portRule {
					r.port, r.match, r.drop, c.ret = 53, 0, 0, srcXDPPass
					if port == 53 {
						c.class = "behavior"
					}
				} // 行为格: port-constrained nonfirst anomaly.
				c.rules = []td035Rule{r}
				cells = append(cells, c)
			}
		}
	}
	// 守卫格: tiny first fragment still reaches the port-constrained anomaly.
	p := td035Packet(4, "first", 17, 53, 0)
	binary.BigEndian.PutUint16(p[16:18], 27)
	cells = append(cells, td035Cell{v: 4, pkt: "tiny-first", rule: "anomaly-port", class: "guard", packet: p, ret: srcXDPDrop, rules: []td035Rule{{name: "tiny", proto: 17, port: 53, value: api.RuleValue{Action: api.ActionDrop, MatchAnomaly: api.AnomalyBadFragment}, match: 1, drop: 1}}})
	for _, cidr := range []bool{false, true} {
		p := td035Packet(4, "last", 6, 53, 0x10)
		binary.BigEndian.PutUint16(p[20:22], 8191)
		// 行为格: readback forced to one must fail the !SYN nonfirst witness.
		cells = append(cells, td035Cell{v: 4, pkt: "bad-last-ack", rule: fmt.Sprintf("anomaly-not-syn-cidr%t", cidr), class: "behavior", packet: p, ret: srcXDPPass, rules: []td035Rule{{name: "anomaly-flags", cidr: cidr, proto: 6, value: api.RuleValue{Action: api.ActionDrop, MatchAnomaly: api.AnomalyBadFragment, TcpFlagsMask: 2}}}})
		p = td035Packet(4, "complete", 6, 53, 2)
		p[46] = 0x40
		// 守卫格: write forced to zero must fail the positive complete/SYN witness.
		cells = append(cells, td035Cell{v: 4, pkt: "invalid-complete-syn", rule: fmt.Sprintf("anomaly-syn-cidr%t", cidr), class: "guard", packet: p, ret: srcXDPDrop, rules: []td035Rule{{name: "anomaly-flags", cidr: cidr, proto: 6, value: api.RuleValue{Action: api.ActionDrop, MatchAnomaly: api.AnomalyInvalid, TcpFlagsMask: 2, TcpFlagsValue: 2}, match: 1, drop: 1}}})
	}
	// 守卫格: existing IPv6 bad_fragment behavior remains inert.
	cells = append(cells, td035Cell{v: 6, pkt: "last", rule: "v6-bad-fragment", class: "guard", packet: td035Packet(6, "last", 6, 53, 0x10), ret: srcXDPPass, rules: []td035Rule{{name: "v6-anomaly", proto: 6, value: api.RuleValue{Action: api.ActionDrop, MatchAnomaly: api.AnomalyBadFragment}}}})
	for _, next := range []byte{17, 60} {
		for _, gate := range []bool{false, true} {
			p := td035Packet(6, "last", 17, 53, 0)
			p[54] = next
			if next == 60 {
				p[62], p[63] = 17, 0
			} // legal fake extension header with eight-byte UDP remainder
			c := td035Cell{v: 6, pkt: fmt.Sprintf("last-next%d-fake-extension", next), rule: fmt.Sprintf("protocol-udp-gate%t", gate), class: "guard", packet: p, ret: srcXDPPass}
			if next == 60 {
				c.class = "behavior"
			} // 行为格 W4: stop before fake extension.
			if gate {
				c.white, c.whiteProto = true, 17
				r := td035Rule{name: "ip", value: api.RuleValue{Action: api.ActionDrop}}
				if next == 17 {
					c.whitelisted = 1
				} else {
					c.ret, r.match, r.drop = srcXDPDrop, 1, 1
				}
				c.rules = []td035Rule{r}
			} else {
				r := td035Rule{name: "udp", proto: 17, value: api.RuleValue{Action: api.ActionDrop}}
				if next == 17 {
					c.ret, r.match, r.drop = srcXDPDrop, 1, 1
				}
				c.rules = []td035Rule{r}
			}
			cells = append(cells, c)
		}
	}
	return append(cells, td035SourcePortCells()...)
}

func td035SourcePortCells() []td035Cell {
	// Keep the UDP cells first and byte-identical; append the TCP dimension.
	return append(td035SourcePortCellsFor(17), td035SourcePortCellsFor(6)...)
}

func td035SourcePortCellsFor(proto byte) []td035Cell {
	var cells []td035Cell
	for _, v := range []int{4, 6} {
		for _, kind := range []string{"complete", "first", "last", "middle"} {
			for _, rule := range []string{"src-port-whitelist-ip-drop", "src-port-blacklist", "cidr-src-port-drop"} {
				for _, sport := range []uint16{1234, 5678} {
					nf := kind == "last" || kind == "middle"
					p := td035Packet(v, kind, proto, 53, 0)
					l4 := 34
					if v == 6 {
						l4 = 54
						if kind != "complete" {
							l4 += 8
						}
					}
					binary.BigEndian.PutUint16(p[l4:l4+2], sport)
					// 守卫格: complete/first matching source ports and all miss twins.
					c := td035Cell{v: v, pkt: fmt.Sprintf("%s-sport%d", kind, sport), rule: rule, class: "guard", packet: p, ret: srcXDPPass}
					r := td035Rule{name: "src-port-target", proto: proto, srcPort: 1234, value: api.RuleValue{Action: api.ActionDrop}}
					hit := !nf && sport == 1234
					if rule == "src-port-whitelist-ip-drop" {
						c.white, c.whiteProto, c.whiteSrcPort = true, proto, 1234
						r.name, r.proto, r.srcPort = "ip-fallback", 0, 0
						if hit {
							c.whitelisted = 1
						} else {
							c.ret, r.match, r.drop = srcXDPDrop, 1, 1
						}
					} else {
						r.cidr = rule == "cidr-src-port-drop"
						if hit {
							c.ret, r.match, r.drop = srcXDPDrop, 1, 1
						}
					}
					// 行为格: nonfirst payload's forged source port must not hit.
					if nf && sport == 1234 {
						c.class = "behavior"
					}
					if proto == 6 {
						c.rule = "tcp-" + c.rule
					}
					c.rules = []td035Rule{r}
					cells = append(cells, c)
				}
			}
		}
	}
	return cells
}

func td035CheckSourcePortTwins(t *testing.T, cells []td035Cell) {
	t.Helper()
	var source []td035Cell
	for _, c := range cells {
		if strings.Contains(c.rule, "src-port") {
			source = append(source, c)
		}
	}
	if len(source) != 96 {
		t.Fatalf("TD035 source-port cells=%d want=96", len(source))
	}
	for i := 0; i < len(source); i += 2 {
		a, b := source[i], source[i+1]
		l4 := 34
		if a.v == 6 {
			l4 = 54
			if !strings.HasPrefix(a.pkt, "complete-") {
				l4 += 8
			}
		}
		if a.v != b.v || a.rule != b.rule || len(a.packet) != len(b.packet) ||
			!bytes.Equal(a.packet[:l4], b.packet[:l4]) || !bytes.Equal(a.packet[l4+2:], b.packet[l4+2:]) ||
			a.packet[l4] == b.packet[l4] || a.packet[l4+1] == b.packet[l4+1] ||
			binary.BigEndian.Uint16(a.packet[l4:l4+2]) != 1234 || binary.BigEndian.Uint16(b.packet[l4:l4+2]) != 5678 {
			t.Fatalf("TD035 source-port twins differ outside exactly two source bytes: v=%d pkt=%s/%s rule=%s", a.v, a.pkt, b.pkt, a.rule)
		}
		if a.whitePort != 0 || b.whitePort != 0 {
			t.Fatal("TD035 source-port whitelist must not constrain destination port")
		}
		for _, c := range []td035Cell{a, b} {
			for _, r := range c.rules {
				if r.port != 0 {
					t.Fatal("TD035 source-port rule must not constrain destination port")
				}
			}
		}
	}
}

func td035Load(t *testing.T, env string, replacements map[string]*ebpf.Map) *ebpf.Collection {
	t.Helper()
	path := os.Getenv(env)
	if path == "" {
		t.Fatalf("TD035 prerequisite: %s required", env)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinNone {
			t.Fatalf("TD035 pinning forbidden: %s", name)
		}
	}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replacements, Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}})
	if err != nil {
		t.Fatalf("TD035 load %s: %+v", env, err)
	}
	t.Cleanup(c.Close)
	t.Logf("TD035_ELF env=%s sha256=%x", env, sha256.Sum256(raw))
	return c
}
func td035Put(t *testing.T, m *ebpf.Map, k, v any) {
	t.Helper()
	if err := m.Put(k, v); err != nil {
		t.Fatal(err)
	}
}
func td035Delete(t *testing.T, m *ebpf.Map, k any) {
	t.Helper()
	if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Error(err)
	}
}
func td035Sum(t *testing.T, m *ebpf.Map, key uint32) uint64 {
	t.Helper()
	var a []uint64
	if err := m.Lookup(key, &a); err != nil {
		t.Fatal(err)
	}
	var n uint64
	for _, v := range a {
		n += v
	}
	return n
}
func td035Stats(t *testing.T, c *ebpf.Collection) (s [5]uint64) {
	for i := range s {
		s[i] = td035Sum(t, c.Maps["stats"], uint32(i))
	}
	return
}
func td035Bucket(t *testing.T, m *ebpf.Map, key []byte) ([]ratelimit.State, bool) {
	t.Helper()
	var a []ratelimit.State
	err := m.Lookup(key, &a)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return a, true
}
func td035Counts(t *testing.T, c *ebpf.Collection, r td035Rule, key []byte) td035Counters {
	t.Helper()
	name := "blacklist"
	if r.cidr {
		name = "cidr_blacklist"
	}
	var v api.RuleValue
	if err := c.Maps[name].Lookup(key, &v); err != nil {
		t.Fatal(err)
	}
	if v.LogicalID != r.value.LogicalID || v.LogicalReserved != ([12]byte{}) {
		t.Fatalf("TD035 immutable rule identity/reserved: %+v", v)
	}
	out := td035Counters{Name: r.name}
	var all []api.LogicalRuleCounters
	err := c.Maps["id_counts"].Lookup(v.LogicalID, &all)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal(err)
	}
	for _, count := range all {
		out.Match += count.Match
		out.Drop += count.Drop
	}

	return out
}
func TestTD035FragmentMatrix(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("TD035 root required")
	}
	main := td035Load(t, "XDROP_BPF_ELF", nil)
	replacements := map[string]*ebpf.Map{}
	for _, name := range []string{"whitelist", "stats", "config_a", "config_b", "active_config", "prog_tail_map", "devmap"} {
		m := main.Maps[name]
		if m == nil {
			t.Fatal("missing shared map " + name)
		}
		replacements[name] = m
	}
	gate := td035Load(t, "XDROP_GATE_ELF", replacements)
	if err := ClearRetiredTailSlot(main.Maps["prog_tail_map"]); err != nil {
		t.Fatal(err)
	}
	td035Put(t, main.Maps["prog_tail_map"], uint32(1), main.Programs["xdp_firewall_main"])
	td035Put(t, main.Maps["active_config"], uint32(0), uint64(0))
	cells := td035Cells()
	td035CheckSourcePortTwins(t, cells)
	behavior, guard := 0, 0
	for cellIndex, cell := range cells {
		t.Run(fmt.Sprintf("v%d/%s/%s", cell.v, cell.pkt, cell.rule), func(t *testing.T) {
			if cell.class == "behavior" {
				behavior++
			} else {
				guard++
			}
			td035RunCell(t, main, gate, cell, cellIndex)
		})
	}
	if len(cells) != 270 {
		t.Fatalf("TD035 matrix cells=%d want=270", len(cells))
	}
	t.Logf("TD035_MATRIX planned=%d cells=%d behavior=%d guard=%d", len(cells), behavior+guard, behavior, guard)
}
func td035RunCell(t *testing.T, main, gate *ebpf.Collection, c td035Cell, cellIndex int) {
	t.Helper()
	cfg := [12]uint64{}
	cfg[api.ConfigRLCPUDivisor] = 1
	var keys [][]byte
	c.rules = append([]td035Rule(nil), c.rules...)
	for i := range c.rules {
		c.rules[i].value.LogicalID = uint32(100000 + cellIndex*10 + i)
	}
	for _, r := range c.rules {
		key := td035Key(c.v, r.cidr, r.proto, r.srcPort, r.port)
		keys = append(keys, key)
		name, cond := "blacklist", "cond_a"
		if r.cidr {
			name, cond = "cidr_blacklist", "cidr_cond_a"
			cfg[api.ConfigCIDRRuleCount]++
			cfg[api.ConfigCIDRBitmap] |= td035Combo(r.proto, r.srcPort, r.port)
		} else {
			cfg[api.ConfigBlacklistCount]++
			cfg[api.ConfigRuleBitmap] |= td035Combo(r.proto, r.srcPort, r.port)
		}
		value := r.value
		if r.condition {
			intent := api.Rule{ID: "td035-condition", LogicalID: value.LogicalID, Protocol: "tcp", Action: "drop", TcpFlags: "!SYN"}
			if r.cidr {
				if c.v == 4 {
					intent.DstCIDR = "198.51.100.0/24"
				} else {
					intent.DstCIDR = "2001:db8:2::/64"
				}
			} else {
				intent.DstIP = td035Dst(c.v).String()
			}
			row, err := api.EncodeConditionValue([]api.Rule{intent})
			if err != nil {
				t.Fatal(err)
			}
			if row.Active != 1 {
				t.Fatal("TD035 condition active must be one")
			}
			// Do not preassert TCPReq: mutation #7 must reach this same packet cell.
			value.Pad2[0] = api.RuleHasConditions
			td035Put(t, main.Maps[cond], key, row)
			t.Cleanup(func() { td035Delete(t, main.Maps[cond], key); td035Delete(t, main.Maps["id_counts"], value.LogicalID) })
		}
		if value.MatchAnomaly != 0 {
			row := b1AnomalyRow(value.LogicalID, value.MatchAnomaly)
			if value.TcpFlagsMask != 0 {
				row.TCPReq = 1
				row.Tab[2] = [128]byte{}
				for flags := 0; flags < 256; flags++ {
					if uint8(flags)&value.TcpFlagsMask == value.TcpFlagsValue {
						row.Tab[2][flags/2] |= 1 << uint(4*(flags%2))
					}
				}
			}
			value.Pad2[0] = api.RuleHasConditions
			value.MatchAnomaly, value.TcpFlagsMask, value.TcpFlagsValue = 0, 0, 0
			td035Put(t, main.Maps[cond], key, row)
			t.Cleanup(func() { td035Delete(t, main.Maps[cond], key) })
		}
		t.Cleanup(func() {
			td035Delete(t, main.Maps["id_counts"], value.LogicalID)
			td035Delete(t, main.Maps["id_rl_states"], value.LogicalID)
		})
		td035Put(t, main.Maps[name], key, value)
		t.Cleanup(func() { td035Delete(t, main.Maps[name], key) })
		if r.cidr {
			trie := "dv4_cidr_trie"
			lpm := make([]byte, 8)
			if c.v == 4 {
				addr := td035Dst(c.v).As4()
				binary.LittleEndian.PutUint32(lpm, 32)
				copy(lpm[4:], addr[:])
			}
			if c.v == 6 {
				trie = "dv6_cidr_trie"
				lpm = make([]byte, 20)
				binary.LittleEndian.PutUint32(lpm, 128)
				a := td035Dst(c.v).As16()
				copy(lpm[4:], a[:])
			}
			td035Put(t, main.Maps[trie], lpm, uint32(9))
			t.Cleanup(func() { td035Delete(t, main.Maps[trie], lpm) })
		}
	}
	if c.white {
		key := td035Key(c.v, false, c.whiteProto, c.whiteSrcPort, c.whitePort)
		td035Put(t, main.Maps["whitelist"], key, uint8(1))
		t.Cleanup(func() { td035Delete(t, main.Maps["whitelist"], key) })
		cfg[api.ConfigWhitelistCount] = 1
		cfg[api.ConfigWLBitmap] = td035Combo(c.whiteProto, c.whiteSrcPort, c.whitePort)
	}
	for i, v := range cfg {
		td035Put(t, main.Maps["config_a"], uint32(i), v)
	}
	bucketKey := make([]byte, 4)
	if c.bucket {
		binary.LittleEndian.PutUint32(bucketKey, c.rules[0].value.LogicalID)
	}
	bucketMap := main.Maps["id_rl_states"]
	var bucketBefore []ratelimit.State
	var beforeExists bool
	if c.bucket {
		if c.seedBucket {
			values := make([]ratelimit.State, mustPossibleCPUs(t))
			now := td074Clock(t)
			for i := range values {
				values[i] = ratelimit.State{Tokens: 13, LastUpdate: now + 1000000000}
			}
			td035Put(t, bucketMap, bucketKey, values)
		}
		bucketBefore, beforeExists = td035Bucket(t, bucketMap, bucketKey)
		t.Cleanup(func() { td035Delete(t, bucketMap, bucketKey) })
	}
	before := td035Stats(t, main)
	tailBefore := td035Sum(t, gate.Maps["tailcall_fail_stats"], 0)
	beforeRules := make([]td035Counters, len(c.rules))
	for i, r := range c.rules {
		beforeRules[i] = td035Counts(t, main, r, keys[i])
	}
	ret, _, err := gate.Programs["xdp_whitelist_gate"].Test(c.packet) // exactly one Program.Test per cell
	got := td035Observation{Ret: ret, Stats: td035Stats(t, main), TailFail: td035Sum(t, gate.Maps["tailcall_fail_stats"], 0) - tailBefore, Rules: []td035Counters{}}
	if err != nil {
		got.Error = err.Error()
	}
	for i := range got.Stats {
		got.Stats[i] -= before[i]
	}
	want := td035Observation{Ret: c.ret, Rules: []td035Counters{}}
	want.Stats[0] = 1
	want.Stats[3] = c.whitelisted
	if c.ret == srcXDPDrop {
		want.Stats[1] = 1
	} else {
		want.Stats[2] = 1
	}
	for i, r := range c.rules {
		x := td035Counts(t, main, r, keys[i])
		b := beforeRules[i]
		x.Match -= b.Match
		x.Drop -= b.Drop
		x.PhysicalMatch -= b.PhysicalMatch
		x.PhysicalDrop -= b.PhysicalDrop
		got.Rules = append(got.Rules, x)
		w := td035Counters{Name: r.name, Match: r.match, Drop: r.drop}
		want.Rules = append(want.Rules, w)
	}
	if c.bucket {
		a, exists := td035Bucket(t, bucketMap, bucketKey)
		got.BucketExists = exists
		got.BucketUnchanged = exists == beforeExists && reflect.DeepEqual(a, bucketBefore)
		for _, s := range a {
			got.BucketTokens += s.Tokens
		}
		want.BucketExists = c.bucketExists
		want.BucketUnchanged = c.rules[0].match == 0
		if c.seedBucket {
			for _, s := range bucketBefore {
				want.BucketTokens += s.Tokens
			}
		} else if c.bucketExists {
			want.BucketTokens = 33
		}
	}
	verdict := "PASS"
	if !reflect.DeepEqual(got, want) {
		verdict = "FAIL"
	}
	t.Logf("TD035_CELL verdict=%s class=%s v=%d pkt=%s rule=%s got=%s want=%s", verdict, c.class, c.v, c.pkt, c.rule, td035JSON(got), td035JSON(want))
	if got.Stats[0] != 1 || got.TailFail != 0 {
		t.Fatalf("TD035 self-check total=%d tailcall_fail=%d want=1/0", got.Stats[0], got.TailFail)
	}
	if verdict != "PASS" {
		t.Fatal("TD035_CELL mismatch")
	}
}

func TestTD035Verifier(t *testing.T) {
	// 所有者 10-04 接受 TD-035 main Δ87,918（> 仓库单刀 20,000 的破例，仅限本刀对 003e473）
	const td035AcceptedMainDelta = 90000
	if os.Geteuid() != 0 {
		t.Fatal("TD035 root required")
	}
	type reading struct {
		instructions int
		frames       []int
	}
	read := func(env string, names []string) map[string]reading {
		c := td035Load(t, env, nil)
		if len(c.Programs) != len(names) {
			t.Fatalf("TD035 entry set mismatch actual=%d expected=%v", len(c.Programs), names)
		}
		out := map[string]reading{}
		for _, name := range names {
			p := c.Programs[name]
			if p == nil {
				t.Fatal("missing " + name)
			}
			t.Logf("TD035_VERIFIER_RAW env=%s program=%s\n%s", env, name, p.VerifierLog)
			ins := regexp.MustCompile(`processed ([0-9]+) insns`).FindAllStringSubmatch(p.VerifierLog, -1)
			stack := regexp.MustCompile(`(?m)^stack depth ([0-9]+(?:\+[0-9]+)*)\s*$`).FindAllStringSubmatch(p.VerifierLog, -1)
			if len(ins) != 1 || len(stack) != 1 {
				t.Fatalf("TD035 verifier summaries instructions=%d stack=%d", len(ins), len(stack))
			}
			n, e := strconv.Atoi(ins[0][1])
			if e != nil || n <= 0 {
				t.Fatal("bad verifier instructions")
			}
			r := reading{instructions: n}
			for _, f := range strings.Split(stack[0][1], "+") {
				n, e := strconv.Atoi(f)
				if e != nil {
					t.Fatal(e)
				}
				r.frames = append(r.frames, n)
			}
			out[name] = r
		}
		return out
	}
	beforeEntries, afterEntries := cut54VerifierEntries(t)
	before := read("XDROP_BASE_BPF_ELF", beforeEntries)
	after := read("XDROP_BPF_ELF", afterEntries)
	bg := read("XDROP_BASE_GATE_ELF", []string{"xdp_whitelist_gate"})
	ag := read("XDROP_GATE_ELF", []string{"xdp_whitelist_gate"})
	before["xdp_whitelist_gate"], after["xdp_whitelist_gate"] = bg["xdp_whitelist_gate"], ag["xdp_whitelist_gate"]
	for _, name := range append(append([]string{}, afterEntries...), "xdp_whitelist_gate") {
		b, a := before[name], after[name]
		oldSum, newSum := 0, 0
		for _, n := range b.frames {
			oldSum += n
		}
		for _, n := range a.frames {
			newSum += n
		}
		deltaLimit := 20000
		if name == "xdp_firewall_main" {
			deltaLimit = td035AcceptedMainDelta
		}
		// 基线 003e473 main 保守帧和已为 536 > 512；判据改按增量（所有者 10-04）
		pass := a.instructions <= 500000 && a.instructions-b.instructions <= deltaLimit && newSum-oldSum <= 64
		if name == "xdp_firewall_main" {
			pass = pass && a.frames[0]-b.frames[0] <= 32
		}
		verdict := "PASS"
		if !pass {
			verdict = "FAIL"
		}
		t.Logf("TD035_VERIFIER verdict=%s program=%s before=%d after=%d delta=%d frames_before=%v frames_after=%v sum=%d stack_delta=%d first_delta=%d", verdict, name, b.instructions, a.instructions, a.instructions-b.instructions, b.frames, a.frames, newSum, newSum-oldSum, a.frames[0]-b.frames[0])
		if !pass {
			t.Errorf("TD035 verifier budget exceeded: %s", name)
		}
	}
}
