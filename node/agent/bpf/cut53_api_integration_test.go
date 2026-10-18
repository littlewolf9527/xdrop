//go:build linux && integration

package bpf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"github.com/littlewolf9527/xdrop/node/agent/eval"
)

func cut53APIFixture(t *testing.T) (*api.Handlers, *ebpf.Collection) {
	t.Helper()
	c := b1Load(t, os.Getenv("XDROP_BPF_ELF"))
	m := c.Maps
	spec, err := ebpf.LoadCollectionSpec(os.Getenv("XDROP_BPF_ELF"))
	if err != nil {
		t.Fatal(err)
	}
	wl, err := ebpf.NewMap(spec.Maps["whitelist"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wl.Close() })
	mgr := cidr.NewManager(m["sv4_cidr_trie"], m["dv4_cidr_trie"], m["sv6_cidr_trie"], m["dv6_cidr_trie"], m["sv4_cidr_trie_b"], m["dv4_cidr_trie_b"], m["sv6_cidr_trie_b"], m["dv6_cidr_trie_b"])
	h := api.NewHandlers(m["blacklist"], m["whitelist"], wl, m["stats"], m["config_a"], m["config_b"], m["active_config"], m["cidr_blacklist"], mgr, m["blacklist_b"], m["cidr_blist_b"], nil, m["id_counts"], m["cond_a"], m["cond_b"], m["cidr_cond_a"], m["cidr_cond_b"], m["id_rl_states"], m["cond_row_missing"])
	t.Cleanup(h.Shutdown)
	if err := ClearRetiredTailSlot(c.Maps["prog_tail_map"]); err != nil {
		t.Fatal(err)
	}
	return h, c
}
func cut53APISelectors(t *testing.T, c *ebpf.Collection) (uint64, uint64) {
	t.Helper()
	var slot, rule uint64
	if err := c.Maps["active_config"].Lookup(uint32(0), &slot); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps[[]string{"config_a", "config_b"}[slot]].Lookup(uint32(api.ConfigRuleMapSelector), &rule); err != nil {
		t.Fatal(err)
	}
	return slot, rule
}
func cut53APIInstall(t *testing.T, h *api.Handlers, c *ebpf.Collection, rules []api.Rule, slot, rule uint64) {
	t.Helper()
	_, before := cut53APISelectors(t, c)
	if before != 1-rule {
		if _, err := h.DoAtomicSync(nil); err != nil {
			t.Fatal(err)
		}
	}
	active, _ := cut53APISelectors(t, c)
	if active != 1-slot {
		if err := h.DoWhitelistAtomicSync(nil); err != nil {
			t.Fatal(err)
		}
	}
	result, err := h.DoAtomicSync(rules)
	if err != nil || result.Added != len(rules) || result.Failed != 0 {
		t.Fatalf("direct API failed to install intent: result=%+v error=%v rules=%+v", result, err, rules)
	}
	a, b := cut53APISelectors(t, c)
	if a != slot || b != rule {
		t.Fatalf("assembly got=%d/%d want=%d/%d", a, b, slot, rule)
	}
}
func cut53APIIntent(c b1ParityCase, isCIDR bool) []api.Rule {
	out := append([]api.Rule(nil), c.rules...)
	if isCIDR {
		for i := range out {
			out[i].SrcIP, out[i].DstIP = "", ""
			out[i].SrcCIDR, out[i].DstCIDR = "192.0.2.0/24", "198.51.100.0/24"
			if c.attrs.Src.Is6() {
				out[i].SrcCIDR, out[i].DstCIDR = "2001:db8:1::/64", "2001:db8:2::/64"
			}
		}
	}
	return out
}
func cut53APIJudge(t *testing.T, c *ebpf.Collection, tables eval.Tables, tc b1ParityCase, isCIDR bool) {
	t.Helper()
	rs, _, _ := b1ParityOracle(tc, isCIDR, tables)
	prediction, err := eval.EvaluateB1Cut54(tables, rs, tc.attrs)
	if err != nil {
		t.Fatal(err)
	}
	before := map[uint32]api.LogicalRuleCounters{}
	for _, r := range tc.rules {
		v, e := api.ReadLogicalRuleCounters(c.Maps["id_counts"], r.LogicalID)
		if e != nil {
			t.Fatal(e)
		}
		before[r.LogicalID] = v
	}
	verdict, _, err := c.Programs["xdp_firewall_main"].Test(tc.packet)
	want := uint32(2)
	if prediction.ActionCode == api.ActionDrop {
		want = 1
	}
	if err != nil || verdict != want {
		t.Fatalf("API independent prediction %s got=%d want=%d decision=%+v error=%v", tc.name, verdict, want, prediction, err)
	}
	for _, r := range tc.rules {
		after, e := api.ReadLogicalRuleCounters(c.Maps["id_counts"], r.LogicalID)
		if e != nil {
			t.Fatal(e)
		}
		match, drop := uint64(0), uint64(0)
		if prediction.LogicalID == r.LogicalID {
			match = 1
			if want == 1 {
				drop = 1
			}
		}
		if after.Match-before[r.LogicalID].Match != match || after.Drop-before[r.LogicalID].Drop != drop {
			t.Fatalf("API candidate winner %s logical=%d counters=%+v/%+v prediction=%+v", tc.name, r.LogicalID, before[r.LogicalID], after, prediction)
		}
	}
}
func cut53APITables(t *testing.T) eval.Tables {
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

// Every generated rule enters through DoAtomicSync. The existing independent
// evaluator consumes only logical intent and packet attributes, never wire rows.
func TestCut53APIAttributeSweeps(t *testing.T) {
	tables := cut53APITables(t)
	writer := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(writer)
	packets := 0
	for _, isCIDR := range []bool{false, true} {
		for slot := uint64(0); slot < 2; slot++ {
			for rule := uint64(0); rule < 2; rule++ {
				t.Run(fmt.Sprintf("cidr=%v/config=%d/rule=%d", isCIDR, slot, rule), func(t *testing.T) {
					h, c := cut53APIFixture(t)
					for _, v6 := range []bool{false, true} {
						for _, axis := range []string{"ttl", "dscp", "tcp_flags", "icmp_type", "icmp_code"} {
							proto := byte(6)
							if strings.HasPrefix(axis, "icmp") {
								proto = 1
								if v6 {
									proto = 58
								}
							}
							base := b1ParityBase(axis, v6, proto)
							expr := "3,17,64,129"
							switch axis {
							case "ttl":
								base.rules[0].TTL = &expr
							case "dscp":
								expr = "3,17,32,63"
								base.rules[0].DSCP = &expr
							case "tcp_flags":
								base.rules[0].TcpFlags = "SYN,!ACK"
							case "icmp_type":
								base.rules[0].ICMPType = &expr
							case "icmp_code":
								base.rules[0].ICMPCode = &expr
							}
							cut53APIInstall(t, h, c, cut53APIIntent(base, isCIDR), slot, rule)
							for n := 0; n < 256; n++ {
								tc := base
								tc.name = fmt.Sprintf("%s/%d/v6=%v", axis, n, v6)
								tc.packet = append([]byte(nil), base.packet...)
								l4 := 34
								if v6 {
									l4 = 54
								}
								switch axis {
								case "ttl":
									at := 22
									if v6 {
										at = 21
									}
									tc.packet[at] = byte(n)
									tc.attrs.TTL = byte(n)
								case "dscp":
									tc.attrs.DSCP = byte(n >> 2)
									if v6 {
										tc.packet[14] = 0x60 | byte(n>>4)
										tc.packet[15] = byte(n << 4)
									} else {
										tc.packet[15] = byte(n)
									}
								case "tcp_flags":
									tc.packet[l4+13] = byte(n)
									tc.attrs.Flags = byte(n)
								case "icmp_type":
									tc.packet[l4] = byte(n)
									tc.attrs.ICMPType = byte(n)
								case "icmp_code":
									tc.packet[l4+1] = byte(n)
									tc.attrs.ICMPCode = byte(n)
								}
								cut53APIJudge(t, c, tables, tc, isCIDR)
								packets++
							}
						}
					}
				})
			}
		}
	}
	if packets != 20480 {
		t.Fatalf("attribute packet cells=%d want=20480", packets)
	}
	t.Logf("CUT53_API_SWEEP assemblies=4 kinds=2 families=2 axes=5 wire_domain=256 packets=%d evaluator_mismatches=0", packets)
}

func TestCut53APIParityGrid(t *testing.T) {
	tables := cut53APITables(t)
	writer := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(writer)
	packets, rejections, synthetic := 0, 0, 0
	for _, isCIDR := range []bool{false, true} {
		for slot := uint64(0); slot < 2; slot++ {
			for rule := uint64(0); rule < 2; rule++ {
				t.Run(fmt.Sprintf("cidr=%v/config=%d/rule=%d", isCIDR, slot, rule), func(t *testing.T) {
					h, c := cut53APIFixture(t)
					for _, tc := range b1ParityGrid() {
						if tc.probeOnly {
							synthetic++
							continue
						} // Existing extraction/lookup suite owns unreachable synthetic values.
						intent := cut53APIIntent(tc, isCIDR)
						// The node rejects portful non-first-only predicates before encoding.
						if tc.d2Reject {
							beforeSlot, beforeRule := cut53APISelectors(t, c)
							_, rejectErr := h.DoAtomicSync(intent)
							details, marshalErr := json.Marshal(rejectErr)
							if rejectErr == nil || marshalErr != nil || !bytes.Contains(details, []byte("D2:")) {
								t.Fatalf("D2 direct API rejection %s: %v details=%s marshal=%v", tc.name, rejectErr, details, marshalErr)
							}
							a, b := cut53APISelectors(t, c)
							if a != beforeSlot || b != beforeRule {
								t.Fatal("D2 API rejection flipped")
							}
							rejections++
							continue
						}
						cut53APIInstall(t, h, c, intent, slot, rule)
						cut53APIJudge(t, c, tables, tc, isCIDR)
						packets++
						var count uint64
						if err := c.Maps[[]string{"config_a", "config_b"}[slot]].Lookup(uint32(api.ConfigAnomalyRuleCount), &count); err != nil || count != 0 {
							t.Fatalf("K16 serialized anomaly count=%d err=%v", count, err)
						}
						// Every installed conditional row has zero legacy predicates.
						for _, name := range []string{[]string{"blacklist", "blacklist_b"}[rule], []string{"cidr_blacklist", "cidr_blist_b"}[rule]} {
							m := c.Maps[name]
							it := m.Iterate()
							key := make([]byte, m.KeySize())
							v := make([]byte, 32)
							for it.Next(&key, &v) {
								if v[28] == 1 && (v[1] != 0 || v[2] != 0 || v[3] != 0 || !bytes.Equal(v[24:28], make([]byte, 4))) {
									t.Fatalf("W11 API row=%x", v)
								}
							}
							if err := it.Err(); err != nil {
								t.Fatal(err)
							}
						}
					}
				})
			}
		}
	}
	t.Logf("CUT53_API_PARITY assemblies=4 kinds=2 packet_cells=%d D2_rejections=%d synthetic_owned_by_existing_probe=%d", packets, rejections, synthetic)
}

// Adjacent endpoints and each gap are separately exercised through the API.
func TestCut53APILengthIntervals(t *testing.T) {
	tables := cut53APITables(t)
	packets := 0
	for _, isCIDR := range []bool{false, true} {
		for _, v6 := range []bool{false, true} {
			h, c := cut53APIFixture(t)
			base := b1ParityBase("length", v6, 6)
			base.rules[0].PktLen = b1ParityText("80-90,110-120,200-210")
			cut53APIInstall(t, h, c, cut53APIIntent(base, isCIDR), 0, 0)
			for _, n := range []int{0, 39, 40, 79, 80, 85, 90, 91, 100, 109, 110, 115, 120, 121, 199, 200, 205, 210, 211, 65535} {
				tc := base
				tc.name = fmt.Sprint("length/", n)
				tc.packet = append([]byte(nil), base.packet...)
				tc.attrs.Length = uint16(n)
				tc.attrs.Anomaly = 4
				if v6 {
					payload := uint16(n - 40)
					binary.BigEndian.PutUint16(tc.packet[18:], payload)
					tc.attrs.IPv6PayloadLength = &payload
					if n < 40 {
						tc.attrs.Length = uint16(n)
					}
				} else {
					binary.BigEndian.PutUint16(tc.packet[16:], uint16(n))
					if n < 40 {
						tc.attrs.Anomaly = 2
					}
				}
				if n == int(len(tc.packet)-14) {
					tc.attrs.Anomaly = 0
				}
				cut53APIJudge(t, c, tables, tc, isCIDR)
				packets++
			}
		}
	}
	t.Logf("CUT53_API_LENGTH packets=%d endpoints_and_gaps=20 kinds=2 families=2", packets)
}
