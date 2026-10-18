//go:build linux && integration

package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func cut53Packet(src [4]byte, ttl byte) []byte {
	p := b7Packet()
	copy(p[26:30], src[:])
	p[22] = ttl
	p[46] = 0x50
	return p
}
func cut53Verdict(t *testing.T, program *ebpf.Program, packet []byte, want uint32) {
	t.Helper()
	got, _, err := program.Test(packet)
	if err != nil || got != want {
		t.Fatalf("CUT53 packet verdict=%d want=%d err=%v packet=%x", got, want, err, packet)
	}
}
func cut53KernelMapBytes(t *testing.T, m *ebpf.Map) map[string]string {
	t.Helper()
	out := map[string]string{}
	var cursor any
	for {
		key := make([]byte, m.KeySize())
		err := m.NextKey(cursor, &key)
		if isMapEntryMissing(err) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		value, err := m.LookupBytes(key)
		if err != nil || value == nil {
			t.Fatalf("map byte read key=%x err=%v", key, err)
		}
		out[string(key)] = string(value)
		cursor = key
	}
}
func cut53AllMapBytes(t *testing.T, coll *ebpf.Collection) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	for _, name := range []string{"blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b", "cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b", "config_a", "config_b", "active_config", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "sv4_cidr_trie_b", "dv4_cidr_trie_b", "sv6_cidr_trie_b", "dv6_cidr_trie_b", "id_counts", "id_rl_states"} {
		out[name] = cut53KernelMapBytes(t, coll.Maps[name])
	}
	return out
}
func TestCut53FullGroupsReadback(t *testing.T) {
	cells := 0
	for _, ruleSlot := range []int{0, 1} {
		for _, configSlot := range []int{0, 1} {
			t.Run(fmt.Sprintf("rule=%d/config=%d", ruleSlot, configSlot), func(t *testing.T) {
				h, router, program, _ := b7ELFCollection(t)
				h.activeRuleSlot.Store(int32(ruleSlot))
				h.activeSlot = configSlot
				for _, m := range []*ebpf.Map{h.configA, h.configB} {
					if err := m.Put(uint32(ConfigRuleMapSelector), uint64(ruleSlot)); err != nil {
						t.Fatal(err)
					}
				}
				if err := h.activeConfig.Put(uint32(0), uint64(configSlot)); err != nil {
					t.Fatal(err)
				}
				var rules []Rule
				for _, cidrKey := range []bool{false, true} {
					for i, ttl := range []string{" 128 ", " 32 ", " 64 "} {
						r := cut53Pure(cidrKey, fmt.Sprintf("cidr=%v/%d", cidrKey, i), uint32(30-i*10))
						r.TTL = cut4BString(ttl)
						r.TcpFlags = "!ACK"
						r.PktLenMin = 20
						r.PktLenMax = 80
						if cidrKey {
							r.SrcCIDR = "198.51.100.0/24"
							r.LogicalID += 100
						}
						rules = append(rules, r)
					}
				}
				var stages []string
				atomicStageTestHook = func(stage string, got *Handlers) {
					if got != h || !strings.HasPrefix(stage, "2-") {
						return
					}
					stages = append(stages, stage)
					cond, rule := h.shadowCond(), h.shadowBlacklist()
					if strings.Contains(stage, "cidr") {
						cond, rule = h.shadowCidrCond(), h.shadowCidrBlacklist()
					}
					condRows, ruleRows := b7Snapshot(t, cond), b7Snapshot(t, rule)
					if len(condRows) != 1 {
						t.Fatalf("K13 condition row absent at %s", stage)
					}
					want := 0
					if strings.HasSuffix(stage, "-rule") {
						want = 1
					}
					if len(ruleRows) != want {
						t.Fatalf("K13 condition-before-rule violated at %s: rule rows=%d want=%d", stage, len(ruleRows), want)
					}
				}
				defer func() { atomicStageTestHook = nil }()
				w := yiAtomicCall(t, router, rules)
				var response struct{ Added, Rules, CIDRRules int }
				var body map[string]json.RawMessage
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				for key, dst := range map[string]*int{"added": &response.Added, "rules": &response.Rules, "cidr_rules": &response.CIDRRules} {
					if err := json.Unmarshal(body[key], dst); err != nil {
						t.Fatal(err)
					}
				}
				if w.Code != 200 || response.Added != 6 || response.Rules != 3 || response.CIDRRules != 3 {
					t.Fatalf("D12 rules are member counts: %d %s", w.Code, w.Body.String())
				}
				if !reflect.DeepEqual(stages, []string{"2-exact-condition", "2-exact-rule", "2-cidr-condition", "2-cidr-rule"}) {
					t.Fatalf("K13 write trace=%v", stages)
				}
				atomicStageTestHook = nil
				if readCfg(t, h.activeMap(), ConfigBlacklistCount) != 1 || readCfg(t, h.activeMap(), ConfigCIDRRuleCount) != 1 || readCfg(t, h.activeMap(), ConfigAnomalyRuleCount) != 0 {
					t.Fatal("D12/K16 config must count rows, anomaly zero")
				}
				if len(h.rules) != 3 || len(h.cidrRules) != 3 || len(h.ruleKeyIndex) != 1 || len(h.cidrRuleKeyIndex) != 1 {
					t.Fatal("K15 lost same-key members")
				}
				for key, ids := range h.ruleKeyIndex {
					if len(ids) != 3 || h.comboRefCount[getComboType(key)] != 1 {
						t.Fatal("K15 exact reverse index/refcount not a row")
					}
				}
				for key, ids := range h.cidrRuleKeyIndex {
					if len(ids) != 3 || h.cidrComboRefCount[getCIDRComboType(key)] != 1 {
						t.Fatal("K15 CIDR reverse index/refcount not a row")
					}
				}
				for _, m := range []*ebpf.Map{p7ActiveBlacklist(h), p7ActiveCIDR(h)} {
					values := b7Snapshot(t, m)
					if len(values) != 1 {
						t.Fatal("same-key rules wrote multiple rows")
					}
					for _, raw := range values {
						v := []byte(raw)
						if v[28] != 1 || v[1] != 0 || v[2] != 0 || v[3] != 0 || !bytes.Equal(v[24:28], make([]byte, 4)) {
							t.Fatalf("W11 map row=%x", v)
						}
					}
				}
				for group, m := range []*ebpf.Map{h.activeCond(), h.activeCidrCond()} {
					for _, raw := range b7Snapshot(t, m) {
						v := []byte(raw)
						if len(v) != 844 || v[840] != 7 || v[842] != 7 {
							t.Fatalf("condition header=%x", v)
						}
						for k := 0; k < 3; k++ {
							want := uint32((k+1)*10 + group*100)
							if binary.LittleEndian.Uint32(v[824+k*4:]) != want {
								t.Fatalf("K15 logical order candidate=%d wire=%x", k, v[824:840])
							}
						}
					}
				}
				listed := cut53Request(t, cut53MemoryRouter(h), "POST", "/atomic", map[string]any{"rules": rules})
				if listed.Code != 200 {
					t.Fatal(listed.Body.String())
				}
				// Every stored member and its canonical condition survives full replay.
				for _, r := range rules {
					stored, ok := h.storedGroupRule(r.ID)
					if !ok || stored.LogicalID != r.LogicalID || stored.TTL == nil || *stored.TTL != strings.TrimSpace(*r.TTL) {
						t.Fatalf("member readback %s=%+v", r.ID, stored)
					}
				}
				for group, src := range [][4]byte{{192, 0, 2, 1}, {198, 51, 100, 1}} {
					for i, ttl := range []byte{128, 32, 64} {
						id := uint32(30 - i*10 + group*100)
						before, err := ReadLogicalRuleCounters(h.idCounts, id)
						if err != nil {
							t.Fatal(err)
						}
						cut53Verdict(t, program, cut53Packet(src, ttl), 1)
						after, err := ReadLogicalRuleCounters(h.idCounts, id)
						if err != nil || after.Match-before.Match != 1 || after.Drop-before.Drop != 1 {
							t.Fatalf("member logical counter id=%d before=%+v after=%+v err=%v", id, before, after, err)
						}
					}
					cut53Verdict(t, program, cut53Packet(src, 255), 2)
					fragment := cut53Packet(src, 64)
					binary.BigEndian.PutUint16(fragment[20:22], 2)
					cut53Verdict(t, program, fragment, 2) // W12 !ACK still requires a TCP header.
				}
				cells++
			})
		}
	}
	if cells != 4 {
		t.Fatalf("assembly cells=%d want=4", cells)
	}
	t.Log("CUT53_FULL_GROUPS assemblies=4 groups=8 members=24 candidate_hits=24 condition_miss=8 nonfirst=8")
}
