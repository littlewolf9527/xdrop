//go:build linux && integration

package bpf

import (
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
)

// All frames remain in process memory and enter only BPF_PROG_TEST_RUN.
var td149Behavior = []string{
	"B7-H0/S0/W0/R0", "B7-H0/S0/W0/R1",
	"B7-H43/S0/W0/R0", "B7-H43/S0/W0/R1",
	"B7-H60/S0/W0/R0", "B7-H60/S0/W0/R1",
	"B7-H44/S0/W0/R0", "B7-H44/S0/W0/R1",
	"B7-H51/S0/W0/R0", "B7-H51/S0/W0/R1",
}

type td149Cell struct {
	name, shape string
	packet      []byte
	slot        uint64
	white, rule bool
	deep        bool
}

func td149Cells() []td149Cell {
	shapes := []td149Cell{
		{shape: "B6u", packet: td122Packet("B6u", 0)},
		{shape: "B6t", packet: td122Packet("B6t", 0)},
		{shape: "B7u", packet: td122Packet("B7", 253)},
		{shape: "short", packet: td114Packet(td114Shape{head: 60, form: "S1", position: 1})},
		{shape: "nonfirst", packet: td122Packet("A4", 0)},
	}
	for _, head := range []byte{0, 43, 60, 44, 51} {
		shapes = append(shapes, td149Cell{shape: fmt.Sprintf("B7-H%d", head), packet: td122Packet("B7", head), deep: true})
	}
	var cells []td149Cell
	for _, c := range shapes {
		for _, slot := range []uint64{0, 1} {
			for _, white := range []bool{false, true} {
				for _, rule := range []bool{false, true} {
					c.slot, c.white, c.rule = slot, white, rule
					c.name = fmt.Sprintf("%s/S%d/W%d/R%d", c.shape, slot, td149Bit(white), td149Bit(rule))
					cells = append(cells, c)
				}
			}
		}
	}
	return cells
}

func td149Bit(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func td149Schema(t *testing.T) bool {
	t.Helper()
	base := os.Getenv("TD149_BASELINE_CONTROL") == "1"
	cfg, stats := uint32(13), uint32(10)
	if base {
		cfg, stats = 12, 9
	}
	for _, env := range []string{"XDROP_BPF_ELF", "XDROP_GATE_ELF"} {
		spec, err := ebpf.LoadCollectionSpec(os.Getenv(env))
		if err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]uint32{"config_a": cfg, "config_b": cfg, "stats": stats} {
			m := spec.Maps[name]
			if m == nil || m.MaxEntries != want {
				t.Fatalf("TD149 schema env=%s map=%s got=%v want=%d", env, name, m, want)
			}
			t.Logf("TD149_SCHEMA env=%s map=%s entries=%d", env, name, m.MaxEntries)
		}
	}
	return base
}

func td149Load(t *testing.T) (*ebpf.Collection, *ebpf.Collection, bool) {
	t.Helper()
	base := td149Schema(t)
	main := td035Load(t, "XDROP_BPF_ELF", nil)
	replacements := map[string]*ebpf.Map{}
	for _, name := range []string{"whitelist", "stats", "config_a", "config_b", "active_config", "prog_tail_map", "devmap"} {
		replacements[name] = main.Maps[name]
	}
	gate := td035Load(t, "XDROP_GATE_ELF", replacements)
	if err := ClearRetiredTailSlot(main.Maps["prog_tail_map"]); err != nil {
		t.Fatal(err)
	}
	td035Put(t, main.Maps["prog_tail_map"], uint32(1), main.Programs["xdp_firewall_main"])
	td035Put(t, main.Maps["active_config"], uint32(0), uint64(0))
	return main, gate, base
}

func TestTD149Schema(t *testing.T) {
	td149Load(t)
}

func td149Stats(t *testing.T, main *ebpf.Collection, base bool) (s [10]uint64) {
	t.Helper()
	n := 10
	if base {
		n = 9 // Strict 12/9 schema was checked; absent key 9 is defined as zero.
	}
	for i := 0; i < n; i++ {
		s[i] = td035Sum(t, main.Maps["stats"], uint32(i))
	}
	return
}

func td149Run(t *testing.T, main, gate *ebpf.Collection, base bool, c td149Cell, ff bool) {
	t.Helper()
	cfg := make([]uint64, main.Maps["config_a"].MaxEntries())
	cfg[api.ConfigRLCPUDivisor] = 1
	cfg[api.ConfigFastForwardEnabled] = td149Bit(ff)
	if !base {
		cfg[api.ConfigIPv6DeepChainPass] = c.slot
	}
	key := td114Exact(td114Src, netip.Addr{}, 0, 0)
	value := api.RuleValue{LogicalID: 149001, Action: api.ActionDrop}
	if c.rule {
		cfg[api.ConfigBlacklistCount], cfg[api.ConfigRuleBitmap] = 1, 1<<8
		td035Put(t, main.Maps["blacklist"], key, value)
		t.Cleanup(func() {
			td035Delete(t, main.Maps["blacklist"], key)
			td035Delete(t, main.Maps["id_counts"], value.LogicalID)
		})
	}
	if c.white {
		// COMBO_SRC_IP_ONLY (8), WL bitmap and tail slot 1 witness the real gate.
		cfg[api.ConfigWhitelistCount], cfg[api.ConfigWLBitmap] = 1, 1<<8
		td035Put(t, main.Maps["whitelist"], key, uint8(1))
		t.Cleanup(func() { td035Delete(t, main.Maps["whitelist"], key) })
	}
	for i, v := range cfg {
		td035Put(t, main.Maps["config_a"], uint32(i), v)
		var read uint64
		if err := main.Maps["config_a"].Lookup(uint32(i), &read); err != nil || read != v {
			t.Fatalf("slot %d read=%d want=%d error=%v", i, read, v, err)
		}
	}
	before := td149Stats(t, main, base)
	tail := td035Sum(t, gate.Maps["tailcall_fail_stats"], 0)
	ret, _, err := gate.Programs["xdp_whitelist_gate"].Test(c.packet)
	if err != nil {
		t.Fatal(err)
	}
	got := td149Stats(t, main, base)
	for i := range got {
		got[i] -= before[i]
	}
	deepDrop := c.deep && c.slot != 1 && !c.white
	drop := !c.white && (c.rule || deepDrop)
	wantRet := uint32(srcXDPPass)
	if ff {
		wantRet = 0 // Missing devmap entry: flags=0 is XDP_ABORTED, no transmission.
	}
	if drop {
		wantRet = srcXDPDrop
	}
	length := uint64(len(c.packet))
	want := [10]uint64{1, td149Bit(drop), td149Bit(!drop), td149Bit(c.white), 0, 0,
		length, length * td149Bit(drop), length * td149Bit(!drop), td149Bit(deepDrop)}
	if ret != wantRet || got != want || td035Sum(t, gate.Maps["tailcall_fail_stats"], 0) != tail {
		t.Errorf("TD149 ff=%t ret=%d want=%d stats=%v want=%v", ff, ret, wantRet, got, want)
	}
	if c.rule {
		counts := td035Counts(t, main, td035Rule{name: "R1", value: value}, key)
		wantRule := td149Bit(drop && !deepDrop)
		if counts.Match != wantRule || counts.Drop != wantRule {
			t.Errorf("rule counts=%+v want=%d", counts, wantRule)
		}
	}
}

func TestTD149Matrix(t *testing.T) {
	cells := td149Cells()
	if len(cells) != 80 { // (2+5+1+1+1) shapes * 2 slots * 2 whitelist * 2 rules.
		t.Fatalf("TD149 cells=%d want=80", len(cells))
	}
	seen, behavior := map[string]bool{}, []string{}
	for _, c := range cells {
		if seen[c.name] {
			t.Fatal("duplicate TD149 cell " + c.name)
		}
		seen[c.name] = true
		if c.deep && c.slot == 0 && !c.white {
			behavior = append(behavior, c.name)
		}
	}
	sort.Strings(behavior)
	wantBehavior := append([]string(nil), td149Behavior...)
	sort.Strings(wantBehavior)
	if len(behavior) != 10 || !reflect.DeepEqual(behavior, wantBehavior) {
		t.Fatalf("behavior names=%v want=%v", behavior, wantBehavior)
	}
	main, gate, base := td149Load(t)
	for _, c := range cells {
		if base && c.slot != 0 {
			continue // Baseline has no switch; run only its 40 slot-zero equivalents.
		}
		t.Run(c.name, func(t *testing.T) {
			td149Run(t, main, gate, base, c, false)
			if c.shape == "B7-H51" && !c.white && !c.rule {
				td149Run(t, main, gate, base, c, true)
			}
		})
	}
}
