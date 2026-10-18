//go:build linux && integration

package bpf

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
)

func TestAFDataPlane(t *testing.T) {
	main := td035Load(t, "XDROP_BPF_ELF", nil)
	replacements := map[string]*ebpf.Map{}
	for _, name := range []string{"whitelist", "stats", "config_a", "config_b", "active_config", "prog_tail_map", "devmap"} {
		replacements[name] = main.Maps[name]
	}
	gate := td035Load(t, "XDROP_GATE_ELF", replacements)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	const mapped = "::ffff:10.1.2.3"
	type cell struct {
		name, src, dst               string
		white, v4, short, noTail, ff bool
		want                         uint32
		stats                        [6]uint64
		main, tail                   uint64
	}
	cells := []cell{
		{name: "D1", src: mapped, dst: "2001:db8::2", want: 1, stats: [6]uint64{1, 1, 0, 0, 0, 1}},
		{name: "D2", src: mapped, dst: "2001:db8::2", white: true, want: 1, stats: [6]uint64{1, 1, 0, 0, 0, 1}},
		{name: "D3", src: "2001:db8::1", dst: mapped, white: true, want: 1, stats: [6]uint64{1, 1, 0, 0, 0, 1}},
		{name: "D4", src: "10.1.2.3", dst: "192.0.2.2", white: true, v4: true, want: 2, stats: [6]uint64{1, 0, 1, 1, 0, 0}},
		{name: "D7", src: mapped, dst: "2001:db8::2", ff: true, want: 4, stats: [6]uint64{1, 0, 1, 0, 0, 0}},
	}
	for i, src := range []string{"2001:db8::1", "2001:db8::ffff:a01:203", "::a01:203", "64:ff9b::a01:203", "::ffff:0:a01:203"} {
		cells = append(cells, cell{name: fmt.Sprintf("D5/%d", i), src: src, dst: "2001:db8::2", want: 1, stats: [6]uint64{1, 1, 0, 0, 0, 0}, main: 1})
	}
	for _, white := range []bool{false, true} {
		for _, noTail := range []bool{false, true} {
			c := cell{name: fmt.Sprintf("D6/white=%t/tail=%t", white, !noTail), src: mapped, dst: "2001:db8::2", white: white, short: true, noTail: noTail, stats: [6]uint64{1, 0, 0, 0, 0, 0}}
			if !white && noTail {
				c.want, c.stats[2], c.tail = 2, 1, 1
			}
			cells = append(cells, c)
		}
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			stats := main.Maps["stats"]
			if stats.MaxEntries() != 9 && !(os.Getenv("AF_BASELINE_CONTROL") == "1" && stats.MaxEntries() == 5 && strings.HasPrefix(c.name, "D6/")) {
				t.Fatalf("AF stats schema=%d", stats.MaxEntries())
			}
			read := func() (out [6]uint64) {
				for i := uint32(0); i < min(stats.MaxEntries(), uint32(len(out))); i++ {
					out[i] = td035Sum(t, stats, i)
				}
				return
			}
			key := make([]byte, 40)
			src, dst := netip.MustParseAddr(c.src).As16(), netip.MustParseAddr(c.dst).As16()
			copy(key, src[:])
			td035Put(t, main.Maps["blacklist"], key, api.RuleValue{LogicalID: 9901, Action: api.ActionDrop})
			t.Cleanup(func() {
				td035Delete(t, main.Maps["blacklist"], key)
				td035Delete(t, main.Maps["id_counts"], uint32(9901))
			})
			cfg := [12]uint64{0: 1, 2: 1 << 8, 11: 1}
			if c.white {
				white := make([]byte, 40)
				v4 := netip.MustParseAddr("10.1.2.3").As16()
				copy(white, v4[:])
				cfg[3] = 1 << 8
				if c.name == "D3" {
					clear(white)
					copy(white[16:], v4[:])
					cfg[3] = 1 << 4
				}
				td035Put(t, main.Maps["whitelist"], white, uint8(1))
				cfg[1] = 1
				var value uint8
				if err := main.Maps["whitelist"].Lookup(white, &value); err != nil || value != 1 {
					t.Fatalf("AF whitelist witness: %v", err)
				}
				t.Cleanup(func() { td035Delete(t, main.Maps["whitelist"], white) })
			}
			if c.ff {
				cfg[4], cfg[5] = 1, uint64(lo.Index+1)
				td035Put(t, main.Maps["devmap"], uint32(lo.Index), uint32(lo.Index))
			}
			for i, v := range cfg {
				td035Put(t, main.Maps["config_a"], uint32(i), v)
			}
			if c.noTail {
				td035Delete(t, main.Maps["prog_tail_map"], uint32(1))
			} else {
				td035Put(t, main.Maps["prog_tail_map"], uint32(1), main.Programs["xdp_firewall_main"])
			}
			packet := td035Packet(6, "complete", 6, 80, 2)
			copy(packet[22:38], src[:])
			copy(packet[38:54], dst[:])
			if c.v4 {
				packet = td035Packet(4, "complete", 6, 80, 2)
				copy(packet[26:30], src[12:])
				copy(packet[30:34], dst[12:])
			}
			if c.short {
				packet = packet[:53]
			}
			before, tail := read(), td035Sum(t, gate.Maps["tailcall_fail_stats"], 0)
			ctx := [6]uint32{0, uint32(len(packet)), 0, uint32(lo.Index), 0, 0}
			got, err := gate.Programs["xdp_whitelist_gate"].Run(&ebpf.RunOptions{Data: packet, Context: ctx, Repeat: 1})
			if err != nil {
				t.Fatalf("AF_TEST_RUN: %v", err)
			}
			delta := read()
			for i := range delta {
				delta[i] -= before[i]
			}
			counts := matrixCounter(t, main, 9901)
			if got != c.want || delta != c.stats || counts.Match != c.main || counts.Drop != c.main || td035Sum(t, gate.Maps["tailcall_fail_stats"], 0)-tail != c.tail {
				t.Fatalf("AF verdict=%d want=%d stats=%v want=%v main=%+v want=%d tail=%d", got, c.want, delta, c.stats, counts, c.main, td035Sum(t, gate.Maps["tailcall_fail_stats"], 0)-tail)
			}
			t.Logf("AF_DATAPLANE cell=%s verdict=%d stats=%v main_match=%d tail=%d", c.name, got, delta, counts.Match, c.tail)
		})
	}
}

func afGate7Load(t *testing.T, env string) *ebpf.Collection {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(os.Getenv(env))
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinNone {
			t.Fatalf("AF gate7 pinning forbidden: %s", name)
		}
	}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("AF_VERIFIER_ERROR env=%s\n%+v", env, verifier)
		}
		t.Fatalf("AF gate7 load %s: %v", env, err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestAFGate7(t *testing.T) {
	td074Environment(t)
	for _, entry := range []struct{ name, before, after string }{{"gate", "AF_BEFORE_GATE_ELF", "XDROP_GATE_ELF"}, {"main", "AF_BEFORE_MAIN_ELF", "XDROP_BPF_ELF"}} {
		t.Run(entry.name, func(t *testing.T) {
			var insns, stacks [2]int
			var hashes [2]string
			for i, env := range []string{entry.before, entry.after} {
				c := afGate7Load(t, env)
				if len(c.Programs) != 1 {
					t.Fatal("AF gate7 entry roster")
				}
				name := "xdp_firewall_main"
				if entry.name == "gate" {
					name = "xdp_whitelist_gate"
				}
				p := c.Programs[name]
				if p == nil {
					t.Fatal("AF gate7 wrong program")
				}
				t.Logf("AF_VERIFIER_RAW env=%s\n%s", env, p.VerifierLog)
				ins := regexp.MustCompile(`processed ([0-9]+) insns`).FindAllStringSubmatch(p.VerifierLog, -1)
				stack := regexp.MustCompile(`(?m)^stack depth ([0-9]+(?:\+[0-9]+)*)\s*$`).FindAllStringSubmatch(p.VerifierLog, -1)
				if len(ins) != 1 || len(stack) != 1 {
					t.Fatal("AF gate7 absent/duplicate verifier summaries")
				}
				insns[i], _ = strconv.Atoi(ins[0][1])
				for _, f := range strings.Split(stack[0][1], "+") {
					v, _ := strconv.Atoi(f)
					stacks[i] += v
				}
				raw, err := os.ReadFile(os.Getenv(env))
				if err != nil {
					t.Fatal(err)
				}
				hashes[i] = fmt.Sprintf("%x", sha256.Sum256(raw))
				c.Close()
			}
			t.Logf("AF_GATE7 program=%s source_before=5d1b1648744a55fc0ab0e19447b16179ae27dd7c source_after=5d1b164+af-2 before_sha=%s after_sha=%s before=%d after=%d delta=%d stack_before=%d stack_after=%d stack_delta=%d", entry.name, hashes[0], hashes[1], insns[0], insns[1], insns[1]-insns[0], stacks[0], stacks[1], stacks[1]-stacks[0])
			growth := insns[1] - insns[0]
			if entry.name == "main" {
				growth = insns[1] - td119MainBaseline // TD-119: main's limit restarts after TD-114
			}
			if insns[0] <= 0 || insns[1] <= 0 || insns[1] > 500000 || growth > 20000 || stacks[1]-stacks[0] > 64 {
				t.Fatalf("AF gate7 budget exceeded growth=%d", growth)
			}
		})
	}
}
