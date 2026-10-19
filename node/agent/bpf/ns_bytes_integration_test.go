//go:build linux && integration

package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"golang.org/x/sys/unix"
)

func nsPrerequisite(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Logf("NS_CELL class=apparatus pass=false error=%q", err)
		t.Fatal(err)
	}
}

func nsSetup(t *testing.T) func() {
	ready := false
	t.Cleanup(func() {
		if !ready && t.Failed() {
			t.Log("NS_CELL class=apparatus pass=false reason=setup_incomplete")
		}
	})
	return func() { ready = true }
}

func TestNSBytes(t *testing.T) {
	host := os.Getenv("NS_HOST_NETNS")
	own, err := os.Readlink("/proc/self/ns/net")
	nsPrerequisite(t, err)
	if host == "" || host == own {
		t.Fatal("NS_CELL class=apparatus pass=false reason=private_netns_required")
	}
	command := func(args ...string) {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			nsPrerequisite(t, fmt.Errorf("%v: %s: %w", args, out, err))
		}
	}
	command("ip", "link", "add", "ns0", "type", "veth", "peer", "name", "ns1")
	t.Cleanup(func() { command("ip", "link", "del", "ns0") })
	for _, name := range []string{"ns0", "ns1"} {
		command("sysctl", "-qw", "net.ipv6.conf."+name+".disable_ipv6=1")
		command("ip", "link", "set", name, "up")
	}
	rx, err := net.InterfaceByName("ns0")
	nsPrerequisite(t, err)
	tx, err := net.InterfaceByName("ns1")
	nsPrerequisite(t, err)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(binary.BigEndian.Uint16([]byte{3, 0})))
	nsPrerequisite(t, err)
	defer unix.Close(fd)
	for _, cidr := range []bool{false, true} {
		for _, conditional := range []bool{false, true} {
			for _, mode := range []string{"drop", "rate-new", "rate-zero", "rate-pass", "rate-drop", "rate-full", "ff-filter", "pass"} {
				t.Run(fmt.Sprintf("cidr=%t/condition=%t/%s", cidr, conditional, mode), func(t *testing.T) {
					ready := nsSetup(t)
					small := ""
					if mode == "rate-full" {
						small = "id_rl_states"
					}
					main := b1LogicalLoad(t, small)
					b1LogicalReset(t, main, cidr, 0, 0)
					repl := map[string]*ebpf.Map{}
					for _, name := range []string{"whitelist", "stats", "config_a", "config_b", "active_config", "prog_tail_map", "devmap"} {
						repl[name] = main.Maps[name]
					}
					gate := td035Load(t, "XDROP_GATE_ELF", repl)
					td035Put(t, main.Maps["prog_tail_map"], uint32(1), main.Programs["xdp_firewall_main"])
					attachment, err := link.AttachXDP(link.XDPOptions{Program: gate.Programs["xdp_whitelist_gate"], Interface: rx.Index, Flags: link.XDPGenericMode})
					nsPrerequisite(t, err)
					defer attachment.Close()
					action, rate, wantDrop := uint8(api.ActionRateLimit), uint32(100000), uint64(0)
					switch mode {
					case "drop", "ff-filter":
						action = api.ActionDrop
						wantDrop = 3
					case "pass":
						action = api.ActionPass
					case "rate-drop", "rate-full":
						rate = 1
						wantDrop = 3
					}
					row := b1OpenRow(1)
					row.RuleID[0], row.Action[0], row.Rate[0] = 701, action, rate
					if conditional {
						b1SetRow(t, main, cidr, 0, 6, row)
					} else {
						name, _, _, _ := b1Maps(cidr, 0)
						td035Put(t, main.Maps[name], b1Key(cidr, 6, true), api.RuleValue{LogicalID: 701, Action: action, RateLimit: rate})
					}
					cpus, err := ebpf.PossibleCPU()
					nsPrerequisite(t, err)
					if mode == "rate-zero" || mode == "rate-pass" || mode == "rate-drop" || mode == "rate-full" {
						var ts unix.Timespec
						nsPrerequisite(t, unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts))
						states := make([]b1Bucket, cpus)
						for i := range states {
							if mode != "rate-zero" {
								states[i].Last = uint64(ts.Nano())
							}
							if mode == "rate-pass" {
								states[i].Tokens = 200000
							}
						}
						id := uint32(701)
						if mode == "rate-full" {
							id = 999
						}
						td035Put(t, main.Maps["id_rl_states"], id, states)
					}
					if mode == "ff-filter" {
						td035Put(t, main.Maps["config_a"], uint32(4), uint64(1))
						td035Put(t, main.Maps["config_a"], uint32(5), uint64(rx.Index))
					}
					packet := append(b1LogicalPacket(64), make([]byte, 40)...)
					binary.BigEndian.PutUint16(packet[16:], uint16(len(packet)-14))
					copy(packet[:6], rx.HardwareAddr)
					copy(packet[6:12], tx.HardwareAddr)
					before := nsCoarse(t)
					ready()
					for i := 0; i < 3; i++ {
						nsPrerequisite(t, unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: tx.Index}))
					}
					deadline := time.Now().Add(time.Second)
					for td035Sum(t, main.Maps["stats"], 0) < 3 && time.Now().Before(deadline) {
						time.Sleep(time.Millisecond)
					}
					after := nsCoarse(t)
					counts := b1LogicalCounts(t, main, 701)
					var stats [10]uint64
					for i := range stats {
						stats[i] = td035Sum(t, main.Maps["stats"], uint32(i))
					}
					var hotTime uint64
					hotErr := main.Maps["hot_ids"].Lookup(uint32(701), &hotTime)
					hotOK := hotErr == nil && hotTime >= before && hotTime <= after
					t.Logf("NS_CELL class=behavior name=hot_readback cell=%s last_hit_ns=%d pass=%t", t.Name(), hotTime, hotOK)
					length := uint64(len(packet))
					pass := hotOK && stats[0] == 3 && stats[1] == wantDrop && stats[2] == 3-wantDrop && stats[6] == 3*length && stats[7] == wantDrop*length && stats[8] == (3-wantDrop)*length && counts.Match == 3 && counts.Drop == wantDrop && counts.MatchBytes == 3*length && counts.DropBytes == wantDrop*length && counts.LastHitNS >= before && counts.LastHitNS <= after && counts.LastHitNS > 0
					t.Logf("NS_CELL class=behavior name=%s packets=%d length=%d dropped=%d passed=%d total_bytes=%d dropped_bytes=%d passed_bytes=%d match_bytes=%d drop_bytes=%d last_hit_ns=%d start_ns=%d end_ns=%d pass=%t", t.Name(), stats[0], length, stats[1], stats[2], stats[6], stats[7], stats[8], counts.MatchBytes, counts.DropBytes, counts.LastHitNS, before, after, pass)
					if !pass {
						t.Fatal("node/rule accounting")
					}
				})
			}
		}
	}
	for _, mode := range []string{"whitelist", "miss", "mapped-v6", "ff-nonfilter"} {
		t.Run(mode, func(t *testing.T) {
			ready := nsSetup(t)
			main := b1LogicalLoad(t, "")
			b1LogicalReset(t, main, false, 0, 0)
			repl := map[string]*ebpf.Map{}
			for _, name := range []string{"whitelist", "stats", "config_a", "config_b", "active_config", "prog_tail_map", "devmap"} {
				repl[name] = main.Maps[name]
			}
			gate := td035Load(t, "XDROP_GATE_ELF", repl)
			td035Put(t, main.Maps["prog_tail_map"], uint32(1), main.Programs["xdp_firewall_main"])
			attachment, err := link.AttachXDP(link.XDPOptions{Program: gate.Programs["xdp_whitelist_gate"], Interface: rx.Index, Flags: link.XDPGenericMode})
			nsPrerequisite(t, err)
			defer attachment.Close()
			packet := append(b1LogicalPacket(64), make([]byte, 40)...)
			if mode == "mapped-v6" {
				packet = td035Packet(6, "complete", 6, 80, 2)
				src := netip.MustParseAddr("::ffff:10.0.0.1").As16()
				copy(packet[22:38], src[:])
			}
			if mode == "whitelist" {
				td035Put(t, main.Maps["config_a"], uint32(1), uint64(1))
				td035Put(t, main.Maps["config_a"], uint32(3), uint64(1<<16))
				td035Put(t, main.Maps["whitelist"], b1Key(false, 6, true), uint8(1))
			}
			var before [10]uint64
			if mode == "ff-nonfilter" {
				td035Put(t, main.Maps["config_a"], uint32(4), uint64(1))
				td035Put(t, main.Maps["config_a"], uint32(5), uint64(tx.Index))
				// Return through ingress to the peer, which has no XDP attachment.
				td035Put(t, main.Maps["devmap"], uint32(rx.Index), uint32(rx.Index))
				for i := range before {
					before[i] = td035Sum(t, main.Maps["stats"], uint32(i))
				}
			}
			copy(packet[:6], rx.HardwareAddr)
			copy(packet[6:12], tx.HardwareAddr)
			ready()
			for i := 0; i < 3; i++ {
				nsPrerequisite(t, unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: tx.Index}))
			}
			time.Sleep(20 * time.Millisecond)
			var s [10]uint64
			for i := range s {
				s[i] = td035Sum(t, main.Maps["stats"], uint32(i)) - before[i]
			}
			drop := uint64(0)
			if mode == "mapped-v6" {
				drop = 3
			}
			hotRows := b1KeyCount(t, main.Maps["hot_ids"])
			t.Logf("NS_CELL class=behavior name=hot_absent cell=%s rows=%d pass=%t", mode, hotRows, hotRows == 0)
			pass := hotRows == 0 && s[0] == 3 && s[1] == drop && s[2] == 3-drop && s[6] == 3*uint64(len(packet)) && s[7] == drop*uint64(len(packet)) && s[8] == (3-drop)*uint64(len(packet)) && b1KeyCount(t, main.Maps["id_counts"]) == 0
			if mode == "mapped-v6" {
				pass = pass && s[5] == 3
			}
			if mode == "whitelist" {
				pass = pass && s[3] == 3
			}
			t.Logf("NS_CELL class=behavior name=%s packets=%d length=%d dropped=%d passed=%d mapped=%d rule_rows=%d total_bytes=%d dropped_bytes=%d passed_bytes=%d pass=%t", mode, s[0], len(packet), s[1], s[2], s[5], b1KeyCount(t, main.Maps["id_counts"]), s[6], s[7], s[8], pass)
			if !pass {
				t.Fatal(s)
			}
		})
	}
}
