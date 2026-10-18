//go:build linux && integration

package api

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// B1 retirement is an ELF structure contract, independent of config values.
func TestCut53AnomalyNoTailCalls(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprintf("cidr=%v", isCIDR), func(t *testing.T) {
			h, _, main, coll := b7ELFCollection(t)
			path := os.Getenv("XDROP_BPF_ELF")
			if path == "" {
				path = "../../bpf/xdrop_main.elf"
			}
			spec, err := ebpf.LoadCollectionSpec(path)
			if err != nil {
				t.Fatal(err)
			}
			caller := spec.Programs["xdp_firewall_main"]
			if caller == nil || caller.Type != ebpf.XDP || caller.AttachType != ebpf.AttachXDP {
				t.Fatal("K16 caller must have the ELF XDP attach contract")
			}
			for _, ins := range caller.Instructions {
				if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnTailCall) {
					t.Fatal("main ELF contains bpf_tail_call instruction")
				}
			}
			var fd uint32
			if err := coll.Maps["prog_tail_map"].Lookup(uint32(0), &fd); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("startup tail slot0 must be empty: fd=%d error=%v", fd, err)
			}
			r := cut53Pure(isCIDR, "anomaly", 17)
			r.MatchAnomaly = AnomalyInvalid
			if _, err := h.DoAtomicSync([]Rule{r}); err != nil {
				t.Fatal(err)
			}
			bad := cut53Packet([4]byte{192, 0, 2, 1}, 64)
			bad[46] = 0x40
			cut53Verdict(t, main, bad, 1)
			cut53Verdict(t, main, cut53Packet([4]byte{192, 0, 2, 1}, 64), 2)
			cut53Verdict(t, main, cut53Packet([4]byte{198, 51, 100, 1}, 64), 2)
			if readCfg(t, h.activeMap(), ConfigAnomalyRuleCount) != 0 {
				t.Fatal("K16 retired config anomaly count must be zero")
			}
			if err := h.activeMap().Put(uint32(ConfigAnomalyRuleCount), uint64(1)); err != nil {
				t.Fatal(err)
			}
			cut53Verdict(t, main, cut53Packet([4]byte{198, 51, 100, 1}, 64), 2)
			if err := coll.Maps["prog_tail_map"].Lookup(uint32(0), &fd); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("packet path populated retired tail slot0: %v", err)
			}
			t.Logf("CUT54_K16 cidr=%v production_packets=4 main_tail_call_instructions=0 slot0=empty", isCIDR)
		})
	}
}

func TestCut53W12NonFirst(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprintf("cidr=%v", isCIDR), func(t *testing.T) {
			h, _, p := b7ELF(t)
			r := cut53Pure(isCIDR, "negative-syn", 17)
			r.TcpFlags = "!SYN"
			if _, err := h.DoAtomicSync([]Rule{r}); err != nil {
				t.Fatal(err)
			}
			m := h.activeCond()
			if isCIDR {
				m = h.activeCidrCond()
			}
			packet := cut53Packet([4]byte{192, 0, 2, 1}, 64)
			packet[47] = 0
			cut53Verdict(t, p, packet, 1)
			binary.BigEndian.PutUint16(packet[20:], 2)
			verdict, _, err := p.Test(packet)
			if err != nil || verdict != 2 {
				t.Fatalf("W12 nonfirst verdict=%d want=2 err=%v", verdict, err)
			}
			for _, v := range b7Snapshot(t, m) {
				if []byte(v)[842] != 1 {
					t.Fatal("W12 !SYN must set TCPReq")
				}
			}
			t.Logf("CUT53_W12 cidr=%v TCPReq=1 first_drop=1 nonfirst_pass=1", isCIDR)
		})
	}
}
