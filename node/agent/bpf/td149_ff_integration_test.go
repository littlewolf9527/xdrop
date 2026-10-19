//go:build linux && integration

package bpf

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
)

// TestTD149FFDirections: fast forward with the filter interface selected or not,
// deep chain on lo, slot 12 = 0 / 1 (blind review r1 P2-2).
func TestTD149FFDirections(t *testing.T) {
	main, gate, base := td149Load(t)
	if base {
		t.Fatal("TD149 FF witness requires the 13/10 schema")
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range []bool{true, false} {
		for _, pass := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("selected=%t/S%d", selected, pass), func(t *testing.T) {
				for i := uint32(0); i < api.ConfigMapEntries; i++ {
					td035Put(t, main.Maps["config_a"], i, uint64(0))
				}
				filter := lo.Index
				if !selected {
					filter++
				}
				td035Put(t, main.Maps["config_a"], uint32(api.ConfigFastForwardEnabled), uint64(1))
				td035Put(t, main.Maps["config_a"], uint32(api.ConfigFilterIfindex), uint64(filter))
				td035Put(t, main.Maps["config_a"], uint32(api.ConfigIPv6DeepChainPass), pass)
				packet := td122Packet("B7", 51)
				ctx := [6]uint32{0, uint32(len(packet)), 0, uint32(lo.Index), 0, 0}
				before := td149Stats(t, main, false)
				ret, err := gate.Programs["xdp_whitelist_gate"].Run(&ebpf.RunOptions{Data: packet, Context: ctx, Repeat: 1})
				if err != nil {
					t.Fatal(err)
				}
				got := td149Stats(t, main, false)
				for i := range got {
					got[i] -= before[i]
				}
				drop := selected && pass == 0
				wantRet := uint32(0) // An empty devmap returns XDP_ABORTED without transmitting.
				if drop {
					wantRet = srcXDPDrop
				}
				length := uint64(len(packet))
				want := [10]uint64{1, td149Bit(drop), td149Bit(!drop), 0, 0, 0,
					length, length * td149Bit(drop), length * td149Bit(!drop), td149Bit(drop)}
				if ret != wantRet || got != want {
					t.Fatalf("selected=%t slot=%d ret=%d want=%d stats=%v want=%v", selected, pass, ret, wantRet, got, want)
				}
			})
		}
	}
}
