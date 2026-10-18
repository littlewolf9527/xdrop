//go:build linux && integration

package api

import (
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"testing"
)

func TestCut55R1DeferredPrefixRecreateELF(t *testing.T) {
	for _, src := range []bool{true, false} {
		t.Run(fmt.Sprintf("src=%v", src), func(t *testing.T) {
			h, _, program, coll := b7ELFCollection(t)
			cut55KernelReceipt(t, h)
			name := "dv4_cidr_trie"
			if src {
				name = "sv4_cidr_trie"
			}
			read := func(slot int) (uint32, bool) {
				mapName := name
				if slot == 1 {
					mapName += "_b"
				}
				rows := cut53KernelMapBytes(t, coll.Maps[mapName])
				if len(rows) > 1 {
					t.Fatal("R1 unexpected trie rows", len(rows))
				}
				for k, v := range rows {
					if len(k) != 8 || binary.LittleEndian.Uint32([]byte(k[:4])) != 24 || k[4:] != string([]byte{192, 0, 2, 0}) {
						t.Fatalf("R1 wrong trie prefix %x", k)
					}
					return binary.LittleEndian.Uint32([]byte(v)), true
				}
				return 0, false
			}
			cut55R1Recreate(t, h, src, read, "_ELF")
			cut55KernelMirror(t, h)
			packet := cut53Packet([4]byte{192, 0, 2, 1}, 64)
			if !src {
				copy(packet[26:30], []byte{198, 51, 100, 1})
				copy(packet[30:34], []byte{192, 0, 2, 1})
			}
			cut53Verdict(t, program, packet, 1)
			t.Logf("CUT55_R1_PREFIX_PACKET src=%v packets=1 verdict=DROP", src)
		})
	}
}

func TestCut55R1DeleteReceiptELF(t *testing.T) {
	for _, scenario := range []struct {
		name            string
		abort, deferred bool
	}{{"abort=true", true, false}, {"abort=false", false, false}, {"deferred", false, true}} {
		t.Run(scenario.name, func(t *testing.T) {
			h, _, _, _ := b7ELFCollection(t)
			cut55KernelReceipt(t, h)
			seed := func() { cut5SeedLogical(t, h, 81) }
			read := func() [2][]byte {
				var out [2][]byte
				for i, m := range []*ebpf.Map{h.idCounts, h.idRLStates} {
					value, err := m.LookupBytes(uint32(81))
					if err != nil && !isMapEntryMissing(err) {
						t.Fatal(err)
					}
					out[i] = value
				}
				return out
			}
			cut55R1DeleteReceipt(t, h, seed, read, scenario.abort, scenario.deferred, "ELF")
		})
	}
}
