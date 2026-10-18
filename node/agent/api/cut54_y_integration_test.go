//go:build linux && integration

package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

func cut54LogicalBytes(t *testing.T, m *ebpf.Map, id uint32) []byte {
	t.Helper()
	v, e := m.LookupBytes(id)
	if e != nil || v == nil {
		t.Fatalf("logical state missing ID=%d: %v", id, e)
	}
	return v
}
func TestCut54YLifecycle(t *testing.T) {
	cells := 0
	for _, isCIDR := range []bool{false, true} {
		for _, rate := range []bool{false, true} {
			for _, change := range []string{"same", "move", "swap", "pure_to_condition", "condition_to_pure"} {
				t.Run(fmt.Sprintf("cidr=%v/rate=%v/%s", isCIDR, rate, change), func(t *testing.T) {
					h, _, p, _ := b7ELFCollection(t)
					unpin := cut53PinCPU(t)
					defer unpin()
					for _, m := range []*ebpf.Map{h.configA, h.configB} {
						if e := m.Put(uint32(ConfigRLCPUDivisor), uint64(4096)); e != nil {
							t.Fatal(e)
						}
					}
					a, b := cut53Pure(isCIDR, "a", 17), cut53Pure(isCIDR, "b", 18)
					a.DstPort, b.DstPort = 80, 443
					if rate {
						a.Action, b.Action = "rate_limit", "rate_limit"
						a.RateLimit, b.RateLimit = 1, 1
					}
					if change == "condition_to_pure" {
						a.TTL, b.TTL = cut4BString("64"), cut4BString("64")
					}
					sync := func() {
						out, e := h.DoAtomicSync([]Rule{a, b})
						if e != nil || out.Added != 2 {
							t.Fatalf("Y full sync=%+v %v", out, e)
						}
					}
					packet := func(port uint16) []byte {
						frame := cut53Packet([4]byte{192, 0, 2, 1}, 64)
						binary.BigEndian.PutUint16(frame[36:], port)
						return frame
					}
					sync()
					first := uint32(1)
					if rate {
						first = 2
					}
					cut53Verdict(t, p, packet(80), first)
					cut53Verdict(t, p, packet(80), 1)
					cut53Verdict(t, p, packet(443), first)
					// Give the second logical bucket a different remaining token, so swapping
					// keys cannot pass merely because both buckets happen to be exhausted.
					if rate {
						var slots []struct{ Tokens, Last uint64 }
						if e := h.idRLStates.Lookup(uint32(18), &slots); e != nil {
							t.Fatal(e)
						}
						for i := range slots {
							if slots[i].Last != 0 {
								slots[i].Tokens = 1
							}
						}
						if e := h.idRLStates.Put(uint32(18), slots); e != nil {
							t.Fatal(e)
						}
					}
					counts := map[uint32][]byte{}
					rates := map[uint32][]byte{}
					for _, id := range []uint32{17, 18} {
						counts[id] = cut54LogicalBytes(t, h.idCounts, id)
						if rate {
							rates[id] = cut54LogicalBytes(t, h.idRLStates, id)
						}
					}
					switch change {
					case "move":
						a.DstPort = 8080
					case "swap":
						a.DstPort, b.DstPort = b.DstPort, a.DstPort
					case "pure_to_condition":
						a.TTL, b.TTL = cut4BString("64"), cut4BString("64")
					case "condition_to_pure":
						a.TTL, b.TTL = nil, nil
					}
					sync()
					for _, id := range []uint32{17, 18} {
						if !bytes.Equal(counts[id], cut54LogicalBytes(t, h.idCounts, id)) {
							t.Fatalf("Y full sync lost or exchanged logical counters ID=%d", id)
						}
						if rate && !bytes.Equal(rates[id], cut54LogicalBytes(t, h.idRLStates, id)) {
							t.Fatalf("Y full sync lost or exchanged logical tokens ID=%d", id)
						}
					}
					cut53Verdict(t, p, packet(a.DstPort), 1)
					cut53Verdict(t, p, packet(b.DstPort), first)
					am, ad := h.logicalCounters(17)
					bm, bd := h.logicalCounters(18)
					wantAD, wantBD := uint64(3), uint64(2)
					if rate {
						wantAD, wantBD = 2, 0
					}
					if am != 3 || ad != wantAD || bm != 2 || bd != wantBD {
						t.Fatalf("Y id_counts increments must equal packets without cross-talk: 17=%d/%d 18=%d/%d", am, ad, bm, bd)
					}
					cells++
				})
			}
		}
	}
	t.Logf("CUT54_Y lifecycle_cells=%d packets=%d counter_continuity=20 token_continuity=10 distinct_bucket_tokens=10", cells, cells*5)
}

func TestCut54PureRebuildWritesBeforePayment(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprint(isCIDR), func(t *testing.T) {
			h, _, p, _ := b7ELFCollection(t)
			unpin := cut53PinCPU(t)
			defer unpin()
			for _, m := range []*ebpf.Map{h.configA, h.configB} {
				if e := m.Put(uint32(ConfigRLCPUDivisor), uint64(4096)); e != nil {
					t.Fatal(e)
				}
			}
			rule := cut53Pure(isCIDR, "rebuilt", 17)
			rule.Action, rule.RateLimit = "rate_limit", 1
			p7DeferredCommit(t, h, cut55Group(t, h, rule, rule))
			packet := cut53Packet([4]byte{192, 0, 2, 1}, 64)
			cut53Verdict(t, p, packet, 2)
			cut53Verdict(t, p, packet, 1)
			p7DeferredCommit(t, h, cut55Group(t, h, rule))
			if !h.pendingLogicalIDs[17] {
				t.Fatal("pure rebuild guard: deleted ID must still be pending")
			}
			p7DeferredCommit(t, h, cut55Group(t, h, rule, rule))
			if !h.pendingLogicalIDs[17] || h.logicalOwners[17] != "rebuilt" {
				t.Fatal("pure rebuild guard: live owner must still be pending")
			}
			cut53Verdict(t, p, packet, 1)
			match, drop := h.logicalCounters(17)
			if match != 3 || drop != 2 {
				t.Fatalf("rebuilt flag-zero path must write logical state before payment: %d/%d", match, drop)
			}
			counts, rates := cut54LogicalBytes(t, h.idCounts, 17), cut54LogicalBytes(t, h.idRLStates, 17)
			cut54Pay(t, h)
			if h.pendingLogicalIDs[17] || !bytes.Equal(counts, cut54LogicalBytes(t, h.idCounts, 17)) || !bytes.Equal(rates, cut54LogicalBytes(t, h.idRLStates, 17)) {
				t.Fatal("payment erased rebuilt flag-zero logical state")
			}
		})
	}
	t.Log("CUT54_PURE_REBUILD cases=2 flag_zero_writes=2 pending_live_rechecks=2 counters=3/2")
}
