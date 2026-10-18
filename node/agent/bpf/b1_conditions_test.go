//go:build linux && integration

package bpf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"golang.org/x/sys/unix"
)

// Expectations below are constructed from intent: single accepted values,
// distinct candidate outputs and explicit packet cases. No C-generated oracle.
func b1Wire(t *testing.T, value any) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, value); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func b1Put(t *testing.T, c *ebpf.Collection, m string, k, v any) {
	t.Helper()
	if c.Maps[m] == nil {
		t.Fatalf("missing map %s", m)
	}
	if err := c.Maps[m].Put(k, v); err != nil {
		t.Fatalf("%s.Put: %v", m, err)
	}
}
func b1Erase(t *testing.T, c *ebpf.Collection, m string, k any) {
	t.Helper()
	err := c.Maps[m].Delete(k)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal(err)
	}
}
func b1Load(t *testing.T, path string) *ebpf.Collection {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coll.Close)
	t.Logf("elf=%s sha256=%x", path, sha256.Sum256(raw))
	return coll
}
func b1OpenRow(active uint8) api.ConditionValue {
	var c api.ConditionValue
	c.Active = active
	for d := range c.Tab {
		for x := range c.Tab[d] {
			c.Tab[d][x] = 0xff
		}
	}
	for x := range c.Frag {
		c.Frag[x] = 0xff
	}
	for k := 0; k < 4; k++ {
		c.Len[k] = [2]api.ConditionSpan{{Lo: 0, Hi: 65535}, {Lo: 1, Hi: 0}}
		c.Action[k] = uint8(k % 3)
		c.Rate[k] = uint32(101 + 37*k)
		c.RuleID[k] = uint32(0x80102030 + 0x01020304*k)
	}
	return c
}

// D18: flag-one anomaly rows replace the retired flag-zero anomaly stage.
func b1AnomalyRow(id uint32, mask uint8) api.ConditionValue {
	row := b1OpenRow(1)
	row.RuleID[0], row.Action[0] = id, api.ActionDrop
	row.Tab[5] = [128]byte{}
	for value := 0; value < 16; value++ {
		if uint8(value)&mask != 0 {
			row.Tab[5][value/2] |= 1 << uint(4*(value%2))
		}
	}
	return row
}

func b1Single(c *api.ConditionValue, dim, n, k int) {
	if dim == 2 {
		c.TCPReq |= 1 << k
	}
	c.Tab[dim] = [128]byte{}
	c.Tab[dim][n/2] = byte(1<<k) << uint(4*(n%2))
}
func b1Key(cidr bool, proto byte, fine bool) []byte {
	n, po, pr := 40, 34, 36
	if cidr {
		n, po, pr = 16, 10, 12
	}
	k := make([]byte, n)
	k[pr] = proto
	if fine {
		binary.BigEndian.PutUint16(k[po:], 80)
	}
	return k
}
func b1Maps(cidr bool, sel uint64) (string, string, string, string) {
	r, c, ro, co := "blacklist", "cond_a", "blacklist_b", "cond_b"
	if cidr {
		r, c, ro, co = "cidr_blacklist", "cidr_cond_a", "cidr_blist_b", "cidr_cond_b"
	}
	if sel == 1 {
		r, ro = ro, r
		c, co = co, c
	}
	return r, c, ro, co
}
func b1Config(t *testing.T, c *ebpf.Collection, cidr bool, slot, sel uint64) {
	t.Helper()
	on, off := "config_a", "config_b"
	if slot == 1 {
		on, off = off, on
	}
	b1Put(t, c, "active_config", uint32(0), slot)
	for _, m := range []string{on, off} {
		for i := uint32(0); i < 12; i++ {
			b1Put(t, c, m, i, uint64(0))
		}
	}
	count, bitmap := uint32(0), uint32(2)
	if cidr {
		count, bitmap = 6, 7
	}
	b1Put(t, c, on, count, uint64(2))
	b1Put(t, c, on, bitmap, uint64(1<<16|1<<5))
	b1Put(t, c, on, uint32(9), sel)
	b1Put(t, c, on, uint32(11), uint64(1))
	// Opposite config is a positive poison, not empty: wrong slot selects the
	// opposite rule/condition generation and changes the candidate output.
	b1Put(t, c, off, count, uint64(2))
	b1Put(t, c, off, bitmap, uint64(1<<16|1<<5))
	b1Put(t, c, off, uint32(9), 1-sel)
}
func b1SetRow(t *testing.T, c *ebpf.Collection, cidr bool, sel uint64, proto byte, row api.ConditionValue) {
	t.Helper()
	r, m, ro, mo := b1Maps(cidr, sel)
	key := b1Key(cidr, proto, true)
	v := api.RuleValue{LogicalID: row.RuleID[0], Action: api.ActionDrop, RateLimit: 999}
	v.Pad2[0] = api.RuleHasConditions
	b1Put(t, c, r, key, b1Wire(t, v))
	b1Put(t, c, m, key, b1Wire(t, row))
	poison := b1OpenRow(8)
	poison.Action[3] = api.ActionPass
	poison.Rate[3] = 999999
	poison.RuleID[3] = 0xfedcba98
	b1Put(t, c, ro, key, b1Wire(t, v))
	b1Put(t, c, mo, key, b1Wire(t, poison))
}
func TestB1ConditionLookupELF(t *testing.T) {
	path := os.Getenv("XDROP_B1_CONDITION_ELF")
	if path == "" {
		t.Fatal("XDROP_B1_CONDITION_ELF required")
	}
	c := b1Load(t, path)
	packets, domains, l4Packets := 0, 0, 0
	for _, cidr := range []bool{false, true} {
		for _, asm := range srcAssemblies {
			kind := "exact"
			if cidr {
				kind = "cidr"
			}
			label := kind + "/" + asm.name
			t.Run(label, func(t *testing.T) {
				b1Config(t, c, cidr, asm.slot, asm.sel)
				r, m, _, _ := b1Maps(cidr, asm.sel)
				base := make([]byte, 64)
				binary.LittleEndian.PutUint16(base, 100)
				base[2] = 0x12
				base[4] = 64
				base[5] = 17
				base[6] = 8
				base[7] = 19
				base[9] = 1
				base[10] = 1
				run := func(name string, input []byte, row api.ConditionValue, winner int, hit bool) {
					t.Helper()
					b1SetRow(t, c, cidr, asm.sel, 6, row)
					ret, out, err := c.Programs["b1_condition_"+kind].Test(input)
					if err != nil {
						t.Fatal(err)
					}
					packets++
					wantRet := uint32(0xb3)
					if hit {
						wantRet = 0xb2
					}
					want := make([]byte, 12)
					want[0] = 255
					if winner >= 0 {
						want[0] = byte(winner)
						want[1] = row.Action[winner]
						binary.LittleEndian.PutUint32(want[4:], row.Rate[winner])
						binary.LittleEndian.PutUint32(want[8:], row.RuleID[winner])
					}
					if ret != wantRet || len(out) < 24 || !bytes.Equal(out[12:24], want) {
						t.Fatalf("B1_OUT %s ret=%x want=%x output=%x want=%x", name, ret, wantRet, out[12:24], want)
					}
					if out[10] != input[10] || out[11] != 0 {
						t.Fatalf("B1_PADDING %s: %x", name, out[10:12])
					}
				}
				offsets := []int{4, 5, 2, 6, 7, 3}
				for dim, off := range offsets {
					for n := 0; n < 256; n++ {
						k := n % 4
						row := b1OpenRow(15)
						b1Single(&row, dim, n, k)
						input := append([]byte{}, base...)
						input[off] = byte(n)
						run(fmt.Sprintf("dim%d/value%d", dim, n), input, row, k, true)
						input[off] = byte(n + 1)
						run(fmt.Sprintf("dim%d/neighbor%d", dim, n), input, row, -1, false)
						domains++
					}
				}
				for k := 0; k < 4; k++ {
					row := b1OpenRow(1 << k)
					row.Len[k] = [2]api.ConditionSpan{{Lo: 80, Hi: 90}, {Lo: 110, Hi: 120}}
					for _, n := range []int{0, 79, 80, 85, 90, 91, 100, 109, 110, 115, 120, 121, 65535} {
						input := append([]byte{}, base...)
						binary.LittleEndian.PutUint16(input, uint16(n))
						win := -1
						if (n >= 80 && n <= 90) || (n >= 110 && n <= 120) {
							win = k
						}
						run(fmt.Sprintf("span/k%d/%d", k, n), input, row, win, win >= 0)
					}
				}
				for n := 0; n < 8; n++ {
					row := b1OpenRow(15)
					row.Frag = [4]byte{}
					k := n % 4
					row.Frag[n/2] = byte(1<<k) << uint(4*(n%2))
					input := append([]byte{}, base...)
					input[8] = byte(n)
					run("fragment", input, row, k, true)
					input[8] = byte((n + 1) % 8)
					run("fragment-neighbor", input, row, -1, false)
				}
				for active := 1; active < 16; active++ {
					row := b1OpenRow(byte(active))
					want := 0
					for active&(1<<want) == 0 {
						want++
					}
					run("lowest-bit", base, row, want, true)
				}
				row := b1OpenRow(3)
				row.ICMPReq = 1
				input := append([]byte{}, base...)
				input[9] = 0
				run("icmp-invalid-keep-unconstrained", input, row, 1, true)
				row.Active = 1
				run("icmp-invalid-reject", input, row, -1, false)
				row = b1OpenRow(0)
				run("all-miss-sentinel", base, row, -1, false)
				// A lower-priority pure rule must win after a condition miss or missing row.
				fallback := api.RuleValue{LogicalID: 0x54020000 + 1, Action: api.ActionPass}
				b1Put(t, c, r, b1Key(cidr, 6, false), b1Wire(t, fallback))
				run("fallthrough-to-broader", base, row, -1, true)
				row = b1OpenRow(4)
				run("stop-on-first-hit", base, row, 2, true)
				b1Erase(t, c, m, b1Key(cidr, 6, true))
				ret, out, err := c.Programs["b1_condition_"+kind].Test(base)
				packets++
				if err != nil || ret != 0xb2 || out[12] != 255 {
					t.Fatalf("B1_MISSING_ROW fallback ret=%x output=%x err=%v", ret, out[12:24], err)
				}
				b1Erase(t, c, r, b1Key(cidr, 6, false))
				// Reserved bits must not activate conditions.
				value := api.RuleValue{LogicalID: 0x54020000 + 2, Action: api.ActionPass}
				value.Pad2[0] = 2
				b1Put(t, c, r, b1Key(cidr, 6, true), b1Wire(t, value))
				ret, out, err = c.Programs["b1_condition_"+kind].Test(base)
				packets++
				if err != nil || ret != 0xb2 || out[12] != 255 {
					t.Fatalf("B1_FLAG_BIT reserved-bit ret=%x winner=%d err=%v", ret, out[12], err)
				}
				// TD-035 explicit validity inputs use a no-port key, so the
				// invalid-L4 witness reaches cond_match rather than a key miss.
				b1Erase(t, c, r, b1Key(cidr, 6, true))
				for _, tc := range []struct {
					name       string
					valid, req byte
					hit        bool
				}{
					{"nonfirst-tcp-required", 0, 1, false},
					{"nonfirst-unconstrained", 0, 0, true},
					{"complete-tcp-required", 1, 1, true},
				} {
					input := append([]byte{}, base...)
					input[2], input[10] = 0, tc.valid
					row := b1OpenRow(1)
					b1Single(&row, 2, 0, 0)
					row.TCPReq = tc.req
					value := api.RuleValue{LogicalID: 0x54020000 + 3, Pad2: [4]byte{api.RuleHasConditions}}
					key := b1Key(cidr, 6, false)
					b1Put(t, c, r, key, b1Wire(t, value))
					b1Put(t, c, m, key, b1Wire(t, row))
					ret, out, err := c.Programs["b1_condition_"+kind].Test(input)
					wantRet, winner := uint32(0xb3), byte(255)
					if tc.hit {
						wantRet, winner = 0xb2, 0
					}
					if err != nil || ret != wantRet || len(out) < 24 || out[10] != tc.valid || out[11] != 0 || out[12] != winner {
						t.Fatalf("B1_L4_INPUT %s ret=%x want=%x output=%x winner=%d error=%v", tc.name, ret, wantRet, out, winner, err)
					}
					l4Packets++
					b1Erase(t, c, r, key)
					b1Erase(t, c, m, key)
				}
			})
		}
	}
	// 8 assemblies * (3072 sweep packets + 52 spans + 16 frag + 15 active +
	// 2 ICMP + 1 miss + 2 fallback/hit + 1 missing + 1 reserved).
	if domains != 12288 || packets != 25296 {
		t.Fatalf("B1 execution count domains=%d packets=%d", domains, packets)
	}
	if t.Failed() {
		t.Fatal("B1_H_ELF contains failed assertions")
	}
	t.Logf("B1_H_ELF paths=2 assemblies=4 dimensions=6 values=256 domain_points=%d packets=%d red=0", domains, packets)
	if l4Packets != 24 {
		t.Fatalf("B1_L4_INPUT packets=%d want=24", l4Packets)
	}
	t.Logf("B1_L4_INPUT paths=2 assemblies=4 cases=3 packets=%d red=0", l4Packets)
}

func TestB1ConditionProductionELF(t *testing.T) {
	path := os.Getenv("XDROP_BPF_ELF")
	if path == "" {
		t.Fatal("XDROP_BPF_ELF required")
	}
	c := b1Load(t, path)
	// Packets use private IPv4 / ULA IPv6 addresses; /0 LPM entries force real CIDR traversal.
	for _, name := range []string{"sv4_cidr_trie", "dv4_cidr_trie", "sv4_cidr_trie_b", "dv4_cidr_trie_b"} {
		key := make([]byte, 8)
		b1Put(t, c, name, key, uint32(7))
	}
	for _, name := range []string{"sv6_cidr_trie", "dv6_cidr_trie", "sv6_cidr_trie_b", "dv6_cidr_trie_b"} {
		key := make([]byte, 20)
		b1Put(t, c, name, key, uint32(7))
	}
	packets := 0
	for _, cidr := range []bool{false, true} {
		for _, asm := range srcAssemblies {
			kind := "exact"
			if cidr {
				kind = "cidr"
			}
			t.Run(kind+"/"+asm.name, func(t *testing.T) {
				b1Config(t, c, cidr, asm.slot, asm.sel)
				r, m, _, _ := b1Maps(cidr, asm.sel)
				run := func(name string, pkt []byte, want uint32) {
					t.Helper()
					got, _, err := c.Programs["xdp_firewall_main"].Test(pkt)
					packets++
					if err != nil || got != want {
						t.Fatalf("B1_PRODUCTION %s got=%d want=%d err=%v", name, got, want, err)
					}
				}
				tcp := make([]byte, 20)
				binary.BigEndian.PutUint16(tcp[2:], 80)
				tcp[12] = 0x50
				tcp[13] = 0x12
				frame := func(v6 bool, proto byte, payload []byte) []byte {
					p := b1Frame(v6, proto, payload, 0)
					if v6 {
						p[22] = 0xfd
						p[23] = 0
						p[38] = 0xfd
						p[39] = 0
					} else {
						copy(p[26:30], []byte{10, 1, 2, 3})
						copy(p[30:34], []byte{100, 64, 2, 3})
					}
					return p
				}
				// Real packet extraction into both lookup paths, with independent neighboring negatives.
				for dim := 0; dim < 5; dim++ {
					for n := 0; n < 256; n++ {
						for _, v6 := range []bool{false, true} {
							proto := byte(6)
							payload := tcp
							if dim == 3 || dim == 4 {
								proto = 1
								if v6 {
									proto = 58
								}
								payload = []byte{0, 0}
							}
							p := frame(v6, proto, payload)
							l4 := 34
							if v6 {
								l4 = 54
							}
							value := n
							switch dim {
							case 0:
								if v6 {
									p[21] = byte(n)
								} else {
									p[22] = byte(n)
								}
							case 1:
								value = n >> 2
								if v6 {
									p[14] = 0x60 | byte(n>>4)
									p[15] = byte(n << 4)
								} else {
									p[15] = byte(n)
								}
							case 2:
								p[l4+13] = byte(n)
							case 3:
								p[l4] = byte(n)
							case 4:
								p[l4+1] = byte(n)
							}
							// ICMP has no ports, so use a protocol-only condition key and no broader row.
							fine := dim < 3
							key := b1Key(cidr, proto, fine)
							row := b1OpenRow(1)
							row.Action[0] = api.ActionDrop
							b1Single(&row, dim, value, 0)
							if dim >= 3 {
								row.ICMPReq = 1
							}
							rv := api.RuleValue{LogicalID: 0x54020000 + 4, Action: api.ActionPass}
							rv.Pad2[0] = 1
							b1Put(t, c, r, key, b1Wire(t, rv))
							b1Put(t, c, m, key, b1Wire(t, row))
							run(fmt.Sprintf("dim%d/value%d/v6=%v", dim, n, v6), p, srcXDPDrop)
							b1Single(&row, dim, (value+1)%256, 0)
							b1Put(t, c, m, key, b1Wire(t, row))
							run("neighbor", p, srcXDPPass)
							b1Erase(t, c, r, key)
							b1Erase(t, c, m, key)
						}
					}
				}
				// Fragment representatives and anomaly bits are independently specified by the extraction fixture set.
				for _, fc := range b1Cases() {
					if len(fc.packet) < 34 || fc.abort {
						continue
					}
					proto := fc.packet[23]
					v6 := fc.packet[12] == 0x86
					if v6 {
						proto = fc.packet[20]
						if proto == 0 || proto == 44 {
							continue
						}
					}
					if proto != 6 && proto != 1 && proto != 58 {
						continue
					}
					p := append([]byte{}, fc.packet...)
					if v6 {
						p[22] = 0xfd
						p[23] = 0
						p[38] = 0xfd
						p[39] = 0
					} else {
						copy(p[26:30], []byte{10, 1, 2, 3})
						copy(p[30:34], []byte{100, 64, 2, 3})
					}
					key := b1Key(cidr, proto, false)
					row := b1OpenRow(1)
					row.Action[0] = api.ActionDrop
					b1Single(&row, 5, int(fc.attrs[3]), 0)
					rv := api.RuleValue{LogicalID: 0x54020000 + 5}
					rv.Pad2[0] = 1
					b1Put(t, c, r, key, b1Wire(t, rv))
					b1Put(t, c, m, key, b1Wire(t, row))
					run("anomaly/"+fc.name, p, srcXDPDrop)
					b1Single(&row, 5, (int(fc.attrs[3])+1)%256, 0)
					b1Put(t, c, m, key, b1Wire(t, row))
					run("anomaly-negative/"+fc.name, p, srcXDPPass)
					b1Erase(t, c, r, key)
					b1Erase(t, c, m, key)
				}
				// Real fragment classes and both length intervals, including v6 wrap.
				for class := 0; class < 8; class++ {
					p := frame(false, 6, tcp)
					frag := uint16((class&4)<<12 | (class&2)<<12)
					if class&1 != 0 {
						frag |= 2
					}
					binary.BigEndian.PutUint16(p[20:], frag)
					row := b1OpenRow(1)
					row.Action[0] = api.ActionDrop
					row.Frag = [4]byte{}
					row.Frag[class/2] = 1 << uint(4*(class%2))
					b1SetRow(t, c, cidr, asm.sel, 6, row)
					want := srcXDPDrop
					if class&1 != 0 {
						want = srcXDPPass
					}
					run(fmt.Sprintf("fragment-class-%d", class), p, want)
					row.Frag = [4]byte{}
					other := (class + 1) % 8
					row.Frag[other/2] = 1 << uint(4*(other%2))
					b1Put(t, c, m, b1Key(cidr, 6, true), b1Wire(t, row))
					run("fragment-negative", p, srcXDPPass)
				}
				rowLen := b1OpenRow(1)
				rowLen.Action[0] = api.ActionDrop
				rowLen.Len[0] = [2]api.ConditionSpan{{Lo: 80, Hi: 90}, {Lo: 110, Hi: 120}}
				b1SetRow(t, c, cidr, asm.sel, 6, rowLen)
				for _, v6 := range []bool{false, true} {
					for _, n := range []int{40, 79, 80, 85, 90, 91, 100, 109, 110, 115, 120, 121, 65535} {
						p := frame(v6, 6, tcp)
						if v6 {
							binary.BigEndian.PutUint16(p[18:], uint16(n-40))
						} else {
							binary.BigEndian.PutUint16(p[16:], uint16(n))
						}
						want := srcXDPPass
						if n >= 80 && n <= 90 || n >= 110 && n <= 120 {
							want = srcXDPDrop
						}
						run(fmt.Sprintf("length/%d/v6=%v", n, v6), p, want)
					}
				}
				rowLen.Len[0] = [2]api.ConditionSpan{{Lo: 39, Hi: 39}, {Lo: 1, Hi: 0}}
				b1Put(t, c, m, b1Key(cidr, 6, true), b1Wire(t, rowLen))
				wrap := frame(true, 6, tcp)
				binary.BigEndian.PutUint16(wrap[18:], 65535)
				run("v6-length-wrap39", wrap, srcXDPDrop)
				b1Erase(t, c, r, b1Key(cidr, 6, true))
				b1Erase(t, c, m, b1Key(cidr, 6, true))
				// ICMP validity: zero is a real value; truncated/nonfirst/IHL<5 must reject only constrained candidates.
				for _, v6 := range []bool{false, true} {
					proto := byte(1)
					if v6 {
						proto = 58
					}
					key := b1Key(cidr, proto, false)
					valid := frame(v6, proto, []byte{0, 0})
					short := frame(v6, proto, []byte{0})
					nonfirst := frame(v6, proto, []byte{0, 0})
					if v6 {
						ext := make([]byte, 10)
						ext[0] = 58
						binary.BigEndian.PutUint16(ext[2:], 8)
						nonfirst = frame(true, 44, ext)
					} else {
						binary.BigEndian.PutUint16(nonfirst[20:], 1)
					}
					for _, tc := range []struct {
						name  string
						p     []byte
						valid bool
					}{{"valid-type-zero", valid, true}, {"truncated", short, false}, {"nonfirst", nonfirst, false}} {
						row := b1OpenRow(3)
						row.ICMPReq = 1
						row.Action[0] = api.ActionDrop
						row.Action[1] = api.ActionPass
						b1Single(&row, 3, 0, 0)
						row.Tab[3][0] |= 2 // unconstrained candidate 1 permits every ICMP type.
						for i := range row.Tab[3] {
							row.Tab[3][i] |= 0x22
						}
						rv := api.RuleValue{LogicalID: 0x54020000 + 6, Action: api.ActionDrop}
						rv.Pad2[0] = 1
						b1Put(t, c, r, key, b1Wire(t, rv))
						b1Put(t, c, m, key, b1Wire(t, row))
						want := srcXDPPass
						if tc.valid {
							want = srcXDPDrop
						}
						run("icmp/"+tc.name, tc.p, want)
						row.Active = 1
						b1Put(t, c, m, key, b1Wire(t, row))
						run("icmp-constrained-only/"+tc.name, tc.p, want)
					}
					if !v6 {
						bad := frame(false, 1, []byte{0, 0})
						bad[14] = 0x44
						row := b1OpenRow(1)
						row.ICMPReq = 1
						row.Action[0] = api.ActionDrop
						b1Put(t, c, m, key, b1Wire(t, row))
						run("icmp-invalid-ihl", bad, srcXDPPass)
					}
					b1Erase(t, c, r, key)
					b1Erase(t, c, m, key)
				}
				p := frame(false, 6, tcp)
				row := b1OpenRow(3)
				row.Action[0] = api.ActionPass
				row.Action[1] = api.ActionDrop
				b1SetRow(t, c, cidr, asm.sel, 6, row)
				run("smallest-winner-pass", p, srcXDPPass)
				on := "config_a"
				if asm.slot == 1 {
					on = "config_b"
				}
				if !cidr {
					later, _, _, _ := b1Maps(true, asm.sel)
					b1Put(t, c, on, uint32(6), uint64(1))
					b1Put(t, c, on, uint32(7), uint64(1<<5))
					b1Put(t, c, later, b1Key(true, 6, false), b1Wire(t, api.RuleValue{LogicalID: 0x54020000 + 7, Action: api.ActionDrop}))
					run("condition-pass-before-cidr-drop", p, srcXDPDrop)
					b1Erase(t, c, later, b1Key(true, 6, false))
					b1Put(t, c, on, uint32(6), uint64(0))
				} else {
					later, _, _, _ := b1Maps(false, asm.sel)
					b1Put(t, c, on, uint32(0), uint64(1))
					b1Put(t, c, on, uint32(2), uint64(1<<5))
					b1Put(t, c, on, uint32(10), uint64(1))
					anomalyID := uint32(0x54030000 + asm.slot*2 + asm.sel)
					_, laterCond, _, _ := b1Maps(false, asm.sel)
					b1Put(t, c, later, b1Key(false, 6, false), b1Wire(t, api.RuleValue{LogicalID: anomalyID, Action: api.ActionDrop, Pad2: [4]byte{api.RuleHasConditions}}))
					b1Put(t, c, laterCond, b1Key(false, 6, false), b1Wire(t, b1AnomalyRow(anomalyID, 2)))
					bad := append([]byte{}, p...)
					bad[46] = 0x40
					run("condition-pass-before-anomaly-drop", bad, srcXDPDrop)
					b1Erase(t, c, later, b1Key(false, 6, false))
					b1Erase(t, c, laterCond, b1Key(false, 6, false))
					b1Put(t, c, on, uint32(0), uint64(0))
					b1Put(t, c, on, uint32(10), uint64(0))
				}

				row.Action[0] = api.ActionDrop
				b1SetRow(t, c, cidr, asm.sel, 6, row)
				run("winner-drop", p, srcXDPDrop)
				b1Put(t, c, r, b1Key(cidr, 6, false), b1Wire(t, api.RuleValue{LogicalID: 0x54020000 + 9, Action: api.ActionDrop}))
				row.Active = 0
				b1Put(t, c, m, b1Key(cidr, 6, true), b1Wire(t, row))
				run("all-miss-fallback-drop", p, srcXDPDrop)
				// Missing row fallback to PASS catches an accidental fail-closed branch.
				b1Put(t, c, r, b1Key(cidr, 6, false), b1Wire(t, api.RuleValue{LogicalID: 0x54020000 + 10, Action: api.ActionPass}))
				b1Erase(t, c, m, b1Key(cidr, 6, true))
				run("missing-row-fallback-pass", p, srcXDPPass)
				row = b1OpenRow(1)
				row.Action[0] = api.ActionDrop
				b1Put(t, c, m, b1Key(cidr, 6, true), b1Wire(t, row))
				run("hit-must-stop", p, srcXDPDrop)
				b1Erase(t, c, r, b1Key(cidr, 6, false))
				// Cold logical bucket: first packet consumes one of 2*rate tokens.
				row.Action[0] = api.ActionRateLimit
				row.Rate[0] = 17
				b1SetRow(t, c, cidr, asm.sel, 6, row)
				bucket := "id_rl_states"
				id := row.RuleID[0]
				key := b1Key(cidr, 6, true)
				b1Erase(t, c, bucket, id)
				run("rate-first-pass", p, srcXDPPass)
				values := make([]struct{ Tokens, Last uint64 }, mustPossibleCPUs(t))
				if err := c.Maps[bucket].Lookup(id, &values); err != nil {
					t.Fatal(err)
				}
				seen := 0
				for _, v := range values {
					if v.Last != 0 {
						seen++
						if v.Tokens != 33 {
							t.Fatalf("B1_RATE winner rate tokens=%d want=33", v.Tokens)
						}
					}
				}
				if seen != 1 {
					t.Fatalf("B1_RATE initialized CPUs=%d", seen)
				}
				// Repeat on the test-run CPU to exhaust the rate-1 winner bucket.
				row.Rate[0] = 1
				b1Put(t, c, m, key, b1Wire(t, row))
				b1Erase(t, c, bucket, id)
				// Only Drop > 0 is asserted here, so EINTR batch replays cannot change the conclusion.
				opts := ebpf.RunOptions{Data: p, Repeat: 64}
				_, err := c.Programs["xdp_firewall_main"].Run(&opts)
				if err != nil {
					t.Fatal(err)
				}
				packets += 64
				counters := b1LogicalCounts(t, c, id)
				if counters.Drop == 0 {
					t.Fatalf("B1_RATE no rate-limited DROP after 64 repeats")
				}
				b1Erase(t, c, r, key)
				b1Erase(t, c, m, key)
				packets += b1ProductionActionMatrix(t, c, cidr, asm.slot, asm.sel, p)
			})
		}
	}
	if t.Failed() {
		t.Fatal("B1_PRODUCTION contains failed assertions")
	}
	// TD-035 给 b1Cases() 增 3 个非首片例（2639→2642），其中 2 个 v4 TCP 例进入本测试的异常循环：2 例 × 2 跑 × 8 装配 = +32。
	if packets != 84872 {
		t.Fatalf("B1_PRODUCTION execution count=%d want=84872", packets)
	}
	t.Logf("B1_PRODUCTION paths=2 assemblies=4 action_FF=0/1 action_packets=1152 packets=%d red=0", packets)
}

// Run the production action branches with both FF settings. PASS and an
// uninitialized candidate action have the same wire value (0); both must
// continue to later stages. Unknown actions retain that same old behavior.
func b1ProductionActionMatrix(t *testing.T, c *ebpf.Collection, cidr bool, slot, sel uint64, p []byte) int {
	t.Helper()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	b1Put(t, c, "devmap", uint32(lo.Index), uint32(lo.Index))
	ctx := [6]uint32{0, 0, 0, uint32(lo.Index), 0, 0} // xdp_md; no attach
	r, m, _, _ := b1Maps(cidr, sel)
	key := b1Key(cidr, 6, true)
	bucket := "id_rl_states"
	id := b1OpenRow(1).RuleID[0]
	on := "config_a"
	if slot == 1 {
		on = "config_b"
	}
	stats := func() [3]uint64 {
		t.Helper()
		var sum [3]uint64
		for j, idx := range []uint32{1, 2, 4} { // dropped, passed, rate-limited
			v := make([]uint64, mustPossibleCPUs(t))
			if err := c.Maps["stats"].Lookup(idx, &v); err != nil {
				t.Fatal(err)
			}
			for _, n := range v {
				sum[j] += n
			}
		}
		return sum
	}
	packets := 0
	for _, ff := range []uint64{0, 1} {
		b1Config(t, c, cidr, slot, sel)
		b1Put(t, c, on, uint32(4), ff)
		pass := srcXDPPass
		if ff == 1 {
			pass = 4 // XDP_REDIRECT; devmap entry above must be usable
		}
		run := func(name string, pkt []byte, repeat, want uint32, matches, drops uint64, wantStats [3]uint64) {
			t.Helper()
			// Keep the whole packet sequence on one per-CPU bucket.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var cpus unix.CPUSet
			if err := unix.SchedGetaffinity(0, &cpus); err != nil {
				t.Fatal(err)
			}
			cpu := 0
			for !cpus.IsSet(cpu) {
				cpu++
			}
			var one unix.CPUSet
			one.Set(cpu)
			if err := unix.SchedSetaffinity(0, &one); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := unix.SchedSetaffinity(0, &cpus); err != nil {
					t.Error(err)
				}
			}()
			before := b1LogicalCounts(t, c, id)
			s0 := stats()
			ctx[1] = uint32(len(pkt)) // data_end must describe the supplied packet
			// Run each packet once: EINTR may replay an entire Repeat > 1 batch.
			var got uint32
			var err error
			for i := uint32(0); i < repeat; i++ {
				got, err = c.Programs["xdp_firewall_main"].Run(&ebpf.RunOptions{Data: pkt, Context: ctx, Repeat: 1})
				packetWant := want
				// The exhaustion batch passes its burst before dropping the rest.
				if repeat > 1 && uint64(i) < uint64(repeat)-drops {
					packetWant = pass
				}
				if err != nil || got != packetWant {
					t.Fatalf("B1_ACTION %s cidr=%v FF=%d packet=%d/%d got=%d want=%d err=%v", name, cidr, ff, i+1, repeat, got, packetWant, err)
				}
			}
			packets += int(repeat)
			if err != nil || got != want {
				t.Fatalf("B1_ACTION %s cidr=%v FF=%d got=%d want=%d err=%v", name, cidr, ff, got, want, err)
			}
			after := b1LogicalCounts(t, c, id)
			var tuple api.RuleValue
			if err := c.Maps[r].Lookup(key, &tuple); err != nil {
				t.Fatal(err)
			}
			if tuple.LogicalID != id || tuple.LogicalReserved != ([12]byte{}) {
				t.Fatalf("B1_ACTION duplicate tuple counters=%+v", tuple)
			}
			delta := stats()
			for i := range delta {
				delta[i] -= s0[i]
			}
			if after.Match-before.Match != matches || after.Drop-before.Drop != drops || delta != wantStats {
				t.Fatalf("B1_ACTION %s FF=%d match/drop=%d/%d want=%d/%d stats=%v want=%v", name, ff, after.Match-before.Match, after.Drop-before.Drop, matches, drops, delta, wantStats)
			}
		}
		for actionIndex, tc := range []struct {
			name   string
			action uint8
		}{{"PASS", api.ActionPass}, {"zero-candidate", api.ConditionValue{}.Action[0]}, {"unknown", 255}} {
			row := b1OpenRow(1)
			row.Action[0] = tc.action
			b1SetRow(t, c, cidr, sel, 6, row)
			run(tc.name+"/clean", p, 1, pass, 1, 0, [3]uint64{0, 1, 0})
			later, laterCond, _, _ := b1Maps(!cidr, sel)
			laterKey := b1Key(!cidr, 6, false)
			// Keep these 48 IDs separate from the prelude fallback IDs 0x54020007/09/0a.
			laterID := uint32(0x54040000 + actionIndex*8 + int(ff)*4 + int(slot)*2 + int(sel))
			if !cidr {
				laterID += 0x10000
			}
			// Cleanup must survive Fatal before the normal removal below. In an exact
			// assembly this is a CIDR protocol-only row, reachable by later CIDR cells.
			t.Cleanup(func() {
				b1Erase(t, c, later, laterKey)
				if cidr {
					b1Erase(t, c, laterCond, laterKey)
				}
			})
			laterBefore := b1LogicalCounts(t, c, laterID)
			if laterBefore != (api.LogicalRuleCounters{}) {
				t.Fatalf("B1_ACTION later DROP ID reused: id=%d counters=%+v", laterID, laterBefore)
			}
			laterRule := api.RuleValue{LogicalID: laterID, Action: api.ActionDrop}
			packet := p
			if cidr {
				laterRule.Pad2[0] = api.RuleHasConditions
				b1Put(t, c, laterCond, laterKey, b1Wire(t, b1AnomalyRow(laterID, 2)))
				b1Put(t, c, on, uint32(0), uint64(1))
				b1Put(t, c, on, uint32(2), uint64(1<<5))
				b1Put(t, c, on, uint32(10), uint64(1))
				packet = append([]byte{}, p...)
				packet[46] = 0x40 // invalid TCP doff -> anomaly DROP
			} else {
				b1Put(t, c, on, uint32(6), uint64(1))
				b1Put(t, c, on, uint32(7), uint64(1<<5))
			}
			b1Put(t, c, later, laterKey, b1Wire(t, laterRule))
			// Ruling 3 / J2: evaluator TestCut54LaterDropIndependentPrediction
			// predicts exact DROP before CIDR, hence CIDR has no counter delta.
			matches := uint64(1)
			if cidr {
				matches = 0
			}
			run(tc.name+"/later-drop", packet, 1, srcXDPDrop, matches, 0, [3]uint64{1, 0, 0})
			counter := b1LogicalCounts(t, c, laterID)
			delta := api.LogicalRuleCounters{Match: counter.Match - laterBefore.Match, Drop: counter.Drop - laterBefore.Drop}
			if delta != (api.LogicalRuleCounters{Match: 1, Drop: 1}) {
				t.Fatalf("B1_ACTION later DROP logical counter delta=%+v want=1/1", delta)
			}
			b1Erase(t, c, later, laterKey)
			if cidr {
				b1Erase(t, c, laterCond, laterKey)
			}

			b1Config(t, c, cidr, slot, sel)
			b1Put(t, c, on, uint32(4), ff)
		}
		row := b1OpenRow(1)
		row.Action[0] = api.ActionDrop
		b1SetRow(t, c, cidr, sel, 6, row)
		run("DROP", p, 1, srcXDPDrop, 1, 1, [3]uint64{1, 0, 0})
		row.Action[0], row.Rate[0] = api.ActionRateLimit, 17
		b1SetRow(t, c, cidr, sel, 6, row)
		b1Erase(t, c, bucket, id)
		run("rate/cold", p, 1, pass, 1, 0, [3]uint64{0, 1, 0})
		values := make([]struct{ Tokens, Last uint64 }, mustPossibleCPUs(t))
		if err := c.Maps[bucket].Lookup(id, &values); err != nil {
			t.Fatal(err)
		}
		initialized := 0
		for _, v := range values {
			if v.Last != 0 {
				initialized++
				if v.Tokens != 33 {
					t.Fatalf("B1_ACTION FF=%d logical tokens=%d want=33", ff, v.Tokens)
				}
			}
		}
		if initialized != 1 {
			t.Fatalf("B1_ACTION initialized buckets=%d want=1", initialized)
		}
		row.Rate[0] = 1
		b1SetRow(t, c, cidr, sel, 6, row)
		b1Erase(t, c, bucket, id)
		run("rate/exhausted", p, 64, srcXDPDrop, 64, 62, [3]uint64{62, 2, 62})
		b1Erase(t, c, r, key)
		b1Erase(t, c, m, key)
		b1Erase(t, c, bucket, id)
	}
	if packets != 144 {
		t.Fatalf("B1_ACTION packets=%d want=144", packets)
	}
	t.Logf("B1_ACTION cidr=%v slot=%d sel=%d FF=0/1 packets=%d red=0", cidr, slot, sel, packets)
	return packets
}
func mustPossibleCPUs(t *testing.T) int {
	t.Helper()
	n, e := ebpf.PossibleCPU()
	if e != nil {
		t.Fatal(e)
	}
	return n
}

func TestB1ConditionMapMemory(t *testing.T) {
	spec, _, _ := loadMainELF(t)
	sum := uint64(0)
	for _, name := range []string{"cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b"} {
		ms := spec.Maps[name]
		if ms == nil || ms.MaxEntries != 500000 || ms.Type != ebpf.Hash || ms.Flags != 1 || ms.ValueSize != 844 {
			t.Fatalf("B1_MAP_SCHEMA %s: %+v", name, ms)
		}
		m, err := ebpf.NewMap(ms)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", m.FD()))
		if err != nil {
			m.Close()
			t.Fatal(err)
		}
		hits := regexp.MustCompile(`(?m)^memlock:\s*(\d+)$`).FindSubmatch(raw)
		if len(hits) != 2 {
			m.Close()
			t.Fatalf("fdinfo memlock missing: %s", raw)
		}
		n, err := strconv.ParseUint(string(hits[1]), 10, 64)
		if err != nil {
			m.Close()
			t.Fatal(err)
		}
		sum += n
		t.Logf("B1_MAP_MEMORY map=%s max_entries=%d value_size=%d source=fdinfo memlock_bytes=%d", name, ms.MaxEntries, ms.ValueSize, n)
		m.Close()
	}
	t.Logf("B1_MAP_MEMORY maps=4 total_memlock_bytes=%d", sum)
}

// These small controls are also the named red points for the independent
// scratch mutants; they do not alter the production code or expected values.
func TestB1ConditionMutationWitness(t *testing.T) {
	path := os.Getenv("XDROP_B1_CONDITION_ELF")
	if path == "" {
		t.Fatal("XDROP_B1_CONDITION_ELF required")
	}
	c := b1Load(t, path)
	b1Put(t, c, "sv4_cidr_trie", make([]byte, 8), uint32(7))
	for _, name := range []string{"flagbit", "icmp-validity", "stop-on-hit", "fallback-pass", "winner-sentinel"} {
		t.Run(name, func(t *testing.T) {
			for _, cidr := range []bool{false, true} {
				kind := "exact"
				if cidr {
					kind = "cidr"
				}
				t.Run(kind, func(t *testing.T) {
					b1Config(t, c, cidr, 0, 0)
					r, m, _, _ := b1Maps(cidr, 0)
					fine, broad := b1Key(cidr, 6, true), b1Key(cidr, 6, false)
					row := b1OpenRow(1)
					row.Action[0] = api.ActionDrop
					row.Rate[0] = 17
					row.RuleID[0] = 0x12345678
					b1SetRow(t, c, cidr, 0, 6, row)
					b1Put(t, c, r, broad, b1Wire(t, api.RuleValue{LogicalID: 0x54020000 + 12, Action: api.ActionPass}))
					defer b1Erase(t, c, r, fine)
					defer b1Erase(t, c, r, broad)
					defer b1Erase(t, c, m, fine)
					input := make([]byte, 64)
					binary.LittleEndian.PutUint16(input, 100)
					input[4] = 64
					input[10] = 1
					if name == "icmp-validity" {
						row.ICMPReq = 1
						b1Put(t, c, m, fine, b1Wire(t, row))
					}
					if name == "winner-sentinel" {
						row.Active = 0
						b1Put(t, c, m, fine, b1Wire(t, row))
						b1Erase(t, c, r, broad)
					}
					if name == "flagbit" || name == "icmp-validity" || name == "winner-sentinel" {
						ret, out, err := c.Programs["b1_condition_"+kind].Test(input)
						if err != nil {
							t.Fatal(err)
						}
						wantRet := uint32(0xb2)
						wantWinner := byte(0)
						if name != "flagbit" {
							wantWinner = 255
						}
						if name == "winner-sentinel" {
							wantRet = 0xb3
						}
						if ret != wantRet || out[12] != wantWinner {
							t.Fatalf("B1_WITNESS %s ret=%x want=%x winner=%d want=%d", name, ret, wantRet, out[12], wantWinner)
						}
						return
					}
					tcp := make([]byte, 20)
					binary.BigEndian.PutUint16(tcp[2:], 80)
					tcp[12] = 0x50
					packet := b1Frame(false, 6, tcp, 0)
					copy(packet[26:30], []byte{10, 1, 2, 3})
					copy(packet[30:34], []byte{100, 64, 2, 3})
					want := srcXDPDrop
					if name == "fallback-pass" {
						b1Erase(t, c, m, fine)
						want = srcXDPPass
					}
					ret, _, err := c.Programs["xdp_firewall_main"].Test(packet)
					if err != nil || ret != want {
						t.Fatalf("B1_WITNESS %s verdict=%d want=%d err=%v", name, ret, want, err)
					}
				})
			}
		})
	}
	if t.Failed() {
		t.Fatal("B1_WITNESS failed")
	}
	t.Log("B1_WITNESS controls=5 paths=2 packets=10 red=0")
}
