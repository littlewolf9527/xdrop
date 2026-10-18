//go:build linux && integration

package bpf

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/littlewolf9527/xdrop/node/agent/api"
)

func TestCut53APIICMPFourClasses(t *testing.T) {
	tables := cut53APITables(t)
	packets := 0
	for _, isCIDR := range []bool{false, true} {
		for config := uint64(0); config < 2; config++ {
			for rule := uint64(0); rule < 2; rule++ {
				h, c := cut53APIFixture(t)
				base := b1ParityBase("icmp-zero", false, 1)
				base.rules[0].ICMPType, base.rules[0].ICMPCode = b1ParityText("0"), b1ParityText("0")
				base.packet[34], base.packet[35] = 0, 0
				base.attrs.ICMPType, base.attrs.ICMPCode = 0, 0
				cut53APIInstall(t, h, c, cut53APIIntent(base, isCIDR), config, rule)
				for _, class := range []string{"valid-zero", "truncated", "nonfirst", "bad-ihl"} {
					tc := base
					tc.name = "icmp/" + class
					tc.packet = append([]byte(nil), base.packet...)
					switch class {
					case "truncated":
						tc.packet = tc.packet[:35] // One ICMP octet cannot supply type + code.
						binary.BigEndian.PutUint16(tc.packet[16:], 21)
						tc.attrs.Length, tc.attrs.ICMPValid = 21, false
					case "nonfirst":
						binary.BigEndian.PutUint16(tc.packet[20:], 2)
						tc.attrs.NonFirst, tc.attrs.ICMPValid, tc.attrs.FragClass = true, false, 1
					case "bad-ihl":
						tc.packet[14] = 0x44
						tc.attrs.ICMPValid, tc.attrs.Anomaly = false, 2
					}
					cut53APIJudge(t, c, tables, tc, isCIDR)
					packets++
				}
			}
		}
	}
	t.Logf("CUT53_ICMP_FOUR_CLASSES classes=4 assemblies=4 kinds=2 packets=%d valid_zero_hits=8 invalid_zero_misses=24", packets)
}

// Invalid extraction eliminates only candidates which constrain ICMP fields.
// Keep an unconstrained candidate in the SAME tuple to witness that distinction.
func TestCut53APIICMPUnconstrainedCandidate(t *testing.T) {
	tables := cut53APITables(t)
	packets := 0
	for _, isCIDR := range []bool{false, true} {
		for _, v6 := range []bool{false, true} {
			for config := uint64(0); config < 2; config++ {
				for rule := uint64(0); rule < 2; rule++ {
					h, c := cut53APIFixture(t)
					proto, offset := byte(1), 34
					if v6 {
						proto, offset = 58, 54
					}
					base := b1ParityBase("icmp-unconstrained", v6, proto)
					base.rules[0].ICMPType, base.rules[0].ICMPCode = b1ParityText("0"), b1ParityText("0")
					fallback := base.rules[0]
					fallback.ID, fallback.LogicalID, fallback.ICMPType, fallback.ICMPCode = "unconstrained", 102, nil, nil
					base.rules = append(base.rules, fallback)
					base.packet[offset], base.packet[offset+1] = 0, 0
					base.attrs.ICMPType, base.attrs.ICMPCode = 0, 0
					cut53APIInstall(t, h, c, cut53APIIntent(base, isCIDR), config, rule)
					for _, class := range []string{"valid-zero", "truncated", "nonfirst"} {
						tc := base
						tc.name = fmt.Sprintf("icmp-fallback/%s/v6=%v", class, v6)
						tc.packet = append([]byte(nil), base.packet...)
						if class == "truncated" {
							tc.packet = tc.packet[:offset+1]
							tc.attrs.Length, tc.attrs.ICMPValid = uint16(offset-14+1), false
							if v6 {
								binary.BigEndian.PutUint16(tc.packet[18:], 1)
							} else {
								binary.BigEndian.PutUint16(tc.packet[16:], 21)
							}
						}
						if class == "nonfirst" {
							tc.attrs.NonFirst, tc.attrs.ICMPValid, tc.attrs.FragClass = true, false, 1
							if v6 {
								tc.attrs.FragClass = 0 // Existing IPv6 Fragment extraction leaves this legacy field zero.
								fragment := []byte{58, 0, 0, 8, 0, 0, 0, 1}
								tc.packet = append(append(append([]byte(nil), tc.packet[:54]...), fragment...), tc.packet[54:]...)
								tc.packet[20] = 44
								binary.BigEndian.PutUint16(tc.packet[18:], uint16(len(tc.packet)-54))
								tc.attrs.Length = uint16(len(tc.packet) - 14)
							} else {
								binary.BigEndian.PutUint16(tc.packet[20:], 2)
							}
						}
						want := uint32(101)
						if class != "valid-zero" {
							want = 102
						}
						before, err := api.ReadLogicalRuleCounters(c.Maps["id_counts"], want)
						if err != nil {
							t.Fatal(err)
						}
						cut53APIJudge(t, c, tables, tc, isCIDR)
						after, err := api.ReadLogicalRuleCounters(c.Maps["id_counts"], want)
						if err != nil || after.Match-before.Match != 1 || after.Drop-before.Drop != 1 {
							t.Fatalf("ICMP same-group literal winner class=%s v6=%v id=%d before=%+v after=%+v err=%v", class, v6, want, before, after, err)
						}
						packets++
					}
				}
			}
		}
	}
	t.Logf("CUT53_ICMP_UNCONSTRAINED packets=%d valid_zero_constrained_hits=16 invalid_unconstrained_hits=32 v6_fragment_header=covered", packets)
}

// Legacy min/max use declared IP lengths, including the existing IPv6 wrap.
// The expected decision is supplied by the independent intent evaluator.
func TestCut53APILegacyLengthSource(t *testing.T) {
	tables := cut53APITables(t)
	packets := 0
	for _, isCIDR := range []bool{false, true} {
		for _, v6 := range []bool{false, true} {
			h, c := cut53APIFixture(t)
			for _, bounds := range [][2]uint16{{0, 39}, {40, 0}, {36, 100}, {1, 65535}} {
				base := b1ParityBase("legacy-length", v6, 6)
				base.rules[0].PktLenMin, base.rules[0].PktLenMax = bounds[0], bounds[1]
				cut53APIInstall(t, h, c, cut53APIIntent(base, isCIDR), 0, 0)
				for _, n := range []uint16{0, 1, 35, 36, 39, 40, 41, 99, 100, 101, 65534, 65535} {
					tc := base
					tc.name = fmt.Sprintf("legacy-length/%v/%d/v6=%v", bounds, n, v6)
					tc.packet = append([]byte(nil), base.packet...)
					tc.attrs.Length = n
					if v6 {
						payload := uint16(uint32(n) + 65536 - 40)
						binary.BigEndian.PutUint16(tc.packet[18:], payload)
						tc.attrs.IPv6PayloadLength = &payload
					} else {
						binary.BigEndian.PutUint16(tc.packet[16:], n)
					}
					cut53APIJudge(t, c, tables, tc, isCIDR)
					packets++
				}
			}
		}
	}
	t.Logf("CUT53_LEGACY_LENGTH packets=%d rules=4 declared_lengths=12 families=2 kinds=2 ipv6_payload_65535_wrap39=covered", packets)
}
