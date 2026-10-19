package api

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"testing"

	"github.com/littlewolf9527/xdrop/node/agent/eval"
)

// node/bpf/xdrop.h defines a packed tcphdr ending at window: 2+2+4+4+1+1+2.
// The main-entry tcp+1 bound uses this 16-byte definition, not standard TCP's
// 20-byte minimum used by the separate tiny-first-fragment anomaly predicate.
const cut53MainTCPBytes = 16

// Main-entry ABORTED domain, independently computed from raw IP bytes. IPv6
// extension-walk failures leave L4 unavailable and must not be called ABORTED.
func cut53MainEntryAborts(ip []byte) (bool, error) {
	if len(ip) == 0 {
		return false, fmt.Errorf("empty IP fixture")
	}
	offset, proto, nonfirst := 0, byte(0), false
	switch ip[0] >> 4 {
	case 4:
		if len(ip) < 20 {
			return true, nil
		}
		offset, proto = int(ip[0]&15)*4, ip[9]
		nonfirst = binary.BigEndian.Uint16(ip[6:8])&8191 != 0
		nonfirst = nonfirst || offset < 20
		if offset > len(ip) {
			return true, nil
		}
	case 6:
		if len(ip) < 40 {
			return true, nil
		}
		offset, proto = 40, ip[6]
		// xdrop.h IPV6_EXT_MAX_DEPTH is six. Walk only the on-wire lengths.
	walk:
		for depth := 0; depth < 6; depth++ {
			switch proto {
			case 0, 43, 60, 51:
				if offset+2 > len(ip) {
					return false, nil
				}
				length := (int(ip[offset+1]) + 1) * 8
				if proto == 51 {
					length = (int(ip[offset+1]) + 2) * 4
				}
				proto, offset = ip[offset], offset+length
				if offset > len(ip) {
					return false, nil
				}
			case 44:
				if offset+8 > len(ip) {
					return false, nil
				}
				nonfirst = binary.BigEndian.Uint16(ip[offset+2:offset+4])&0xfff8 != 0
				proto, offset = ip[offset], offset+8
				if nonfirst {
					break walk
				}
			default:
				break walk
			}
		}
	default:
		return false, fmt.Errorf("unsupported fixture IP version %d", ip[0]>>4)
	}
	if nonfirst {
		return false, nil
	}
	need := 0
	if proto == 6 {
		need = cut53MainTCPBytes
	} else if proto == 17 {
		need = 8 // packed udphdr in node/bpf/xdrop.h
	}
	return offset+need > len(ip), nil
}

type cut53XSightFixture struct {
	Name, Hex string
	Invalid   bool `json:"expected_is_invalid"`
	Bad       bool `json:"expected_is_bad_fragment"`
}

func cut53XSightAbortNames(fixtures []cut53XSightFixture) ([]string, error) {
	var names []string
	for _, f := range fixtures {
		ip, err := hex.DecodeString(f.Hex)
		if err != nil {
			return nil, err
		}
		abort, err := cut53MainEntryAborts(ip)
		if err != nil {
			return nil, err
		}
		if abort {
			names = append(names, f.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// Test-only injection: literal-based ELF fixtures need not have initialized
// the deferred ledger. Preserve every existing debt when adding another one.
func cut53SeedPendingLogical(h *Handlers, ids ...uint32) {
	if h.pendingLogicalIDs == nil {
		h.pendingLogicalIDs = make(map[uint32]bool)
	}
	for _, id := range ids {
		h.pendingLogicalIDs[id] = true
	}
}

// Independently extract the S5 witness from Ethernet/IPv4 bytes. No production
// parser, encoded condition row, or observed kernel verdict supplies attributes.
func cut53IPv4Attributes(frame []byte) (eval.B1Packet, error) {
	var out eval.B1Packet
	if len(frame) < 34 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 || frame[14]>>4 != 4 {
		return out, fmt.Errorf("fixture needs a complete Ethernet/IPv4 header")
	}
	ip := frame[14:]
	hdr := int(ip[0]&15) * 4
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	frag := binary.BigEndian.Uint16(ip[6:8])
	offset, more := frag&8191, frag&0x2000 != 0
	out.Src = netip.AddrFrom4([4]byte(ip[12:16]))
	out.Dst = netip.AddrFrom4([4]byte(ip[16:20]))
	out.Proto, out.Length, out.TTL, out.DSCP = ip[9], uint16(total), ip[8], ip[1]>>2
	out.NonFirst = offset != 0
	out.FragClass = uint8((frag >> 12) & 6)
	if out.NonFirst {
		out.FragClass |= 1
	}
	if hdr < 20 {
		out.Anomaly |= 2
	} else {
		if total < hdr {
			out.Anomaly |= 2
		}
		payload := max(0, total-hdr)
		if more || offset != 0 {
			if int(offset)*8+payload > 65535 || more && offset == 0 &&
				(out.Proto == 6 && payload < 20 || out.Proto == 17 && payload < 8) {
				out.Anomaly |= 1
			}
		} else if out.Proto == 6 && len(ip) >= hdr+14 && ip[hdr+12]>>4 < 5 {
			out.Anomaly |= 2
		}
	}
	if out.Proto == 6 && offset == 1 {
		out.Anomaly |= 8
	}
	if len(ip) < total || len(ip)-total > max(0, 60-14-total) {
		out.Anomaly |= 4
	}
	if hdr >= 20 && !out.NonFirst && len(ip) >= hdr+4 && (out.Proto == 6 || out.Proto == 17) {
		out.Sport = binary.BigEndian.Uint16(ip[hdr : hdr+2])
		out.Dport = binary.BigEndian.Uint16(ip[hdr+2 : hdr+4])
		if out.Proto == 6 && len(ip) >= hdr+14 {
			out.Flags = ip[hdr+13]
		}
	}
	if hdr >= 20 && !out.NonFirst && out.Proto == 1 && len(ip) >= hdr+2 {
		out.ICMPValid, out.ICMPType, out.ICMPCode = true, ip[hdr], ip[hdr+1]
	}
	return out, nil
}

func TestCut53S5RawPacketWitness(t *testing.T) {
	frame, err := hex.DecodeString("0000000000000000000000000800450000270000200040060000c00002010a010001303901bb00000000000000005002000000000000")
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := cut53IPv4Attributes(frame)
	if err != nil || attrs.Anomaly != 1 || attrs.Length != 39 || attrs.FragClass != 2 || attrs.NonFirst || attrs.Dport != 443 || attrs.Sport != 12345 || attrs.Flags != 2 {
		t.Fatalf("S5 raw packet attributes=%+v err=%v", attrs, err)
	}
	if len(frame)-14-20 != 20 {
		t.Fatal("S5 physical TCP bytes must pass the main-entry guard")
	}
	// Changing only declared payload from 19 to 20 removes the bad-fragment bit.
	binary.BigEndian.PutUint16(frame[16:18], 40)
	attrs, err = cut53IPv4Attributes(frame)
	if err != nil || attrs.Anomaly != 0 || attrs.Length != 40 {
		t.Fatalf("S5 payload boundary attributes=%+v err=%v", attrs, err)
	}
	t.Log("CUT53_S5_RAW payload19_bad=1 payload20_bad=0 physical_tcp_bytes=20")
}

func TestCut53PendingFixtureInitialization(t *testing.T) {
	h := &Handlers{}
	cut53SeedPendingLogical(h, 90)
	cut53SeedPendingLogical(h, 91)
	if len(h.pendingLogicalIDs) != 2 || !h.pendingLogicalIDs[90] || !h.pendingLogicalIDs[91] {
		t.Fatal("pending fixture must initialize nil and preserve existing debt")
	}
}

func TestCut53MainEntryRawBounds(t *testing.T) {
	t.Run("ihl4_tcp_short", func(t *testing.T) {
		ip := make([]byte, 20)
		ip[0], ip[9] = 0x44, 6
		if got, err := cut53MainEntryAborts(ip); err != nil || got {
			t.Fatalf("IHL=4 short TCP must have no L4: abort=%v err=%v", got, err)
		}
	})
	for _, tc := range []struct {
		name      string
		proto     byte
		available int
		fragment  uint16
		want      bool
	}{
		{"tcp15", 6, 15, 0, true}, {"tcp16", 6, 16, 0, false},
		{"tcp19_first", 6, 19, 0x2000, false}, {"tcp20", 6, 20, 0, false},
		{"udp7_first", 17, 7, 0x2000, true}, {"udp8", 17, 8, 0, false},
		{"tcp_nonfirst", 6, 0, 1, false}, {"udp_nonfirst", 17, 0, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip := make([]byte, 20+tc.available)
			ip[0], ip[9] = 0x45, tc.proto
			binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
			binary.BigEndian.PutUint16(ip[6:8], tc.fragment)
			got, err := cut53MainEntryAborts(ip)
			if err != nil || got != tc.want {
				t.Fatalf("raw main-entry bound abort=%v want=%v err=%v", got, tc.want, err)
			}
		})
	}
	for _, ip := range [][]byte{{0x45}, {0x60}, append([]byte{0x4f}, make([]byte, 19)...)} {
		if got, err := cut53MainEntryAborts(ip); err != nil || !got {
			t.Fatalf("truncated L3/IHL must abort: %x got=%v err=%v", ip, got, err)
		}
	}
	t.Log("CUT53_MAIN_RAW tcp_bound=16 udp_bound=8 transport_cells=8 l3_cells=3 tiny_tcp19=reachable")
}
