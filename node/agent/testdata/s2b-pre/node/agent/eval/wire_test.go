package eval

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
)

func encodeTuple(k Tuple) []byte {
	b := make([]byte, 40)
	if k.Src.IsValid() {
		a := k.Src.As16()
		copy(b[:16], a[:])
	}
	if k.Dst.IsValid() {
		a := k.Dst.As16()
		copy(b[16:32], a[:])
	}
	binary.BigEndian.PutUint16(b[32:34], k.Sport)
	binary.BigEndian.PutUint16(b[34:36], k.Dport)
	b[36] = k.Proto
	return b
}
func encodeCIDR(k CIDRTuple) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], k.SrcID)
	binary.LittleEndian.PutUint32(b[4:8], k.DstID)
	binary.BigEndian.PutUint16(b[8:10], k.Sport)
	binary.BigEndian.PutUint16(b[10:12], k.Dport)
	b[12] = k.Proto
	return b
}
func encodeValue(r Rule) []byte {
	b := make([]byte, 32)
	b[0] = 1
	if r.Rate > 0 {
		b[0] = 2
	}
	b[1] = r.FlagsMask
	b[2] = r.FlagsValue
	b[3] = r.Anomaly
	binary.LittleEndian.PutUint32(b[4:8], r.Rate)
	binary.LittleEndian.PutUint16(b[24:26], r.MinLength)
	binary.LittleEndian.PutUint16(b[26:28], r.MaxLength)
	return b
}
func encodePrefix(p Prefix) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, uint32(p.Network.Bits()))
	a := p.Network.Addr().As4()
	copy(b[4:], a[:])
	return b
}
func makePacket(p Packet) []byte {
	// Full Ethernet + IPv4 buffer; L3 length, flags and ports come from the
	// common fixture. No VLAN, no fragment, no live-frame flags, no real IPs.
	b := make([]byte, 14+int(p.Length))
	b[12] = 8
	b[13] = 0
	b[14] = 0x45
	binary.BigEndian.PutUint16(b[16:18], p.Length)
	b[22] = 64
	b[23] = p.Proto
	s, d := p.Src.As4(), p.Dst.As4()
	copy(b[26:30], s[:])
	copy(b[30:34], d[:])
	binary.BigEndian.PutUint16(b[34:36], p.Sport)
	binary.BigEndian.PutUint16(b[36:38], p.Dport)
	if p.Proto == 6 {
		b[46] = 0x50
		if p.Anomaly&2 != 0 {
			b[46] = 0x40
		}
		b[47] = p.Flags
	} else if p.Proto == 17 {
		binary.BigEndian.PutUint16(b[38:40], p.Length-20)
	}
	return b
}

type golden struct{ Map, Key, Value string }

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestWireVectors(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range fixtures() {
		for stage, rules := range map[Stage][]Rule{Whitelist: f.Rules.Whitelist, Exact: f.Rules.Exact, CIDR: f.Rules.CIDR} {
			for _, r := range rules {
				want, ok := wireGoldens[r.ID]
				if !ok {
					t.Fatalf("missing independent byte vector: %s", r.ID)
				}
				seen[r.ID] = true
				t.Run(r.ID, func(t *testing.T) {
					key, value := encodeTuple(r.Key), encodeValue(r)
					name := "blacklist"
					if stage == Whitelist {
						name = "whitelist"
						value = []byte{1}
					}
					if stage == CIDR {
						name = "cidr_blacklist"
						key = encodeCIDR(r.CIDRKey)
					}
					if name != want.Map || !bytes.Equal(key, unhex(want.Key)) || !bytes.Equal(value, unhex(want.Value)) {
						t.Fatalf("wire got map=%s key=%x value=%x; want=%+v", name, key, value, want)
					}
				})
			}
		}
	}
	if len(seen) == 0 || len(seen) != len(wireGoldens) {
		t.Fatalf("vector coverage used=%d defined=%d", len(seen), len(wireGoldens))
	}
	for _, v := range []struct {
		prefix string
		hex    string
	}{{"192.0.2.0/16", "10000000c0000200"}, {"192.0.2.0/24", "18000000c0000200"}} {
		if got := encodePrefix(Prefix{Network: netip.MustParsePrefix(v.prefix)}); !bytes.Equal(got, unhex(v.hex)) {
			t.Fatalf("LPM key=%x want=%s", got, v.hex)
		}
	}
	t.Logf("independent_rule_vectors=%d prefix_vectors=2", len(seen))
}
func TestPacketVectors(t *testing.T) {
	for _, f := range fixtures() {
		b := makePacket(f.Packet)
		if len(b) != 14+int(f.Packet.Length) || b[14] != 0x45 || b[20] != 0 || b[21] != 0 || !bytes.Equal(b[12:14], []byte{8, 0}) {
			t.Fatalf("%s: packet framing", f.Name)
		}
		if got := binary.BigEndian.Uint16(b[16:18]); got != f.Packet.Length {
			t.Fatalf("%s: length", f.Name)
		}
		if f.Packet.Proto == 6 {
			want := byte(0x50)
			if f.Packet.Anomaly == 2 {
				want = 0x40
			}
			if b[46] != want || b[47] != f.Packet.Flags {
				t.Fatalf("%s: TCP anomaly/flags", f.Name)
			}
		}
	}
}

// Frozen C-layout vectors: explicit bytes, including action, rate and padding.
var wireGoldens = map[string]golden{
	"coarse-drop":         {"blacklist", "00000000000000000000000000000000000000000000000000000000000000000000000011000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"fine-rate":           {"blacklist", "00000000000000000000ffffc000020a0000000000000000000000000000000004d201bb11000000", "02000000e8030000000000000000000000000000000000000000000000000000"},
	"syn-only":            {"blacklist", "00000000000000000000ffffc000020a00000000000000000000ffffc633641404d201bb06000000", "0102020000000000000000000000000000000000000000000000000000000000"},
	"after-flags":         {"blacklist", "00000000000000000000000000000000000000000000000000000000000000000000000006000000", "02000000e8030000000000000000000000000000000000000000000000000000"},
	"too-short":           {"blacklist", "00000000000000000000ffffc000020a00000000000000000000ffffc633641404d201bb06000000", "0100000000000000000000000000000000000000000000003d00000000000000"},
	"after-min":           {"blacklist", "00000000000000000000000000000000000000000000000000000000000000000000000006000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"too-long":            {"blacklist", "00000000000000000000ffffc000020a00000000000000000000ffffc633641404d201bb06000000", "01000000000000000000000000000000000000000000000000003b0000000000"},
	"after-max":           {"blacklist", "00000000000000000000000000000000000000000000000000000000000000000000000006000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"inclusive":           {"blacklist", "00000000000000000000ffffc000020a00000000000000000000ffffc633641404d201bb06000000", "0100000000000000000000000000000000000000000000003c003c0000000000"},
	"later":               {"blacklist", "00000000000000000000000000000000000000000000000000000000000000000000000006000000", "02000000e8030000000000000000000000000000000000000000000000000000"},
	"udp-flags-ignored":   {"blacklist", "00000000000000000000000000000000000000000000000000000000000000000000000011000000", "0102020000000000000000000000000000000000000000000000000000000000"},
	"coarse-rate":         {"blacklist", "00000000000000000000000000000000000000000000000000000000000000000000000011000000", "02000000e8030000000000000000000000000000000000000000000000000000"},
	"fine-drop":           {"blacklist", "00000000000000000000ffffc000020a0000000000000000000000000000000004d201bb11000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"short-drop":          {"cidr_blacklist", "10000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"long-drop":           {"cidr_blacklist", "18000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"short-must-not-win":  {"cidr_blacklist", "10000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"long-syn":            {"cidr_blacklist", "18000000000000000000000000000000", "0102020000000000000000000000000000000000000000000000000000000000"},
	"clear-selected-id":   {"cidr_blacklist", "00000000000000000000000006000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"keep-selected-id":    {"cidr_blacklist", "18000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"only-whitelist":      {"whitelist", "00000000000000000000ffffc000020a000000000000000000000000000000000000000000000000", "01"},
	"blacklist-behind-wl": {"blacklist", "00000000000000000000ffffc000020a00000000000000000000ffffc633641404d201bb06000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"exact-first":         {"blacklist", "00000000000000000000000000000000000000000000000000000000000000000000000006000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"cidr-after-exact":    {"cidr_blacklist", "18000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"anomaly-after-cidr":  {"blacklist", "00000000000000000000ffffc000020a00000000000000000000ffffc633641404d201bb06000000", "0100000200000000000000000000000000000000000000000000000000000000"},
	"ordinary-cidr-first": {"cidr_blacklist", "18000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000"},
	"anomaly-exact-first": {"blacklist", "00000000000000000000ffffc000020a00000000000000000000ffffc633641404d201bb06000000", "0100000200000000000000000000000000000000000000000000000000000000"},
	"anomaly-cidr-second": {"cidr_blacklist", "18000000000000000000000000000000", "0100000200000000000000000000000000000000000000000000000000000000"},
	"wrong-anomaly-bit":   {"blacklist", "00000000000000000000ffffc000020a00000000000000000000ffffc633641404d201bb06000000", "0100000100000000000000000000000000000000000000000000000000000000"},
	"anomaly-cidr":        {"cidr_blacklist", "18000000000000000000000000000000", "0100000200000000000000000000000000000000000000000000000000000000"},
	"udp-miss":            {"blacklist", "00000000000000000000000000000000000000000000000000000000000000000000000011000000", "0100000000000000000000000000000000000000000000000000000000000000"},
}
