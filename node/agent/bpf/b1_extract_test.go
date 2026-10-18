//go:build linux && integration

package bpf

// The test-only probe copies main's actual extraction and initializers. Its
// attrs/cidr_attrs entries stop before lookups; anomaly stops before the old
// short-L4 early returns. This is not evidence of production lookup wiring.
// Production old-field behavior is separately tested by PktAttrsSourceMain.
import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

type b1Case struct {
	name   string
	packet []byte
	attrs  [11]byte
	abort  bool
}

func b1Frame(v6 bool, proto byte, payload []byte, vlans int) []byte {
	h := 20
	ether := uint16(0x0800)
	if v6 {
		h = 40
		ether = 0x86dd
	}
	l2 := 14 + 4*vlans
	p := make([]byte, l2+h+len(payload))
	if vlans > 0 {
		binary.BigEndian.PutUint16(p[12:14], 0x8100)
		for i := 0; i < vlans; i++ {
			next := ether
			if i+1 < vlans {
				next = 0x8100
			}
			binary.BigEndian.PutUint16(p[16+4*i:18+4*i], next)
		}
	} else {
		binary.BigEndian.PutUint16(p[12:14], ether)
	}
	ip := p[l2:]
	if v6 {
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(payload)))
		ip[6] = proto
		ip[7] = 64
	} else {
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(h+len(payload)))
		ip[8] = 64
		ip[9] = proto
	}
	copy(ip[h:], payload)
	return p
}

func b1Base(v6 bool, proto byte, payload []byte) b1Case {
	h := 20
	if v6 {
		h = 40
	}
	c := b1Case{packet: b1Frame(v6, proto, payload, 0)}
	binary.LittleEndian.PutUint16(c.attrs[:2], uint16(h+len(payload)))
	c.attrs[4] = 64
	if proto == 1 || proto == 58 {
		if len(payload) >= 2 {
			c.attrs[6] = payload[0]
			c.attrs[7] = payload[1]
			c.attrs[9] = 1
		}
	}
	if proto == 6 && len(payload) >= 20 {
		c.attrs[2] = payload[13]
	}
	return c
}

func b1Cases() []b1Case {
	var cases []b1Case
	for _, v6 := range []bool{false, true} {
		proto := byte(1)
		h := 20
		if v6 {
			proto = 58
			h = 40
		}
		for n := 0; n < 256; n++ {
			for _, field := range []string{"ttl", "dscp", "icmp_type", "icmp_code", "flags"} {
				c := b1Base(v6, proto, []byte{0, 0})
				ip := c.packet[14:]
				switch field {
				case "ttl":
					if v6 {
						ip[7] = byte(n)
					} else {
						ip[8] = byte(n)
					}
					c.attrs[4] = byte(n)
				case "dscp":
					if v6 {
						ip[0] = 0x60 | byte(n>>4)
						ip[1] = byte(n << 4)
					} else {
						ip[1] = byte(n)
					}
					c.attrs[5] = byte(n >> 2)
				case "icmp_type":
					ip[h], ip[h+1] = byte(n), 0xa5
					c.attrs[6], c.attrs[7] = byte(n), 0xa5
				case "icmp_code":
					ip[h], ip[h+1] = 0x5a, byte(n)
					c.attrs[6], c.attrs[7] = 0x5a, byte(n)
				case "flags":
					tcp := make([]byte, 20)
					tcp[12] = 0x50
					tcp[13] = byte(n)
					c = b1Base(v6, 6, tcp)
				}
				c.name = fmt.Sprintf("v6=%t/%s/%d", v6, field, n)
				cases = append(cases, c)
			}
		}
		for _, size := range []int{0, 1, 2} {
			c := b1Base(v6, proto, make([]byte, size))
			c.name = fmt.Sprintf("v6=%t/icmp-bytes/%d", v6, size)
			cases = append(cases, c)
		}
		// Full length mismatch / min-frame-padding boundary, including VLAN/QinQ.
		for vlan := 0; vlan <= 2; vlan++ {
			for _, total := range []int{14 + 4*vlan + h + 1, 14 + 4*vlan + h + 2, 60, 61, 100} {
				c := b1Base(v6, proto, []byte{0, 0})
				p := b1Frame(v6, proto, []byte{0, 0}, vlan)
				if total < len(p) {
					p = p[:total]
					c.attrs[9] = 0
				} else {
					p = append(p, make([]byte, total-len(p))...)
				}
				c.packet = p
				c.abort = total < 14+4*vlan+h
				c.name = fmt.Sprintf("v6=%t/vlan%d/frame%d", v6, vlan, total)
				if total < 14+4*vlan+h+2 || (total > 14+4*vlan+h+2 && total > 60) {
					c.attrs[3] = 4
				}
				cases = append(cases, c)
			}
		}
		// TCP doff scope: direct TCP is checked, IPv6 extensions are not.
		for _, doff := range []byte{4, 5, 15} {
			tcp := make([]byte, 20)
			tcp[12] = doff << 4
			c := b1Base(v6, 6, tcp)
			if doff == 4 {
				c.attrs[3] = 2
			}
			c.name = fmt.Sprintf("v6=%t/direct-doff%d", v6, doff)
			cases = append(cases, c)
			if v6 {
				ext := append([]byte{6, 0, 0, 0, 0, 0, 0, 0}, tcp...)
				c = b1Base(true, 0, ext)
				c.name = fmt.Sprintf("v6/hbh-doff%d", doff)
				cases = append(cases, c)
			}
		}
	}
	for class := 0; class < 8; class++ {
		tcp := make([]byte, 20)
		tcp[12] = 0x50
		c := b1Base(false, 6, tcp)
		frag := uint16(0)
		if class&4 != 0 {
			frag |= 0x4000
		}
		if class&2 != 0 {
			frag |= 0x2000
		}
		if class&1 != 0 {
			frag |= 2
		}
		binary.BigEndian.PutUint16(c.packet[20:22], frag)
		c.attrs[8] = byte(class)
		c.name = fmt.Sprintf("fragment-class/%d", class)
		cases = append(cases, c)
	}
	for _, proto := range []byte{6, 17} {
		for _, off := range []uint16{0, 1, 2} {
			l4 := make([]byte, 20)
			l4[12] = 0x50
			c := b1Base(false, proto, l4)
			binary.BigEndian.PutUint16(c.packet[20:22], off)
			if off > 0 {
				c.attrs[8] = 1
			}
			if proto == 6 && off == 1 {
				c.attrs[3] = 8
			}
			c.name = fmt.Sprintf("offset/proto%d/%d", proto, off)
			cases = append(cases, c)
		}
	}
	for _, off := range []uint16{0, 1, 2} {
		c := b1Base(false, 1, []byte{8, 7})
		binary.BigEndian.PutUint16(c.packet[20:22], off|0x2000)
		c.attrs[8] = 2
		if off > 0 {
			c.attrs[8] = 3
			c.attrs[6] = 0
			c.attrs[7] = 0
			c.attrs[9] = 0
		}
		c.name = fmt.Sprintf("v4/icmp-fragment/%d", off)
		cases = append(cases, c)
		ext := []byte{58, 0, 0, 0, 0, 0, 0, 0, 8, 7}
		binary.BigEndian.PutUint16(ext[2:4], off<<3)
		c = b1Base(true, 44, ext)
		c.name = fmt.Sprintf("v6/icmp-fragment/%d", off)
		cases = append(cases, c)
	}

	for class := 0; class < 8; class++ {
		tcp := make([]byte, 20)
		tcp[12] = 0x40
		c := b1Base(false, 6, tcp)
		frag := uint16(0)
		if class&4 != 0 {
			frag |= 0x4000
		}
		if class&2 != 0 {
			frag |= 0x2000
		}
		if class&1 != 0 {
			frag |= 2
		}
		binary.BigEndian.PutUint16(c.packet[20:22], frag)
		c.attrs[8] = byte(class)
		if class == 0 || class == 4 {
			c.attrs[3] = 2
		}
		c.name = fmt.Sprintf("fragment-doff4/%d", class)
		cases = append(cases, c)
	}
	for _, off := range []uint16{0, 1, 2} {
		tcp := make([]byte, 20)
		tcp[12] = 0x40
		ext := append([]byte{6, 0, 0, 0, 0, 0, 0, 0}, tcp...)
		binary.BigEndian.PutUint16(ext[2:4], off<<3)
		c := b1Base(true, 44, ext)
		c.name = fmt.Sprintf("v6/tcp-fragment-doff4/%d", off)
		cases = append(cases, c)
	}
	for _, v6 := range []bool{false, true} {
		proto := byte(58)
		if v6 {
			proto = 1
		}
		c := b1Base(v6, proto, []byte{8, 7})
		c.attrs[6] = 0
		c.attrs[7] = 0
		c.attrs[9] = 0
		c.name = fmt.Sprintf("v6=%t/wrong-icmp-protocol", v6)
		cases = append(cases, c)
	}

	// Wider anomaly arithmetic while pkt_len deliberately keeps its u16 wrap.
	c := b1Base(true, 58, []byte{0, 0})
	binary.BigEndian.PutUint16(c.packet[18:20], 65535)
	binary.LittleEndian.PutUint16(c.attrs[:2], 39)
	c.attrs[3] = 4
	c.packet = append(c.packet, make([]byte, 60-len(c.packet))...)
	c.name = "v6/65535-plus40"
	cases = append(cases, c)
	for _, tc := range []struct {
		name string
		v6   bool
		mf   bool
	}{
		{"td035/v4-last-flags", false, false},
		{"td035/v4-middle-flags", false, true},
		{"td035/v6-last-flags", true, false},
	} {
		payload := make([]byte, 20)
		payload[12], payload[13] = 0x50, 0x12
		c := b1Base(tc.v6, 6, payload)
		if tc.v6 {
			ext := append([]byte{6, 0, 0, 16, 0, 0, 0, 0}, payload...)
			c = b1Base(true, 44, ext)
		} else {
			off := uint16(2)
			if tc.mf {
				off |= 0x2000
			}
			binary.BigEndian.PutUint16(c.packet[20:22], off)
			c.attrs[8] = 1
			if tc.mf {
				c.attrs[8] = 3
			}
		}
		c.name = tc.name
		c.attrs[2] = 0
		cases = append(cases, c)
	}
	for i := range cases {
		c := &cases[i]
		c.attrs[10] = 1
		if c.abort {
			continue
		}
		l3 := 14
		ether := binary.BigEndian.Uint16(c.packet[12:14])
		for ether == 0x8100 || ether == 0x88a8 {
			ether = binary.BigEndian.Uint16(c.packet[l3+2 : l3+4])
			l3 += 4
		}
		if ether == 0x0800 && binary.BigEndian.Uint16(c.packet[l3+6:l3+8])&0x1fff != 0 {
			c.attrs[10] = 0
		}
		if ether == 0x86dd && c.packet[l3+6] == 44 && binary.BigEndian.Uint16(c.packet[l3+42:l3+44])&0xfff8 != 0 {
			c.attrs[10] = 0
		}
	}

	return cases
}

func TestB1Extraction(t *testing.T) {
	path := os.Getenv("XDROP_B1_PROBE_ELF")
	if path == "" {
		t.Fatal("XDROP_B1_PROBE_ELF required; generate with b1_extract_probe.py")
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	cases := b1Cases()
	if len(cases) != 2642 {
		t.Fatalf("case count=%d want=2642", len(cases))
	}
	packets := 0
	early := 0
	for _, name := range []string{"b1_extract_attrs", "b1_extract_cidr_attrs"} {
		prog := coll.Programs[name]
		if prog == nil {
			t.Fatal("missing probe entry " + name)
		}
		t.Run(name, func(t *testing.T) {
			for _, c := range cases {
				packets++
				ret, out, err := prog.Test(c.packet)
				if err != nil {
					t.Fatal(c.name, err)
				}
				if c.abort {
					early++
					if ret != 0 || !bytes.Equal(out, c.packet) {
						t.Fatalf("%s short IP header: ret=%d", c.name, ret)
					}
					continue
				}
				if ret != 0xB1 || len(out) < 11 || !bytes.Equal(out[:11], c.attrs[:]) {
					t.Fatalf("%s ret=%d attrs=%x want=%x", c.name, ret, out[:min(11, len(out))], c.attrs)
				}
			}
		})
	}
	raw, err := os.ReadFile(os.Getenv("XDROP_B1_XSIGHT_FIXTURES"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Fixtures []struct {
			Name    string `json:"name"`
			Hex     string `json:"hex"`
			Invalid bool   `json:"expected_is_invalid"`
			Bad     bool   `json:"expected_is_bad_fragment"`
		}
	}
	if err = json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures.Fixtures) != 33 {
		t.Fatalf("xsight count=%d", len(fixtures.Fixtures))
	}
	prog := coll.Programs["b1_extract_anomaly"]
	if prog == nil {
		t.Fatal("missing anomaly probe")
	}
	for _, f := range fixtures.Fixtures {
		t.Run(f.Name, func(t *testing.T) {
			ip, err := hex.DecodeString(f.Hex)
			if err != nil {
				t.Fatal(err)
			}
			ether := uint16(0x0800)
			if ip[0]>>4 == 6 {
				ether = 0x86dd
			}
			p := make([]byte, 14)
			binary.BigEndian.PutUint16(p[12:14], ether)
			p = append(p, ip...)
			packets++
			ret, out, err := prog.Test(p)
			if err != nil {
				t.Fatal(err)
			}
			want := byte(0)
			if f.Invalid {
				want |= 2
			}
			if f.Bad {
				want |= 1
			}
			if ret != 0xB1 || len(out) < 10 || out[3]&3 != want {
				t.Fatalf("ret=%d old anomaly bits=%x want=%x", ret, out[:min(10, len(out))], want)
			}
		})
	}
	if early != 4 {
		t.Fatalf("early returns=%d want=4", early)
	}
	if packets != 5317 {
		t.Fatalf("executed packets=%d want=5317", packets)
	}
	t.Logf("B1_EXTRACTION entries=3 construction_cases=2642 xsight_fixtures=33 packets=%d early_returns=%d", packets, early)
}
