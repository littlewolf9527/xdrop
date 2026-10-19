//go:build linux && integration

// anomaly_verify_ff_test.go — v2.6.1 FF regression runtime lock (codex round 11
// residual P3).
//
// The v2.6.1 B5 tail_call refactor introduced a subtle FF-mode regression:
// once any anomaly rule was registered, xdp_anomaly_verify's three pass-paths
// (stash-miss, pkt_anomaly==0, and no-match-at-end) were returning plain
// XDP_PASS instead of bpf_redirect_map. In FF mode that routed ~99% of normal
// traffic into the Linux stack on an interface with no IP → flow died. D8
// shell regression didn't catch it (D8 runs traditional mode).
//
// This test loads xdrop_main.elf, populates a devmap entry + a tail_stash entry
// with is_ff=1 and ingress_ifindex=INGRESS_SIM, then feeds
// xdp_anomaly_verify a normal TCP SYN packet (pkt_anomaly=0 path). The program
// MUST return XDP_REDIRECT (4), proving the FF pass_or_redirect sink works.
//
// Build tag: linux + integration. Skipped without CAP_BPF or compiled ELF.
//
// Run:
//
//	go test -tags=integration -run AnomalyVerifyFF ./node/agent/bpf/...
//
// Counterpart: node/agent/api/tail_stash_layout_test.go has a source-text
// structural lock that runs in plain `go test ./...`.
package bpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
)

// The former anomaly FF witness now enters main directly. The three cases
// exercise empty rules, a clean packet, and an anomaly predicate miss.
func TestAnomalyVerifyFFRedirect(t *testing.T) {
	path := os.Getenv("XDROP_BPF_ELF")
	if path == "" {
		path = "../../bpf/xdrop_main.elf"
	}
	c := b1Load(t, path)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	b1Put(t, c, "devmap", uint32(lo.Index), uint32(lo.Index))
	b1Put(t, c, "config_a", uint32(4), uint64(1))
	ctx := [6]uint32{0, 0, 0, uint32(lo.Index), 0, 0}
	for _, name := range []string{"empty-rules", "clean-packet", "anomaly-no-match"} {
		t.Run(name, func(t *testing.T) {
			pkt := buildNormalTCPSYN()
			if name != "empty-rules" {
				b1Put(t, c, "config_a", uint32(0), uint64(1))
				b1Put(t, c, "config_a", uint32(2), uint64(1<<5))
				key := b1Key(false, 6, false)
				b1Put(t, c, "blacklist", key, b1Wire(t, api.RuleValue{LogicalID: 540501, Pad2: [4]byte{api.RuleHasConditions}}))
				b1Put(t, c, "cond_a", key, b1Wire(t, b1AnomalyRow(540501, 1)))
				if name == "anomaly-no-match" {
					pkt[46] = 0x40
				}
			}
			ctx[1] = uint32(len(pkt))
			ret, err := c.Programs["xdp_firewall_main"].Run(&ebpf.RunOptions{Data: pkt, Context: ctx, Repeat: 1})
			if err != nil || ret != 4 {
				t.Fatalf("main FF %s verdict=%d want=XDP_REDIRECT(4) error=%v", name, ret, err)
			}
		})
	}
	t.Log("CUT54_FF main_cases=3 redirects=3")
}

// buildNormalTCPSYN constructs a 54-byte Ethernet/IPv4/TCP frame with:
//   - src MAC / dst MAC: dummy (not validated by XDP filter path)
//   - IPv4 ihl=5, proto=TCP, src=10.99.0.11, dst=10.99.0.13
//   - TCP sport=1234 dport=80 doff=5 flags=SYN
//
// No anomaly bits should be detected by parse_v4_anomaly, so the packet
// takes the pkt_anomaly==0 goto pass_or_redirect branch.
func buildNormalTCPSYN() []byte {
	var buf bytes.Buffer

	// Ethernet: dst=0c:29:30:a5:0e, src=0c:29:7a:19:0a, type=0x0800
	buf.Write([]byte{0x00, 0x0c, 0x29, 0x30, 0xa5, 0x0e})
	buf.Write([]byte{0x00, 0x0c, 0x29, 0x7a, 0x19, 0x0a})
	buf.Write([]byte{0x08, 0x00})

	// IPv4: ver=4 ihl=5 (0x45), tos=0, tot_len=40, id=1, flags=0, ttl=64, proto=6, csum=0,
	// src=10.99.0.11 (0x0a63000b), dst=10.99.0.13 (0x0a63000d)
	buf.Write([]byte{0x45, 0x00})
	binary.Write(&buf, binary.BigEndian, uint16(40))
	binary.Write(&buf, binary.BigEndian, uint16(1))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	buf.Write([]byte{64, 6})
	binary.Write(&buf, binary.BigEndian, uint16(0))
	buf.Write([]byte{10, 99, 0, 11})
	buf.Write([]byte{10, 99, 0, 13})

	// TCP: sport=1234, dport=80, seq=0, ackseq=0, doff_res=0x50 (doff=5), flags=0x02 (SYN),
	// win=0xffff, csum=0, urg=0
	binary.Write(&buf, binary.BigEndian, uint16(1234))
	binary.Write(&buf, binary.BigEndian, uint16(80))
	binary.Write(&buf, binary.BigEndian, uint32(0))
	binary.Write(&buf, binary.BigEndian, uint32(0))
	buf.Write([]byte{0x50, 0x02})
	binary.Write(&buf, binary.BigEndian, uint16(0xffff))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))

	return buf.Bytes()
}
