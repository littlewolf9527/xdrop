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
// This test loads xdrop.elf, populates a devmap entry + a tail_stash entry
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
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
)

// Stashed ingress_ifindex we will write into tail_stash so that
// bpf_redirect_map(&devmap, ingress_ifindex, 0) in anomaly_verify finds a
// mapped entry. Arbitrary non-zero ifindex that we also populate in devmap.
const ffTestIngressIfindex = uint32(4)
const ffTestEgressIfindex = uint32(5)

// tailStashWire mirrors xdrop.h `struct tail_stash` byte-for-byte. Any
// change to the C struct layout MUST be reflected here or the test writes
// garbage into the map and produces confusing failures.
//
//	struct tail_stash {
//	  __u32 stage;               // offset 0
//	  __u8  action;              // offset 4
//	  __u8  match_anomaly;       // offset 5
//	  __u16 pkt_len;             // offset 6
//	  __u32 rate_limit;          // offset 8
//	  __u32 payload_pattern_id;  // offset 12
//	  __u8  tcp_flags;           // offset 16
//	  __u8  eth_proto_is_v6;     // offset 17
//	  __u8  is_ff;               // offset 18  ← FF regression field
//	  __u8  reserved_b[1];       // offset 19
//	  __u32 ingress_ifindex;     // offset 20  ← FF regression field
//	  struct rule_key key;       // offset 24, 40 bytes
//	  __u8  reserved[28];        // offset 64
//	} __attribute__((aligned(8)));
//
// C size: 92 explicitly declared bytes + 4 tail pad (aligned(8)) = 96 bytes.
// BPF map value_size is 96 so the Go encoder must produce exactly 96 bytes,
// hence the explicit TailPad below (binary.Write doesn't insert any padding).
type tailStashWire struct {
	Stage            uint32
	Action           uint8
	MatchAnomaly     uint8
	PktLen           uint16
	RateLimit        uint32
	PayloadPatternID uint32
	TcpFlags         uint8
	EthProtoIsV6     uint8
	IsFF             uint8
	ReservedB        [1]uint8
	IngressIfindex   uint32
	Key              [40]byte
	Reserved         [28]byte
	TailPad          [4]byte // compiler-inserted for __attribute__((aligned(8)))
}

// TestAnomalyVerifyFFRedirect runs xdp_anomaly_verify via BPF_PROG_TEST_RUN
// and asserts it returns XDP_REDIRECT (4) when invoked on a normal TCP SYN
// packet with a valid FF tail_stash. This is the direct runtime lock for the
// FF regression fix — if anyone reintroduces the `return XDP_PASS` at any of
// the three pass-paths, this test fails with retval=2.
func TestAnomalyVerifyFFRedirect(t *testing.T) {
	elfPath := os.Getenv("XDROP_BPF_ELF")
	if elfPath == "" {
		// Test CWD is node/agent/bpf/; xdrop.elf lives in node/bpf/.
		elfPath = "../../bpf/xdrop.elf"
	}
	if _, err := os.Stat(elfPath); err != nil {
		t.Skipf("%s not found (build BPF first, or set XDROP_BPF_ELF): %v", elfPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		t.Fatalf("LoadCollectionSpec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// Most commonly: permission denied (needs CAP_BPF) or verifier failed.
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("NewCollection: permission denied — needs CAP_BPF / root: %v", err)
		}
		t.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["xdp_anomaly_verify"]
	if prog == nil {
		t.Fatal("xdp_anomaly_verify program not found in collection")
	}

	devmap := coll.Maps["devmap"]
	if devmap == nil {
		t.Fatal("devmap not found in collection")
	}
	tailStash := coll.Maps["tail_stash"]
	if tailStash == nil {
		t.Fatal("tail_stash map not found in collection")
	}

	// Populate devmap[ingressIfindex] = egressIfindex. Without this entry,
	// bpf_redirect_map returns 0 (XDP_ABORTED) when anomaly_verify tries to
	// redirect — that would mask the FF regression (wrong failure mode).
	if err := devmap.Put(ffTestIngressIfindex, ffTestEgressIfindex); err != nil {
		t.Fatalf("devmap.Put: %v", err)
	}

	// Populate tail_stash[0] with FF=1 + ingress_ifindex=4. All other fields
	// zero. Wire format matches C `struct tail_stash` exactly.
	stash := tailStashWire{
		IsFF:           1,
		IngressIfindex: ffTestIngressIfindex,
	}
	var stashBytes bytes.Buffer
	if err := binary.Write(&stashBytes, binary.LittleEndian, &stash); err != nil {
		t.Fatalf("encode stash: %v", err)
	}
	// tail_stash is PER-CPU array with max_entries=1; cilium/ebpf's Put for
	// per-CPU maps requires a slice with one value per online CPU (so the
	// caller can populate per-CPU values independently). We write the same
	// stash to every CPU slot since the packet under BPF_PROG_TEST_RUN will
	// execute on one unknown CPU and must see our values regardless.
	nCPU := runtime.NumCPU()
	perCPU := make([][]byte, nCPU)
	for i := range perCPU {
		perCPU[i] = stashBytes.Bytes()
	}
	zero := uint32(0)
	if err := tailStash.Put(zero, perCPU); err != nil {
		t.Fatalf("tail_stash.Put: %v", err)
	}

	// Normal TCP SYN packet (no anomaly) — will hit pkt_anomaly==0 path →
	// goto pass_or_redirect → bpf_redirect_map. 54-byte Ethernet/IP/TCP.
	pkt := buildNormalTCPSYN()

	ret, _, err := prog.Test(pkt)
	if err != nil {
		t.Fatalf("prog.Test: %v", err)
	}

	// XDP_REDIRECT = 4. If regression: XDP_PASS = 2.
	const XDP_ABORTED = 0
	const XDP_DROP = 1
	const XDP_PASS = 2
	const XDP_REDIRECT = 4

	switch ret {
	case XDP_REDIRECT:
		// Expected.
	case XDP_PASS:
		t.Fatalf("anomaly_verify returned XDP_PASS — v2.6.1 FF regression reintroduced!\n"+
			"see tail_stash is_ff/ingress_ifindex lock in api/tail_stash_layout_test.go\n"+
			"and xdrop.c xdp_anomaly_verify pass_or_redirect sink")
	case XDP_ABORTED:
		t.Fatalf("anomaly_verify returned XDP_ABORTED — devmap setup likely broken")
	default:
		t.Fatalf("anomaly_verify returned %d, want %d (XDP_REDIRECT)", ret, XDP_REDIRECT)
	}
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
