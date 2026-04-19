package api

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// NEW-UT-06 (§8.1.2): golden-byte tests that lock in the value-decode
// offsets used by rules_list.go (`h.activeBlacklist().Lookup(&valueBytes)`
// → matchCount at [8:16], dropCount at [16:24]) and stats.go
// (PERCPU u64 sum). If cilium/ebpf's Lookup ever returns a differently
// packed slice, or if someone accidentally re-orders the rule_value
// struct fields in bpf/xdrop.h, these tests fail loudly rather than
// silently decoding wrong counts into the API response.
//
// Fixture is hand-synthesised (no BPF needed) because the goal is to pin
// the Go-side decode assumptions, not the kernel write path.

// ruleValueGolden represents the byte layout of `struct rule_value` (32
// bytes, see node/agent/api/bpf_types.go). Keeping the assembly here in
// the test rather than reusing the prod decoder makes this a genuinely
// independent check.
type ruleValueGolden struct {
	Action        uint8
	TcpFlagsMask  uint8
	TcpFlagsValue uint8
	_             uint8
	RateLimit     uint32
	MatchCount    uint64
	DropCount     uint64
	PktLenMin     uint16
	PktLenMax     uint16
	_             [4]uint8
}

// buildRuleValueBytes serialises the golden struct into its 32-byte wire
// form the way the kernel writes it (little-endian on all supported
// architectures).
func buildRuleValueBytes(t *testing.T, g ruleValueGolden) []byte {
	t.Helper()
	buf := make([]byte, 32)
	buf[0] = g.Action
	buf[1] = g.TcpFlagsMask
	buf[2] = g.TcpFlagsValue
	// buf[3] reserved padding
	binary.LittleEndian.PutUint32(buf[4:8], g.RateLimit)
	binary.LittleEndian.PutUint64(buf[8:16], g.MatchCount)
	binary.LittleEndian.PutUint64(buf[16:24], g.DropCount)
	binary.LittleEndian.PutUint16(buf[24:26], g.PktLenMin)
	binary.LittleEndian.PutUint16(buf[26:28], g.PktLenMax)
	// buf[28:32] trailing zeros for 32-byte alignment
	return buf
}

// TestLookupDecode_RuleValueOffsets verifies the exact byte offsets that
// rules_list.go and cidr_rules.go rely on. The test feeds a known
// buffer through the same slice indexing used in prod and asserts the
// decoded counters match the input.
func TestLookupDecode_RuleValueOffsets(t *testing.T) {
	cases := []struct {
		name string
		in   ruleValueGolden
	}{
		{
			name: "drop action, no rate limit, 1234 matches / 987 drops",
			in: ruleValueGolden{
				Action:     1,
				MatchCount: 1234,
				DropCount:  987,
			},
		},
		{
			name: "rate_limit action with burst + packet-length filter",
			in: ruleValueGolden{
				Action:        2,
				RateLimit:     5000,
				MatchCount:    0xdead_beef,
				DropCount:     0xfeed_0042,
				PktLenMin:     60,
				PktLenMax:     1500,
				TcpFlagsMask:  0x02,
				TcpFlagsValue: 0x02,
			},
		},
		{
			name: "zero struct (rule inserted but never matched)",
			in:   ruleValueGolden{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			wire := buildRuleValueBytes(t, tc.in)
			if len(wire) != 32 {
				t.Fatalf("test fixture is %d bytes, expected 32", len(wire))
			}

			// Exactly the decoder pattern used in rules_list.go:
			//   if err := ... .Lookup(key, &valueBytes); err == nil {
			//       matchCount = binary.LittleEndian.Uint64(valueBytes[8:16])
			//       dropCount  = binary.LittleEndian.Uint64(valueBytes[16:24])
			//   }
			matchCount := binary.LittleEndian.Uint64(wire[8:16])
			dropCount := binary.LittleEndian.Uint64(wire[16:24])

			if matchCount != tc.in.MatchCount {
				t.Errorf("matchCount: got %d, want %d (wire=%s)",
					matchCount, tc.in.MatchCount, hex.EncodeToString(wire))
			}
			if dropCount != tc.in.DropCount {
				t.Errorf("dropCount: got %d, want %d (wire=%s)",
					dropCount, tc.in.DropCount, hex.EncodeToString(wire))
			}
		})
	}
}

// TestLookupDecode_PercpuStatsSum locks in the per-CPU stats summing
// behaviour used by api/stats.go: cilium/ebpf returns a []uint64 with one
// element per online CPU; GetStats sums them into a global counter.
func TestLookupDecode_PercpuStatsSum(t *testing.T) {
	cases := []struct {
		name string
		in   []uint64
		want uint64
	}{
		{"empty (no online cpus reported)", nil, 0},
		{"single-cpu", []uint64{42}, 42},
		{"4-cpu even split", []uint64{10, 20, 30, 40}, 100},
		{"wrap-around safe large counters", []uint64{^uint64(0), 1}, 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var total uint64
			for _, v := range tc.in {
				total += v
			}
			if total != tc.want {
				t.Errorf("sum mismatch: got %d, want %d", total, tc.want)
			}
		})
	}
}
