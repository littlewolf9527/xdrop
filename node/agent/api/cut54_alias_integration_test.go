//go:build linux && integration

package api

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/eval"
)

// Replays the r1 publication/withdrawal counterexample and its destination-side
// mirror in the real main program. The unrelated C row enables the zero-side
// combination; X keeps exact and CIDR rows installed together in every cell.
func TestCut54AliasPublicationWithdrawal(t *testing.T) {
	cells := 0
	for _, missing := range []string{"source", "destination"} {
		for _, exactWins := range []bool{false, true} {
			t.Run(fmt.Sprintf("missing=%s/exact=%v", missing, exactWins), func(t *testing.T) {
				h, _, program, coll := b7ELFCollection(t)
				packet := cut53Packet([4]byte{192, 0, 2, 1}, 64)
				copy(packet[30:34], []byte{198, 51, 100, 1})
				binary.BigEndian.PutUint16(packet[34:36], 12345)
				binary.BigEndian.PutUint16(packet[36:38], 443)
				a := Rule{ID: "A", LogicalID: 17, DstCIDR: "198.51.100.0/24", SrcPort: 12345, Protocol: "tcp", Action: "drop"}
				b := Rule{ID: "B", LogicalID: 18, DstCIDR: "198.51.100.0/24", DstPort: 443, Protocol: "tcp", Action: "rate_limit", RateLimit: 1}
				c := Rule{ID: "C-enabler", LogicalID: 19, SrcCIDR: "203.0.113.0/24", DstCIDR: "198.51.100.0/24", SrcPort: 12345, Protocol: "tcp", Action: "drop"}
				x := Rule{ID: "X-exact", LogicalID: 20, SrcIP: "203.0.113.1", Protocol: "tcp", Action: "drop"}
				if exactWins {
					x.SrcIP = "192.0.2.1"
				}
				trie, rawIP, network := "sv4_cidr_trie", [4]byte{192, 0, 2, 0}, "192.0.2.0/24"
				if missing == "destination" {
					// Native A=18, B=14; unrelated C=30 permits old alias A at 30.
					a.SrcCIDR, a.DstCIDR = "192.0.2.0/24", ""
					b.SrcCIDR, b.DstCIDR = "192.0.2.0/24", ""
					c.SrcCIDR, c.DstCIDR = "192.0.2.0/24", "203.0.113.0/24"
					trie, rawIP, network = "dv4_cidr_trie", [4]byte{198, 51, 100, 0}, "198.51.100.0/24"
				}
				rules := []Rule{a, b, c, x}
				if result, err := h.DoAtomicSync(rules); err != nil || result.Added != 4 {
					t.Fatalf("alias seed=%+v %v", result, err)
				}
				if h.activeRuleSlot.Load() == 1 {
					trie += "_b"
				}
				tables := cut53EvalTables(t)
				attrs := eval.B1Packet{Packet: eval.Packet{Tuple: eval.Tuple{Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("198.51.100.1"), Sport: 12345, Dport: 443, Proto: 6}, Length: 40}, TTL: 64}
				prefixKey := make([]byte, 8)
				binary.LittleEndian.PutUint32(prefixKey, 24)
				copy(prefixKey[4:], rawIP[:])
				qKey := CIDRRuleKey{SrcID: 9000, Protocol: 6}
				qCombo := uint32(9)
				qOracleKey := eval.CIDRTuple{SrcID: 9000, Proto: 6}
				if missing == "destination" {
					qKey = CIDRRuleKey{DstID: 9000, Protocol: 6}
					qCombo = 3
					qOracleKey = eval.CIDRTuple{DstID: 9000, Proto: 6}
				}
				var baseBitmap uint64
				if err := h.activeMap().Lookup(uint32(ConfigCIDRBitmap), &baseBitmap); err != nil {
					t.Fatal(err)
				}
				for _, stage := range []string{"OLD", "PUBLISHED_NOT_FLIPPED", "NEW", "RETIRE_OLD", "RETIRE_FLIPPED_WAITING_RC", "RETIRE_AFTER_RELEASE"} {
					present := stage != "OLD" && stage != "RETIRE_AFTER_RELEASE"
					if stage == "PUBLISHED_NOT_FLIPPED" {
						if err := coll.Maps[trie].Put(prefixKey, uint32(9000)); err != nil {
							t.Fatal(err)
						}
					}
					if stage == "RETIRE_AFTER_RELEASE" {
						if err := coll.Maps[trie].Delete(prefixKey); err != nil {
							t.Fatal(err)
						}
					}
					action := uint8(ActionRateLimit)
					if stage == "NEW" || stage == "RETIRE_OLD" {
						action = ActionDrop
					}
					wire := b7Read(t, p7ActiveCIDR(h), cidrRuleKeyToBytes(h.cidrRules["B"].Key))
					wire[0] = action
					if err := p7ActiveCIDR(h).Update(cidrRuleKeyToBytes(h.cidrRules["B"].Key), wire, ebpf.UpdateExist); err != nil {
						t.Fatal(err)
					}
					if stage == "NEW" {
						qWire := ruleValueToBytes(RuleValue{Action: ActionDrop, LogicalID: 21})
						if err := p7ActiveCIDR(h).Put(cidrRuleKeyToBytes(qKey), qWire); err != nil {
							t.Fatal(err)
						}
						if err := h.activeMap().Put(uint32(ConfigCIDRBitmap), baseBitmap|uint64(1)<<qCombo); err != nil {
							t.Fatal(err)
						}
						if err := h.activeMap().Put(uint32(ConfigCIDRRuleCount), uint64(4)); err != nil {
							t.Fatal(err)
						}
					}
					if stage == "RETIRE_FLIPPED_WAITING_RC" {
						if err := p7ActiveCIDR(h).Delete(cidrRuleKeyToBytes(qKey)); err != nil {
							t.Fatal(err)
						}
						if err := h.activeMap().Put(uint32(ConfigCIDRBitmap), baseBitmap); err != nil {
							t.Fatal(err)
						}
						if err := h.activeMap().Put(uint32(ConfigCIDRRuleCount), uint64(3)); err != nil {
							t.Fatal(err)
						}
					}
					current := append([]Rule(nil), rules...)
					if action == ActionDrop {
						current[1].Action = "drop"
						current[1].RateLimit = 0
					}
					oracle := cut53Oracle(t, tables, current)
					if present {
						prefix := eval.Prefix{Network: netip.MustParsePrefix(network), ID: 9000}
						if missing == "source" {
							oracle.SrcPrefixes = append(oracle.SrcPrefixes, prefix)
						} else {
							oracle.DstPrefixes = append(oracle.DstPrefixes, prefix)
						}
					}
					if stage == "NEW" || stage == "RETIRE_OLD" {
						oracle.CIDR = append(oracle.CIDR, eval.B1Rule{Rule: eval.Rule{ID: "Q", CIDRKey: qOracleKey}, LogicalID: 21})
						oracle.CIDRBitmap |= uint64(1) << qCombo
					}
					predicted, err := eval.EvaluateB1Cut54(tables, oracle, attrs)
					want := "B"
					if exactWins {
						want = "X-exact"
					}
					if err != nil || predicted.RuleID != want {
						t.Fatalf("independent r1/r2 prediction stage=%s got=%+v err=%v want=%s", stage, predicted, err, want)
					}
					old, err := eval.EvaluateB1(tables, oracle, attrs)
					if err != nil {
						t.Fatal(err)
					}
					if !exactWins && !present && old.RuleID != "A" {
						t.Fatalf("alias precondition not reached: old=%+v", old)
					}
					before := map[uint32]LogicalRuleCounters{}
					for _, r := range rules {
						before[r.LogicalID], err = ReadLogicalRuleCounters(h.idCounts, r.LogicalID)
						if err != nil {
							t.Fatal(err)
						}
					}
					verdict, _, err := program.Test(packet)
					if err != nil {
						t.Fatal(err)
					}
					if verdict != 1 && verdict != 2 {
						t.Fatalf("unexpected main verdict=%d", verdict)
					}
					if (exactWins || action == ActionDrop) && verdict != 1 {
						t.Fatalf("predicted drop returned %d", verdict)
					}
					for _, r := range rules {
						after, err := ReadLogicalRuleCounters(h.idCounts, r.LogicalID)
						if err != nil {
							t.Fatal(err)
						}
						delta := LogicalRuleCounters{Match: after.Match - before[r.LogicalID].Match, Drop: after.Drop - before[r.LogicalID].Drop}
						expected := LogicalRuleCounters{}
						if r.ID == predicted.RuleID {
							expected.Match = 1
							if verdict == 1 {
								expected.Drop = 1
							}
						}
						if delta != expected {
							t.Fatalf("TD084 real winner differs from evaluator: missing=%s stage=%s rule=%s delta=%+v want=%+v", missing, stage, r.ID, delta, expected)
						}
					}
					qCounts, err := ReadLogicalRuleCounters(h.idCounts, 21)
					if err != nil || qCounts.Match != 0 || qCounts.Drop != 0 {
						t.Fatalf("publication Q must remain nonwinning: %+v %v", qCounts, err)
					}
					t.Logf("CUT54_J9_ELF missing=%s exact=%v stage=%s old=%s new=%s actual_match_increment=1", missing, exactWins, stage, old.RuleID, predicted.RuleID)
					cells++
				}
			})
		}
	}
	if cells != 24 {
		t.Fatalf("publication/withdrawal cells=%d want=24", cells)
	}
	t.Logf("CUT54_J9_PUBLICATION cells=%d source=12 destination=12", cells)
}
