package eval

import (
	"net/netip"
	"path/filepath"
	"testing"
)

func TestCut54B1AliasGenerationGrid(t *testing.T) {
	tables, err := LoadTables(instrumentRoot(t), B1)
	if err != nil {
		t.Fatal(err)
	}
	cells, forks, exactWins := 0, 0, 0
	for _, srcPresent := range []bool{false, true} {
		for _, dstPresent := range []bool{false, true} {
			for _, exactHit := range []bool{false, true} {
				for _, combo := range tables.Order {
					p := B1Packet{Packet: Packet{Tuple: Tuple{Src: ip("192.0.2.9"), Dst: ip("198.51.100.9"), Sport: 1234, Dport: 443, Proto: 6}, Length: 60}}
					src, dst := uint32(0), uint32(0)
					rs := B1RuleSet{CIDRBitmap: uint64(1) << combo}
					if srcPresent {
						src = 11
						rs.SrcPrefixes = []Prefix{{netip.MustParsePrefix("192.0.2.0/24"), src}}
					}
					if dstPresent {
						dst = 22
						rs.DstPrefixes = []Prefix{{netip.MustParsePrefix("198.51.100.0/24"), dst}}
					}
					key := maskCIDR(CIDRTuple{src, dst, p.Sport, p.Dport, p.Proto}, tables.Masks[combo])
					rs.CIDR = []B1Rule{{Rule: Rule{ID: "alias-candidate", CIDRKey: key}, LogicalID: 1}}
					// A real row enables the probed combination even when the
					// candidate has a missing LPM side. It never matches this packet.
					enabler := maskCIDR(CIDRTuple{77, 88, p.Sport, p.Dport, p.Proto}, tables.Masks[combo])
					if enabler != key {
						rs.CIDR = append(rs.CIDR, B1Rule{Rule: Rule{ID: "enabler", CIDRKey: enabler}, LogicalID: 2})
					}
					if exactHit {
						rs.Exact = []B1Rule{{Rule: Rule{ID: "exact", Key: p.Tuple}, LogicalID: 3}}
						rs.ExactBitmap = 1
					}
					old, e := EvaluateB1(tables, rs, p)
					if e != nil {
						t.Fatal(e)
					}
					got, e := EvaluateB1Cut54(tables, rs, p)
					if e != nil {
						t.Fatal(e)
					}
					alias := (src != 0 || dst != 0) && ((tables.Masks[combo]&SrcIP != 0 && src == 0) || (tables.Masks[combo]&DstIP != 0 && dst == 0)) && !exactHit
					if (old != got) != alias {
						t.Fatalf("J9 fork outside alias: src=%v dst=%v exact=%v combo=%d old=%+v new=%+v", srcPresent, dstPresent, exactHit, combo, old, got)
					}
					if alias {
						forks++
						if old.RuleID != "alias-candidate" || got.Stage != None {
							t.Fatalf("J9 alias winner: old=%+v new=%+v", old, got)
						}
					}
					if exactHit {
						exactWins++
						if got.RuleID != "exact" {
							t.Fatal("exact precedence changed")
						}
					}
					cells++
				}
			}
		}
	}
	if forks != 32 || cells != 248 || exactWins != 124 {
		t.Fatalf("grid coverage cells=%d forks=%d exact=%d", cells, forks, exactWins)
	}
	t.Logf("CUT54_J9 grid_cells=%d alias_forks=%d exact_wins=%d", cells, forks, exactWins)
}

func TestCut54HistoricalCIDRContractsUnchanged(t *testing.T) {
	current, err := LoadTables(instrumentRoot(t), B1)
	if err != nil {
		t.Fatal(err)
	}
	p := Packet{Tuple: Tuple{Src: ip("192.0.2.9"), Dst: ip("198.51.100.9"), Proto: 6}, Length: 60}
	rs := RuleSet{CIDR: []Rule{{ID: "old-alias", CIDRKey: CIDRTuple{DstID: 22, Proto: 6}}, {ID: "source-enabler", CIDRKey: CIDRTuple{SrcID: 77, DstID: 22, Proto: 6}}}, DstPrefixes: []Prefix{{netip.MustParsePrefix("198.51.100.0/24"), 22}}, CIDRBitmap: 1<<13 | 1<<3}
	for _, contract := range []Contract{S2a, S2b} {
		fixture := "s2b-post"
		if contract == S2a {
			fixture = "s2b-pre"
		}
		tables, e := LoadTables(filepath.Join(instrumentRoot(t), "node/agent/testdata", fixture), contract)
		if e != nil {
			t.Fatal(e)
		}
		got, e := Evaluate(tables, rs, p)
		if e != nil {
			t.Fatal(e)
		}
		wantCombo := 13
		if contract == S2a {
			wantCombo = 3
		}
		if got != (Decision{CIDR, wantCombo, "old-alias", "drop"}) {
			t.Fatalf("%s historical alias changed: %+v", contract, got)
		}
	}
	got, e := EvaluateCut54(current, rs, p)
	if e != nil {
		t.Fatal(e)
	}
	if got != (Decision{CIDR, 3, "old-alias", "drop"}) {
		t.Fatalf("J9 B1 corrected combo: %+v", got)
	}
	t.Log("CUT54_HISTORICAL contracts=2 unchanged_alias_cells=2 B1_corrected_cells=1")
}

// Ruling 3: exact anomaly wins before the CIDR stage. CIDR action bytes
// PASS/zero/unknown cannot affect a stage the selected exact DROP never reaches.
func TestCut54LaterDropIndependentPrediction(t *testing.T) {
	tables, err := LoadTables(instrumentRoot(t), B1)
	if err != nil {
		t.Fatal(err)
	}
	cells := 0
	for _, action := range []string{"PASS", "zero-candidate", "unknown"} {
		for ff := 0; ff < 2; ff++ {
			for assembly := 0; assembly < 4; assembly++ {
				id := uint32(0x54010000 + cells)
				rs := B1RuleSet{
					Exact:       []B1Rule{{Rule: Rule{ID: "anomaly-exact", Key: Tuple{Proto: 6}, Conditions: Conditions{Anomaly: 2}}, LogicalID: id, HasConditions: true}},
					CIDR:        []B1Rule{{Rule: Rule{ID: "cidr-candidate", CIDRKey: CIDRTuple{Proto: 6, Dport: 80}}, LogicalID: 0x80102030, HasConditions: true}},
					ExactBitmap: 1 << 5, CIDRBitmap: 1<<16 | 1<<5,
					SrcPrefixes: []Prefix{{netip.MustParsePrefix("192.0.2.0/24"), 7}},
				}
				p := B1Packet{Packet: Packet{Tuple: Tuple{Src: ip("192.0.2.1"), Dst: ip("198.51.100.1"), Sport: 12345, Dport: 80, Proto: 6}, Length: 40, Anomaly: 2}}
				d, e := EvaluateB1Cut54(tables, rs, p)
				if e != nil {
					t.Fatal(e)
				}
				if d.Stage != Exact || d.LogicalID != id || d.ActionCode != 1 || !d.HasConditions {
					t.Fatalf("independent J2 prediction: %+v", d)
				}
				t.Logf("CUT54_J2 action=%s FF=%d assembly=%d exact_id=%d exact=1/1 CIDR=0/0 verdict=DROP stats=1/0/0", action, ff, assembly, id)
				cells++
			}
		}
	}
	if cells != 24 {
		t.Fatalf("J2 cells=%d want=24", cells)
	}
	t.Logf("CUT54_J2 independent_predictions=%d", cells)
}
