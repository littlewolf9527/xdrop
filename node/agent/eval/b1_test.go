package eval

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestB1KnifeTwoContract(t *testing.T) {
	root := instrumentRoot(t)
	current, err := LoadTables(root, B1)
	if err != nil {
		t.Fatal(err)
	}
	historical := t.TempDir()
	for name := range contractHashes[S2b] {
		raw, e := exec.Command("git", "-C", root, "show", "d0bf3a7:"+name).Output()
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(historical, name)
		if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	old, err := LoadTables(historical, S2b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(current.Order, old.Order) || !reflect.DeepEqual(current.Masks, old.Masks) || !reflect.DeepEqual(current.WhitelistOrder, old.WhitelistOrder) {
		t.Fatal("B1 knife two changed S2b tables")
	}
	if _, err = LoadTables(root, S2b); err == nil {
		t.Fatal("historical S2b must reject B1 header")
	}
	if _, err = LoadTables(historical, B1); err == nil {
		t.Fatal("B1 must reject historical header")
	}
	p := Packet{Tuple: Tuple{Src: ip("10.2.3.4"), Dst: ip("100.64.2.3"), Sport: 1234, Dport: 443, Proto: 6}, Length: 60, Flags: 16, Anomaly: 2}
	rs := RuleSet{Exact: []Rule{{ID: "coarse", Key: Tuple{Proto: 6}}, {ID: "fine", Key: p.Tuple, Rate: 17}}, ExactBitmap: 1<<0 | 1<<5}
	got, err := EvaluateCut54(current, rs, p)
	if err != nil {
		t.Fatal(err)
	}
	if got != (Decision{Exact, 0, "fine", "rate_limit@17"}) {
		t.Fatalf("B1 knife-two decision: %+v", got)
	}
	oldGot, err := Evaluate(old, rs, p)
	if err != nil || got != oldGot {
		t.Fatalf("B1/S2b mismatch: %+v %+v %v", got, oldGot, err)
	}
	// J9 is the single deliberate CIDR contract fork. A real source row
	// enables the source-bearing combination while this packet misses it.
	aliasPacket := Packet{Tuple: Tuple{Src: ip("192.0.2.9"), Dst: ip("198.51.100.9"), Proto: 6}, Length: 60}
	aliasRules := RuleSet{CIDR: []Rule{{ID: "alias", CIDRKey: CIDRTuple{DstID: 22, Proto: 6}}, {ID: "enabler", CIDRKey: CIDRTuple{SrcID: 77, DstID: 22, Proto: 6}}}, DstPrefixes: []Prefix{{netip.MustParsePrefix("198.51.100.0/24"), 22}}, CIDRBitmap: 1<<13 | 1<<3}
	aliasOld, err := Evaluate(old, aliasRules, aliasPacket)
	if err != nil {
		t.Fatal(err)
	}
	aliasNew, err := EvaluateCut54(current, aliasRules, aliasPacket)
	if err != nil {
		t.Fatal(err)
	}
	if aliasOld != (Decision{CIDR, 13, "alias", "drop"}) || aliasNew != (Decision{CIDR, 3, "alias", "drop"}) {
		t.Fatalf("J9 B1/S2b alias split: old=%+v new=%+v", aliasOld, aliasNew)
	}
	t.Log("CUT54_CONTRACT ordinary_equal=1 J9_alias_split=1 source_enabler=1")
	t.Log("B1_CONTRACT source_identities=3 crossed_rejected=2 ordered_masks=31 semantic_controls=1")
}
