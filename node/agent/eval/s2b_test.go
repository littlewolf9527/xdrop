package eval

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var s2bBeforeRoot = flag.String("s2b-before-root", "", "explicit frozen S2a source root")
var s2bAfterRoot = flag.String("s2b-after-root", "", "explicit candidate S2b source root")
var s2bInput = flag.String("s2b-input", "", "synthetic case specification JSON")
var s2bOutput = flag.String("s2b-output", "", "actual evaluator decisions JSON")

func s2bRoots(t *testing.T) (string, string) {
	t.Helper()
	before, after := *s2bBeforeRoot, *s2bAfterRoot
	if before == "" {
		before = filepath.Join(instrumentRoot(t), "node/agent/testdata/s2b-pre")
	}
	if after == "" {
		after = filepath.Join(instrumentRoot(t), "node/agent/testdata/s2b-post")
	}
	if !filepath.IsAbs(before) || !filepath.IsAbs(after) {
		t.Fatal("explicit absolute s2b roots required")
	}
	return before, after
}

func TestS2bFrozenContracts(t *testing.T) {
	want := map[Contract]map[string]string{
		PreS2a: {"node/bpf/xdrop.h": "5beb7825c01f141f054981cbd810cb08b7ca9721765219e447583ecca1cb62cf", "node/bpf/combo_masks.h": "9cfa30722183816b4cc860b7822827a34e2da2c1f8daf17a167de95997e1de3c", "node/bpf/xdrop_gate.c": "a15a6d1081d82c7d815d18a0918198876240d69be0ba843e67c4f28ac5f58199"},
		S2a:    {"node/bpf/xdrop.h": "d1dd8269ab0dfb0923e565fe075f830f652e150b0e741f9869d1231d967833d2", "node/bpf/combo_masks.h": "0246f4655ea2cad3adfa958112a6db800d05705064efc634a5360796e92318f5", "node/bpf/xdrop_gate.c": "a15a6d1081d82c7d815d18a0918198876240d69be0ba843e67c4f28ac5f58199"},
	}
	for c, v := range want {
		if !reflect.DeepEqual(contractHashes[c], v) {
			t.Fatalf("frozen %s contract hashes changed: got=%v want=%v", c, contractHashes[c], v)
		}
	}
}

func TestS2bHistoricalRouting(t *testing.T) {
	if Contract(*evalContract) != S2a {
		t.Fatal("historical routing test requires explicit s2a")
	}
	want := filepath.Join(instrumentRoot(t), "node/agent/testdata/s2b-pre")
	if filepath.Clean(testRoot(t)) != want {
		t.Fatalf("S2a must use frozen before root: got=%s want=%s", testRoot(t), want)
	}
}

func TestS2bAnchor(t *testing.T) {
	before, after := s2bRoots(t)
	var found []fixture
	for _, f := range fixtures() {
		if f.Name == "1-priority" {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		t.Fatalf("anchor identities=%d want=1", len(found))
	}
	f := found[0]
	for _, tc := range []struct {
		root string
		c    Contract
		want Decision
	}{
		{before, S2a, Decision{Exact, 5, "coarse-drop", "drop"}},
		{after, S2b, Decision{Exact, 24, "fine-rate", "rate_limit@1000"}},
	} {
		t.Run(string(tc.c), func(t *testing.T) {
			table := certifiedTablesAt(t, tc.root, tc.c)
			got, err := Evaluate(table, f.Rules, f.Packet)
			if err != nil {
				t.Fatal(err)
			}
			checkDecision(t, got, tc.want)
			t.Logf("actual anchor %s root=%s decision=%+v", tc.c, tc.root, got)
		})
	}
}

func TestS2bStrictTables(t *testing.T) {
	_, after := s2bRoots(t)
	base, err := LoadTables(after, S2b)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, red string
		mut       func(*Tables)
	}{
		{"numbered", "s2b K order", func(x *Tables) {
			x.Order = nil
			for n := 0; n < 34; n++ {
				if S2b.active(n) {
					x.Order = append(x.Order, n)
				}
			}
		}},
		{"tie", "s2b K order", func(x *Tables) { x.Order[1], x.Order[2] = x.Order[2], x.Order[1] }},
		{"missing", "order missing valid entries", func(x *Tables) { x.Order = x.Order[:30] }},
		{"duplicate", "out of range/absent/duplicate", func(x *Tables) { x.Order[1] = x.Order[0] }},
		{"retired", "out of range/absent/duplicate", func(x *Tables) { x.Order[1] = 20 }},
		{"negative", "out of range/absent/duplicate", func(x *Tables) { x.Order[1] = -1 }},
		{"combo-max", "out of range/absent/duplicate", func(x *Tables) { x.Order[1] = 34 }},
		{"shift-width", "out of range/absent/duplicate", func(x *Tables) { x.Order[1] = 64 }},
		{"whitelist", "whitelist order", func(x *Tables) { x.WhitelistOrder = append([]int(nil), x.Order...) }},
		{"unknown-contract", "explicit known", func(x *Tables) { x.contract = "unknown" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			x := cloneTable(base)
			tc.mut(&x)
			err := x.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.red) {
				t.Fatalf("expected %s got %v", tc.red, err)
			}
			t.Log(err)
		})
	}
}

func TestS2bCrossedSources(t *testing.T) {
	before, after := s2bRoots(t)
	for _, tc := range []struct {
		name, root string
		c          Contract
	}{{"old-as-new", before, S2b}, {"new-as-old", after, S2a}, {"unknown", after, "unknown"}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadTables(tc.root, tc.c); err == nil {
				t.Fatal("crossed/unknown source accepted")
			} else {
				t.Log(err)
			}
		})
	}
}

type s2bRule struct {
	Rule
	Combo   int
	WireKey string
}
type s2bRuleSet struct {
	Whitelist, Exact, CIDR   []s2bRule
	SrcPrefixes, DstPrefixes []Prefix
}
type s2bCase struct {
	Pair           string            `json:"pair_id"`
	PairRelation   string            `json:"pair_relation"`
	Stage          string            `json:"stage"`
	Variant        string            `json:"variant"`
	Packet         Packet            `json:"packet"`
	Rules          s2bRuleSet        `json:"rules"`
	Bitmaps        map[string]uint64 `json:"bitmaps"`
	LPM            []uint32          `json:"lpm_expected"`
	CReplay        bool              `json:"c_replay"`
	BeforeExpected Decision          `json:"before_expected"`
	AfterExpected  Decision          `json:"after_expected"`
}
type s2bActual struct {
	Pair          string `json:"pair_id"`
	Stage         string `json:"stage"`
	Variant       string `json:"variant"`
	Before, After Decision
}

func TestS2bCompetition(t *testing.T) {
	beforeRoot, afterRoot := s2bRoots(t)
	before := certifiedTablesAt(t, beforeRoot, S2a)
	after := certifiedTablesAt(t, afterRoot, S2b)
	var raw []byte
	var err error
	if *s2bInput != "" {
		raw, err = os.ReadFile(*s2bInput)
	} else {
		raw, err = exec.Command("python3", filepath.Join(instrumentRoot(t), "node/agent/tools/s2b_cases.py"), "--test-input").Output()
	}
	if err != nil {
		t.Fatal(err)
	}
	var rows []s2bCase
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rows); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	actual := make([]s2bActual, 0, len(rows))
	for _, row := range rows {
		name := row.Pair + "/" + row.Stage + "/" + row.Variant
		if seen[name] {
			t.Fatalf("duplicate input identity %s", name)
		}
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			rs := RuleSet{WhitelistBitmap: row.Bitmaps["Whitelist"], ExactBitmap: row.Bitmaps["Exact"], CIDRBitmap: row.Bitmaps["CIDR"], SrcPrefixes: row.Rules.SrcPrefixes, DstPrefixes: row.Rules.DstPrefixes}
			for g, rules := range map[string][]s2bRule{"Whitelist": row.Rules.Whitelist, "Exact": row.Rules.Exact, "CIDR": row.Rules.CIDR} {
				for _, r := range rules {
					var wire []byte
					switch g {
					case "Whitelist":
						rs.Whitelist = append(rs.Whitelist, r.Rule)
						wire = encodeTuple(r.Key)
					case "Exact":
						rs.Exact = append(rs.Exact, r.Rule)
						wire = encodeTuple(r.Key)
					case "CIDR":
						rs.CIDR = append(rs.CIDR, r.Rule)
						wire = encodeCIDR(r.CIDRKey)
					}
					if hex.EncodeToString(wire) != r.WireKey {
						t.Fatalf("independent key bytes %s/%s", name, r.ID)
					}
				}
			}
			if len(row.LPM) != 2 || longest(rs.SrcPrefixes, row.Packet.Src) != row.LPM[0] || longest(rs.DstPrefixes, row.Packet.Dst) != row.LPM[1] {
				t.Fatal("selected LPM identity")
			}
			a, err := Evaluate(before, rs, row.Packet)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Evaluate(after, rs, row.Packet)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range []struct {
				side      string
				got, want Decision
			}{{"before", a, row.BeforeExpected}, {"after", b, row.AfterExpected}} {
				if v.got.Stage != v.want.Stage {
					t.Errorf("%s Stage got=%s want=%s", v.side, v.got.Stage, v.want.Stage)
				}
				if v.got.Combo != v.want.Combo {
					t.Errorf("%s Combo got=%d want=%d", v.side, v.got.Combo, v.want.Combo)
				}
				if v.got.RuleID != v.want.RuleID {
					t.Errorf("%s RuleID got=%s want=%s", v.side, v.got.RuleID, v.want.RuleID)
				}
				if v.got.Action != v.want.Action {
					t.Errorf("%s Action got=%s want=%s", v.side, v.got.Action, v.want.Action)
				}
			}
			actual = append(actual, s2bActual{row.Pair, row.Stage, row.Variant, a, b})
		})
	}
	if len(rows) != 25753 || len(actual) != 25753 {
		t.Fatalf("competition actual count=%d input=%d want=25753", len(actual), len(rows))
	}
	path := *s2bOutput
	if path == "" {
		f, err := os.CreateTemp("/tmp", "s2b-eval-*.json")
		if err != nil {
			t.Fatal(err)
		}
		path = f.Name()
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	out, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, out, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual decisions=%d source_before=%s commit=b07a004950e2f813545db540599767e2a4dc214e source_after=%s commit=b07a004950e2f813545db540599767e2a4dc214e+working-tree output=%s", len(actual), beforeRoot, afterRoot, path)
}

// The mutation driver invokes this same loader assertion with a /tmp source
// root. Semantic parsing/Validate must reject defects before source hashes.
func TestS2bSourceProbe(t *testing.T) {
	_, after := s2bRoots(t)
	table, err := LoadTables(after, S2b)
	if err != nil {
		t.Fatal(err)
	}
	if err = table.Validate(); err != nil {
		t.Fatal(err)
	}
}
