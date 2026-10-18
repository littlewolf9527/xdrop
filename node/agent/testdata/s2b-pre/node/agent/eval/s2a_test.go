package eval

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A separate test process lets the test observe the real certifiedTables
// fatal assertions without replacing them with a second acceptance function.
func TestS2aParityCallerChild(t *testing.T) {
	if os.Getenv("S2A_PARITY_CHILD") == "1" {
		certifiedTablesAt(t, instrumentRoot(t), S2a)
	}
}

func TestS2aParityCallerIdentity(t *testing.T) {
	root := instrumentRoot(t)
	cmd := exec.Command("python3", filepath.Join(root, "internal_docs/plans/phase1/gate-mask-parity.py"), "--root", root, "--contract", "s2a", "--ck")
	// Output() returns stdout separately; ExitError is never accepted here.
	var diag strings.Builder
	cmd.Stderr = &diag
	if out, err := cmd.Output(); err != nil || string(out) != "0\n" {
		t.Fatalf("positive parity: %v %s %s", err, out, diag.String())
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(diag.String()), &report); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "s2a-caller-")
	if err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\ncat \"$S2A_PARITY_STDERR\" >&2\nprintf '%s\\n' \"$S2A_PARITY_STDOUT\"\nexit \"$S2A_PARITY_STATUS\"\n"
	if err := os.WriteFile(filepath.Join(dir, "python3"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, red      string
		mut            func(map[string]any)
		stdout, status string
	}{
		{"positive", "", func(map[string]any) {}, "0", "0"},
		{"root", "S1-5 input/count contract", func(r map[string]any) { r["root"] = "/tmp/wrong-root" }, "0", "0"},
		{"contract", "S1-5 input/count contract", func(r map[string]any) { r["contract"] = "pre-s2a" }, "0", "0"},
		{"authority", "S1-5 input/count contract", func(r map[string]any) { r["authority_baseline"] = "wrong" }, "0", "0"},
		{"hash", "input identity", func(r map[string]any) {
			r["inputs"].(map[string]any)["node/bpf/xdrop.h"].(map[string]any)["sha256"] = "wrong"
		}, "0", "0"},
		{"path", "input identity", func(r map[string]any) {
			r["inputs"].(map[string]any)["node/bpf/xdrop.h"].(map[string]any)["path"] = "/tmp/wrong.h"
		}, "0", "0"},
		{"count", "S1-5 input/count contract", func(map[string]any) {}, "1", "0"},
		{"exit", "S1-5:", func(map[string]any) {}, "0", "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r map[string]any
			if err := json.Unmarshal([]byte(diag.String()), &r); err != nil {
				t.Fatal(err)
			}
			tc.mut(r)
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(p, b, 0600); err != nil {
				t.Fatal(err)
			}
			c := exec.Command(binary, "-test.run=^TestS2aParityCallerChild$", "-test.v")
			c.Env = append(os.Environ(), "S2A_PARITY_CHILD=1", "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "S2A_PARITY_STDERR="+p, "S2A_PARITY_STDOUT="+tc.stdout, "S2A_PARITY_STATUS="+tc.status)
			out, err := c.CombinedOutput()
			if e := os.WriteFile(filepath.Join(dir, tc.name+".log"), out, 0600); e != nil {
				t.Fatal(e)
			}
			if tc.red == "" {
				if err != nil || !strings.Contains(string(out), "--- PASS: TestS2aParityCallerChild") {
					t.Fatalf("positive child: %v %s", err, out)
				}
			} else if err == nil || !strings.Contains(string(out), "--- FAIL: TestS2aParityCallerChild") || !strings.Contains(string(out), tc.red) {
				t.Fatalf("want %s: %v %s", tc.red, err, out)
			}
		})
	}
	t.Log("S2a actual_certifiedTables_caller: positive=1 identity_count_exit_rejections=7")
}

// Translate the historical wire fixture addresses explicitly for local model
// inputs. The frozen RFC5737 wire vectors and lab evidence keep their identity.
func privateModelFixture(f fixture) fixture {
	addr := func(a netip.Addr) netip.Addr {
		if !a.IsValid() {
			return a
		}
		b := a.As4()
		switch {
		case b[0] == 192 && b[1] == 0 && b[2] == 2:
			b[0], b[1] = 10, 0
		case b[0] == 198 && b[1] == 51 && b[2] == 100:
			b[0], b[1] = 10, 1
		case b[0] == 203 && b[1] == 0 && b[2] == 113:
			b[0], b[1] = 10, 2
		default:
			if !a.IsPrivate() {
				panic("unknown model address source")
			}
		}
		return netip.AddrFrom4(b)
	}
	f.Packet.Src, f.Packet.Dst = addr(f.Packet.Src), addr(f.Packet.Dst)
	copyRules := func(rules []Rule) []Rule {
		out := append([]Rule(nil), rules...)
		for i := range out {
			out[i].Key.Src = addr(out[i].Key.Src)
			out[i].Key.Dst = addr(out[i].Key.Dst)
		}
		return out
	}
	f.Rules.Exact = copyRules(f.Rules.Exact)
	f.Rules.Whitelist = copyRules(f.Rules.Whitelist)
	f.Rules.CIDR = copyRules(f.Rules.CIDR)
	copyPrefixes := func(prefixes []Prefix) []Prefix {
		out := append([]Prefix(nil), prefixes...)
		for i := range out {
			p := out[i].Network
			out[i].Network = netip.PrefixFrom(addr(p.Addr()), p.Bits())
		}
		return out
	}
	f.Rules.SrcPrefixes = copyPrefixes(f.Rules.SrcPrefixes)
	f.Rules.DstPrefixes = copyPrefixes(f.Rules.DstPrefixes)
	return f
}

func TestS2aEvaluationParity(t *testing.T) {
	old := historicalTables(t)
	current := certifiedTablesAt(t, testRoot(t), S2a)
	compare := func(t *testing.T, rs RuleSet, p Packet, want Decision) {
		t.Helper()
		before, err := Evaluate(old, rs, p)
		if err != nil {
			t.Fatal(err)
		}
		after, err := Evaluate(current, rs, p)
		if err != nil {
			t.Fatal(err)
		}
		if before != after {
			t.Fatalf("S2a zero-behavior mismatch rules=%+v packet=%+v before=%+v after=%+v", rs, p, before, after)
		}
		checkDecision(t, after, want)
	}
	// Fixed masks independent of either input table, from the frozen C extraction.
	masks := []Mask{31, 30, 26, 18, 2, 16, 4, 8, 1, 17, 3, 9, 10, 19, 25, 20, 24, 5, 21, 0, 0, 11, 27, 13, 29, 6, 22, 12, 28, 7, 23, 14, 0, 15}
	witnesses := 0
	for combo, m := range masks {
		if m == 0 {
			continue
		}
		for _, stage := range []Stage{Whitelist, Exact, CIDR, AnomalyExact, AnomalyCIDR} {
			t.Run(fmt.Sprintf("witness-%d-%s", combo, stage), func(t *testing.T) {
				p := Packet{Tuple: Tuple{Src: ip("10.0.2.10"), Dst: ip("10.1.100.20"), Sport: 1234, Dport: 443, Proto: 6}, Length: 60, Flags: 16, Anomaly: 2}
				r := Rule{ID: "selected", Key: maskTuple(p.Tuple, m), CIDRKey: maskCIDR(CIDRTuple{17, 29, 1234, 443, 6}, m)}
				rs := RuleSet{SrcPrefixes: []Prefix{{netip.MustParsePrefix("10.0.2.0/24"), 17}}, DstPrefixes: []Prefix{{netip.MustParsePrefix("10.1.100.0/24"), 29}}}
				action := "drop"
				switch stage {
				case Whitelist:
					rs.Whitelist = []Rule{r}
					rs.WhitelistBitmap = 1 << combo
					action = "pass_whitelist"
				case Exact:
					r.Rate = 1000
					rs.Exact = []Rule{r}
					rs.ExactBitmap = 1 << combo
					action = "rate_limit@1000"
				case CIDR:
					rs.CIDR = []Rule{r}
					rs.CIDRBitmap = 1 << combo
				case AnomalyExact:
					r.Anomaly = 2
					rs.Exact = []Rule{r}
					rs.ExactBitmap = 1 << combo
				case AnomalyCIDR:
					r.Anomaly = 2
					rs.CIDR = []Rule{r}
					rs.CIDRBitmap = 1 << combo
				}
				compare(t, rs, p, Decision{stage, combo, r.ID, action})
			})
			witnesses++
		}
	}
	for _, original := range fixtures() {
		f := privateModelFixture(original)
		t.Run("fixture-"+f.Name, func(t *testing.T) { compare(t, f.Rules, f.Packet, f.Want) })
	}
	t.Run("zero-bitmaps", func(t *testing.T) {
		f := privateModelFixture(fixtures()[0])
		f.Rules.ExactBitmap = 0
		compare(t, f.Rules, f.Packet, noMatch())
	})
	t.Run("anomaly-disabled", func(t *testing.T) {
		f := privateModelFixture(fixtures()[13])
		f.Packet.Anomaly = 0
		compare(t, f.Rules, f.Packet, noMatch())
	})
	t.Run("no-lpm-match", func(t *testing.T) {
		f := privateModelFixture(fixtures()[7])
		f.Rules.SrcPrefixes = nil
		compare(t, f.Rules, f.Packet, noMatch())
	})
	t.Logf("S2a evaluator: active_witnesses=%d stages=5 fixtures=16 additional_misses=3 comparisons=%d fields=%d", witnesses, witnesses+19, (witnesses+19)*4)
}

func TestS2aDirtyPinBoundary(t *testing.T) {
	old := historicalTables(t)
	current := certifiedTablesAt(t, testRoot(t), S2a)
	for _, alias := range []struct {
		dead, live int
		mask       Mask
	}{{20, 2, 26}, {32, 1, 30}} {
		for _, stage := range []Stage{Exact, CIDR, AnomalyExact, AnomalyCIDR} {
			t.Run(fmt.Sprintf("%d-%s", alias.dead, stage), func(t *testing.T) {
				p := Packet{Tuple: Tuple{Src: ip("10.0.2.10"), Dst: ip("10.1.100.20"), Sport: 1234, Dport: 443, Proto: 6}, Length: 60, Flags: 16, Anomaly: 2}
				r := Rule{ID: "dirty-pin", Key: maskTuple(p.Tuple, alias.mask), CIDRKey: maskCIDR(CIDRTuple{17, 29, 1234, 443, 6}, alias.mask)}
				if stage == AnomalyExact || stage == AnomalyCIDR {
					r.Anomaly = 2
				}
				rs := RuleSet{SrcPrefixes: []Prefix{{netip.MustParsePrefix("10.0.2.0/24"), 17}}, DstPrefixes: []Prefix{{netip.MustParsePrefix("10.1.100.0/24"), 29}}}
				isCIDR := stage == CIDR || stage == AnomalyCIDR
				if isCIDR {
					rs.CIDR = []Rule{r}
					rs.CIDRBitmap = 1 << alias.dead
				} else {
					rs.Exact = []Rule{r}
					rs.ExactBitmap = 1 << alias.dead
				}
				frozen := fmt.Sprintf("%+v", rs)
				if _, err := Evaluate(current, rs, p); err == nil || !strings.Contains(err.Error(), "bitmap contains absent combo") {
					t.Fatalf("dirty state not rejected: %v", err)
				}
				// Explicit lower-level raw-state probe, never passed off as a
				// validated RuleSet or included in the zero-behavior domain.
				probe := func(table Tables) Decision {
					if err := table.Validate(); err != nil {
						t.Fatal(err)
					}
					if isCIDR {
						d, _ := lookupCIDR(table, rs, p, stage)
						return d
					}
					d, _ := lookupExact(table, rs, p, stage)
					return d
				}
				before, after := probe(old), probe(current)
				if before != (Decision{stage, alias.dead, r.ID, "drop"}) || after != noMatch() {
					t.Fatalf("dirty pin counterexample: old=%+v new=%+v", before, after)
				}
				if fmt.Sprintf("%+v", rs) != frozen {
					t.Fatal("raw input was silently changed")
				}
				if isCIDR {
					rs.CIDRBitmap |= 1 << alias.live
				} else {
					rs.ExactBitmap |= 1 << alias.live
				}
				if a, b := probe(old), probe(current); a != b || a != (Decision{stage, alias.live, r.ID, "drop"}) {
					t.Fatalf("live-bit positive control old=%+v new=%+v", a, b)
				}
			})
		}
	}
	t.Log("S2a dirty_pin: counterexamples=8 validated_rejections=8 live_bit_controls=8; raw_rules_unchanged=8")
}

func cloneTable(t Tables) Tables {
	t.Masks = append([]Mask(nil), t.Masks...)
	t.Order = append([]int(nil), t.Order...)
	t.WhitelistOrder = append([]int(nil), t.WhitelistOrder...)
	return t
}

func TestS2aStrictTableContracts(t *testing.T) {
	for _, base := range []Tables{historicalTables(t), certifiedTablesAt(t, testRoot(t), S2a)} {
		t.Run(string(base.contract), func(t *testing.T) {
			mutations := map[string]func(*Tables){
				"out-of-range":          func(x *Tables) { x.Valid |= 1 << 63 },
				"duplicate-order":       func(x *Tables) { x.Order[1] = x.Order[0] },
				"missing-order":         func(x *Tables) { x.Order = x.Order[1:] },
				"wrong-order":           func(x *Tables) { x.Order[0], x.Order[1] = x.Order[1], x.Order[0] },
				"wrong-whitelist-order": func(x *Tables) { x.WhitelistOrder[0], x.WhitelistOrder[1] = x.WhitelistOrder[1], x.WhitelistOrder[0] },
				"wrong-mask":            func(x *Tables) { x.Masks[0] = 1 },
				"nonzero-hole":          func(x *Tables) { x.Masks[19] = 1 },
				"delete-valid": func(x *Tables) {
					x.Valid &^= 1
					x.Masks[0] = 0
					x.Order = x.Order[1:]
					x.WhitelistOrder = x.WhitelistOrder[1:]
				},
				"wrong-contract": func(x *Tables) {
					if x.contract == S2a {
						x.contract = PreS2a
					} else {
						x.contract = S2a
					}
				},
				"unknown-contract": func(x *Tables) { x.contract = "untrusted" },
			}
			for name, mut := range mutations {
				t.Run(name, func(t *testing.T) {
					x := cloneTable(base)
					mut(&x)
					if err := x.Validate(); err == nil {
						t.Fatal("invalid table accepted")
					} else {
						t.Log(err)
					}
				})
			}
		})
	}
	if _, err := LoadTables(testRoot(t), PreS2a); err == nil {
		t.Fatal("new root accepted as historical")
	}
	if _, err := LoadTables(filepath.Join(instrumentRoot(t), "node/agent/testdata/s2a-pre"), S2a); err == nil {
		t.Fatal("historical root accepted as new")
	}
	if _, err := LoadTables(testRoot(t), ""); err == nil {
		t.Fatal("unspecified contract accepted")
	}
	t.Log("S2a strict_contract: contracts=2 table_rejections=20 crossed_roots=2 unknown_contract=1")
}

func TestS2aSourceRejections(t *testing.T) {
	root := testRoot(t)
	for _, tc := range []struct{ name, file, old, new, red string }{
		{"unknown-token", "node/bpf/combo_masks.h", "[0] = CM_SRC_IP", "[0] = CM_UNKNOWN", "unknown/duplicate mask token"},
		{"unknown-syntax", "node/bpf/combo_masks.h", "[0] =", "[0] ?=", "unknown table entry"},
		{"missing-entry", "node/bpf/combo_masks.h", "[1] =", "[2] =", "table index="},
		{"roster-name", "node/bpf/xdrop.h", "COMBO_EXACT_5TUPLE", "COMBO_UNRECOGNIZED", "combo roster mapping differs"},
		{"identity", "node/bpf/xdrop.h", "// S2a:", "// changed identity:", "input identity mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "s2a-source-")
			if err != nil {
				t.Fatal(err)
			}
			for name := range contractHashes[S2a] {
				b, err := sourceFile(root, name)
				if err != nil {
					t.Fatal(err)
				}
				if name == tc.file {
					s := string(b)
					if !strings.Contains(s, tc.old) {
						t.Fatal("mutation anchor absent")
					}
					b = []byte(strings.Replace(s, tc.old, tc.new, 1))
				}
				dest := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dest, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err = LoadTables(dir, S2a)
			if err == nil || !strings.Contains(err.Error(), tc.red) {
				t.Fatalf("want %q got %v", tc.red, err)
			}
			t.Log(err)
		})
	}
	old := historicalTables(t)
	current := certifiedTablesAt(t, root, S2a)
	for i, m := range old.Masks {
		if i != 20 && i != 32 && m != current.Masks[i] {
			t.Errorf("surviving mask changed at %d", i)
		}
	}
	if !reflect.DeepEqual(old.WhitelistOrder, current.WhitelistOrder) {
		t.Fatal("whitelist sequence changed")
	}
	t.Log("S2a source_rejections=5 surviving_slots_equal=32 whitelist_sequence_equal=31")
}
