package eval

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"math/bits"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var evalContract = flag.String("eval-contract", string(S2a), "explicit table contract: s2a or pre-s2a; historical calibration requires pre-s2a")

var evalInstrumentRoot = flag.String("eval-instrument-root", "", "absolute instrument tree; defaults to git show-toplevel")

var sourceRoot = flag.String("eval-root", "", "absolute source tree; defaults to this test source's tree, never cwd")

func testRoot(t *testing.T) string {
	t.Helper()
	if *sourceRoot != "" {
		return *sourceRoot
	}
	root := instrumentRoot(t)
	switch Contract(*evalContract) {
	case S2a:
		return filepath.Join(root, "node/agent/testdata/s2b-pre")
	case PreS2a:
		return filepath.Join(root, "node/agent/testdata/s2a-pre")
	case S2b:
		return root
	default:
		t.Fatalf("explicit known combo contract required: %s", *evalContract)
		return ""
	}
}
func testTables(t *testing.T) Tables { t.Helper(); return certifiedTables(t) }

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestSourceContract(t *testing.T) { certifiedTables(t) }
func instrumentRoot(t *testing.T) string {
	t.Helper()
	if *evalInstrumentRoot != "" {
		if !filepath.IsAbs(*evalInstrumentRoot) {
			t.Fatal("absolute instrument root required")
		}
		return *evalInstrumentRoot
	}
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
func historicalTables(t *testing.T) Tables {
	t.Helper()
	return certifiedTablesAt(t, filepath.Join(instrumentRoot(t), "node/agent/testdata/s2a-pre"), PreS2a)
}
func certifiedTables(t *testing.T) Tables {
	t.Helper()
	return certifiedTablesAt(t, testRoot(t), Contract(*evalContract))
}
func certifiedTablesAt(t *testing.T, root string, contract Contract) Tables {
	t.Helper()
	cmd := exec.Command("python3", filepath.Join(instrumentRoot(t), "node/agent/eval/testdata/parity/gate-mask-parity.py"), "--root", root, "--contract", string(contract), "--ck")
	var out, diag bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &diag
	expected := map[string]map[string]string{}
	for _, name := range []string{"node/bpf/xdrop.h", "node/bpf/combo_masks.h", "node/bpf/xdrop_gate.c"} {
		b, err := sourceFile(root, name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := filepath.EvalSymlinks(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		expected[name] = map[string]string{"path": p, "sha256": fmt.Sprintf("%x", sha256.Sum256(b))}
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("S1-5: %v; stdout=%s stderr=%s", err, &out, &diag)
	}
	var report struct {
		Root      string
		Contract  string
		Authority string `json:"authority_baseline"`
		Inputs    map[string]map[string]string
		CallCount int `json:"call_count"`
		Errors    []json.RawMessage
	}
	if err := json.Unmarshal(diag.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	wantRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.Contract != string(contract) || report.Authority != "bd686710e3fd9fbb54bf889b2cc1d197873af906" || out.String() != "0\n" || report.Root != wantRoot || report.CallCount != 31 || len(report.Errors) != 0 || len(report.Inputs) != len(expected) {
		t.Fatalf("S1-5 input/count contract: stdout=%s stderr=%s", &out, &diag)
	}
	for name, want := range expected {
		got := report.Inputs[name]
		if got["path"] != want["path"] || got["sha256"] != want["sha256"] {
			t.Fatalf("input identity %s: got=%v want=%v", name, got, want)
		}
	}
	table, err := LoadTables(root, contract)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Masks) != 34 || table.Valid != contract.bitmap() {
		t.Fatalf("mask contract: %+v", table)
	}
	t.Logf("contract=%s table_length=%d valid_bits=%d whitelist_calls=%d root=%s", contract, len(table.Masks), bits.OnesCount64(table.Valid), len(table.WhitelistOrder), wantRoot)
	return table
}
func TestCoreLookup(t *testing.T) {
	table := testTables(t)
	packet := Packet{Tuple: Tuple{Src: ip("10.0.2.1"), Dst: ip("10.1.100.2"), Sport: 1234, Dport: 443, Proto: 6}, Length: 40, Flags: 16}
	rules := RuleSet{Exact: []Rule{{ID: "tcp", Key: Tuple{Proto: 6}, Rate: 1000}}, ExactBitmap: 1 << 5}
	got, err := Evaluate(table, rules, packet)
	if err != nil {
		t.Fatal(err)
	}
	want := Decision{Exact, 5, "tcp", "rate_limit@1000"}
	if got != want {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
	rules.ExactBitmap = 0
	got, err = Evaluate(table, rules, packet)
	if err != nil {
		t.Fatal(err)
	}
	if got != noMatch() {
		t.Fatalf("zero bitmap: %+v", got)
	}
	rules.Exact[0].Anomaly = 2
	rules.ExactBitmap = 1 << 5
	packet.Anomaly = 2
	got, err = Evaluate(table, rules, packet)
	if err != nil {
		t.Fatal(err)
	}
	want = Decision{AnomalyExact, 5, "tcp", "drop"}
	if got != want {
		t.Fatalf("anomaly positive-rate branch: got=%+v want=%+v", got, want)
	}
}
func TestMissingSourceFails(t *testing.T) {
	if _, err := LoadTables(t.TempDir(), S2a); err == nil {
		t.Fatal("absent source accepted")
	}
	if _, err := LoadTables(".", S2a); err == nil {
		t.Fatal("relative root accepted")
	}
	if _, err := Evaluate(Tables{}, RuleSet{}, Packet{}); err == nil {
		t.Fatal("absent tables accepted")
	}
}

func TestAliasBitmap(t *testing.T) {
	// Preserve the strict historical alias contract and its independent answers.
	table := historicalTables(t)
	packet := Packet{Tuple: Tuple{Src: ip("10.0.2.1"), Dst: ip("10.1.100.2"), Sport: 1234, Dport: 443, Proto: 6}, Length: 40}
	for _, c := range []struct {
		combo int
		key   Tuple
	}{{2, Tuple{Dst: packet.Dst, Dport: 443, Proto: 6}}, {20, Tuple{Dst: packet.Dst, Dport: 443, Proto: 6}}, {1, Tuple{Dst: packet.Dst, Sport: 1234, Dport: 443, Proto: 6}}, {32, Tuple{Dst: packet.Dst, Sport: 1234, Dport: 443, Proto: 6}}} {
		t.Run(fmt.Sprint(c.combo), func(t *testing.T) {
			rs := RuleSet{Exact: []Rule{{ID: "alias-probe", Key: c.key}}, ExactBitmap: 1 << c.combo}
			got, err := Evaluate(table, rs, packet)
			if err != nil {
				t.Fatal(err)
			}
			want := Decision{Exact, c.combo, "alias-probe", "drop"}
			if got != want {
				t.Fatalf("explicit alias bitmap got=%+v want=%+v", got, want)
			}
		})
	}
}
