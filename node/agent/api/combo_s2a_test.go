package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const preComboSHA = "8f4c8d099f4f6e8fbbb2a1cd9cafe2399e06883cd61740b1cd561f1c643cc076"

func s2aComboSources(t *testing.T) ([]byte, []byte) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	read := func(path string) []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	old := read(filepath.Join(dir, "../testdata/s2a-pre/node/agent/api/combo.go"))
	if fmt.Sprintf("%x", sha256.Sum256(old)) != preComboSHA {
		t.Fatal("S2a frozen classifier identity mismatch")
	}
	return read(filepath.Join(dir, "combo.go")), old
}

func s2aAST(t *testing.T, data []byte) (*ast.File, map[string]*ast.FuncDecl) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "combo.go", data, 0)
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok {
			funcs[fn.Name.Name] = fn
		}
	}
	return f, funcs
}

func s2aFormat(n ast.Node) string {
	var b bytes.Buffer
	if err := format.Node(&b, token.NewFileSet(), n); err != nil {
		panic(err)
	}
	return b.String()
}

// Every expression is interpreted independently. Unsupported AST fails closed;
// no conditions are inferred from the result of Go's first-match switch.
func s2aCondition(t *testing.T, e ast.Expr, vars map[string]bool) bool {
	t.Helper()
	switch x := e.(type) {
	case *ast.Ident:
		if b, ok := vars[x.Name]; ok {
			return b
		}
	case *ast.ParenExpr:
		return s2aCondition(t, x.X, vars)
	case *ast.UnaryExpr:
		if x.Op == token.NOT {
			return !s2aCondition(t, x.X, vars)
		}
	case *ast.BinaryExpr:
		// Evaluate both operands even when Go could short circuit: an unknown
		// dependency must not hide behind a false/true left operand.
		a, b := s2aCondition(t, x.X, vars), s2aCondition(t, x.Y, vars)
		if x.Op == token.LAND {
			return a && b
		}
		if x.Op == token.LOR {
			return a || b
		}
	}
	t.Fatalf("S2a AST dependency/syntax rejected: %s", s2aFormat(e))
	return false
}

func s2aNumber(t *testing.T, e ast.Expr, constants map[string]int) int {
	t.Helper()
	if id, ok := e.(*ast.Ident); ok {
		if n, found := constants[id.Name]; found {
			return n
		}
	}
	if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.INT {
		n, err := strconv.Atoi(lit.Value)
		if err == nil {
			return n
		}
	}
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.SUB {
		return -s2aNumber(t, u.X, constants)
	}
	t.Fatalf("S2a return/constant syntax rejected: %s", s2aFormat(e))
	return 0
}

func s2aConstants(t *testing.T, f *ast.File) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			v := s.(*ast.ValueSpec)
			if len(v.Names) != 1 || len(v.Values) != 1 {
				t.Fatal("S2a explicit constants required")
			}
			out[v.Names[0].Name] = s2aNumber(t, v.Values[0], out)
		}
	}
	return out
}

func s2aActual(input int, cidr bool) int {
	b := bits(input)
	if cidr {
		var k CIDRRuleKey
		if b[0] {
			k.SrcID = 17
		}
		if b[1] {
			k.DstID = 29
		}
		if b[2] {
			k.SrcPort = 40000
		}
		if b[3] {
			k.DstPort = 8443
		}
		if b[4] {
			k.Protocol = 17
		}
		return getCIDRComboType(k)
	}
	return getComboType(keyFor(b[0], b[1], b[2], b[3], b[4]))
}

// TestS2aClassifierConditions is deliberately runnable on the unmodified
// 126b4cb classifier: its duplicate and unreachable cases MUST make it red.
func TestS2aClassifierConditions(t *testing.T) {
	current, old := s2aComboSources(t)
	f, funcs := s2aAST(t, current)
	_, before := s2aAST(t, old)
	constants := s2aConstants(t, f)
	if s2aFormat(funcs["isZeroIP"]) != s2aFormat(before["isZeroIP"]) {
		t.Fatal("S2a AST isZeroIP dependency changed")
	}
	for _, name := range []string{"getComboType", "getCIDRComboType"} {
		t.Run(name, func(t *testing.T) {
			fn, pre := funcs[name], before[name]
			if fn == nil || len(fn.Body.List) != 6 || s2aFormat(fn.Type) != s2aFormat(pre.Type) {
				t.Fatal("S2a AST classifier shape changed")
			}
			for i := 0; i < 5; i++ {
				if s2aFormat(fn.Body.List[i]) != s2aFormat(pre.Body.List[i]) {
					t.Fatalf("S2a AST derived boolean changed at %d", i)
				}
			}
			sw, ok := fn.Body.List[5].(*ast.SwitchStmt)
			if !ok || sw.Init != nil || sw.Tag != nil {
				t.Fatal("S2a AST requires expressionless switch")
			}
			var cases []*ast.CaseClause
			for i, stmt := range sw.Body.List {
				c, ok := stmt.(*ast.CaseClause)
				if !ok || len(c.List) > 1 || len(c.Body) != 1 {
					t.Fatal("S2a AST case shape changed")
				}
				r, ok := c.Body[0].(*ast.ReturnStmt)
				if !ok || len(r.Results) != 1 {
					t.Fatal("S2a AST case must return once")
				}
				if c.List == nil {
					if i != len(sw.Body.List)-1 || s2aNumber(t, r.Results[0], constants) != ComboUnknown {
						t.Fatal("S2a AST default contract changed")
					}
					continue
				}
				cases = append(cases, c)
			}
			if len(cases) != len(sw.Body.List)-1 {
				t.Fatal("S2a AST requires one default")
			}
			satisfied, first := make([]int, len(cases)), make([]int, len(cases))
			varsNames := []string{"hasSrcIP", "hasDstIP", "hasSrcPort", "hasDstPort", "hasProto"}
			if name == "getCIDRComboType" {
				varsNames[0], varsNames[1] = "hasSrcID", "hasDstID"
			}
			for input := 0; input < 32; input++ {
				vars := map[string]bool{}
				for j, n := range varsNames {
					vars[n] = input&(1<<j) != 0
				}
				var hits []int
				for j, c := range cases {
					if s2aCondition(t, c.List[0], vars) {
						hits = append(hits, j)
						satisfied[j]++
					}
				}
				wantCount := 1
				if input == 0 {
					wantCount = 0
				}
				if len(hits) != wantCount {
					t.Errorf("S2a condition overlap/coverage: input=%05b matches=%v want_count=%d", input, hits, wantCount)
				}
				want := ComboUnknown
				if len(hits) > 0 {
					first[hits[0]]++
					want = s2aNumber(t, cases[hits[0]].Body[0].(*ast.ReturnStmt).Results[0], constants)
				}
				if got := s2aActual(input, name == "getCIDRComboType"); got != want {
					t.Errorf("S2a actual/AST mismatch input=%05b got=%d want=%d", input, got, want)
				}
			}
			for i, c := range cases {
				if satisfied[i] == 0 {
					t.Errorf("S2a unsatisfiable case=%d condition=%s", i, s2aFormat(c.List[0]))
				}
				if first[i] == 0 {
					t.Errorf("S2a first-hit unreachable case=%d satisfied=%d condition=%s", i, satisfied[i], s2aFormat(c.List[0]))
				}
			}
			t.Logf("S2a conditions: inputs=32 cases=%d satisfied=%v first_hit=%v", len(cases), satisfied, first)
		})
	}
}

// Compile the frozen, hash-certified actual Go classifier (no interpretation
// of its switch), then compare every input against the live production funcs.
func TestS2aClassifierBeforeAfter(t *testing.T) {
	_, old := s2aComboSources(t)
	dir := t.TempDir()
	source := strings.Replace(string(old), "package api", "package main", 1)
	source += `
type IPAddr [16]byte
type RuleKey struct { SrcIP, DstIP IPAddr; SrcPort, DstPort uint16; Protocol uint8 }
type CIDRRuleKey struct { SrcID, DstID uint32; SrcPort, DstPort uint16; Protocol uint8 }
func main() {
 for i:=0; i<32; i++ {
  var k RuleKey; var c CIDRRuleKey
  if i&1!=0 { k.SrcIP[0]=10; k.SrcIP[15]=7; c.SrcID=17 }
  if i&2!=0 { k.DstIP[0]=10; k.DstIP[15]=9; c.DstID=29 }
  if i&4!=0 { k.SrcPort=40000; c.SrcPort=40000 }
  if i&8!=0 { k.DstPort=8443; c.DstPort=8443 }
  if i&16!=0 { k.Protocol=17; c.Protocol=17 }
  fmt.Printf("[%d,%d]\n",getComboType(k),getCIDRComboType(c))
 }
}
`
	path := filepath.Join(dir, "before.go")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", path).CombinedOutput()
	if err != nil {
		t.Fatalf("frozen classifier compile/run: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 32 {
		t.Fatalf("frozen inputs=%d want=32: %s", len(lines), out)
	}
	for input, line := range lines {
		var pre [2]int
		if err := json.Unmarshal([]byte(line), &pre); err != nil {
			t.Fatal(err)
		}
		post := [2]int{s2aActual(input, false), s2aActual(input, true)}
		if pre != post {
			t.Errorf("S2a zero-behavior mismatch input=%05b before=%v after=%v", input, pre, post)
		}
		t.Logf("input=%05b before=%v after=%v", input, pre, post)
	}
	t.Log("S2a before_after: exact_inputs=32 cidr_inputs=32 compared=64")
}

func TestS2aClassifierRosterAndMapping(t *testing.T) {
	current, old := s2aComboSources(t)
	f, _ := s2aAST(t, current)
	pre, _ := s2aAST(t, old)
	want := s2aConstants(t, pre)
	delete(want, "ComboDstIPDstPortProto")
	delete(want, "ComboDstIPPortsProto")
	if got := s2aConstants(t, f); !reflect.DeepEqual(got, want) {
		t.Errorf("S2a active roster mismatch got=%v want=%v", got, want)
	}
	// Fixed pre-S2a C masks, independently extracted before any edit, indexed
	// by stable combo ID. Only the two retired slots are projected to zero.
	masks := []int{31, 30, 26, 18, 2, 16, 4, 8, 1, 17, 3, 9, 10, 19, 25, 20, 24, 5, 21, 0, 0, 11, 27, 13, 29, 6, 22, 12, 28, 7, 23, 14, 0, 15}
	for _, cidr := range []bool{false, true} {
		seen := map[int]bool{}
		for input := 0; input < 32; input++ {
			got := s2aActual(input, cidr)
			if input == 0 {
				if got != ComboUnknown {
					t.Error("S2a empty input domain changed")
				}
				continue
			}
			if got < 0 || got >= len(masks) || masks[got] == 0 {
				t.Errorf("S2a retired/unknown return cidr=%v input=%05b got=%d", cidr, input, got)
				continue
			}
			if masks[got] != input {
				t.Errorf("S2a field mapping mismatch cidr=%v input=%05b combo=%d mask=%05b", cidr, input, got, masks[got])
			}
			seen[got] = true
		}
		for n, m := range masks {
			if (m != 0) != seen[n] {
				t.Errorf("S2a return set mismatch combo=%d mask=%d seen=%v", n, m, seen[n])
			}
		}
		t.Logf("S2a mapping: cidr=%v inputs=32 active=%d holes=[19 20 32]", cidr, len(seen))
	}
}
