package abi

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
)

func TestB1LogicalStateABI(t *testing.T) {
	spec := loadSpec(t)
	for name, width := range map[string]uint32{"id_counts": 40, "id_rl_states": 16} {
		m := spec.Maps[name]
		if m == nil || m.Type != ebpf.PerCPUHash || m.KeySize != 4 || m.ValueSize != width || m.MaxEntries != 2*500000 || m.Flags != 1 {
			t.Fatalf("B1 logical map schema %s: %+v", name, m)
		}
	}
	// The C compiler enforces the matching xdrop.h _Static_asserts at 0/8.
	// ELF key/value sizes above and Go offsets here bind the wire reader.
	var v api.LogicalRuleCounters
	if unsafe.Sizeof(v) != 40 || unsafe.Offsetof(v.Match) != 0 || unsafe.Offsetof(v.Drop) != 8 {
		t.Fatalf("logical counter ABI size/match/drop=%d/%d/%d want=40/0/8", unsafe.Sizeof(v), unsafe.Offsetof(v.Match), unsafe.Offsetof(v.Drop))
	}
	if unsafe.Offsetof(v.MatchBytes) != 16 || unsafe.Offsetof(v.DropBytes) != 24 || unsafe.Offsetof(v.LastHitNS) != 32 {
		t.Fatal("logical counter byte/time offsets must be 16/24/32")
	}
}

func checkStartupWiring(src []byte, helperSources ...[]byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", src, 0)
	if err != nil {
		return []string{fmt.Sprintf("parse startup source: %v", err)}
	}
	var violations []string
	var helper []byte
	if len(helperSources) > 0 {
		helper = helperSources[0]
	} else {
		helper, err = os.ReadFile("../api/startup_clear.go")
		if err != nil {
			return []string{err.Error()}
		}
	}
	isCall := func(c *ast.CallExpr, receiver, name string) bool {
		s, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := s.X.(*ast.Ident)
		return ok && id.Name == receiver && s.Sel.Name == name
	}
	var calls, direct, fatal int
	var startupPos, handlersPos token.Pos
	required := map[string]int{}
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isCall(c, "api", "PreparePinnedStartup") {
			calls++
			startupPos = c.Pos()
		}
		if isCall(c, "api", "NewHandlers") {
			handlersPos = c.Pos()
		}
		if isCall(c, "xdropbpf", "ClearDataMaps") || isCall(c, "xdropbpf", "ClearMapKeys") {
			violations = append(violations, "legacy startup clearing is forbidden")
		}
		if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "requireMapFrom" && len(c.Args) == 3 {
			coll, ok := c.Args[0].(*ast.Ident)
			lit, lok := c.Args[2].(*ast.BasicLit)
			if ok && coll.Name == "mainColl" && lok {
				name, _ := strconv.Unquote(lit.Value)
				required[name]++
			}
		}
		return true
	})
	for _, d := range f.Decls {
		main, ok := d.(*ast.FuncDecl)
		if !ok || main.Name.Name != "main" || main.Body == nil {
			continue
		}
		for _, statement := range main.Body.List {
			pin, ok := statement.(*ast.IfStmt)
			if !ok {
				continue
			}
			condition, ok := pin.Cond.(*ast.BinaryExpr)
			if !ok || condition.Op != token.NEQ {
				continue
			}
			path, ok := condition.X.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			owner, ok := path.X.(*ast.Ident)
			empty, eok := condition.Y.(*ast.BasicLit)
			if !ok || owner.Name != "mainPinResult" || path.Sel.Name != "PinPath" || !eok || empty.Value != `""` {
				continue
			}
			for _, child := range pin.Body.List {
				branch, ok := child.(*ast.IfStmt)
				if !ok {
					continue
				}
				assignment, ok := branch.Init.(*ast.AssignStmt)
				if !ok || len(assignment.Rhs) != 1 {
					continue
				}
				call, ok := assignment.Rhs[0].(*ast.CallExpr)
				if !ok || !isCall(call, "api", "PreparePinnedStartup") {
					continue
				}
				if len(call.Args) != 2 {
					continue
				}
				mainID, mok := call.Args[0].(*ast.Ident)
				gateID, gok := call.Args[1].(*ast.Ident)
				if !mok || !gok || mainID.Name != "mainColl" || gateID.Name != "gateColl" {
					continue
				}
				direct++
				condition, ok := branch.Cond.(*ast.BinaryExpr)
				if !ok || condition.Op != token.NEQ {
					continue
				}
				lhs, lok := condition.X.(*ast.Ident)
				rhs, rok := condition.Y.(*ast.Ident)
				if !lok || !rok || lhs.Name != "err" || rhs.Name != "nil" {
					continue
				}
				for _, s := range branch.Body.List {
					if e, ok := s.(*ast.ExprStmt); ok {
						if c, ok := e.X.(*ast.CallExpr); ok && isCall(c, "log", "Fatalf") {
							fatal++
						}
					}
				}
			}
		}
	}
	if calls != 1 || direct != 1 || fatal != 1 || handlersPos == 0 || startupPos >= handlersPos {
		violations = append(violations, fmt.Sprintf("startup gate calls/direct/fatal=%d/%d/%d must precede NewHandlers", calls, direct, fatal))
	}
	for _, name := range []string{"id_counts", "id_rl_states"} {
		if required[name] != 1 {
			violations = append(violations, "required logical map "+name+" missing")
		}
	}
	hf, err := parser.ParseFile(token.NewFileSet(), "startup_clear.go", helper, 0)
	if err != nil {
		return append(violations, err.Error())
	}
	listed := map[string]int{}
	strictCalls, localMapTypes := 0, 0
	ast.Inspect(hf, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "StrictClearAndRecount" {
				strictCalls++
			}
		}
		if field, ok := n.(*ast.Field); ok {
			if id, ok := field.Type.(*ast.Ident); ok && id.Name == "StartupMap" {
				localMapTypes++
			}
		}
		return true
	})
	if strictCalls != 2 || localMapTypes != 1 {
		violations = append(violations, fmt.Sprintf("local strict startup calls/types=%d/%d want=2/1", strictCalls, localMapTypes))
	}
	for _, imp := range hf.Imports {
		if imp.Path.Value == `"github.com/littlewolf9527/xdrop/node/agent/bpf"` {
			violations = append(violations, "api startup must not import bpf")
		}
	}
	var order []string
	for _, d := range hf.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Name.Name == "PreparePinnedStartup" {
			for _, stmt := range fn.Body.List {
				loop, ok := stmt.(*ast.RangeStmt)
				if !ok {
					continue
				}
				list, ok := loop.X.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, el := range list.Elts {
					if lit, ok := el.(*ast.BasicLit); ok {
						name, _ := strconv.Unquote(lit.Value)
						listed[name]++
					}
				}
			}
		}
		if fn.Name.Name == "clearStartupTables" {
			for _, stmt := range fn.Body.List {
				if loop, ok := stmt.(*ast.RangeStmt); ok {
					if id, ok := loop.X.(*ast.Ident); ok {
						order = append(order, id.Name)
					}
				}
				if branch, ok := stmt.(*ast.IfStmt); ok {
					if a, ok := branch.Init.(*ast.AssignStmt); ok && len(a.Rhs) == 1 {
						if c, ok := a.Rhs[0].(*ast.CallExpr); ok && isCall(c, "receipt", "Quiesce") {
							order = append(order, "receipt")
						}
					}
				}
			}
		}
	}
	wantNames := []string{"blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b", "cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "sv4_cidr_trie_b", "dv4_cidr_trie_b", "sv6_cidr_trie_b", "dv6_cidr_trie_b", "whitelist", "whitelist_b", "id_counts", "id_rl_states"}
	for _, name := range wantNames {
		if listed[name] != 1 {
			violations = append(violations, fmt.Sprintf("strict startup list %s count=%d want=1", name, listed[name]))
		}
	}
	if len(listed) != len(wantNames) {
		violations = append(violations, "strict startup roster must match the named business and logical maps")
	}
	if strings.Join(order, ",") != "business,receipt,logical" {
		violations = append(violations, "startup order="+strings.Join(order, ","))
	}
	return violations
}

func TestB1LogicalStateStartupContract(t *testing.T) {
	src, err := os.ReadFile("../main.go")
	if err != nil {
		t.Fatal(err)
	}
	if violations := checkStartupWiring(src); len(violations) != 0 {
		t.Fatalf("startup wiring violations:\n%s", strings.Join(violations, "\n"))
	}
	t.Log("real main.go startup wiring violations=0")
}

func TestB1LogicalStateStartupContractNegativeControls(t *testing.T) {
	src, err := os.ReadFile("../main.go")
	if err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile("../api/startup_clear.go")
	if err != nil {
		t.Fatal(err)
	}
	const call = `		if err := api.PreparePinnedStartup(mainColl, gateColl); err != nil {
			log.Fatalf("[startup] pinned state reset failed: %v", err)
		}
`
	replaceOnce := func(t *testing.T, s, old, new string) string {
		t.Helper()
		if strings.Count(s, old) != 1 {
			t.Fatalf("mutation replacement hits=%d want=1 for %q", strings.Count(s, old), old)
		}
		return strings.Replace(s, old, new, 1)
	}
	for _, name := range []string{"a_if_false", "b_uncalled_function", "c_outside_pin_branch", "d_missing_id_rl_states", "e_logical_before_receipt", "f_warn_continue", "g_after_NewHandlers", "h_non_strict_business"} {
		t.Run(name, func(t *testing.T) {
			main, impl := string(src), string(helper)
			switch name {
			case "h_non_strict_business":
				impl = replaceOnce(t, impl, "range business {\n\t\tif err := StrictClearAndRecount(table.table)", "range business {\n\t\tif err := nonStrictClear(table.table)")
			case "a_if_false":
				main = replaceOnce(t, main, call, "if false {\n"+call+"}\n")
			case "b_uncalled_function":
				main = replaceOnce(t, main, call, "") + "\nfunc unusedB1StartupClear(mainColl,gateColl *ebpf.Collection){\n" + call + "}\n"
			case "c_outside_pin_branch":
				main = replaceOnce(t, main, call, "")
				main = replaceOnce(t, main, "\tif mainPinResult.PinPath != \"\" {\n", call+"\tif mainPinResult.PinPath != \"\" {\n")
			case "d_missing_id_rl_states":
				impl = replaceOnce(t, impl, `[]string{"id_counts", "id_rl_states"}`, `[]string{"id_counts"}`)
			case "e_logical_before_receipt":
				// The temporary cursor distinguishes the two loop identities;
				// every replacement must still hit exactly one occurrence.
				impl = replaceOnce(t, impl, "range business {", "range __swap {")
				impl = replaceOnce(t, impl, "range logical {", "range business {")
				impl = replaceOnce(t, impl, "range __swap {", "range logical {")
			case "f_warn_continue":
				main = replaceOnce(t, main, `log.Fatalf("[startup] pinned state reset failed: %v", err)`, `log.Printf("[startup] pinned state reset failed: %v", err)`)
			case "g_after_NewHandlers":
				main = replaceOnce(t, main, call, "")
				main = replaceOnce(t, main, "\thandlers.SetRateLimitSnapshot(rateLimit)\n", "\thandlers.SetRateLimitSnapshot(rateLimit)\n"+call)
			}
			if _, err := parser.ParseFile(token.NewFileSet(), "mutant.go", main, 0); err != nil {
				t.Fatal(err)
			}
			violations := checkStartupWiring([]byte(main), []byte(impl))
			if len(violations) == 0 {
				t.Fatal("mutated startup wiring unexpectedly accepted")
			}
			for _, v := range violations {
				t.Log(v)
			}
		})
	}
}
