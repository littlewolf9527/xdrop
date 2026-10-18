package bpf

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func cut54StartupContract(source []byte) ([]string, error) {
	file, e := parser.ParseFile(token.NewFileSet(), "main.go", source, 0)
	if e != nil {
		return nil, e
	}
	var stack []ast.Node
	calls := 0
	var stale []string
	var failure error
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if ok && sel.Sel.Name == "ClearRetiredTailSlot" {
			calls++
			for _, parent := range stack {
				branch, ok := parent.(*ast.IfStmt)
				if !ok {
					continue
				}
				inInit := false
				for _, ancestor := range stack {
					if ancestor == branch.Init {
						inInit = true
					}
				}
				if !inInit {
					failure = fmt.Errorf("slot 0 clearing must run on every kernel, outside conditional branches")
				}
			}
		}
		if ok && sel.Sel.Name == "CleanStalePins" {
			ast.Inspect(call.Args[1], func(n ast.Node) bool {
				if v, ok := n.(*ast.BasicLit); ok && v.Kind == token.STRING {
					stale = append(stale, strings.Trim(v.Value, "\""))
				}
				return true
			})
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "requireMapFrom" {
			for _, arg := range call.Args {
				if v, ok := arg.(*ast.BasicLit); ok && (v.Value == `"rl_states"` || v.Value == `"cidr_rl_states"` || v.Value == `"tail_stash"`) {
					failure = fmt.Errorf("retired map remains required: %s", v.Value)
				}
			}
		}
		return true
	})
	if failure != nil {
		return nil, failure
	}
	if calls != 1 {
		return nil, fmt.Errorf("unconditional retired-slot clearing calls=%d want=1", calls)
	}
	for _, name := range []string{"tail_stash", "rl_states", "cidr_rl_states"} {
		found := false
		for _, v := range stale {
			if v == name {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("stale pin cleanup missing %s", name)
		}
	}
	return stale, nil
}
func TestCut54StartupContract(t *testing.T) {
	source, e := os.ReadFile("../main.go")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = cut54StartupContract(source); e != nil {
		t.Fatal(e)
	}
	text := string(source)
	negative := []string{
		strings.Replace(text, "xdropbpf.ClearRetiredTailSlot(progTailMap)", "unrelated(progTailMap)", 1),
		strings.Replace(text, "if err := xdropbpf.ClearRetiredTailSlot(progTailMap); err != nil {\n\t\tlog.Fatalf(\"[startup] %v\", err)\n\t}", "if false { if err := xdropbpf.ClearRetiredTailSlot(progTailMap); err != nil { panic(err) } }", 1),
		strings.Replace(text, `"tail_stash", "rl_states", "cidr_rl_states"`, `"tail_stash", "rl_states"`, 1),
	}
	for i, mutant := range negative {
		if mutant == text {
			t.Fatalf("startup negative control %d did not mutate source", i)
		}
		if _, e = cut54StartupContract([]byte(mutant)); e == nil {
			t.Fatalf("startup negative control %d falsely green", i)
		}
	}
	t.Log("CUT54_STARTUP_CONTRACT every_kernel=1 retired_required=0 stale_names=3 negative_controls=3")
}
