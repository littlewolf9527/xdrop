package cidr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"reflect"
	"testing"
)

func TestHCA13ApplyArgs(t *testing.T) {
	for _, known := range []bool{true, false} {
		name := "unknown"
		if known {
			name = "known"
		}
		t.Run(name, func(t *testing.T) {
			m, tables := newTestManager() // manager_test.go: in-memory TrieWriter.
			var before, want, saved TrieEntries
			for i := range want {
				before[i] = map[string]uint32{"keep": 1, "change": 2, "remove": 3}
				want[i] = map[string]uint32{"keep": 1, "change": 4, "add": 5}
				saved[i] = maps.Clone(want[i])
				tables[1][i].entries = maps.Clone(before[i])
			}
			m.known[1] = known
			if err := m.Apply(1, before, want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, saved) {
				t.Fatal("caller want changed")
			}
			for i := range want {
				if !reflect.DeepEqual(tables[1][i].entries, saved[i]) {
					t.Fatalf("table %d: %v", i, tables[1][i].entries)
				}
				if tables[1][i].deleteCalls != 1 || tables[1][i].putCalls != 2 {
					t.Fatal("unexpected delta writes", i)
				}
			}
		})
	}
	t.Run("source", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "copies.go", nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		functions, writes := 0, 0
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "Apply" {
				continue
			}
			functions++
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				var lhs []ast.Expr
				switch x := n.(type) {
				case *ast.AssignStmt:
					lhs = x.Lhs
				case *ast.IncDecStmt:
					lhs = []ast.Expr{x.X}
				}
				for _, e := range lhs {
					index, ok := e.(*ast.IndexExpr)
					if !ok {
						continue
					}
					if id, ok := index.X.(*ast.Ident); ok && id.Name == "want" {
						writes++
					}
				}
				return true
			})
		}
		if functions != 1 || writes != 0 {
			t.Fatalf("Apply functions=%d want element writes=%d", functions, writes)
		}
	})
}
