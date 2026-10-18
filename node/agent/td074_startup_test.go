package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestTD074StartupAndProtectedRoute(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	var mainBody *ast.BlockStmt
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "main" {
			mainBody = fn.Body
		}
	}
	if mainBody == nil {
		t.Fatal("main missing")
	}
	var handlers, divisor, snapshot token.Pos
	var attaches []token.Pos
	routes, divisorCalls, snapshotCalls := 0, 0, 0
	ast.Inspect(mainBody, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok {
			switch id.Name {
			case "configureRateLimitDivisor":
				divisor = call.Pos()
				divisorCalls++
			case "resolveLink":
				attaches = append(attaches, call.Pos())
			}
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "NewHandlers" {
			handlers = call.Pos()
		}
		if sel.Sel.Name == "SetRateLimitSnapshot" {
			snapshot = call.Pos()
			snapshotCalls++
		}
		if sel.Sel.Name == "GET" && len(call.Args) > 0 {
			if s, ok := call.Args[0].(*ast.BasicLit); ok {
				path, _ := strconv.Unquote(s.Value)
				if path == "/stats/cpu" {
					routes++
					receiver, ok := sel.X.(*ast.Ident)
					if !ok || receiver.Name != "protected" {
						t.Error("TD074_ROUTE stats/cpu must use protected group")
					}
					target, ok := call.Args[1].(*ast.SelectorExpr)
					if !ok || target.Sel.Name != "GetCPUStats" {
						t.Error("TD074_ROUTE must invoke GetCPUStats")
					}
				}
			}
		}
		return true
	})
	if divisorCalls != 1 || snapshotCalls != 1 || handlers == 0 || divisor <= handlers || snapshot <= divisor || len(attaches) == 0 {
		t.Fatalf("TD074_STARTUP handlers=%d divisor=%d/%d snapshot=%d/%d attaches=%v", handlers, divisor, divisorCalls, snapshot, snapshotCalls, attaches)
	}
	for _, pos := range attaches {
		if pos <= snapshot {
			t.Errorf("TD074_STARTUP XDP attach at %d before divisor snapshot at %d", pos, snapshot)
		}
	}
	if routes != 1 {
		t.Fatalf("TD074_ROUTE count=%d want=1", routes)
	}
}
