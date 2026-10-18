package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	xdropbpf "github.com/littlewolf9527/xdrop/node/agent/bpf"
	"github.com/littlewolf9527/xdrop/node/agent/config"
)

func TestFFStartupOrder(t *testing.T) {
	parse := func(path, name string) *ast.FuncDecl {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
				return fn
			}
		}
		t.Fatalf("missing %s in %s", name, path)
		return nil
	}
	calls := func(n ast.Node) map[string][]token.Pos {
		out := map[string][]token.Pos{}
		ast.Inspect(n, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				name := ""
				switch fn := c.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					if id, ok := fn.X.(*ast.Ident); ok {
						name = id.Name + "." + fn.Sel.Name
					}
				}
				out[name] = append(out[name], c.Pos())
			}
			return true
		})
		return out
	}
	main := parse("main.go", "main")
	all := calls(main.Body)
	names := []string{"api.PreparePinnedStartup", "setupDevmap", "configureFastForward", "clearFastForwardSlots", "xdropbpf.ClearRetiredTailSlot"}
	for _, name := range names {
		if len(all[name]) != 1 {
			t.Errorf("%s calls=%d want=1", name, len(all[name]))
		}
	}
	if len(all[names[0]]) == 1 && len(all[names[4]]) == 1 {
		for _, name := range names[1:4] {
			for _, pos := range all[name] {
				if pos <= all[names[0]][0] || pos >= all[names[4]][0] {
					t.Errorf("%s must follow PreparePinnedStartup and precede ClearRetiredTailSlot", name)
				}
			}
		}
	}
	wired := 0
	for _, stmt := range main.Body.List {
		branch, ok := stmt.(*ast.IfStmt)
		if !ok || branch.Else == nil {
			continue
		}
		cond, ok := branch.Cond.(*ast.Ident)
		if !ok || cond.Name != "fastForwardMode" {
			continue
		}
		ff, traditional := calls(branch.Body), calls(branch.Else)
		if len(ff["setupDevmap"]) == 1 && len(ff["configureFastForward"]) == 1 && ff["setupDevmap"][0] < ff["configureFastForward"][0] && len(traditional["clearFastForwardSlots"]) == 1 {
			wired++
		}
	}
	if wired != 1 {
		t.Errorf("FF write and traditional clear branch wiring=%d want=1", wired)
	}
	ast.Inspect(parse("api/handlers.go", "initDynamicConfig").Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && (id.Name == "ConfigFastForwardEnabled" || id.Name == "ConfigFilterIfindex") {
			t.Errorf("initDynamicConfig must preserve %s", id.Name)
		}
		return true
	})
}

func TestRestoreSkipsAttached(t *testing.T) {
	failure := errors.New("synthetic readback failure")
	for _, tc := range []struct {
		name     string
		attached uint8
		err      error
		want     []string
	}{{"attached", 2, nil, nil}, {"detached", 0, nil, []string{"in", "out"}}, {"read-error", 2, failure, []string{"in", "out"}}} {
		t.Run(tc.name, func(t *testing.T) {
			var restored, read []string
			err := restoreFFInterfaces(config.InterfacePair{Inbound: "in", Outbound: "out"}, func(name string) (xdropbpf.XDPAttachment, error) {
				read = append(read, name)
				return xdropbpf.XDPAttachment{Attached: tc.attached}, tc.err
			}, func(name string) error { restored = append(restored, name); return nil })
			if err != nil || !reflect.DeepEqual(restored, tc.want) || !reflect.DeepEqual(read, []string{"in", "out"}) {
				t.Errorf("restore=%v read=%v err=%v want=%v", restored, read, err, tc.want)
			}
		})
	}
}
