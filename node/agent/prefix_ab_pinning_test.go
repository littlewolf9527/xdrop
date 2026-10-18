package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
)

func TestPrefixABEffectivePinMode(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	render := func(n ast.Node) string {
		var b bytes.Buffer
		if err := printer.Fprint(&b, fset, n); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	gate, links, configuredMain := 0, 0, 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if render(call.Fun) == "resolveLink" {
			if len(call.Args) != 4 || render(call.Args[2]) != "string(mainPinResult.EffectiveMode)" {
				t.Fatal("link does not follow the main collection's actual mode")
			}
			links++
		}
		if render(call.Fun) == "xdropbpf.Load" && len(call.Args) == 1 {
			lit, ok := call.Args[0].(*ast.CompositeLit)
			if !ok {
				t.Fatal("unmodeled loader options")
			}
			values := map[string]string{}
			for _, el := range lit.Elts {
				kv := el.(*ast.KeyValueExpr)
				values[render(kv.Key)] = render(kv.Value)
			}
			if values["SpecPath"] == "gatePath" {
				if values["Mode"] != "mainPinResult.EffectiveMode" {
					t.Fatal("gate does not follow main's actual mode")
				}
				gate++
			} else if values["Mode"] == "xdropbpf.Mode(cfg.BPF.Pinning)" {
				configuredMain++
			}
		}
		return true
	})
	if gate != 1 || links != 3 || configuredMain != 1 {
		t.Fatalf("mode paths: gate=%d links=%d configured_main=%d", gate, links, configuredMain)
	}
	t.Log("CLOSEOUT_TD093_MODE gate=1 links=3 configured_main=1")
}
