package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Structural interface inventory includes config/trie wrappers embedding *ebpf.Map.
// Each implementing type must own the three methods, never merely promote them.
func flipBMirrorGuard(files []*ast.File) ([]string, []string) {
	required := strings.Fields("KeySize NextKey Delete ValueSize MaxEntries Lookup Update BatchLookup BatchUpdate BatchDelete")
	own, embedded := map[string]map[string]bool{}, map[string][]string{}
	var name func(ast.Expr) string
	name = func(e ast.Expr) string {
		switch x := e.(type) {
		case *ast.Ident:
			return x.Name
		case *ast.StarExpr:
			return name(x.X)
		case *ast.SelectorExpr:
			return name(x.X) + "." + x.Sel.Name
		}
		return ""
	}
	for _, f := range files {
		for _, d := range f.Decls {
			switch x := d.(type) {
			case *ast.GenDecl:
				for _, s := range x.Specs {
					if d, ok := s.(*ast.TypeSpec); ok {
						if st, ok := d.Type.(*ast.StructType); ok {
							if own[d.Name.Name] == nil {
								own[d.Name.Name] = map[string]bool{}
							}
							for _, field := range st.Fields.List {
								if len(field.Names) == 0 {
									embedded[d.Name.Name] = append(embedded[d.Name.Name], name(field.Type))
								}
							}
						}
					}
				}
			case *ast.FuncDecl:
				if x.Recv != nil {
					receiver := name(x.Recv.List[0].Type)
					if own[receiver] == nil {
						own[receiver] = map[string]bool{}
					}
					own[receiver][x.Name.Name] = true
				}
			}
		}
	}
	var has func(string, string, map[string]bool) bool
	has = func(typ, method string, seen map[string]bool) bool {
		if typ == "ebpf.Map" || typ == "ruleMirrorMap" {
			return true
		}
		if seen[typ] {
			return false
		}
		seen[typ] = true
		if own[typ][method] {
			return true
		}
		for _, base := range embedded[typ] {
			if has(base, method, seen) {
				return true
			}
		}
		return false
	}
	var owners, bad []string
	for typ := range own {
		matches := true
		for _, method := range required {
			matches = matches && has(typ, method, map[string]bool{})
		}
		if !matches {
			continue
		}
		owners = append(owners, typ)
		for _, method := range required[7:] {
			if !own[typ][method] {
				bad = append(bad, typ+"."+method)
			}
		}
	}
	sort.Strings(owners)
	sort.Strings(bad)
	return owners, bad
}
func TestFlipBMirrorOverrides(t *testing.T) {
	for _, dir := range []string{".", "../sync"} {
		paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		var files []*ast.File
		for _, path := range paths {
			f, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if e != nil {
				t.Fatal(e)
			}
			files = append(files, f)
		}
		owners, bad := flipBMirrorGuard(files)
		t.Logf("FLIPB_MIRROR_TYPES package=%s types=%s", dir, strings.Join(owners, ","))
		if len(owners) == 0 || len(bad) != 0 {
			t.Fatalf("promoted batch methods: %v", bad)
		}
	}
	f, err := parser.ParseFile(token.NewFileSet(), "control.go", "package control; type promoted struct { ruleMirrorMap }", 0)
	if err != nil {
		t.Fatal(err)
	}
	owners, bad := flipBMirrorGuard([]*ast.File{f})
	if len(owners) != 1 || len(bad) != 3 {
		t.Fatal("promoted-method positive control escaped", owners, bad)
	}
	t.Log("FLIPB_PROMOTED_CONTROL rejected=1 methods=3")
}
