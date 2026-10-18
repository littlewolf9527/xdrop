// Run from the repository root: go run scripts/check-condexpr-isolation.go
// This proves a stronger boundary than entry-specific reachability: no existing
// production declaration may reference any new declaration or new package.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	overlayPath := flag.String("overlay", "", "same overlay used for a mutation")
	flag.Parse()
	root, e := os.Getwd()
	must(e)
	overlay := struct{ Replace map[string]string }{}
	if *overlayPath != "" {
		b, e := os.ReadFile(*overlayPath)
		must(e)
		must(json.Unmarshal(b, &overlay))
	}
	read := func(p string) []byte {
		abs := filepath.Join(root, p)
		if replace, ok := overlay.Replace[abs]; ok {
			abs = replace
		}
		b, e := os.ReadFile(abs)
		must(e)
		return b
	}
	b, e := exec.Command("git", "ls-tree", "-r", "--name-only", "9f6fa1e84f0c4f0582349ce6b8eacce59d361ea5", "controller", "node/agent").Output()
	must(e)
	old := map[string]bool{}
	for _, p := range strings.Split(string(b), "\n") {
		old[p] = true
	}
	b, e = exec.Command("git", "ls-tree", "-r", "--name-only", "16da50fe28f33896a5146b06ffb7c17160283160", "controller", "node/agent").Output()
	must(e)
	protected := map[string]bool{}
	for _, p := range strings.Split(string(b), "\n") {
		if !old[p] && strings.HasPrefix(p, "node/agent/") && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			protected[p] = true
		}
	}
	if len(protected) != 5 {
		must(fmt.Errorf("protected file anchor mismatch: got %d, want 5", len(protected)))
	}
	files := map[string]*ast.File{}
	newNames := map[string]map[string]bool{}
	newTypes := map[string]map[string]bool{}
	newPackages := map[string]bool{}
	packagePath := func(p string) string { return "github.com/littlewolf9527/xdrop/" + filepath.ToSlash(filepath.Dir(p)) }
	for _, dir := range []string{"controller", "node/agent"} {
		must(filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "web" || d.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, e := parser.ParseFile(token.NewFileSet(), p, read(p), parser.ParseComments)
			if e != nil {
				return e
			}
			for _, imp := range f.Imports {
				path, e := strconv.Unquote(imp.Path.Value)
				if e != nil {
					return e
				}
				if imp.Name != nil && imp.Name.Name == "." {
					return fmt.Errorf("dot import is forbidden: %s: %s", p, path)
				}
				if path == "C" {
					return fmt.Errorf("cgo import C is forbidden: %s", p)
				}
			}
			for _, group := range f.Comments {
				for _, comment := range group.List {
					for _, directive := range []string{"//go:linkname", "//export"} {
						if strings.Contains(comment.Text, directive) {
							return fmt.Errorf("%s directive is forbidden: %s", directive, p)
						}
					}
				}
			}
			files[p] = f
			pkg := packagePath(p)
			if protected[p] {
				if newNames[pkg] == nil {
					newNames[pkg] = map[string]bool{}
					newTypes[pkg] = map[string]bool{}
				}
				for _, decl := range f.Decls {
					switch v := decl.(type) {
					case *ast.FuncDecl:
						if v.Name.Name == "init" {
							return fmt.Errorf("new init creates a production entry: %s", p)
						}
						newNames[pkg][v.Name.Name] = true
					case *ast.GenDecl:
						for _, spec := range v.Specs {
							if typ, ok := spec.(*ast.TypeSpec); ok {
								newNames[pkg][typ.Name.Name] = true
								// An alias can still denote a baseline type; it creates no new type.
								if !typ.Assign.IsValid() {
									newTypes[pkg][typ.Name.Name] = true
								}
							}
							if values, ok := spec.(*ast.ValueSpec); ok {
								for _, name := range values.Names {
									if name.Name != "_" {
										newNames[pkg][name.Name] = true
									}
								}
								for _, expr := range values.Values {
									hasCall := false
									hasReceive := false
									ast.Inspect(expr, func(n ast.Node) bool {
										if _, ok := n.(*ast.CallExpr); ok {
											hasCall = true
										}
										if unary, ok := n.(*ast.UnaryExpr); ok && unary.Op == token.ARROW {
											hasReceive = true
										}
										return true
									})
									if hasCall {
										return fmt.Errorf("new package initializer calls code: %s", p)
									}
									if hasReceive {
										return fmt.Errorf("new package initializer contains channel receive: %s", p)
									}
								}
							}
						}
					}
				}
			}
			return nil
		}))
	}
	// Collect all new types first: a receiver's definition may be in another file.
	for p, f := range files {
		if !protected[p] {
			continue
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil {
				for _, recv := range fn.Recv.List {
					name := receiverTypeName(recv.Type)
					if !newTypes[packagePath(p)][name] {
						must(fmt.Errorf("new method on non-new receiver type: %s: %s.%s (baseline types or aliases allow method-value/interface entry; forbidden)", p, name, fn.Name.Name))
					}
				}
			}
		}
	}
	for pkg := range newNames {
		known := false
		for p := range files {
			if !protected[p] && packagePath(p) == pkg {
				known = true
			}
		}
		if !known {
			newPackages[pkg] = true
		}
	}
	// B1 cut 5-3: exact source declaration -> protected symbol/import edges.
	// Counts must match too: extra references in an approved function are red.
	permitted := map[string]int{
		"node/agent/api/commit_preflight.go#<import>: imports new package github.com/littlewolf9527/xdrop/node/agent/condexpr": 1,
		"node/agent/api/commit_preflight.go#encodeCommitGroup: references EncodeConditionValue":                                1,
		"node/agent/api/commit_preflight.go#commitEncodingError: references condexpr.CapacityError":                            1,
		"node/agent/api/condition_atomic.go#preflightAtomicConditions: references EncodeConditionValue":                        1,
		"node/agent/api/condition_groups.go#<import>: imports new package github.com/littlewolf9527/xdrop/node/agent/condexpr": 1,
		"node/agent/api/condition_groups.go#normalizeConditionRule: references condexpr.Compile":                               1,
		"node/agent/api/condition_groups.go#normalizeConditionRule: references conditionInput":                                 1,
		"node/agent/api/condition_groups.go#normalizeConditionRule: references ValidateCanonicalConditionRule":                 1,
	}
	matched := map[string]int{}
	refs := []string{}
	record := func(path, owner, reference string) {
		edge := path + "#" + owner + ": " + reference
		if _, ok := permitted[edge]; ok {
			matched[edge]++
			return
		}
		refs = append(refs, path+": "+reference)
	}
	checked := 0
	for p, f := range files {
		if protected[p] {
			continue
		}
		checked++
		pkg := packagePath(p)
		imports := map[string]string{}
		for _, imp := range f.Imports {
			path, e := strconv.Unquote(imp.Path.Value)
			must(e)
			alias := filepath.Base(path)
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			imports[alias] = path
			if newPackages[path] {
				record(p, "<import>", "imports new package "+path)
			}
		}
		for _, decl := range f.Decls {
			owner := "<declaration>"
			if fn, ok := decl.(*ast.FuncDecl); ok {
				owner = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.Ident:
					if newNames[pkg][v.Name] {
						if v.Obj == nil || v.Obj.Kind == ast.Fun || v.Obj.Kind == ast.Typ {
							record(p, owner, "references "+v.Name)
						}
					}
				case *ast.SelectorExpr:
					if base, ok := v.X.(*ast.Ident); ok {
						if newNames[imports[base.Name]][v.Sel.Name] {
							record(p, owner, "references "+base.Name+"."+v.Sel.Name)
						}
					}
				}
				return true
			})
		}
	}
	allowedCount := 0
	for edge, want := range permitted {
		allowedCount += matched[edge]
		if matched[edge] != want {
			refs = append(refs, fmt.Sprintf("planned edge count %s got=%d want=%d", edge, matched[edge], want))
		}
	}
	fmt.Printf("B1_ALLOWED_EDGES expected=%d matched=%d\n", len(permitted), allowedCount)
	fmt.Printf("B1_PRODUCTION_ISOLATION existing_files=%d protected_files=%d incoming_references=%d new_init_entries=0\n", checked, len(protected), len(refs))
	for _, r := range refs {
		fmt.Println(r)
	}
	if len(refs) != 0 {
		os.Exit(1)
	}
}
func receiverTypeName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return receiverTypeName(v.X)
	case *ast.ParenExpr:
		return receiverTypeName(v.X)
	case *ast.IndexExpr:
		return receiverTypeName(v.X)
	case *ast.IndexListExpr:
		return receiverTypeName(v.X)
	default:
		return ""
	}
}
func must(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
}
