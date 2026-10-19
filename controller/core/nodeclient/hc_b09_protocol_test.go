package nodeclient

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"testing"
)

func hcB09Protocol(source []byte) (int, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "handlers.go", source, 0)
	if err != nil {
		return 0, err
	}
	n, declarations := 0, 0
	for _, decl := range f.Decls {
		group, ok := decl.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value := spec.(*ast.ValueSpec)
			for _, name := range value.Names {
				if name.Name != "SyncProtocol" {
					continue
				}
				declarations++
				if len(value.Names) != 1 || len(value.Values) != 1 {
					return 0, fmt.Errorf("SyncProtocol must have a single integer literal")
				}
				literal, ok := value.Values[0].(*ast.BasicLit)
				if !ok || literal.Kind != token.INT {
					return 0, fmt.Errorf("SyncProtocol must be an integer literal")
				}
				n, err = strconv.Atoi(literal.Value)
				if err != nil {
					return 0, err
				}
			}
		}
	}
	if declarations != 1 {
		return 0, fmt.Errorf("SyncProtocol declarations=%d, want 1", declarations)
	}
	return n, nil
}

func hcB09NodeProtocol(t *testing.T) int {
	t.Helper()
	path := filepath.Join("..", "..", "..", "node", "agent", "api", "handlers.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := hcB09Protocol(source)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("HCB09 node SyncProtocol=%d", n)
	return n
}

func TestHCB09ProbeFollowsNodeProtocol(t *testing.T) {
	for _, control := range []struct {
		name, source string
		want         int
	}{
		{"single-declaration", "package api\nconst SyncProtocol = 7\n", 7},
		{"comment-and-group", "package api\n/*\nconst SyncProtocol = 11\n*/\nconst (\n\tSyncProtocol = 12\n)\n", 12},
	} {
		t.Run(control.name, func(t *testing.T) {
			got, err := hcB09Protocol([]byte(control.source))
			if err != nil || got != control.want {
				t.Fatalf("AST control got=%d want=%d err=%v", got, control.want, err)
			}
			t.Logf("AST protocol=%d", got)
		})
	}
	n := hcB09NodeProtocol(t)
	for _, value := range []int{n, n - 1, n + 1} {
		t.Run(fmt.Sprintf("protocol-%d", value), func(t *testing.T) {
			c := testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"sync_protocol":%d}`, value)
			}), Options{})
			got, err := c.Probe(context.Background())
			want := Incompatible
			if value == n {
				want = OK
			}
			if err != nil || got != want {
				t.Fatalf("protocol=%d got=%v err=%v want=%v", value, got, err, want)
			}
		})
	}
}

func TestHCB09ControllerProtocolDocs(t *testing.T) {
	n := hcB09NodeProtocol(t)
	pattern := regexp.MustCompile("(?i)(?:sync_protocol[\"`]?\\s*[:=]\\s*|protocol\\s+|协议\\s*)(\\d+)")
	t.Run("regex-control", func(t *testing.T) {
		matches := pattern.FindAllStringSubmatch("Protocol 7 · 协议 8 · `sync_protocol: 9` · sync_protocol:10", -1)
		var got []int
		for _, match := range matches {
			value, err := strconv.Atoi(match[1])
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, value)
		}
		if !reflect.DeepEqual(got, []int{7, 8, 9, 10}) {
			t.Fatalf("regex control got=%v want=[7 8 9 10]", got)
		}
		jsonMatches := pattern.FindAllStringSubmatch(`{"sync_protocol":7}`, -1)
		if len(jsonMatches) != 1 || len(jsonMatches[0]) != 2 || jsonMatches[0][1] != "7" {
			t.Fatalf("JSON regex control got=%v want=1 match with capture [7]", jsonMatches)
		}
	})
	for _, path := range []string{"../../README.md", "../../README.zh.md", "../API.md", "../API.zh.md", "types.go"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		matches := pattern.FindAllStringSubmatch(string(data), -1)
		if len(matches) == 0 {
			t.Errorf("%s has no protocol mention", path)
		}
		for _, match := range matches {
			value, err := strconv.Atoi(match[1])
			if err != nil || value != n {
				t.Errorf("%s protocol=%s want=%d err=%v", path, match[1], n, err)
			}
		}
		t.Logf("HCB09 ctl-doc %s mentions=%d", path, len(matches))
	}
}
