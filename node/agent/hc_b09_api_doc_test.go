package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/node/agent/api"
)

func hcB09ParseNodeRouteTable(document, header string, authWords map[string]bool) ([]closeoutRoute, error) {
	lines := strings.Split(document, "\n")
	start, headers := -1, 0
	for i, line := range lines {
		if line == header {
			start, headers = i+1, headers+1
		}
	}
	if headers != 1 {
		return nil, fmt.Errorf("route headers=%d want=1", headers)
	}
	var routes []closeoutRoute
	seen := map[string]bool{}
	for _, line := range lines[start:] {
		if strings.TrimSpace(line) == "" {
			break
		}
		if strings.HasPrefix(line, "|---") {
			continue
		}
		cells := strings.Split(line, "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if len(cells) != 6 || cells[0] != "" || cells[5] != "" {
			return nil, fmt.Errorf("unparsed route row %q", line)
		}
		auth, ok := authWords[cells[3]]
		if !ok {
			return nil, fmt.Errorf("unknown authentication word %q", cells[3])
		}
		if cells[4] != "200" {
			return nil, fmt.Errorf("route %s %s success=%q want=200", cells[1], cells[2], cells[4])
		}
		key := cells[1] + " " + cells[2]
		if seen[key] {
			return nil, fmt.Errorf("duplicate route %s", key)
		}
		seen[key] = true
		routes = append(routes, closeoutRoute{Method: cells[1], Path: cells[2], Auth: auth})
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Method+" "+routes[i].Path < routes[j].Method+" "+routes[j].Path
	})
	return routes, nil
}

func TestHCB09NodeRouteDocs(t *testing.T) {
	t.Run("table-control", func(t *testing.T) {
		const document = "| Method | Path | Authentication | Success |\n|---|---|---|---|\n| GET | / | Public | 200 |\n| GET | /api/v1/stats | Key | 200 |\n\n"
		got, err := hcB09ParseNodeRouteTable(document, "| Method | Path | Authentication | Success |", map[string]bool{"Public": false, "Key": true})
		want := []closeoutRoute{{Method: "GET", Path: "/", Auth: false}, {Method: "GET", Path: "/api/v1/stats", Auth: true}}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("table control got=%v want=%v err=%v", got, want, err)
		}
	})

	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	want, err := closeoutParseRoutes(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range []struct {
		name      string
		header    string
		authWords map[string]bool
	}{
		{"API.md", "| Method | Path | Authentication | Success |", map[string]bool{"Public": false, "Key": true}},
		{"API.zh.md", "| 方法 | 路径 | 鉴权 | 成功码 |", map[string]bool{"公开": false, "密钥": true}},
	} {
		t.Run(doc.name, func(t *testing.T) {
			path := filepath.Join("..", doc.name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			routes, err := hcB09ParseNodeRouteTable(string(data), doc.header, doc.authWords)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			if !reflect.DeepEqual(routes, want) {
				t.Fatalf("%s route table mismatch: got=%v want=%v", path, routes, want)
			}
			auth := 0
			for _, route := range routes {
				if route.Auth {
					auth++
				}
			}
			t.Logf("HCB09 node-doc %s routes=%d auth=%d", path, len(routes), auth)
		})
	}
}

func TestHCB09NodeProtocolDocs(t *testing.T) {
	protocol := regexp.MustCompile("(?i)(?:sync_protocol[\"`]?\\s*[:=]\\s*|protocol\\s+|协议\\s*)(\\d+)")
	t.Run("regex-control", func(t *testing.T) {
		matches := protocol.FindAllStringSubmatch("Protocol 7 · 协议 8 · `sync_protocol: 9` · sync_protocol:10", -1)
		var got []string
		for _, match := range matches {
			got = append(got, match[1])
		}
		if want := []string{"7", "8", "9", "10"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("protocol regex control got=%v want=%v", got, want)
		}
		quoted := protocol.FindAllStringSubmatch(`{"sync_protocol":7}`, -1)
		if len(quoted) != 1 || len(quoted[0]) != 2 || quoted[0][1] != "7" {
			t.Fatalf("quoted protocol regex control got=%v want=one match with capture %q", quoted, "7")
		}
	})
	for _, path := range []string{
		filepath.Join("..", "API.md"),
		filepath.Join("..", "API.zh.md"),
		filepath.Join("..", "README.md"),
		filepath.Join("..", "README.zh.md"),
		filepath.Join("..", "..", "GETTING_STARTED.md"),
		filepath.Join("..", "..", "GETTING_STARTED.zh.md"),
	} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			matches := protocol.FindAllStringSubmatch(string(data), -1)
			if len(matches) == 0 {
				t.Fatalf("%s: no protocol mentions", path)
			}
			for _, match := range matches {
				value, err := strconv.Atoi(match[1])
				if err != nil || value != api.SyncProtocol {
					t.Errorf("%s: protocol=%s want=%d err=%v", path, match[1], api.SyncProtocol, err)
				}
			}
			t.Logf("HCB09 node-proto %s mentions=%d", path, len(matches))
		})
	}
}
