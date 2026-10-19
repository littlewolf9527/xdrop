package api

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func hcB05Writes(f *cut55Fixture) [][2]int {
	var counts [][2]int
	for _, slot := range f.tables {
		for _, table := range slot {
			counts = append(counts, [2]int{table.writes, table.deletes})
		}
	}
	for _, table := range f.configs {
		counts = append(counts, [2]int{table.writes, table.deletes})
	}
	return append(counts, [2]int{f.selector.writes, f.selector.deletes})
}

func TestHCB05StrictBodyReject(t *testing.T) {
	for _, route := range []struct {
		name, path, outer, nested string
		handler                   func(*Handlers, *gin.Context)
	}{
		{"atomic", "/api/v1/sync/atomic", `{"rules":[],"rulez":[]}`, `{"rules":[{"id":"test-rule","logical_id":1,"src_ip":"192.0.2.1","protocol":"udp","action":"drop",%s}]}`, (*Handlers).AtomicSync},
		{"whitelist", "/api/v1/sync/whitelist", `{"entries":[],"rulez":[]}`, `{"entries":[{"id":"test-entry","src_ip":"192.0.2.1","protocol":"udp",%s}]}`, (*Handlers).SyncWhitelistHandler},
		{"commit", "/api/v1/rules/commit", `{"groups":[],"rulez":[]}`, `{"groups":[{"key":{"kind":"exact","src_ip":"192.0.2.1","src_port":0,"dst_port":0,"protocol":"udp"},"rules":[{"id":"test-rule","logical_id":1,"src_ip":"192.0.2.1","protocol":"udp","action":"drop",%s}]}]}`, (*Handlers).CommitRules},
	} {
		t.Run(route.name, func(t *testing.T) {
			for _, tc := range []struct{ name, body, field string }{
				{"top_level", route.outer, "rulez"},
				{"nested", strings.Replace(route.nested, "%s", `"dst_por":53`, 1), "dst_por"},
				{"condition_typo", strings.Replace(route.nested, "%s", `"ttll":"64"`, 1), "ttll"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := cut55Memory(t)
					before := hcB05Writes(f)
					r := gin.New()
					r.POST(route.path, func(c *gin.Context) { route.handler(f.h, c) })
					request := httptest.NewRequest(http.MethodPost, route.path, strings.NewReader(tc.body))
					request.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					func() {
						// Keep each mutation case observable if a broken whitelist
						// decoder reaches its absent concrete BPF map.
						defer func() {
							if recovered := recover(); recovered != nil {
								t.Errorf("handler panicked beyond decode boundary: %v", recovered)
							}
						}()
						r.ServeHTTP(w, request)
					}()
					if w.Code != http.StatusBadRequest {
						t.Errorf("status=%d want 400", w.Code)
					}
					var got map[string]any
					if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
						t.Fatalf("response JSON: %v", err)
					}
					want := map[string]any{"error": `json: unknown field "` + tc.field + `"`}
					if route.name == "commit" {
						want["code"] = "validation_rejected"
						want["groups"] = []any{}
					}
					if !reflect.DeepEqual(got, want) {
						t.Errorf("response=%v want exact decode-failure shape %v", got, want)
					}
					if after := hcB05Writes(f); !reflect.DeepEqual(before, after) {
						t.Errorf("writes/deletes changed: before=%v after=%v", before, after)
					}
					// Whitelist maps are concrete *ebpf.Map, not counted here.
					// Its early decode return plus mutation M2 cover that boundary.
				})
			}
		})
	}
}

func hcB05Tags(typ reflect.Type) map[string]reflect.Type {
	tags := make(map[string]reflect.Type)
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			tags[name] = f.Type
		}
	}
	return tags
}

func TestHCB05StrictBodyAcceptAllTags(t *testing.T) {
	values := map[string]any{
		"logical_id": 1, "ttl": "64", "dscp": "0", "icmp_type": "8", "icmp_code": "0", "fragment": "nofrag", "pkt_len": "64",
		"id": "test-rule", "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1", "src_cidr": "192.0.2.0/24", "dst_cidr": "198.51.100.0/24",
		"src_port": 1024, "dst_port": 53, "protocol": "udp", "action": "drop", "rate_limit": 1,
		"pkt_len_min": 64, "pkt_len_max": 128, "tcp_flags": "syn", "match_anomaly": 1, "comment": "test comment",
		"stats": map[string]any{"match_count": 1, "drop_count": 1, "match_bytes": 64, "drop_bytes": 64, "drop_pps": 1.0},
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(Rule{}), reflect.TypeOf(SyncWhitelistEntry{})} {
		t.Run(typ.Name(), func(t *testing.T) {
			payload := make(map[string]any)
			for name := range hcB05Tags(typ) {
				value, ok := values[name]
				if !ok {
					t.Fatalf("no legal fixture value for JSON tag %q", name)
				}
				payload[name] = value
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
			if err := bindStrictJSON(c, reflect.New(typ).Interface()); err != nil {
				t.Fatalf("all tags must decode: %v", err)
			}
		})
	}
}

func TestHCB05ControllerFieldCompatibility(t *testing.T) {
	for _, tc := range []struct {
		typ   reflect.Type
		names []string
	}{
		{reflect.TypeOf(Rule{}), []string{"id", "logical_id", "src_ip", "dst_ip", "src_cidr", "dst_cidr", "src_port", "dst_port", "protocol", "action", "rate_limit", "tcp_flags", "match_anomaly", "ttl", "dscp", "icmp_type", "icmp_code", "fragment", "pkt_len"}},
		{reflect.TypeOf(SyncWhitelistEntry{}), []string{"id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"}},
		{reflect.TypeOf(CommitGroup{}), []string{"key", "rules"}},
		{reflect.TypeOf(groupIdentity{}), []string{"kind", "src_ip", "dst_ip", "src_cidr", "dst_cidr", "src_port", "dst_port", "protocol"}},
	} {
		t.Run(tc.typ.Name(), func(t *testing.T) {
			tags := hcB05Tags(tc.typ)
			for _, name := range tc.names {
				if _, ok := tags[name]; !ok {
					t.Errorf("controller field %q missing from node JSON tags", name)
				}
			}
		})
	}
	// The handlers' request types are anonymous; inspect their actual tags,
	// rather than asserting against a duplicated test-only request type.
	for _, tc := range []struct{ file, handler, name string }{
		{"sync.go", "AtomicSync", "rules"},
		{"sync.go", "SyncWhitelistHandler", "entries"},
		{"commit.go", "CommitRules", "groups"},
	} {
		t.Run(tc.handler, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tc.file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != tc.handler {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					spec, ok := n.(*ast.ValueSpec)
					if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "req" {
						return true
					}
					st, ok := spec.Type.(*ast.StructType)
					if !ok {
						return false
					}
					for _, field := range st.Fields.List {
						if field.Tag != nil {
							tag, err := strconv.Unquote(field.Tag.Value)
							if err != nil {
								t.Fatal(err)
							}
							found = found || reflect.StructTag(tag).Get("json") == tc.name
						}
					}
					return false
				})
			}
			if !found {
				t.Errorf("controller outer field %q missing from %s request tags", tc.name, tc.handler)
			}
		})
	}
}

func TestHCB05StrictJSONCompatibility(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty_body", ""},
		{"whitespace_body", " \n\t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			strictContext, _ := gin.CreateTestContext(httptest.NewRecorder())
			strictContext.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			var strictRule Rule
			strictErr := bindStrictJSON(strictContext, &strictRule)
			if !errors.Is(strictErr, io.EOF) {
				t.Errorf("bindStrictJSON error=%v want io.EOF", strictErr)
			}
			ginContext, _ := gin.CreateTestContext(httptest.NewRecorder())
			ginContext.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			var ginRule Rule
			ginErr := ginContext.ShouldBindJSON(&ginRule)
			if !errors.Is(ginErr, io.EOF) {
				t.Errorf("ShouldBindJSON error=%v want io.EOF", ginErr)
			}
		})
	}
	for _, tc := range []struct{ name, body string }{
		{"trailing_data", `{"id":"test-first"} {"unknown":true}`},
		{"duplicate_key", `{"id":"test-old","id":"test-first"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			var rule Rule
			if err := bindStrictJSON(c, &rule); err != nil || rule.ID != "test-first" {
				t.Fatalf("existing decode behavior changed: id=%q error=%v", rule.ID, err)
			}
		})
	}
	for _, name := range []string{"nil_request", "nil_body"} {
		t.Run(name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			if name == "nil_body" {
				c.Request = &http.Request{}
			}
			var rule Rule
			if err := bindStrictJSON(c, &rule); err == nil || err.Error() != "invalid request" {
				t.Fatalf("error=%v want invalid request", err)
			}
		})
	}
}
