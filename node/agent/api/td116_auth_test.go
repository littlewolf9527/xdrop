package api

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTD116AuthMiddleware(t *testing.T) {
	for _, tc := range []struct {
		name, configured, provided string
		status                     int
	}{
		{"empty", "", "", http.StatusServiceUnavailable},
		{"empty-with-header", "", "test-node-key-0001", http.StatusServiceUnavailable},
		{"missing", "test-node-key-0001", "", http.StatusUnauthorized},
		{"wrong", "test-node-key-0001", "test-node-key-0002", http.StatusUnauthorized},
		{"different-length", "test-node-key-0001", "test-short", http.StatusUnauthorized},
		{"valid", "test-node-key-0001", "test-node-key-0001", http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			router := gin.New()
			router.POST("/api/v1/rules/commit", AuthMiddleware(tc.configured), func(c *gin.Context) {
				called = true
				c.Status(http.StatusNoContent)
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/commit", nil)
			if tc.provided != "" {
				req.Header.Set("X-API-Key", tc.provided)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.status || called != (tc.status == http.StatusNoContent) {
				t.Fatalf("status=%d handler_called=%t want=%d", rec.Code, called, tc.status)
			}
			if !called {
				var body map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" || body["message"] == "" {
					t.Fatalf("authentication error must preserve error/message fields: %s", rec.Body.String())
				}
			}
		})
	}
}

// Functional cases cannot distinguish a variable-time comparison. Check the
// security primitive at its decision point without relying on noisy timings.
func TestTD116ConstantTimeComparison(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "middleware.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	alias := ""
	for _, imp := range file.Imports {
		if imp.Path.Value == `"crypto/subtle"` {
			alias = "subtle"
			if imp.Name != nil {
				alias = imp.Name.Name
			}
		}
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		branch, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		compare, ok := branch.Cond.(*ast.BinaryExpr)
		if !ok || compare.Op != token.NEQ {
			return true
		}
		call, ok := compare.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "ConstantTimeCompare" {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if ok && alias != "" && pkg.Name == alias {
			one, ok := compare.Y.(*ast.BasicLit)
			found = ok && one.Value == "1"
		}
		return true
	})
	if !found {
		t.Fatal("API key decision must use crypto/subtle.ConstantTimeCompare")
	}
}
