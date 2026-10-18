package api

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"

	"github.com/gin-gonic/gin"
)

// These are actual HTTP handlers with map syscall fixtures. The same cases are
// compared to the same fixed bytes by the private-map integration suite.
func TestPrefixABAtomicGoldens(t *testing.T) {
	call := func(f *cut55Fixture, body interface{}) *httptest.ResponseRecorder {
		f.bindConfig()
		// Receipt R0 succeeds; R5c is deferred because this local fixture has
		// no kernel logical-state maps. Atomic response bytes are unchanged.
		f.h.quiescenceConfirmed = false
		calls := 0
		f.h.quiescer = cut5ReceiptFunc(func() error {
			calls++
			if calls == 1 {
				return nil
			}
			return fmt.Errorf("local golden R5c deferred")
		})
		return cut53Request(t, cut53MemoryRouter(f.h), "POST", "/atomic", body)
	}
	f := cut55Memory(t)
	var rules []Rule
	for n := 0; n <= 2; n++ {
		if n == 1 {
			rules = append(rules, Rule{ID: "r", LogicalID: 17, SrcIP: "10.0.0.1", Protocol: "tcp", Action: "rate_limit", RateLimit: 100})
		}
		if n == 2 {
			rules = append(rules, Rule{ID: "r2", LogicalID: 18, SrcIP: "10.0.0.2", Action: "drop"})
		}
		w := call(f, map[string]any{"rules": rules})
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		cut53P3Golden(t, fmt.Sprintf("atomic_%d_p8", n), "TestJiaHandlerGolden/SnapshotsAndWhitelist", w)
	}
	w := call(f, map[string]any{"rules": []Rule{{ID: "bad", SrcIP: "bad", Action: "drop"}}})
	cut53P3Golden(t, "atomic_invalid_p8", "TestJiaHandlerGolden/SnapshotsAndWhitelist", w)
	f = cut55Memory(t)
	w = call(f, map[string]any{"rules": []Rule{{LogicalID: 17, ID: "r", SrcIP: "10.0.0.1", Protocol: "tcp", Action: "rate_limit", RateLimit: 100}, {LogicalID: 543010, ID: "r2", SrcIP: "invalid", Action: "drop"}}})
	cut53P3Golden(t, "atomic_partial_p8", "TestJiaHandlerGolden/YiFailures/Partial", w)
	router := gin.New()
	router.POST("/atomic", f.h.AtomicSync)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/atomic", strings.NewReader("{")))
	cut53P3Golden(t, "atomic_bad_json_p8", "TestJiaHandlerGolden/YiFailures/Partial", w)
	for _, name := range []string{"atomic_kernel_error_p8", "atomic_config_error_p8", "atomic_flip_error_p8"} {
		f := cut55Memory(t)
		fault := fmt.Errorf("update: %w", syscall.EPERM)
		switch name {
		case "atomic_kernel_error_p8":
			f.tables[1][mirrorExact].updateErr = fault
		case "atomic_config_error_p8":
			f.configs[1].updateErr = fault
		case "atomic_flip_error_p8":
			f.selector.updateErr = fault
		}
		w := call(f, map[string]any{"rules": []Rule{{LogicalID: 17, ID: "r", SrcIP: "10.0.0.1", Action: "drop"}}})
		if w.Code != 500 {
			t.Fatal(name, w.Code, w.Body.String())
		}
		cut53P3Golden(t, name, "TestJiaHandlerGolden/YiFailures/"+name, w)
	}
	for _, isCIDR := range []bool{false, true} {
		f := cut55Memory(t)
		body := map[string]any{"rules": []Rule{cut56Rule(isCIDR)}}
		if first := call(f, body); first.Code != 200 {
			t.Fatal(first.Code, first.Body.String())
		}
		w := call(f, body)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		cut53P3Golden(t, "anomaly_full_p8", fmt.Sprintf("cidr=%v", isCIDR), w)
	}
	t.Log("CLOSEOUT_P8_ATOMIC_GOLDEN files=10 response_cases=11 true_handlers=1")
}
