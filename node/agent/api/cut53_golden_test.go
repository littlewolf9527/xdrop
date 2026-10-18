package api

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type cut53GoldenResponse struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// Protocol-3 rejections include a canonical key. A historical response fixture
// reused across keys therefore has exact, separately named cases in its p3 file.
func cut53P3Golden(t *testing.T, name, caseName string, w *httptest.ResponseRecorder) {
	t.Helper()
	if (!strings.HasSuffix(name, "_p3") && !strings.HasSuffix(name, "_p4") && !strings.HasSuffix(name, "_p5") && !strings.HasSuffix(name, "_p6") && !strings.HasSuffix(name, "_p8") && !strings.HasSuffix(name, "_p9") && !strings.HasSuffix(name, "_p10") && !strings.HasSuffix(name, "_p11")) || strings.ContainsAny(name, "/\\") {
		t.Fatalf("invalid p3 golden name %q", name)
	}
	path := filepath.Join("..", "testdata", "sync-jia", name+".json")
	cases := map[string]cut53GoldenResponse{}
	b, err := os.ReadFile(path)
	if err == nil {
		if err = json.Unmarshal(b, &cases); err != nil {
			t.Fatal(err)
		}
	} else if !os.IsNotExist(err) || os.Getenv("P11_WRITE_GOLDEN") != "1" {
		t.Fatal(err)
	}
	actual := cut53GoldenResponse{Status: w.Code, Body: w.Body.String()}
	if os.Getenv("P11_WRITE_GOLDEN") == "1" && strings.HasSuffix(name, "_p11") {
		if !prefixABWritableGolden[name] {
			t.Fatalf("unregistered protocol-11 golden: %s", name)
		}
		cases[caseName] = actual
		b, err = json.MarshalIndent(cases, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, append(b, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	expected, ok := cases[caseName]
	if !ok || expected != actual {
		t.Fatalf("%s case=%s golden mismatch\nactual=%+v\nexpected=%+v exists=%v", name, caseName, actual, expected, ok)
	}
}

// These preflight-only requests record actual node responses without a kernel.
// The integration suite checks the same full responses against real map state.
func TestCut53Protocol3GoldenPreflight(t *testing.T) {
	type example struct {
		name, caseName, method, path string
		old                          []Rule
		body                         any
		code                         string
	}
	var examples []example
	root := "TestJiaHandlerGolden/"
	exact := Rule{ID: "r", SrcIP: "10.0.0.1", Protocol: "tcp", Action: "rate_limit", RateLimit: 100}
	second := exact
	second.ID = "r2"
	second.Action = "drop"
	second.RateLimit = 0
	examples = append(examples, example{"atomic_duplicate_key_p8", root + "YiFailures/DuplicateKey", "POST", "/atomic", nil, map[string]any{"rules": []Rule{exact, second}}, "condition_group_invalid"})
	for _, e := range examples {
		t.Run(e.name+"/"+e.caseName, func(t *testing.T) {
			h := cut53MemoryHandler(t, e.old...)
			before := cut53State(h)
			w := cut53Request(t, cut53MemoryRouter(h), e.method, e.path, e.body)
			var response struct{ Code string }
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != 409 || response.Code != e.code {
				t.Fatalf("p3 preflight=%d %s want=%s", w.Code, w.Body.String(), e.code)
			}
			if before != cut53State(h) {
				t.Fatal("p3 golden recording changed business state")
			}
			cut53P3Golden(t, e.name, e.caseName, w)
		})
	}
	if len(examples) != 1 {
		t.Fatalf("p3 response cases=%d want=1", len(examples))
	}
	t.Logf("CUT53_P3_GOLDEN files=1 response_cases=%d", len(examples))
}

// Finite write register; all previously existing protocol fixtures remain read-only.
var prefixABWritableGolden = map[string]bool{
	"welcome_p11": true, "stats_0_p11": true, "stats_1_p11": true, "stats_2_p11": true,
	"stats_slot5_p11": true, "rules_1_p11": true, "rules_2_p11": true,
	"stats_0_p10": true, "stats_1_p10": true, "stats_2_p10": true,
	"atomic_address_family_p9":    true,
	"commit_address_family_p9":    true,
	"whitelist_address_family_p9": true,
	"stats_0_p9":                  true, "stats_1_p9": true, "stats_2_p9": true,
	"stats_slot5_p9":          true,
	"atomic_0_p8":             true,
	"atomic_1_p8":             true,
	"atomic_2_p8":             true,
	"atomic_invalid_p8":       true,
	"atomic_partial_p8":       true,
	"atomic_bad_json_p8":      true,
	"atomic_duplicate_key_p8": true,
	"atomic_kernel_error_p8":  true,
	"atomic_config_error_p8":  true,
	"atomic_flip_error_p8":    true,
	"commit_committed_p8":     true,
	"commit_unchanged_p8":     true,
	"commit_deferred_p8":      true,
	"commit_validation_p8":    true,
	"commit_failed_p8":        true,
	"anomaly_full_p8":         true,
	"anomaly_commit_p8":       true,
	"anomaly_rejected_p8":     true,
}
