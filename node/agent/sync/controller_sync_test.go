// controller_sync_test.go — AUD-002 startup sync DTO round-trip test.
// Verifies tcp_flags and match_anomaly fields make it through:
//   Controller HTTP response → sync.Rule decode → expected api.Rule fields
package sync

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestFetchRules_PreservesTcpFlagsAndMatchAnomaly verifies the DTO carries
// the v2.6 fields end to end. AUD-002 root-cause was the DTO silently
// dropping these on Node restart.
func TestFetchRules_PreservesTcpFlagsAndMatchAnomaly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/rules" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 2,
			"rules": []map[string]interface{}{
				{
					"id":        "rule-tcp-rst",
					"protocol":  "tcp",
					"action":    "drop",
					"tcp_flags": "RST",
					"dst_ip":    "10.99.0.13",
				},
				{
					"id":            "rule-bad-frag",
					"protocol":      "all",
					"action":        "drop",
					"match_anomaly": 1,
					"dst_cidr":      "10.99.0.0/24",
				},
			},
		})
	}))
	defer srv.Close()

	cs := NewControllerSync(SyncConfig{
		ControllerURL: srv.URL,
		APIKey:        "test-key",
		Timeout:       2 * time.Second,
	})

	rules, err := cs.FetchRules()
	if err != nil {
		t.Fatalf("FetchRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	// Rule 0: tcp_flags must be present (regression for AUD-002)
	if rules[0].TcpFlags != "RST" {
		t.Fatalf("rules[0].TcpFlags expected 'RST', got %q", rules[0].TcpFlags)
	}
	if rules[0].MatchAnomaly != 0 {
		t.Fatalf("rules[0].MatchAnomaly expected 0, got %d", rules[0].MatchAnomaly)
	}

	// Rule 1: match_anomaly must be present (regression for AUD-002)
	if rules[1].MatchAnomaly != 1 {
		t.Fatalf("rules[1].MatchAnomaly expected 1, got %d", rules[1].MatchAnomaly)
	}
	if rules[1].TcpFlags != "" {
		t.Fatalf("rules[1].TcpFlags expected '', got %q", rules[1].TcpFlags)
	}
}
