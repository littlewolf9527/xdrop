package nodeclient

import (
	"io"
	"net/http"
	"testing"
)

func nestedShapeTests(t *testing.T) {
	cases := []struct {
		name  string
		route Route
		body  string
	}{
		{"commit-index-missing", CommitRoute, `{"code":"committed","groups":[{"result":"created"}]}`},
		{"commit-index-null", CommitRoute, `{"code":"committed","groups":[{"index":null,"result":"created"}]}`},
		{"commit-index-fraction", CommitRoute, `{"code":"committed","groups":[{"index":0.1,"result":"created"}]}`},
		{"commit-result-missing", CommitRoute, `{"code":"committed","groups":[{"index":0}]}`},
		{"commit-result-null", CommitRoute, `{"code":"committed","groups":[{"index":0,"result":null}]}`},
		{"commit-result-number", CommitRoute, `{"code":"committed","groups":[{"index":0,"result":1}]}`},
		{"rules-pagination-empty", RulesRoute, `{"rules":[],"pagination":{}}`},
		{"rules-pagination-null-field", RulesRoute, `{"rules":[],"pagination":{"page":1,"limit":1000,"total":null,"pages":0}}`},
		{"rules-pagination-string", RulesRoute, `{"rules":[],"pagination":{"page":1,"limit":1000,"total":"0","pages":0}}`},
		{"rules-member-empty", RulesRoute, `{"rules":[{}],"pagination":{"page":1,"limit":1000,"total":1,"pages":1}}`},
		{"rules-id-empty", RulesRoute, `{"rules":[{"id":"","logical_id":1,"protocol":"tcp","action":"drop"}],"pagination":{"page":1,"limit":1000,"total":1,"pages":1}}`},
		{"rules-logical-null", RulesRoute, `{"rules":[{"id":"r","logical_id":null,"protocol":"tcp","action":"drop"}],"pagination":{"page":1,"limit":1000,"total":1,"pages":1}}`},
		{"rules-protocol-null", RulesRoute, `{"rules":[{"id":"r","logical_id":1,"protocol":null,"action":"drop"}],"pagination":{"page":1,"limit":1000,"total":1,"pages":1}}`},
		{"rules-action-missing", RulesRoute, `{"rules":[{"id":"r","logical_id":1,"protocol":"tcp"}],"pagination":{"page":1,"limit":1000,"total":1,"pages":1}}`},
		{"whitelist-id-missing", WhitelistRoute, `{"entries":[{}],"count":1}`},
		{"whitelist-id-null", WhitelistRoute, `{"entries":[{"id":null}],"count":1}`},
		{"atomic-id-missing", AtomicRoute, `{"success":true,"added":0,"failed":1,"rules":0,"cidr_rules":0,"rejected":[{"reason":"bad"}]}`},
		{"atomic-reason-null", AtomicRoute, `{"success":true,"added":0,"failed":1,"rules":0,"cidr_rules":0,"rejected":[{"id":"r","reason":null}]}`},
		{"atomic-reason-number", AtomicRoute, `{"success":true,"added":0,"failed":1,"rules":0,"cidr_rules":0,"rejected":[{"id":"r","reason":1}]}`},
		{"stats-string-counter", StatsRoute, `{"total_packets":"2","dropped_packets":1,"passed_packets":1}`},
		{"stats-null-counter", StatsRoute, `{"total_packets":2,"dropped_packets":null,"passed_packets":1}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tc.body) }), Options{})
			if e := callRoute(c, tc.route); e == nil || e.Kind != "invalid" {
				t.Fatalf("nested shape accepted: %v", e)
			}
		})
	}
	t.Run("unknown-fields-allowed", func(t *testing.T) {
		c := testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"code":"committed","groups":[{"index":0,"result":"created","future":null}],"future":[]}`)
		}), Options{})
		if e := callRoute(c, CommitRoute); e != nil {
			t.Fatal(e)
		}
	})
}
