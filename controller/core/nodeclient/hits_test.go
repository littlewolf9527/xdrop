package nodeclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNSHitsClient(t *testing.T) {
	valid := `{"now_ns":18446744073709551615,"truncated":false,"scanned":1,"hits":[{"rule_id":"rule-1","logical_id":7,"match_count":9,"drop_count":2,"match_bytes":810,"drop_bytes":180,"last_hit_ns":100}]}`
	c := testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != string(HitsRoute) || r.URL.RawQuery != "since_ns=18446744073709551615" || r.Header.Get("X-API-Key") == "" {
			t.Error("request contract", r.URL)
		}
		fmt.Fprint(w, valid)
	}), Options{})
	r, err := c.Hits(context.Background(), ^uint64(0))
	if err != nil || r.NowNS != ^uint64(0) || len(r.Hits) != 1 || r.Hits[0].DropBytes != 180 || c.timeouts[HitsRoute] != 5*time.Second || c.limit(HitsRoute, 0, 0) != 4<<20 {
		t.Fatal(r, err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(valid), &root); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"now_ns", "truncated", "scanned", "hits"} {
		for _, value := range []json.RawMessage{nil, json.RawMessage(`"wrong-type"`), json.RawMessage(`null`)} {
			copy := map[string]json.RawMessage{}
			for k, v := range root {
				copy[k] = v
			}
			if value == nil {
				delete(copy, field)
			} else {
				copy[field] = value
			}
			b, _ := json.Marshal(copy)
			if nsHitsShape(b) {
				t.Fatalf("accepted root %s=%s", field, value)
			}
		}
	}
	for _, field := range []string{"rule_id", "logical_id", "match_count", "drop_count", "match_bytes", "drop_bytes", "last_hit_ns"} {
		var hits []map[string]json.RawMessage
		json.Unmarshal(root["hits"], &hits)
		for _, value := range []json.RawMessage{nil, json.RawMessage(`false`), json.RawMessage(`null`)} {
			old := hits[0][field]
			if value == nil {
				delete(hits[0], field)
			} else {
				hits[0][field] = value
			}
			changed, _ := json.Marshal(hits)
			root["hits"] = changed
			b, _ := json.Marshal(root)
			if nsHitsShape(b) {
				t.Fatalf("accepted hit %s=%s", field, value)
			}
			hits[0][field] = old
		}
		root["hits"] = json.RawMessage(valid[strings.Index(valid, `[{`) : len(valid)-1])
	}
	c = testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat(" ", 4<<20)+valid) }), Options{})
	if _, err := c.Hits(context.Background(), 0); err == nil {
		t.Fatal("accepted >4 MiB")
	}
}

func nsHitsShape(b []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	return shape(HitsRoute, m)
}

func TestNSHits429(t *testing.T) {
	calls := 0
	c := testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
		fmt.Fprint(w, `{"error":"rate_limited"}`)
	}), Options{})
	_, err := c.Hits(context.Background(), 0)
	var e *CallError
	pass := errors.As(err, &e) && e.HTTPStatus == 429 && e.Kind == "status" && calls == 1
	t.Logf("NS_CELL class=behavior name=client_429 calls=%d pass=%t", calls, pass)
	if !pass {
		t.Fatal(calls, err)
	}
}
