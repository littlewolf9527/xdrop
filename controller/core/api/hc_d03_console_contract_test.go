package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type hcD03Entry struct {
	Root     string `json:"root"`
	Endpoint string `json:"endpoint"`
	Path     string `json:"path"`
	Nullable bool   `json:"nullable,omitempty"`
	Event    string `json:"event,omitempty"`
	When     string `json:"when,omitempty"`
	Status   int    `json:"status,omitempty"`
	Query    string `json:"query,omitempty"`
}

type hcD03Key struct {
	endpoint, event string
	status          int
	query           string
}

type hcD03Resolution struct {
	status  string
	witness bool
}

func (r hcD03Resolution) covered() bool { return r.status == "hit" && r.witness }

// Port of console/scripts/contract-check.mjs resolvePath. Null parents retain
// the script's hit semantics, but only reaching the leaf records a witness.
func hcD03ResolvePath(value any, path string, nullable bool) hcD03Resolution {
	segments := strings.Split(path, ".")
	var walk func(any, int) []hcD03Resolution
	walk = func(current any, i int) []hcD03Resolution {
		if current == nil {
			if nullable {
				return []hcD03Resolution{{"hit", i == len(segments)}}
			}
			return []hcD03Resolution{{"missing", false}}
		}
		if i == len(segments) {
			return []hcD03Resolution{{"hit", true}}
		}
		part := segments[i]
		array := strings.HasSuffix(part, "[]")
		key := strings.TrimSuffix(part, "[]")
		next := current
		if part != "[]" {
			object, ok := current.(map[string]any)
			if !ok {
				return []hcD03Resolution{{"missing", false}}
			}
			next, ok = object[key]
			if !ok {
				return []hcD03Resolution{{"missing", false}}
			}
		}
		if !array {
			return walk(next, i+1)
		}
		items, ok := next.([]any)
		if !ok {
			return []hcD03Resolution{{"missing", false}}
		}
		if len(items) == 0 {
			return []hcD03Resolution{{"uncovered", false}}
		}
		var result []hcD03Resolution
		for _, item := range items {
			result = append(result, walk(item, i+1)...)
		}
		return result
	}
	result := walk(value, 0)
	missing, hit, witness := false, false, false
	for _, r := range result {
		missing = missing || r.status == "missing"
		hit = hit || r.status == "hit"
		witness = witness || r.witness
	}
	status := "uncovered"
	if missing {
		status = "missing"
	} else if hit {
		status = "hit"
	}
	return hcD03Resolution{status, witness}
}

type hcD03Source struct {
	*c5dSource
	points []store.TrafficRow
	now    time.Time
}

func (s *hcD03Source) TrafficMemory(string, time.Duration) ([]store.TrafficRow, time.Time, bool) {
	return s.points, s.now, false
}

type hcD03Fixture struct {
	*c5dFixture
	cookie, ruleID, nodeURL string
	events                  map[string]any
}

func hcD03Fresh(t *testing.T) *hcD03Fixture {
	f := &hcD03Fixture{c5dFixture: c5dFresh(t, nil)}
	f.cookie = f.login("alice")
	who := rules.Actor{Kind: rules.UI, Name: "alice", Admin: true}
	seed := f.create(80, "")
	f.ruleID = seed.Rule.ID
	_, failure := f.s.Create(who, "", rules.RulePatch{DstCIDR: c5dPtr("198.51.100.0/24")})
	require(t, failure == nil, "seed prefix")
	_, failure = f.s.CreateWhitelist(who, rules.WhitelistInput{DstIP: "192.0.2.20"})
	require(t, failure == nil, "seed whitelist")
	_, failure = f.acc.PutTemplate(who, "", "contract-template", "TEST_ONLY_TEMPLATE")
	require(t, failure == nil, "seed template")
	// The write sample will rotate this name, giving retired[] a real member.
	f.call(t, "POST", "/api/v1/credentials", `{"name":"contract-key"}`, 201, f.cookie)
	_, failure = f.a.systemOptions.NodeStore.Change(who, "create", "n1", NodePatch{c5dPtr("http://192.0.2.2"), c5dPtr("TEST_ONLY_NODE_KEY")})
	require(t, failure == nil, "seed stored node")
	f.n.change(func(n *orch.NodeStatus) {
		n.Stats = map[string]any{"system": map[string]any{"cpu_percent": 1.0, "mem_percent": 2.0}, "ipv6_deep_chain_dropped": 0.0}
		n.StatsAt, n.HealthAt = f.s.Now(), f.s.Now()
		n.Health.Status = "healthy"
		n.Rules.Rejected = []orch.Rejected{{Code: "TEST_ONLY_REJECTION"}}
		n.Whitelist.Rejected = []orch.Rejected{{Code: "TEST_ONLY_REJECTION"}}
	}, true)
	f.n.mu.Lock()
	f.n.rates = map[string]orch.RuleRate{f.ruleID: {PPS: 5, BytesPS: 50, Nodes: 1}}
	f.n.mu.Unlock()
	now := f.s.Now()
	points := []store.TrafficRow{{T: now.Add(-time.Minute).Unix(), N: 1, Avg: [4]float64{5, 7, 50, 70}, Max: [4]float64{5, 7, 50, 70}}}
	_, err := f.db.WriteTraffic(points, now.Add(-time.Hour).Unix(), now, [2]int{}, nil)
	require(t, err == nil, "seed minute and hour history")
	// Configure the API before opening any stream or ticking its hub. The
	// wrapper supplies short-range memory; long ranges still read real SQLite.
	f.a.nodes = &hcD03Source{f.n, points, now}
	node := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			io.WriteString(w, `{"sync_protocol":11}`)
		case "/api/v1/stats":
			io.WriteString(w, `{"total_packets":12,"dropped_packets":5,"passed_packets":7}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	// Exercise nc.New, Probe and Stats through a real handler without opening
	// a listener. The transport never dials the loopback URL (ruling 5c #1).
	f.a.systemOptions.NodeStore.client.Transport = c5bTransport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		return w.Result(), nil
	})
	f.nodeURL = "http://127.0.0.1"
	stream := f.stream(f.cookie)
	f.step()
	snapshot := f.snapshot(stream)
	f.events = map[string]any{"rules": snapshot[0], "nodes": snapshot[1], "traffic": snapshot[2]}
	stream.client.Close()
	stream.end(t)
	return f
}

func (f *hcD03Fixture) call(t *testing.T, method, path, body string, status int, cookie string) any {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	}
	w := httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	// Never print response bodies: the credential endpoint returns a secret.
	require(t, w.Code == status, method, path, "status", w.Code, "want", status)
	var value any
	require(t, json.Unmarshal(w.Body.Bytes(), &value) == nil, method, path, "invalid JSON")
	return value
}

type hcD03Sample struct {
	name, body, errorCode string
	status                int
	full                  bool
}

type hcD03Endpoint struct {
	key     hcD03Key
	samples []hcD03Sample
}

func hcD03SampleTable() []hcD03Endpoint {
	return []hcD03Endpoint{
		{hcD03Key{"GET /api/v1/users", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/credentials", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/settings", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/nodes", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/events", "nodes", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/auth/me", "", 401, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/auth/me", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/events", "rules", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/traffic/top?n=5", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/events", "traffic", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/capacity", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/traffic/history?range=15m", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/traffic/history?range=1h", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/traffic/history?range=6h", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/traffic/history?range=24h", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/traffic/history?range=7d", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/traffic/history?range=30d", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/rules/{rule_id}", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/rules?counts=1", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/traffic/top?n=all", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/rules", "", 400, "q=not-an-address"}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/whitelist", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/templates", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"GET /api/v1/audit?limit=100", "", 0, ""}, []hcD03Sample{{name: "default"}}},
		{hcD03Key{"POST /api/v1/rules", "", 0, ""}, []hcD03Sample{{name: "default", body: `{"dst_ip":"192.0.2.10","protocol":"tcp","dst_port":81}`, status: 201}}},
		{hcD03Key{"POST /api/v1/whitelist", "", 0, ""}, []hcD03Sample{{name: "default", body: `{"dst_ip":"192.0.2.21"}`, status: 201}}},
		{hcD03Key{"POST /api/v1/credentials", "", 0, ""}, []hcD03Sample{{name: "default", body: `{"name":"contract-key"}`, status: 201}}},
		{hcD03Key{"POST /api/v1/nodes/test", "", 0, ""}, []hcD03Sample{{name: "default", body: `{"base_url":"{node_url}","api_key":"TEST_ONLY_NODE_KEY"}`, status: 200}}},
		{hcD03Key{"PATCH /api/v1/rules/{rule_id}", "", 0, ""}, []hcD03Sample{{name: "default", body: `{"comment":"contract"}`, status: 200}}},
		{hcD03Key{"PUT /api/v1/rules/{rule_id}/enabled", "", 0, ""}, []hcD03Sample{{name: "default", body: `{"enabled":true}`, status: 200}}},
		{hcD03Key{"POST /api/v1/rules/batch", "", 0, ""}, []hcD03Sample{{name: "default", body: `{"items":[{"dst_ip":"192.0.2.10","protocol":"tcp","dst_port":82}]}`, status: 200}}},
		{hcD03Key{"POST /api/v1/rules/batch?validate=1", "", 0, ""}, []hcD03Sample{
			{name: "ok", body: `{"items":[{"dst_ip":"192.0.2.10","protocol":"tcp","dst_port":83}]}`, status: 200},
			{name: "err-field", body: `{"items":[{"dst_ip":"192.0.2.10","protocol":"tcp","dst_port":65536}]}`, errorCode: "invalid_rule", status: 200},
			{name: "err-rule-id", body: `{"items":[{"dst_ip":"192.0.2.10","protocol":"tcp","dst_port":80,"action":"rate_limit","rate_limit":1}]}`, errorCode: "rule_conflict", status: 200},
			{name: "err-rule-ids", body: `{"items":[{"dst_cidr":"198.51.100.0/25"}]}`, errorCode: "cidr_overlap", status: 200},
			{name: "err-table", body: `{"items":[{"dst_ip":"192.0.2.10","protocol":"tcp","dst_port":84}]}`, errorCode: "table_full", status: 200, full: true},
		}},
	}
}

func hcD03Applicable(path string) []string {
	return map[string][]string{
		"epoch":                      {"ok", "err-field", "err-rule-id", "err-rule-ids", "err-table"},
		"results[].index":            {"ok", "err-field", "err-rule-id", "err-rule-ids", "err-table"},
		"results[].existing":         {"ok"},
		"results[].rule.id":          {"ok"},
		"results[].error.code":       {"err-field", "err-rule-id", "err-rule-ids", "err-table"},
		"results[].error.field":      {"err-field"},
		"results[].error.rule_id":    {"err-rule-id"},
		"results[].error.rule_ids[]": {"err-rule-ids"},
		"results[].error.table":      {"err-table"},
	}[path]
}

func TestHCD03ConsoleContract(t *testing.T) {
	path := filepath.Join("..", "..", "..", "console", "src", "api", "contract.ts")
	data, err := os.ReadFile(path)
	require(t, err == nil, err)
	text := string(data)
	const declaration = "export interface ContractEntry { root: string; endpoint: string; path: string; nullable?: boolean; event?: string; when?: string; status?: number; query?: string }"
	declarations := 0
	for _, line := range strings.Split(text, "\n") {
		if line == declaration {
			declarations++
		}
	}
	require(t, declarations == 1, "ContractEntry declaration count", declarations)
	_, tail, found := strings.Cut(text, "export const contracts: ContractEntry[] = ")
	require(t, found, "contracts declaration missing")
	encoded, _, found := strings.Cut(tail, "// END CONTRACT JSON")
	require(t, found, "contract JSON end missing")
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var entries []hcD03Entry
	require(t, decoder.Decode(&entries) == nil, "invalid contract JSON or unknown contract field")
	var extra any
	require(t, decoder.Decode(&extra) == io.EOF, "trailing contract JSON")
	keys := map[hcD03Key]bool{}
	for _, entry := range entries {
		if entry.When != "" {
			t.Fatal("unsupported contract field when")
		}
		keys[hcD03Key{entry.Endpoint, entry.Event, entry.Status, entry.Query}] = true
	}
	f := hcD03Fresh(t)
	samples := map[hcD03Key]map[string]any{}
	sampleCount := 0
	for _, endpoint := range hcD03SampleTable() {
		key := endpoint.key
		require(t, keys[key] && samples[key] == nil, "unused or duplicate sample endpoint", key)
		samples[key] = map[string]any{}
		for _, sample := range endpoint.samples {
			require(t, samples[key][sample.name] == nil, "duplicate sample", key, sample.name)
			var value any
			if key.event != "" {
				value = f.events[key.event]
				require(t, value != nil, "missing first SSE snapshot", key.event)
			} else {
				parts := strings.SplitN(key.endpoint, " ", 2)
				requestPath := strings.ReplaceAll(parts[1], "{rule_id}", f.ruleID)
				if key.query != "" {
					separator := "?"
					if strings.Contains(requestPath, "?") {
						separator = "&"
					}
					requestPath += separator + key.query
				}
				status, cookie := sample.status, f.cookie
				if parts[0] == "GET" {
					status = key.status
					if status == 0 {
						status = 200
					}
					if status == 401 {
						cookie = ""
					}
				}
				if sample.full {
					occupancy, failure := f.s.Occupancy()
					require(t, failure == nil, "read fixture occupancy")
					limits := rules.BuiltinLimits()
					limits.Values[0] = occupancy.Used[0]
					f.s.UseLimits(func() rules.Limits { return limits })
				}
				value = f.call(t, parts[0], requestPath, strings.ReplaceAll(sample.body, "{node_url}", f.nodeURL), status, cookie)
				if sample.full {
					f.s.UseLimits(nil)
				}
				if key.endpoint == "POST /api/v1/rules/batch?validate=1" {
					results := value.(map[string]any)["results"].([]any)
					require(t, len(results) == 1, "validate sample must contain one result", sample.name)
					item := results[0].(map[string]any)
					if sample.errorCode == "" {
						require(t, item["error"] == nil && item["rule"] != nil, "ok sample must succeed")
					} else {
						envelope, ok := item["error"].(map[string]any)
						require(t, ok && envelope["code"] == sample.errorCode, "validate error sample", sample.name, "want", sample.errorCode)
					}
				}
			}
			samples[key][sample.name] = value
			sampleCount++
		}
	}
	for key := range keys {
		if samples[key] == nil {
			t.Fatal("unknown contract endpoint", key)
		}
	}
	hit, missing, uncovered, unwitnessed := 0, 0, 0, 0
	for i, entry := range entries {
		t.Run(fmt.Sprintf("entry-%03d/%s/%s/%s", i+1, entry.Endpoint, entry.Event, entry.Path), func(t *testing.T) {
			key := hcD03Key{entry.Endpoint, entry.Event, entry.Status, entry.Query}
			applicable := []string{"default"}
			if entry.Endpoint == "POST /api/v1/rules/batch?validate=1" {
				applicable = hcD03Applicable(entry.Path)
				if len(applicable) == 0 {
					t.Fatal("no applicable sample", entry.Endpoint, entry.Path)
				}
			}
			entryMissing, entryUncovered, witnessed := false, false, false
			for _, name := range applicable {
				value, exists := samples[key][name]
				if !exists {
					entryMissing = true
					t.Error("no applicable sample", entry.Endpoint, entry.Path, name)
					continue
				}
				result := hcD03ResolvePath(value, entry.Path, entry.Nullable)
				entryMissing = entryMissing || result.status == "missing"
				entryUncovered = entryUncovered || result.status == "uncovered"
				witnessed = witnessed || result.witness
				if result.status != "hit" {
					t.Errorf("endpoint=%s path=%s sample=%s result=%s", entry.Endpoint, entry.Path, name, result.status)
				}
			}
			if entryMissing {
				missing++
			}
			if entryUncovered {
				uncovered++
			}
			if !witnessed {
				unwitnessed++
				t.Errorf("endpoint=%s path=%s samples=%v no leaf witness", entry.Endpoint, entry.Path, applicable)
			}
			if !entryMissing && !entryUncovered && witnessed {
				hit++
			}
		})
	}
	controls := 0
	for _, control := range []struct{ endpoint, path string }{
		{"GET /api/v1/capacity", "tightest.used"},
		{"GET /api/v1/auth/me", "rolee"},
		{"GET /api/v1/rules", "items[].claimants"},
	} {
		t.Run("control-A/"+control.path, func(t *testing.T) {
			value := f.call(t, "GET", strings.TrimPrefix(control.endpoint, "GET "), "", 200, f.cookie)
			result := hcD03ResolvePath(value, control.path, false)
			require(t, result.status == "missing", "positive control", control.path, result)
		})
		controls++
	}
	for _, control := range []struct {
		name, json, path, status string
		nullable, witness        bool
	}{
		{"B-empty-array", `{"a":[]}`, "a[].b", "uncovered", false, false},
		{"C-null-parent", `{"nodes":[{"stats":null}]}`, "nodes[].stats.system.cpu_percent", "hit", true, false},
		{"D-renamed-leaf", `{"nodes":[{"stats":{"system":{"cpu_pct":1}}}]}`, "nodes[].stats.system.cpu_percent", "missing", true, false},
		{"F-mixed-elements", `{"nodes":[{"stats":{"system":{"cpu_percent":1}}},{"stats":{"system":{"cpu_pct":1}}}]}`, "nodes[].stats.system.cpu_percent", "missing", true, true},
	} {
		t.Run("control-"+control.name, func(t *testing.T) {
			var value any
			require(t, json.Unmarshal([]byte(control.json), &value) == nil, "control JSON")
			result := hcD03ResolvePath(value, control.path, control.nullable)
			require(t, result.status == control.status && result.witness == control.witness && !result.covered(), "resolver control", result)
			if control.name == "C-null-parent" {
				t.Log("hit 但无叶子见证 ⇒ 不覆盖")
			}
		})
		controls++
	}
	t.Run("control-E-multiple-samples", func(t *testing.T) {
		value := samples[hcD03Key{"POST /api/v1/rules/batch?validate=1", "", 0, ""}]["ok"]
		result := hcD03ResolvePath(value, "results[].error.code", false)
		require(t, result.status == "missing" && !result.covered(), "ok cannot cover an error contract", result)
		t.Log("ok-only results[].error.code ⇒ missing")
	})
	controls++
	t.Logf("HCD03 entries=%d endpoints=%d samples=%d hit=%d missing=%d uncovered=%d unwitnessed=%d controls=%d", len(entries), len(keys), sampleCount, hit, missing, uncovered, unwitnessed, controls)
	require(t, len(entries) == 277 && len(keys) == 32 && sampleCount == 36 && hit == 277 && missing == 0 && uncovered == 0 && unwitnessed == 0 && controls == 8, "HCD03 coverage totals")
}
