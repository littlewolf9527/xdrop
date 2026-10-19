package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type stubNodes struct {
	changes           []rules.Change
	syncs, reconciles int
}

func (n *stubNodes) AddNode(nc.NodeSpec) error { return nil }
func (n *stubNodes) RemoveNode(string)         {}
func (n *stubNodes) Changed(c rules.Change)    { n.changes = append(n.changes, c) }
func (n *stubNodes) Status() []orch.NodeStatus {
	return []orch.NodeStatus{{Name: "n1", Rules: orch.SideStatus{State: "pending"}}}
}
func (n *stubNodes) ForceSync(string)    { n.syncs++ }
func (n *stubNodes) ReconcileNow(string) { n.reconciles++ }

type fixture struct {
	db   *store.DB
	s    *rules.Service
	n    *stubNodes
	e    *gin.Engine
	logs *bytes.Buffer
}

func fresh(t *testing.T) *fixture {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	n := &stubNodes{}
	s := rules.New(db, n, DeliveryStatus(n))
	logs := &bytes.Buffer{}
	return &fixture{db, s, n, New(s, n, testActor, log.New(logs, "", 0)), logs}
}
func require(t *testing.T, ok bool, args ...any) {
	t.Helper()
	if !ok {
		t.Fatal(args...)
	}
}
func request(t *testing.T, e *gin.Engine, method, path, identity, body string, status int) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-Xdrop-Actor", identity)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	require(t, w.Code == status, method, path, "status", w.Code, "want", status, w.Body.String())
	return w
}
func decoded[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	require(t, json.Unmarshal(w.Body.Bytes(), &out) == nil, "invalid JSON", w.Body.String())
	return out
}
func body(port int) string {
	return fmt.Sprintf(`{"dst_ip":"192.0.2.10","protocol":"tcp","dst_port":%d}`, port)
}
func created(t *testing.T, f *fixture, port int) CreateResponse {
	t.Helper()
	return decoded[CreateResponse](t, request(t, f.e, "POST", "/api/v1/rules", "machine:a", body(port), 201))
}

// This is the independent contract oracle, never derived from handler metadata.
var permissionOracle = map[string]string{
	"PUT /auth/me/password": "ui",

	"GET /events":          "ui",
	"GET /traffic/history": "all", "GET /traffic/top": "all",
	"POST /nodes": "admin", "PATCH /nodes/:name": "admin", "DELETE /nodes/:name": "admin", "POST /nodes/:name/test": "admin", "POST /nodes/test": "admin",
	"PUT /users/:name/role": "admin", "GET /auth/me/prefs": "ui", "PUT /auth/me/prefs": "ui", "GET /templates": "ui", "POST /templates": "admin", "PUT /templates/:id": "admin", "DELETE /templates/:id": "admin",
	"GET /audit": "ui", "GET /audit/export": "admin",
	"POST /auth/login": "public", "POST /auth/logout": "ui", "GET /auth/me": "all",
	"GET /users": "ui", "POST /users": "admin", "DELETE /users/:name": "admin", "PUT /users/:name/password": "admin",
	"GET /credentials": "admin", "POST /credentials": "admin", "DELETE /credentials/:id": "admin", "GET /settings": "ui", "PUT /settings": "admin",
	"GET /capacity": "all", "GET /system": "all",
	"GET /health": "public", "POST /rules": "all", "POST /rules/batch": "all", "GET /rules": "all", "GET /rules/:id": "all", "GET /rules/:id/delivery": "all",
	"PATCH /rules/:id": "ui", "PUT /rules/:id/enabled": "ui", "DELETE /rules/:id": "all", "GET /whitelist": "all", "POST /whitelist": "ui", "DELETE /whitelist/:id": "ui",
	"GET /nodes": "all", "POST /nodes/:name/sync": "ui", "POST /nodes/:name/reconcile": "ui",
}
var codeOracle = map[string]int{"admin_required": 403, "last_admin": 409, "invalid_credentials": 401, "login_throttled": 429, "invalid_field": 400, "user_exists": 409, "user_not_found": 404, "last_user": 409, "credential_not_found": 404, "invalid_rule": 400, "empty_value": 400, "invalid_expires_in": 400, "mapped_ipv6": 400, "address_family_mismatch": 400, "bad_request": 400, "batch_too_large": 400, "unauthenticated": 401, "forbidden": 403, "not_found": 404, "node_not_found": 404, "route_not_found": 404, "method_not_allowed": 405, "rule_conflict": 409, "condition_capacity": 409, "cidr_overlap": 409, "table_full": 409, "gen_epoch_mismatch": 409, "internal": 500}

var successOracle = map[string]string{
	"POST /rules":                 "201 / 200",
	"POST /whitelist":             "201 / 200",
	"POST /users":                 "201",
	"POST /credentials":           "201",
	"POST /templates":             "201",
	"POST /nodes":                 "201",
	"POST /nodes/:name/sync":      "202",
	"POST /nodes/:name/reconcile": "202",
	"DELETE /rules/:id":           "204",
	"DELETE /whitelist/:id":       "204",
	"DELETE /nodes/:name":         "204",
	"DELETE /users/:name":         "204",
	"DELETE /credentials/:id":     "204",
	"DELETE /templates/:id":       "204",
	"POST /auth/logout":           "204",
	"PUT /auth/me/password":       "204",
	"PUT /auth/me/prefs":          "204",
	"PUT /users/:name/password":   "204",
	"PUT /users/:name/role":       "204",
	"GET /events":                 "200",
	"GET /traffic/history":        "200",
	"GET /traffic/top":            "200",
	"PATCH /nodes/:name":          "200",
	"POST /nodes/:name/test":      "200",
	"POST /nodes/test":            "200",
	"GET /auth/me/prefs":          "200",
	"GET /templates":              "200",
	"PUT /templates/:id":          "200",
	"GET /audit":                  "200",
	"GET /audit/export":           "200",
	"POST /auth/login":            "200",
	"GET /auth/me":                "200",
	"GET /users":                  "200",
	"GET /credentials":            "200",
	"GET /settings":               "200",
	"PUT /settings":               "200",
	"GET /capacity":               "200",
	"GET /system":                 "200",
	"GET /health":                 "200",
	"POST /rules/batch":           "200",
	"GET /rules":                  "200",
	"GET /rules/:id":              "200",
	"GET /rules/:id/delivery":     "200",
	"PATCH /rules/:id":            "200",
	"PUT /rules/:id/enabled":      "200",
	"GET /whitelist":              "200",
	"GET /nodes":                  "200",
}

func routeSet(e *gin.Engine) map[string]bool {
	out := map[string]bool{}
	for _, r := range e.Routes() {
		out[r.Method+" "+r.Path] = true
	}
	return out
}
func TestCtlCut3API(t *testing.T) {
	t.Run("API-routes", func(t *testing.T) {
		want := map[string]bool{}
		for key := range permissionOracle {
			p := strings.SplitN(key, " ", 2)
			want[p[0]+" /api/v1"+p[1]] = true
		}
		require(t, reflect.DeepEqual(routeSet(fresh(t).e), want), "route set differs")
	})
	t.Run("API-authz", func(t *testing.T) {
		for route := range routeSet(fresh(t).e) {
			key := strings.Replace(route, "/api/v1", "", 1)
			_, ok := permissionOracle[key]
			require(t, ok, "route missing independent permission expectation", route)
		}
		for key, permission := range permissionOracle {
			for _, identity := range []string{"", "ui", "operator", "machine:b"} {
				if c4aRoute(key) && !(permission != "public" && identity == "" || (permission == "ui" && identity == "machine:b" || permission == "admin" && identity != "ui" && identity != "")) {
					continue
				}
				f := fresh(t)
				r := created(t, f, 80)
				w, e := f.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{DstIP: "192.0.2.20"})
				require(t, e == nil, e)
				parts := strings.SplitN(key, " ", 2)
				method, path := parts[0], parts[1]
				if path == "/traffic/history" {
					path += "?range=15m"
				}
				id := r.ID
				if strings.HasPrefix(path, "/whitelist/") {
					id = w.Whitelist.ID
				}
				path = strings.ReplaceAll(strings.ReplaceAll(path, ":id", id), ":name", "n1")
				input := body(81)
				if strings.HasSuffix(path, "/enabled") {
					input = `{"enabled":false}`
				}
				if strings.HasSuffix(path, "/batch") {
					input = `{"items":[` + body(81) + `]}`
				}
				if method == "PATCH" {
					input = `{"comment":"changed"}`
				}
				if strings.HasSuffix(path, "/delivery") {
					path += "?gen=1&epoch=" + f.s.Epoch()
				}
				status := 200
				if method == "POST" && (path == "/rules" || path == "/whitelist") {
					status = 201
				}
				if method == "DELETE" {
					status = 204
				}
				if strings.HasSuffix(path, "/sync") || strings.HasSuffix(path, "/reconcile") {
					status = 202
				}
				if c5bNodeRoute(key) {
					input, status = c5bMatrixNode(t, f, nil, key)
				}
				blocked := permission != "public" && identity == "" || (permission == "ui" && identity == "machine:b" || permission == "admin" && identity != "ui" && identity != "")
				if permission != "public" && identity == "" {
					status = 401
				} else if permission == "ui" && identity == "machine:b" || permission == "admin" && identity != "ui" && identity != "" {
					status = 403
				}
				before, _ := f.s.List()
				beforeWL, _ := f.s.ListWhitelist()
				changes := len(f.n.changes)
				send := request
				if path == "/events" {
					input, send = "", c5dRequest
				}
				response := send(t, f.e, method, "/api/v1"+path, identity, input, status)
				if permission == "admin" && status == 403 {
					require(t, decoded[Error](t, response).Code == "admin_required", "admin code")
				}
				if blocked {
					after, _ := f.s.List()
					afterWL, _ := f.s.ListWhitelist()
					require(t, reflect.DeepEqual(before, after) && reflect.DeepEqual(beforeWL, afterWL) && len(f.n.changes) == changes && f.n.syncs == 0 && f.n.reconciles == 0, "denied request reached service", key)
				}
			}
		}
		for _, identity := range []string{"machine:", "machine:bad name", "machine:" + strings.Repeat("x", 65), "UI"} {
			request(t, fresh(t).e, "GET", "/api/v1/nodes", identity, "", 401)
		}
	})
	t.Run("API-create", func(t *testing.T) {
		f := fresh(t)
		r := created(t, f, 80)
		require(t, r.Gen == 1 && r.Gen == f.n.changes[0].Gen && r.Epoch == f.s.Epoch() && len(r.Epoch) == 32, "create receipt", r)
		request(t, f.e, "POST", "/api/v1/whitelist", "ui", `{"dst_ip":"192.0.2.20"}`, 201)
		other := created(t, f, 81)
		for _, identity := range []string{"machine:a", "machine:b"} {
			got := decoded[CreateResponse](t, request(t, f.e, "POST", "/api/v1/rules", identity, body(80), 200))
			require(t, got.Existing && got.Gen == r.Gen && got.ID == r.ID && got.Epoch == f.s.Epoch(), "duplicate receipt", got)
		}
		n, err := store.ClaimCount(f.db, r.ID)
		require(t, err == nil && n == 2, "claim count", n, err)
		bad := strings.TrimSuffix(body(80), "}") + `,"action":"rate_limit","rate_limit":10}`
		got := decoded[Error](t, request(t, f.e, "POST", "/api/v1/rules", "machine:a", bad, 409))
		require(t, got.Code == "rule_conflict" && got.RuleID == r.ID, got)
		batch := decoded[BatchResponse](t, request(t, f.e, "POST", "/api/v1/rules/batch", "machine:a", `{"items":[`+body(80)+`,`+body(82)+`,`+body(81)+`]}`, 200))
		require(t, len(batch.Results) == 3 && batch.Epoch == r.Epoch, "batch shape")
		for i, want := range []uint64{r.Gen, f.n.changes[len(f.n.changes)-1].Gen, other.Gen} {
			item := batch.Results[i]
			require(t, item.Index == i && item.Gen != nil && *item.Gen == want && item.Existing != nil && *item.Existing == (i != 1) && item.Rule != nil, "per-item gen", item, want)
		}
		f.s = rules.New(f.db, f.n, DeliveryStatus(f.n))
		f.e = New(f.s, f.n, testActor, nil)
		reused := decoded[CreateResponse](t, request(t, f.e, "POST", "/api/v1/rules", "machine:a", body(80), 200))
		require(t, reused.Gen == 0 && reused.Epoch != r.Epoch, "restart receipt", reused)
	})
	t.Run("API-renew", func(t *testing.T) {
		f := fresh(t)
		post := func(duration string, status int) CreateResponse {
			input := body(80)
			if duration != "" {
				input = strings.TrimSuffix(input, "}") + `,"expires_in":"` + duration + `"}`
			}
			return decoded[CreateResponse](t, request(t, f.e, "POST", "/api/v1/rules", "machine:a", input, status))
		}
		first := post("2h", 201)
		later := post("4h", 200)
		shorter := post("1h", 200)
		forever := post("", 200)
		still := post("1h", 200)
		require(t, first.ExpiresAt != nil && later.ExpiresAt != nil && *later.ExpiresAt > *first.ExpiresAt && shorter.ExpiresAt != nil && *shorter.ExpiresAt == *later.ExpiresAt && forever.ExpiresAt == nil && still.ExpiresAt == nil, "renewal is not max")
		require(t, len(f.n.changes) == 1, "renew notified")
		request(t, f.e, "PUT", "/api/v1/rules/"+first.ID+"/enabled", "ui", `{"enabled":false}`, 200)
		repeated := post("", 200)
		require(t, !repeated.Enabled, "duplicate re-enabled rule")
	})
	t.Run("API-batch", func(t *testing.T) {
		f := fresh(t)
		for _, items := range []string{"", strings.TrimSuffix(strings.Repeat(body(80)+",", 1001), ",")} {
			e := decoded[Error](t, request(t, f.e, "POST", "/api/v1/rules/batch", "ui", `{"items":[`+items+`]}`, 400))
			require(t, e.Code == "batch_too_large", e)
		}
		b := decoded[BatchResponse](t, request(t, f.e, "POST", "/api/v1/rules/batch", "ui", `{"items":[`+body(80)+`,{"dst_port":-1}]}`, 200))
		require(t, len(b.Results) == 2 && b.Results[0].Rule != nil && b.Results[0].Gen != nil && b.Results[1].Error.Code == "invalid_rule", "partial result", b)
		_, err := f.s.Get(b.Results[0].Rule.ID)
		require(t, err == nil, "valid batch member absent")
	})
	t.Run("API-batch-501", func(t *testing.T) {
		f := fresh(t)
		items := strings.TrimSuffix(strings.Repeat(body(80)+",", 501), ",")
		e := decoded[Error](t, request(t, f.e, "POST", "/api/v1/rules/batch", "ui", `{"items":[`+items+`]}`, 400))
		require(t, e.Code == "batch_too_large" && e.Message == "items must contain 1..500 rules; split larger batches into sequential requests of at most 500 items", e)
	})
	t.Run("API-batch-500", func(t *testing.T) {
		f := fresh(t)
		items := []string{}
		for i := 0; i < 500; i++ {
			items = append(items, body(100+i))
		}
		b := decoded[BatchResponse](t, request(t, f.e, "POST", "/api/v1/rules/batch", "ui", `{"items":[`+strings.Join(items, ",")+`]}`, 200))
		require(t, len(b.Results) == 500, "500 results required", len(b.Results))
		for i, item := range b.Results {
			require(t, item.Index == i && item.Rule != nil && item.Error == nil, "500 item success", i, item)
		}
	})
	t.Run("API-page", testPages)
	t.Run("API-ryw", func(t *testing.T) {
		f := fresh(t)
		r := created(t, f, 80)
		got := decoded[RuleDTO](t, request(t, f.e, "GET", "/api/v1/rules/"+r.ID, "ui", "", 200))
		require(t, reflect.DeepEqual(got, r.RuleDTO), "read-your-writes mismatch")
	})
	t.Run("API-delete", func(t *testing.T) {
		f := fresh(t)
		r := created(t, f, 80)
		for _, pair := range [][2]string{{"machine:a", "x"}, {"machine:b", ""}, {"ui", ""}} {
			input := strings.TrimSuffix(body(80), "}") + `,"claim_ref":"` + pair[1] + `"}`
			request(t, f.e, "POST", "/api/v1/rules", pair[0], input, 200)
		}
		for _, pair := range [][2]string{{"machine:a", "x"}, {"machine:a", "x"}, {"machine:a", ""}, {"machine:b", ""}} {
			request(t, f.e, "DELETE", "/api/v1/rules/"+r.ID+"?claim_ref="+pair[1], pair[0], "", 204)
			_, err := f.s.Get(r.ID)
			require(t, err == nil, "removed another claim")
		}
		request(t, f.e, "DELETE", "/api/v1/rules/"+r.ID, "ui", "", 204)
		_, err := f.s.Get(r.ID)
		require(t, err != nil && err.Code == "not_found", "force delete absent")
		r = created(t, f, 81)
		request(t, f.e, "DELETE", "/api/v1/rules/"+r.ID, "machine:a", "", 204)
		_, err = f.s.Get(r.ID)
		require(t, err != nil && err.Code == "not_found", "last claim did not remove rule")
		for _, identity := range []string{"ui", "machine:a"} {
			request(t, f.e, "DELETE", "/api/v1/rules/missing", identity, "", 204)
		}
	})
	t.Run("API-errors", testErrors)
	t.Run("API-nodes", func(t *testing.T) {
		f := fresh(t)
		w := request(t, f.e, "GET", "/api/v1/nodes", "ui", "", 200)
		var got struct {
			Epoch string    `json:"epoch"`
			Nodes []NodeDTO `json:"nodes"`
		}
		got = decoded[struct {
			Epoch string    `json:"epoch"`
			Nodes []NodeDTO `json:"nodes"`
		}](t, w)
		require(t, got.Epoch == f.s.Epoch() && len(got.Nodes) == 1 && !strings.Contains(w.Body.String(), "NODE-KEY-SENTINEL") && !strings.Contains(strings.ToLower(w.Body.String()), "fingerprint"), "node projection")
		for _, action := range []string{"sync", "reconcile"} {
			e := decoded[Error](t, request(t, f.e, "POST", "/api/v1/nodes/missing/"+action, "ui", "", 404))
			require(t, e.Code == "node_not_found", e)
			request(t, f.e, "POST", "/api/v1/nodes/n1/"+action, "ui", "", 202)
		}
		require(t, f.n.syncs == 1 && f.n.reconciles == 1, "node action not called")
	})
	t.Run("API-doc", testDocs)
}

func testPages(t *testing.T) {
	f := fresh(t)
	initial := map[string]bool{}
	whites := map[string]bool{}
	for i := 1; i <= 250; i++ {
		c, e := rules.Canonicalize(store.Match{DstIP: "192.0.2.10", DstPort: i, Protocol: "tcp"})
		require(t, e == nil, e)
		r := store.Rule{ID: fmt.Sprintf("rule_%04d", 1000-i), LogicalID: int64(i), Match: c.RuleInput, Kind: c.Kind, GroupKey: c.GroupKey, CondKey: c.CondKey, Enabled: true, CreatedAt: "2026-10-11T00:00:00Z", UpdatedAt: "2026-10-11T00:00:00Z"}
		require(t, store.InsertRule(f.db, r) == nil, "insert page row")
		initial[r.ID] = true
		w, e := f.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{DstIP: "192.0.2.10", DstPort: i, Protocol: "tcp"})
		require(t, e == nil, e)
		whites[w.Whitelist.ID] = true
	}
	_, err := f.db.Exec("UPDATE logical_id_hw SET high_water=250")
	require(t, err == nil, err)
	for _, kind := range []string{"rules", "whitelist"} {
		seen := map[string]bool{}
		after := ""
		if kind == "rules" {
			after = "0"
		}
		last := int64(0)
		for page := 0; page < 5; page++ {
			w := request(t, f.e, "GET", "/api/v1/"+kind+"?limit=100&after="+after, "ui", "", 200)
			var next any
			if kind == "rules" {
				p := decoded[Page[RuleDTO]](t, w)
				next = p.NextAfter
				for _, r := range p.Items {
					require(t, !seen[r.ID] && r.LogicalID > last, "rule cursor repeated or misordered", r)
					seen[r.ID] = true
					last = r.LogicalID
				}
			} else {
				p := decoded[Page[WhitelistDTO]](t, w)
				next = p.NextAfter
				for _, r := range p.Items {
					require(t, !seen[r.ID], "whitelist repeated")
					seen[r.ID] = true
				}
			}
			if page == 0 {
				if kind == "rules" {
					r := created(t, f, 300)
					initial[r.ID] = true
				} else {
					_, e := f.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{DstIP: "192.0.2.10", DstPort: 300})
					require(t, e == nil, e)
				}
			}
			if next == nil {
				require(t, page == 2, "wrong last page", page)
				break
			}
			after = fmt.Sprint(next)
		}
		want := initial
		if kind == "whitelist" {
			want = whites
		}
		for id := range want {
			require(t, seen[id], "missing page member", kind, id)
		}
		for _, limit := range []string{"0", "1001"} {
			request(t, f.e, "GET", "/api/v1/"+kind+"?limit="+limit, "ui", "", 400)
		}
	}
}

func testErrors(t *testing.T) {
	require(t, reflect.DeepEqual(errorStatus, codeOracle), "code registration differs")
	for code, status := range codeOracle {
		f := fresh(t)
		a := &API{log: log.New(f.logs, "", 0)}
		f.e = gin.New()
		f.e.Use(a.recovery())
		f.e.GET("/api/v1/injected", func(c *gin.Context) {
			a.serviceError(c, &rules.Error{Code: code, Message: "storage-message", Field: "field", RuleID: "r", RuleIDs: []string{"r"}, Table: "table"})
		})
		e := decoded[Error](t, request(t, f.e, "GET", "/api/v1/injected", "ui", "", status))
		require(t, e.Code == code, "wrong code", e)
		if code == "internal" {
			require(t, e.Message == "internal error" && !strings.Contains(fmt.Sprint(e), "storage-message"), "internal exposed")
		}
	}
	f := fresh(t)
	for _, test := range []struct{ body, code string }{
		{`{"dst_port":-1}`, "invalid_rule"}, {`{"dst_ip":""}`, "empty_value"}, {`{"dst_ip":"192.0.2.1","expires_in":"bad"}`, "invalid_expires_in"},
		{`{"dst_ip":"::ffff:192.0.2.1"}`, "mapped_ipv6"}, {`{"src_ip":"192.0.2.1","dst_ip":"2001:db8::1"}`, "address_family_mismatch"},
		{`{"unknown":true}`, "bad_request"}, {body(80) + ` {}`, "bad_request"}, {`{"dst_port":"bad"}`, "bad_request"}, {`{"comment":"` + strings.Repeat("a", 1<<20) + `"}`, "bad_request"},
	} {
		e := decoded[Error](t, request(t, f.e, "POST", "/api/v1/rules", "ui", test.body, 400))
		require(t, e.Code == test.code, e)
	}
	for _, item := range []struct {
		method, path, code string
		status             int
	}{{"GET", "/unknown", "route_not_found", 404}, {"PATCH", "/health", "method_not_allowed", 405}, {"GET", "/rules/missing", "not_found", 404}} {
		e := decoded[Error](t, request(t, f.e, item.method, "/api/v1"+item.path, "ui", "", item.status))
		require(t, e.Code == item.code, e)
	}
	for i := 1; i <= 5; i++ {
		status := 201
		if i == 5 {
			status = 409
		}
		e := request(t, f.e, "POST", "/api/v1/rules", "ui", strings.TrimSuffix(body(80), "}")+`,"ttl":"`+strconv.Itoa(i)+`"}`, status)
		if i == 5 {
			require(t, decoded[Error](t, e).Code == "condition_capacity", "capacity code")
		}
	}
	request(t, f.e, "POST", "/api/v1/rules", "ui", `{"dst_cidr":"198.51.100.0/24"}`, 201)
	e := decoded[Error](t, request(t, f.e, "POST", "/api/v1/rules", "ui", `{"dst_cidr":"198.51.100.0/25"}`, 409))
	require(t, e.Code == "cidr_overlap", e)
	_, err := f.db.Exec("UPDATE logical_id_hw SET high_water=4294967295")
	require(t, err == nil, err)
	e = decoded[Error](t, request(t, f.e, "POST", "/api/v1/rules", "ui", body(81), 409))
	require(t, e.Code == "table_full" && e.Table == "logical_id", e)
	f = fresh(t)
	_, err = f.db.Exec("CREATE TRIGGER broken BEFORE INSERT ON rules BEGIN SELECT RAISE(ABORT,'STORAGE-C3A-SENTINEL'); END")
	require(t, err == nil, err)
	w := request(t, f.e, "POST", "/api/v1/rules", "ui", body(80), 500)
	e = decoded[Error](t, w)
	require(t, e.Code == "internal" && e.Message == "internal error" && !strings.Contains(w.Body.String(), "STORAGE-C3A-SENTINEL"), "single leaked")
	b := decoded[BatchResponse](t, request(t, f.e, "POST", "/api/v1/rules/batch", "ui", `{"items":[`+body(81)+`]}`, 200))
	require(t, b.Results[0].Error.Code == "internal" && b.Results[0].Error.Message == "internal error" && !strings.Contains(fmt.Sprint(b.Results[0].Error), "STORAGE-C3A-SENTINEL") && strings.Contains(f.logs.String(), "STORAGE-C3A-SENTINEL"), "batch internal leaked or log missing")
	testLateRoute(t, f)
	f.e = gin.New()
	f.e.Use((&API{log: log.New(f.logs, "", 0)}).recovery())
	f.e.GET("/api/v1/panic", func(*gin.Context) { panic("panic-value") })
	w = request(t, f.e, "GET", "/api/v1/panic", "machine:HEADER-C3A-SENTINEL", "", 500)
	e = decoded[Error](t, w)
	require(t, e.Code == "internal" && e.Message == "internal error" && !strings.Contains(f.logs.String(), "HEADER-C3A-SENTINEL") && strings.Contains(f.logs.String(), "panic-value"), "panic recovery contract")
}

func testDocs(t *testing.T) {
	want := routeSet(fresh(t).e)
	successKeys, permissionKeys := map[string]bool{}, map[string]bool{}
	for key := range successOracle {
		successKeys[key] = true
	}
	for key := range permissionOracle {
		permissionKeys[key] = true
	}
	require(t, reflect.DeepEqual(successKeys, permissionKeys), "successOracle key set mismatch")
	for _, doc := range []struct {
		path, header string
		cells        int
		permissions  map[string]string
	}{
		{filepath.Join("..", "API.md"), "| 方法 | 路径 | 谁可调 | 成功码 |", 6, map[string]string{"免身份": "public", "仅 UI": "ui", "UI / 机器": "all", "admin": "admin", "仅管理员": "admin"}},
		{filepath.Join("..", "API.zh.md"), "| 方法 | 路径 | 谁可调 | 成功码 |", 6, map[string]string{"免身份": "public", "仅 UI": "ui", "UI / 机器": "all", "admin": "admin", "仅管理员": "admin"}},
		{filepath.Join("..", "..", "API.md"), "| Method | Path | Permission | Success | Request → response |", 7, map[string]string{"Public": "public", "UI": "ui", "UI / machine": "all", "Admin": "admin"}},
		{filepath.Join("..", "..", "API.zh.md"), "| 方法 | 路径 | 权限 | 成功码 | 请求 → 响应 |", 7, map[string]string{"公开": "public", "UI": "ui", "UI / 机器": "all", "Admin": "admin"}},
	} {
		path := doc.path
		name := filepath.Join("controller", "core", "api", path)
		data, err := os.ReadFile(path)
		require(t, err == nil, err)
		routes, codes := map[string]bool{}, map[string]int{}
		routeSections, codeSections := 0, 0
		section := ""
		for _, line := range strings.Split(string(data), "\n") {
			if line == doc.header {
				routeSections++
				section = "routes"
				continue
			}
			if line == "| code | HTTP |" {
				codeSections++
				section = "codes"
				continue
			}
			if section == "" {
				continue
			}
			if strings.TrimSpace(line) == "" {
				section = ""
				continue
			}
			if strings.HasPrefix(line, "|---") {
				continue
			}
			cells := strings.Split(line, "|")
			for i := range cells {
				cells[i] = strings.TrimSpace(strings.Trim(cells[i], " `"))
			}
			if section == "routes" {
				require(t, len(cells) == doc.cells && cells[0] == "" && cells[doc.cells-1] == "", "unparsed route row", name, line)
				path := strings.ReplaceAll(strings.ReplaceAll(cells[2], "{id}", ":id"), "{name}", ":name")
				key := cells[1] + " " + path
				require(t, !routes[key], "duplicate route", key)
				routes[key] = true
				oracleKey := strings.Replace(key, "/api/v1", "", 1)
				permission, known := doc.permissions[cells[3]]
				require(t, known, name, key, "unknown permission", cells[3])
				require(t, permission == permissionOracle[oracleKey], name, key, "permission mismatch", cells[3])
				require(t, cells[4] == successOracle[oracleKey], name, key, "success mismatch", cells[4], successOracle[oracleKey])
			} else {
				require(t, len(cells) == 4 && cells[0] == "" && cells[3] == "", "unparsed code row", line)
				_, duplicate := codes[cells[1]]
				require(t, !duplicate, "duplicate code", line)
				n, e := strconv.Atoi(cells[2])
				require(t, e == nil, e)
				codes[cells[1]] = n
			}
		}
		require(t, routeSections == 1 && codeSections == 1, name, "table section count", routeSections, codeSections)
		require(t, len(routes) > 0 && reflect.DeepEqual(routes, want), name, "route table mismatch", routes, want)
		require(t, len(codes) > 0 && reflect.DeepEqual(codes, codeOracle) && reflect.DeepEqual(codes, errorStatus), name, "code table mismatch", codes)
		t.Logf("API-doc %s routes=%d codes=%d", path, len(routes), len(codes))
	}
}
