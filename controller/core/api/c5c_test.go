package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type c5cSource struct {
	*orch.Manager
	input  orch.TrafficInput
	byNode map[string]map[string]orch.RuleRate
	points []store.TrafficRow
	now    time.Time
	capped bool
}

func (s *c5cSource) TrafficInput() orch.TrafficInput {
	real := s.Manager.TrafficInput()
	out := s.input
	out.Key = real.Key + "/" + out.Key
	out.Names = real.Names
	out.Rates = map[string]orch.RuleRate{}
	for name, rows := range s.byNode {
		if !real.Names[name] {
			continue
		}
		for id, v := range rows {
			if v.PPS <= 0 {
				continue
			}
			r := out.Rates[id]
			r.PPS += v.PPS
			r.BytesPS += v.BytesPS
			r.Nodes++
			out.Rates[id] = r
		}
	}
	return out
}
func (s *c5cSource) TrafficMemory(string, time.Duration) ([]store.TrafficRow, time.Time, bool) {
	return s.points, s.now, s.capped
}

type c5cQuery struct {
	store.Queryer
	batches   int
	failNodes bool
}

func (q *c5cQuery) Query(query string, args ...any) (*sql.Rows, error) {
	if q.failNodes && strings.HasPrefix(query, "SELECT name,base_url,key_nonce,key_cipher") {
		return nil, fmt.Errorf("fixture node read failed")
	}
	if strings.HasPrefix(query, "SELECT id,dst_ip,dst_cidr FROM rules WHERE id IN") {
		q.batches++
	}
	return q.Queryer.Query(query, args...)
}
func c5cFixture(t *testing.T) (*fixture, *c5cSource, *c5cQuery) {
	f := fresh(t)
	m := orch.New([]nc.NodeSpec{{Name: "a"}, {Name: "b"}}, orch.Options{})
	src := &c5cSource{Manager: m, input: orch.TrafficInput{DroppedPPS: 3000, DroppedBytesPS: 300000, At: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, byNode: map[string]map[string]orch.RuleRate{"a": {}, "b": {}}, points: []store.TrafficRow{}, now: time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)}
	f.s = rules.New(f.db, src)
	q := &c5cQuery{Queryer: f.db.Reader()}
	f.e = New(f.s, src, testActor, nil, Options{trafficQuery: q})
	return f, src, q
}
func c5cTop(t *testing.T, f *fixture, n string) topResponse {
	t.Helper()
	return decoded[topResponse](t, request(t, f.e, "GET", "/api/v1/traffic/top"+n, "ui", "", 200))
}
func c5cRule(t *testing.T, f *fixture, body string) string {
	t.Helper()
	return decoded[CreateResponse](t, request(t, f.e, "POST", "/api/v1/rules", "ui", body, 201)).ID
}

type c5cSlowWriter struct {
	*httptest.ResponseRecorder
	entered, release chan struct{}
	once             sync.Once
}

func (w *c5cSlowWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.ResponseRecorder.Write(p)
}
func TestC5CTop(t *testing.T) {
	t.Run("db-only-node-warm-cache", func(t *testing.T) {
		for _, empty := range []bool{false, true} {
			empty := empty
			t.Run(fmt.Sprintf("empty-orch-%t", empty), func(t *testing.T) {
				f, src, q := c5cFixture(t)
				id := c5cRule(t, f, "{\"dst_ip\":\"192.0.2.10\"}")
				src.byNode["a"][id] = orch.RuleRate{PPS: 100}
				if empty {
					src.Manager.RemoveNode("a")
					src.Manager.RemoveNode("b")
				}
				key := src.TrafficInput().Key
				warm := c5cTop(t, f, "")
				batches := q.batches
				require(t, !warm.Incomplete && batches == len(warm.Rules), "warm prerequisite", warm, batches)
				if !empty {
					require(t, len(warm.Rules) == 1 && warm.Rules[0].Share != nil, "known denominator")
				}
				require(t, store.PutNode(f.db, store.Node{Name: "db-only", BaseURL: "http://192.0.2.20", KeyNonce: []byte{}, KeyCipher: []byte{}}, true) == nil, "external add")
				out := c5cTop(t, f, "")
				require(t, out.Incomplete && q.batches == 2*batches, "database addition invalidates", out, q.batches)
				for i, row := range out.Rules {
					require(t, row.Share != nil && *row.Share == *warm.Rules[i].Share, "missing denominator rule")
				}
				for i, row := range out.Targets {
					require(t, row.Share != nil && *row.Share == *warm.Targets[i].Share, "missing denominator target")
				}
				c5cTop(t, f, "")
				require(t, q.batches == 2*batches, "unchanged missing set is cached")
				require(t, store.DeleteNode(f.db, "db-only") == nil, "external delete")
				out = c5cTop(t, f, "")
				require(t, !out.Incomplete && q.batches == 3*batches && src.TrafficInput().Key == key, "database deletion invalidates without new sample", out, q.batches)
				if !empty {
					require(t, out.Rules[0].Share != nil && *out.Rules[0].Share == *warm.Rules[0].Share, "denominator restored")
				}
				q.failNodes = true
				err := decoded[Error](t, request(t, f.e, "GET", "/api/v1/traffic/top", "ui", "", 500))
				require(t, err.Code == "internal" && q.batches == 3*batches, "warm database read error")
				t.Logf("empty_orch=%t unchanged_orch_key=1 incomplete=false,true,false initial_batches=%d final_batches=%d warm_db_error=internal", empty, batches, q.batches)
			})
		}
	})
	t.Run("slow-client-does-not-hold-topMu", func(t *testing.T) {
		for _, mode := range []string{"miss", "hit", "error"} {
			mode := mode
			t.Run(mode, func(t *testing.T) {
				f, src, q := c5cFixture(t)
				var a *API
				f.e = New(f.s, src, testActor, nil, Options{trafficQuery: q, NodeStore: NewNodeService(f.db, nil), nodeAPI: func(v *API) { a = v }})
				id := c5cRule(t, f, "{\"dst_ip\":\"192.0.2.10\"}")
				src.byNode["a"][id] = orch.RuleRate{PPS: 100}
				require(t, store.PutNode(f.db, store.Node{Name: "a", BaseURL: "http://192.0.2.20", KeyNonce: []byte{}, KeyCipher: []byte{}}, true) == nil, "stored member")
				if mode == "hit" {
					c5cTop(t, f, "")
				}
				q.failNodes = mode == "error"
				w := &c5cSlowWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
				var once sync.Once
				unblock := func() { once.Do(func() { close(w.release) }) }
				firstDone := make(chan struct{})
				r := httptest.NewRequest("GET", "/api/v1/traffic/top", nil)
				r.Header.Set("X-Xdrop-Actor", "ui")
				go func() { f.e.ServeHTTP(w, r); close(firstDone) }()
				defer func() {
					unblock()
					select {
					case <-firstDone:
					case <-time.After(time.Second):
						t.Error("first response did not finish after fixture release")
					}
				}()
				select {
				case <-w.entered:
				case <-time.After(time.Second):
					t.Fatal("first response never entered Write")
				}
				q.failNodes = false
				for _, op := range []struct {
					method, path string
					status       int
				}{{"GET", "/traffic/top", 200}, {"DELETE", "/nodes/a", 204}} {
					op := op
					done := make(chan *httptest.ResponseRecorder, 1)
					go func() { done <- c5bCall(f.e, op.method, op.path, "") }()
					select {
					case response := <-done:
						require(t, response.Code == op.status, "concurrent response", op, response.Code)
					case <-time.After(time.Second):
						unblock()
						select {
						case <-done:
						case <-time.After(time.Second):
							t.Error("concurrent request did not finish after release")
						}
						t.Fatal("slow response held topMu", op.method)
					}
				}
				a.topMu.Lock()
				cleared := a.top == nil
				a.topMu.Unlock()
				require(t, cleared && q.batches == 1, "writeNode cleared cache while first response blocked", q.batches)
				unblock()
				<-firstDone
				want := 200
				if mode == "error" {
					want = 500
				}
				require(t, w.Code == want, "first response completed", w.Code)
				t.Logf("mode=%s write_entered=1 second_top_200_within_1s=1 writeNode_204_within_1s=1 cache_cleared=1 first_status=%d target_batches=1", mode, want)
			})
		}
	})
	t.Run("top-not-blocked-by-node-write", func(t *testing.T) {
		f, src, q := c5cFixture(t)
		var a *API
		f.e = New(f.s, src, testActor, nil, Options{trafficQuery: q, nodeAPI: func(v *API) { a = v }})
		id := c5cRule(t, f, `{"dst_ip":"192.0.2.10"}`)
		src.byNode["a"][id] = orch.RuleRate{PPS: 100, BytesPS: 10000}
		tx, err := f.db.Begin()
		require(t, err == nil, "hold write connection", err)
		defer tx.Rollback()
		a.nodeWrite.Lock()
		held := true
		defer func() {
			if held {
				a.nodeWrite.Unlock()
			}
		}()
		var body string
		for _, identity := range []string{"ui", "operator", "machine:reader"} {
			done := make(chan *httptest.ResponseRecorder, 1)
			r := httptest.NewRequest("GET", "/api/v1/traffic/top", nil)
			r.Header.Set("X-Xdrop-Actor", identity)
			started := time.Now()
			go func() {
				w := httptest.NewRecorder()
				f.e.ServeHTTP(w, r)
				done <- w
			}()
			var w *httptest.ResponseRecorder
			select {
			case w = <-done:
			case <-time.After(time.Second):
				a.nodeWrite.Unlock()
				held = false
				_ = tx.Rollback()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("request did not finish after fixture release")
				}
				t.Fatal("Top waited while nodeWrite and write connection were held")
			}
			require(t, w.Code == 200 && time.Since(started) <= time.Second, "Top response while locks held", identity, w.Code)
			var top topResponse
			require(t, json.Unmarshal(w.Body.Bytes(), &top) == nil && len(top.Rules) == 1 && top.Rules[0].RuleID == id && top.Rules[0].PPS == 100, "Top data", top)
			if body == "" {
				body = w.Body.String()
			}
			require(t, w.Body.String() == body && q.batches == 1, "held-lock cache consistency")
		}
		a.nodeWrite.Unlock()
		held = false
		require(t, tx.Rollback() == nil, "release write connection")
		w := request(t, f.e, "GET", "/api/v1/traffic/top", "ui", "", 200)
		require(t, w.Body.String() == body && q.batches == 1, "cache after release")
		t.Log("nodeWrite_held=1 write_connection_held=1 identities=3 held_responses_200=3 each_within_1s=1 target_batches=1 cache_after_release_equal=1")
	})
	t.Run("aggregation-cache", func(t *testing.T) {
		f, s, q := c5cFixture(t)
		a := c5cRule(t, f, `{"dst_ip":"192.0.2.10","dst_port":80}`)
		b := c5cRule(t, f, `{"dst_ip":"192.0.2.10","dst_port":81}`)
		prefix := c5cRule(t, f, `{"dst_cidr":"192.0.2.0/24"}`)
		global := c5cRule(t, f, `{"protocol":"udp"}`)
		s.byNode["a"] = map[string]orch.RuleRate{a: {PPS: 100, BytesPS: 10000}, b: {PPS: 50, BytesPS: 5000}, prefix: {PPS: 500, BytesPS: 50000}, global: {PPS: 1, BytesPS: 100}, "already-deleted": {PPS: 9000}}
		s.byNode["b"][a] = orch.RuleRate{PPS: 200, BytesPS: 20000}
		out := c5cTop(t, f, "")
		require(t, len(out.Rules) == 4 && len(out.Targets) == 2 && !out.Incomplete, "shape", out)
		require(t, out.Rules[1].RuleID == a && out.Rules[1].Nodes == 2 && out.Rules[1].PPS == 300 && out.Rules[1].BytesPS == 30000, "two node sum", out.Rules)
		require(t, out.Targets[1].Target == "192.0.2.10" && out.Targets[1].Rules == 2 && out.Targets[1].PPS == 350, "target count", out.Targets)
		require(t, out.TotalPPS == 3000 && *out.Rules[1].Share == 300.0/9851 && *out.Targets[1].Share == 350.0/9851, "all drops denominator", out)
		for i := 0; i < 99; i++ {
			c5cTop(t, f, "")
		}
		require(t, q.batches == 1 && len(out.Rules) > 0, "warm target query count", q.batches)
		s.input.Key = "next"
		c5cTop(t, f, "")
		require(t, q.batches == 2, "new sample query")
		request(t, f.e, "DELETE", "/api/v1/rules/"+a, "ui", "", 204)
		_, e := store.Get(f.db.Reader(), a)
		require(t, e == sql.ErrNoRows, "delete prerequisite")
		out = c5cTop(t, f, "")
		for _, r := range out.Rules {
			require(t, r.RuleID != a, "warm deleted rule")
		}
		require(t, q.batches == 3, "gen invalidation", q.batches)
		request(t, f.e, "PATCH", "/api/v1/rules/"+b, "ui", `{"dst_ip":"192.0.2.99"}`, 200)
		out = c5cTop(t, f, "")
		found := false
		for _, r := range out.Rules {
			if r.RuleID == b {
				found = r.Target == "192.0.2.99"
			}
		}
		require(t, found && q.batches == 4, "warm target patch", out)
		s.Manager.RemoveNode("a")
		out = c5cTop(t, f, "")
		require(t, len(out.Rules) == 0 && len(out.Targets) == 0, "removed member contribution", out)
		t.Log("two_node_rule_nodes=2 two_rule_target_rules=2 denominator=9851 warm_requests=100 initial_target_batches=1 new_sample_batches=1 delete_gen_invalidated=1 patch_gen_invalidated=1 removal_invalidated=1")
	})
	t.Run("bounds-null-incomplete", func(t *testing.T) {
		f, s, _ := c5cFixture(t)
		id := c5cRule(t, f, `{"dst_ip":"192.0.2.1"}`)
		s.byNode["a"][id] = orch.RuleRate{PPS: 6000, BytesPS: 60000}
		out := c5cTop(t, f, "?n=1")
		require(t, len(out.Rules) == 1 && *out.Rules[0].Share == 1 && !out.Incomplete, "single rule share", out)
		require(t, len(c5cTop(t, f, "?n=20").Rules) == 1, "n20")
		for _, n := range []string{"0", "21", "bad", ""} {
			request(t, f.e, "GET", "/api/v1/traffic/top?n="+n, "ui", "", 400)
		}
		s.input.Key = "zero"
		s.input.DroppedPPS = 0
		out = c5cTop(t, f, "")
		require(t, out.Rules[0].Share != nil && *out.Rules[0].Share == 1, "stats zero share")
		s.input.Key = "missing"
		s.input.DroppedPPS = 3000
		s.input.DenominatorMissing = true
		s.input.Incomplete = true
		out = c5cTop(t, f, "")
		require(t, out.Rules[0].Share != nil && *out.Rules[0].Share == 1 && out.Incomplete, "missing share incomplete")
		s.input.Key = "truncated"
		s.input.DenominatorMissing = false
		s.input.Incomplete = true
		require(t, c5cTop(t, f, "").Incomplete, "incomplete flag")
		s.input.Key = "unknown-only"
		s.input.Incomplete = false
		s.byNode["a"] = map[string]orch.RuleRate{}
		out = c5cTop(t, f, "")
		require(t, !out.Incomplete && len(out.Rules) == 0, "unknown alone is not incomplete")
		t.Log("n_accept=1,20 n_reject=0,21,bad single_rule_share=1 stats_zero_share=1 missing_share_incomplete=1 truncated_true=1 unknown_only_incomplete_false=1")
	})
	t.Run("query-chunks", func(t *testing.T) {
		f, s, q := c5cFixture(t)
		for i := 0; i < 501; i++ {
			id := fmt.Sprintf("rule_%d", i)
			r := store.Rule{ID: id, LogicalID: int64(i + 1), Kind: "exact", GroupKey: id, CondKey: id, Match: store.Match{DstIP: "192.0.2.1", Action: "drop"}}
			require(t, store.InsertRule(f.db, r) == nil, "seed")
			s.byNode["a"][id] = orch.RuleRate{PPS: float64(i + 1)}
		}
		for i := 0; i < 100; i++ {
			out := c5cTop(t, f, "")
			require(t, len(out.Rules) == 5 && out.Targets[0].Rules == 501, "chunk result")
		}
		require(t, q.batches == 2, "query batch count", q.batches)
		t.Log("positive_targets=501 requests=100 chunk_limit=500 batches=2")
	})
}
func TestC5CHistoryAPI(t *testing.T) {
	f, s, _ := c5cFixture(t)
	s.points = []store.TrafficRow{{T: s.now.Add(-time.Minute).Unix(), N: 1, Avg: [4]float64{1, 2, 3, 4}}}
	s.capped = true
	minute := store.TrafficRow{T: s.now.Add(-2 * time.Hour).Unix(), N: 2, Avg: [4]float64{5, 6, 7, 8}, Max: [4]float64{9, 10, 11, 12}}
	_, err := f.db.WriteTraffic([]store.TrafficRow{minute}, 0, s.now, [2]int{}, nil)
	require(t, err == nil, err)
	for _, tc := range []struct {
		span string
		step int
	}{{"15m", 5}, {"1h", 5}, {"6h", 60}, {"24h", 60}, {"7d", 3600}, {"30d", 3600}} {
		tc := tc
		t.Run(tc.span, func(t *testing.T) {
			out := decoded[map[string]any](t, request(t, f.e, "GET", "/api/v1/traffic/history?range="+tc.span, "ui", "", 200))
			pts := out["points"].([]any)
			require(t, int(out["step_s"].(float64)) == tc.step && len(pts) == 1 && out["capped"] == true, "range", out)
			p := pts[0].(map[string]any)
			_, max := p["dropped_pps_max"]
			require(t, max == (tc.step > 5), "max presence", p)
			t.Logf("range=%s step_s=%d points=1 max_present=%t capped=true", tc.span, tc.step, max)
		})
	}
	for _, query := range []string{"", "?range=bad", "?range="} {
		request(t, f.e, "GET", "/api/v1/traffic/history"+query, "ui", "", 400)
	}
	request(t, f.e, "GET", "/api/v1/traffic/history?range=15m&node=missing", "ui", "", 404)
}
func TestC5CHistorySettings(t *testing.T) {
	f := c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
	for _, days := range []int{0, 91} {
		out := decoded[Error](t, f.call(t, "PUT", "/settings", f.cookie, fmt.Sprintf(`{"history_retention_days":%d}`, days), 400))
		require(t, out.Code == "invalid_field" && out.Field == "history_retention_days", "setting rejected")
	}
	for _, days := range []int{1, 90} {
		out := decoded[SettingsDTO](t, f.call(t, "PUT", "/settings", f.cookie, fmt.Sprintf(`{"history_retention_days":%d}`, days), 200))
		require(t, out.HistoryRetentionDays == days, "setting accepted")
	}
	rows, e := store.AuditPage(f.db.Reader(), "", "", "", 0, 100)
	require(t, e == nil, e)
	count := 0
	for _, row := range rows {
		if row.Action == "settings.update" {
			var before, after map[string]any
			require(t, json.Unmarshal(row.Before, &before) == nil && json.Unmarshal(row.After, &after) == nil && len(before) == 5 && len(after) == 5, "five keys")
			count++
		}
	}
	require(t, count == 2, "audit events", count)
	t.Log("rejected=0,91 accepted=1,90 settings_update_events=2 before_keys=5 after_keys=5")
}
