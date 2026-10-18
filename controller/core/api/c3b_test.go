package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type c3bNodes struct {
	stubNodes
	values []orch.NodeStatus
	calls  int
}

func (n *c3bNodes) Status() []orch.NodeStatus { n.calls++; return n.values }
func c3bFields(t *testing.T, obj map[string]any, want string) {
	t.Helper()
	keys := []string{}
	for k := range obj {
		keys = append(keys, k)
	}
	expected := strings.Fields(want)
	sort.Strings(keys)
	sort.Strings(expected)
	require(t, reflect.DeepEqual(keys, expected), "field set", keys, expected)
}
func c3bService(t *testing.T) (*rules.Service, *c3bNodes) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	require(t, err == nil, err)
	t.Cleanup(func() { db.Close() })
	n := &c3bNodes{values: []orch.NodeStatus{{Name: "n1", Online: true, Health: nc.Health{RulesSynced: true, WhitelistSynced: true}, Rules: orch.SideStatus{State: "normal", Confirmable: true, ConfirmedGen: 99}}}}
	s := rules.New(db, n, DeliveryStatus(n))
	for i := 1; i <= 3; i++ {
		_, e := s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{SrcIP: ptrC3B("192.0.2.1"), DstPort: ptrC3B(i), Protocol: ptrC3B("tcp"), Enabled: ptrC3B(i != 3)})
		require(t, e == nil, e)
	}
	_, e := s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: "192.0.2.2"})
	require(t, e == nil, e)
	return s, n
}
func ptrC3B[T any](v T) *T { return &v }
func TestC3BAPI(t *testing.T) {
	t.Run("API-capacity", func(t *testing.T) {
		s, n := c3bService(t)
		limits := rules.BuiltinLimits()
		limits.Values[0], limits.Values[4], limits.Values[9] = 10, 4, 6
		for i := range limits.Sources {
			limits.Sources[i] = "fixture"
		}
		limits.Overloaded = []rules.OverloadedNode{{Name: "small", Dims: []rules.Overload{{Dim: "blacklist", Limit: 1, Used: 2}}}}
		calls := 0
		s.UseLimits(func() rules.Limits { calls++; return limits })
		s.UseLogicalReserve(2)
		e := New(s, n, testActor, nil)
		read := func() map[string]any {
			return decoded[map[string]any](t, request(t, e, "GET", "/api/v1/capacity", "machine:reader", "", 200))
		}
		root := read()
		require(t, calls == 1 && n.calls == 0, "one limits call, zero Status", calls, n.calls)
		c3bFields(t, root, "dimensions tightest candidates rules overloaded_nodes")
		dimensions := root["dimensions"].([]any)
		names := []string{"blacklist", "cidr_blacklist", "cond", "cidr_cond", "whitelist", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "logical_state"}
		used := []float64{2, 0, 0, 0, 1, 0, 0, 0, 0, 2}
		require(t, len(dimensions) == 10, "dimension count")
		for i, v := range dimensions {
			d := v.(map[string]any)
			c3bFields(t, d, "name used limit admission_limit limit_source free ratio exhausted")
			limit := float64(limits.Values[i])
			admission := limit
			if i == 9 {
				admission -= 2
			}
			require(t, d["name"] == names[i] && d["used"] == used[i] && d["limit"] == limit && d["admission_limit"] == admission && d["free"] == admission-used[i] && d["ratio"] == used[i]/admission && d["limit_source"] == "fixture" && d["exhausted"] == false, "dimension", i, d)
		}
		tight := root["tightest"].(map[string]any)
		c3bFields(t, tight, "name limit_source free ratio exhausted")
		require(t, tight["name"] == "logical_state" && tight["free"] == float64(2) && tight["ratio"] == 0.5, "tightest", tight)
		c3bFields(t, root["candidates"].(map[string]any), "limit full_keys near_keys")
		require(t, reflect.DeepEqual(root["candidates"], map[string]any{"limit": float64(4), "full_keys": float64(0), "near_keys": float64(0)}), "candidates", root)
		require(t, reflect.DeepEqual(root["rules"], map[string]any{"enabled": float64(2), "total": float64(3)}), "rules", root)
		overloaded := root["overloaded_nodes"].([]any)[0].(map[string]any)
		c3bFields(t, overloaded, "name dims")
		d := overloaded["dims"].([]any)[0].(map[string]any)
		c3bFields(t, d, "name limit used")
		require(t, overloaded["name"] == "small" && d["name"] == "blacklist" && d["limit"] == float64(1) && d["used"] == float64(2), "overload", overloaded)
		for _, limit := range []int{2, 1} {
			limits.Values[0], limits.Values[9] = 3, limit
			root = read()
			logical := root["dimensions"].([]any)[9].(map[string]any)
			tight = root["tightest"].(map[string]any)
			require(t, logical["admission_limit"] == float64(limit-2) && logical["ratio"] == nil && logical["exhausted"] == true && tight["name"] == "logical_state" && tight["ratio"] == nil && tight["exhausted"] == true, "nonpositive admission denominator", logical, tight)
		}
		ratio := 2.5
		a, b := TightestDTO{Free: -3, Exhausted: true, Ratio: &ratio}, TightestDTO{Free: -3, Exhausted: true}
		require(t, !tighter(a, b) && !tighter(b, a), "equal exhausted free must ignore ratios")
	})
	t.Run("API-system", func(t *testing.T) {
		s, n := c3bService(t)
		at := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
		node := &n.values[0]
		node.Overload = []rules.Overload{{Dim: "blacklist", Limit: 1, Used: 2}}
		node.Rules.State, node.Whitelist.State = "overloaded", "overloaded"
		node.StatsAt = at
		node.Stats = map[string]any{"system": map[string]any{"uptime_seconds": 1234, "cpu_percent": 12.5, "mem_percent": 41, "load_avg_1": 1.5, "load_avg_5": 2, "load_avg_15": 3}, "agent_state": map[string]any{"exact_rules": 7, "cidr_rules": 0, "whitelist_entries": 1}, "capacity": map[string]any{"blacklist": map[string]any{"limit": 9, "used": 7}}}
		counters := []string{"total_packets", "dropped_packets", "passed_packets", "whitelisted_packets", "rate_limited_packets", "mapped_v6_dropped", "cond_row_missing", "tailcall_fail", "total_bytes", "dropped_bytes", "passed_bytes"}
		for i, k := range counters {
			node.Stats[k] = 10 + i
		}
		node.Rates = map[string]float64{"total_packets": 1.25, "total_bytes": 90, "dropped_bytes": 30, "passed_bytes": 60}
		node.RuleReconcile = orch.ReconcileStatus{LastAt: at, Result: "drift", Diff: orch.Diff{Extra: 3, Missing: 4, Different: 5}}
		node.WhitelistReconcile = orch.ReconcileStatus{LastAt: at, Result: "equal"}
		path := filepath.Join(t.TempDir(), "size.db")
		for i, suffix := range []string{"", "-wal", "-shm"} {
			require(t, os.WriteFile(path+suffix, make([]byte, 11+i*2), 0600) == nil, "size file")
		}
		started := time.Now().Add(-10 * time.Second)
		e := New(s, n, testActor, nil, Options{Database: path, StartedAt: started})
		root := decoded[map[string]any](t, request(t, e, "GET", "/api/v1/system", "machine:reader", "", 200))
		require(t, n.calls == 1, "Status calls", n.calls)
		c3bFields(t, root, "controller nodes")
		ctl := root["controller"].(map[string]any)
		c3bFields(t, ctl, "started_at uptime_seconds db_bytes rules_enabled rules_total whitelist go_mem")
		require(t, ctl["started_at"] == stamp(started) && ctl["db_bytes"] == float64(39) && ctl["rules_enabled"] == float64(2) && ctl["rules_total"] == float64(3) && ctl["whitelist"] == float64(1), "controller fields", ctl)
		require(t, ctl["uptime_seconds"].(float64) >= 10 && ctl["uptime_seconds"].(float64) < 30, "uptime", ctl)
		mem := ctl["go_mem"].(map[string]any)
		c3bFields(t, mem, "alloc_bytes sys_bytes")
		require(t, mem["alloc_bytes"].(float64) > 0 && mem["sys_bytes"].(float64) > 0, "memory", mem)
		d := root["nodes"].([]any)[0].(map[string]any)
		c3bFields(t, d, "name online incompatible overloaded rules_state whitelist_state stats_at host_uptime_seconds cpu_percent mem_percent load_avg_1 load_avg_5 load_avg_15 counters rates agent_state capacity rule_reconcile whitelist_reconcile")
		expected := map[string]any{"name": "n1", "online": true, "incompatible": false, "overloaded": true, "rules_state": "overloaded", "whitelist_state": "overloaded", "stats_at": stamp(at), "host_uptime_seconds": float64(1234), "cpu_percent": 12.5, "mem_percent": float64(41), "load_avg_1": 1.5, "load_avg_5": float64(2), "load_avg_15": float64(3)}
		for k, v := range expected {
			require(t, reflect.DeepEqual(d[k], v), k, d[k], v)
		}
		c3bFields(t, d["counters"].(map[string]any), strings.Join(counters, " "))
		for i, k := range counters {
			require(t, d["counters"].(map[string]any)[k] == float64(10+i), "counter", k)
		}
		require(t, reflect.DeepEqual(d["rates"], map[string]any{"total_packets": 1.25, "total_bytes": float64(90), "dropped_bytes": float64(30), "passed_bytes": float64(60)}) && reflect.DeepEqual(d["agent_state"], map[string]any{"exact_rules": float64(7), "cidr_rules": float64(0), "whitelist_entries": float64(1)}), "cached metrics", d)
		caps := d["capacity"].([]any)
		require(t, len(caps) == 10, "capacity dimensions")
		for i, entry := range caps {
			m := entry.(map[string]any)
			c3bFields(t, m, "name limit node_used controller_used")
			want := []float64{2, 0, 0, 0, 1, 0, 0, 0, 0, 2}[i]
			require(t, m["controller_used"] == want, "controller comparison", m)
			if i == 0 {
				require(t, m["name"] == "blacklist" && m["limit"] == float64(9) && m["node_used"] == float64(7), "neutral comparison", m)
			} else {
				require(t, m["limit"] == nil && m["node_used"] == nil, "missing sample", m)
			}
		}
		for _, key := range []string{"rule_reconcile", "whitelist_reconcile"} {
			c3bFields(t, d[key].(map[string]any), "last_at result extra missing different")
		}
		require(t, reflect.DeepEqual(d["rule_reconcile"], map[string]any{"last_at": stamp(at), "result": "drift", "extra": float64(3), "missing": float64(4), "different": float64(5)}), "rule reconcile", d)
		require(t, reflect.DeepEqual(d["whitelist_reconcile"], map[string]any{"last_at": stamp(at), "result": "equal", "extra": float64(0), "missing": float64(0), "different": float64(0)}), "whitelist reconcile", d)
	})
	t.Run("API-batch-msg", func(t *testing.T) {
		e := New(nil, &stubNodes{}, testActor, nil)
		input := `{"items":[` + strings.Repeat("{},", 500) + "{}]}"
		var shape struct {
			Items []json.RawMessage `json:"items"`
		}
		require(t, json.Unmarshal([]byte(input), &shape) == nil && len(shape.Items) == 501, "501 witness")
		got := decoded[Error](t, request(t, e, "POST", "/api/v1/rules/batch", "machine:caller", input, 400))
		require(t, got.Code == "batch_too_large" && got.Field == "items" && got.Message == "items must contain 1..500 rules; split larger batches into sequential requests of at most 500 items", "batch rejection", got)
	})
	t.Run("CAP-delivery-overloaded", func(t *testing.T) {
		s, n := c3bService(t)
		rows, e := s.List()
		require(t, e == nil, e)
		var id string
		for _, r := range rows {
			if r.Enabled {
				id = r.ID
				break
			}
		}
		n.values[0].Overload = []rules.Overload{{Dim: "blacklist", Limit: 1, Used: 2}}
		eapi := New(s, n, testActor, nil)
		path := fmt.Sprintf("/api/v1/rules/%s/delivery?gen=0&epoch=%s", id, s.Epoch())
		for _, want := range []string{"overloaded", "offline", "incompatible"} {
			if want == "offline" {
				n.values[0].Online = false
			}
			if want == "incompatible" {
				n.values[0].Online = true
				n.values[0].Incompatible = true
			}
			got := decoded[DeliveryResponse](t, request(t, eapi, "GET", path, "machine:reader", "", 200))
			require(t, len(got.Nodes) == 1 && got.Nodes[0].State == want, "delivery precedence", got, want)
		}
	})
}
