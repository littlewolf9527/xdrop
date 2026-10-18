//go:build linux && integration

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
)

func flipFixture(t *testing.T) (*Handlers, *gin.Engine, *ebpf.Program, *ebpf.Collection) {
	t.Helper()
	h, r, p, c := prefixABCollection(t, nil)
	old := h.quiescer
	cut55KernelReceipt(t, h)
	if h.quiescer == nil || h.quiescer == old {
		t.Fatal("FLIP_FIXTURE kernel receipt not replaced")
	}
	r.POST("/api/v1/rules/commit", h.CommitRules)
	t.Log("FLIP_FIXTURE loaded=1 receipt_replaced=1 receipt=kernel auth=omitted")
	return h, r, p, c
}
func flipSelector(t *testing.T, c *ebpf.Collection) uint64 {
	t.Helper()
	var config, rule uint64
	if e := c.Maps["active_config"].Lookup(uint32(0), &config); e != nil || config > 1 {
		t.Fatalf("FLIP_FIXTURE config=%d err=%v", config, e)
	}
	if e := c.Maps[[]string{"config_a", "config_b"}[config]].Lookup(uint32(ConfigRuleMapSelector), &rule); e != nil || rule > 1 {
		t.Fatalf("FLIP_FIXTURE rule=%d err=%v", rule, e)
	}
	return rule
}
func flipTries(c *ebpf.Collection, slot uint64) []*ebpf.Map {
	names := []string{"sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie"}
	var maps []*ebpf.Map
	for _, name := range names {
		if slot == 1 {
			name += "_b"
		}
		maps = append(maps, c.Maps[name])
	}
	return maps
}
func flipKeys(t *testing.T, m *ebpf.Map) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	var prev any
	for {
		key := make([]byte, m.KeySize())
		e := m.NextKey(prev, &key)
		if errors.Is(e, ebpf.ErrKeyNotExist) {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if keys[string(key)] {
			t.Fatal("FLIP_FIXTURE repeated NextKey")
		}
		keys[string(key)] = true
		prev = key
	}
	return keys
}
func flipQuiet() func() {
	w := log.Writer()
	log.SetOutput(io.Discard)
	return func() { log.SetOutput(w) }
}
func flipAtomic(t *testing.T, h *Handlers, rules []Rule) {
	t.Helper()
	r, e := h.DoAtomicSync(rules)
	if e != nil || r.Failed != 0 || r.Added != len(rules) {
		t.Fatalf("FLIP_FIXTURE atomic added=%d failed=%d err=%v", r.Added, r.Failed, e)
	}
}
func flipCommit(t *testing.T, h *Handlers, groups []CommitGroup) {
	t.Helper()
	r, e := h.DoCommitRules(groups)
	if e != nil || r.Code != "committed" {
		t.Fatalf("FLIP_FIXTURE commit=%+v err=%v", r, e)
	}
}

// Every generated address stays in the PLAN's fixed pools. j+N selects the
// unused half for T3; N<=50000 and each direction's /26 pool has131072 keys.
func flipScaleRules(n int, variant string, newSet bool) []Rule {
	exact := 0
	if variant == "E" {
		exact = 100000
	} else if variant == "F" {
		exact = 400000
	}
	rules := make([]Rule, 0, 2*n+exact)
	for family := 0; family < 2; family++ {
		for i := 0; i < n; i++ {
			j := i
			if newSet && i < n/2 {
				j += n
			}
			src, dst := "", ""
			if family == 0 {
				v := uint32(j * 64)
				src = fmt.Sprintf("10.%d.%d.%d/26", v>>16, (v>>8)&255, v&255)
				dst = fmt.Sprintf("10.%d.%d.%d/26", 128+(v>>16), (v>>8)&255, v&255)
			} else {
				src = fmt.Sprintf("2001:db8:%x:%x::/56", j>>8, (j&255)<<8)
				dst = fmt.Sprintf("2001:db8:%x:%x::/56", 0x8000+(j>>8), (j&255)<<8)
			}
			id := uint32(family*n + i + 1)
			rules = append(rules, Rule{ID: fmt.Sprint("scale-", id), LogicalID: id, SrcCIDR: src, DstCIDR: dst, Protocol: "tcp", Action: "drop"})
		}
	}
	for i := 0; i < exact; i++ {
		v := uint32(i + 1)
		rules = append(rules, Rule{ID: fmt.Sprint("exact-", i), LogicalID: uint32(2*n + i + 1), SrcIP: fmt.Sprintf("10.%d.%d.%d", v>>16, (v>>8)&255, v&255), Protocol: "tcp", Action: "drop"})
	}
	return rules
}

type flipScaleReading struct {
	N, Rep                        int
	Variant, Op                   string
	HTTP, ToFlip, FromFlip, Stats float64
}

func TestFlipScaleELF(t *testing.T) {
	defer flipQuiet()()
	h, r, _, c := flipFixture(t)
	t.Cleanup(func() { atomicStageTestHook = nil; h.commitStageTestHook = nil })
	server := httptest.NewServer(r)
	defer server.Close()
	client := server.Client()
	client.Timeout = 120 * time.Minute
	all := []flipScaleReading{}
	samples, valid := 0, 0
	max50000 := 0.0
	for _, cfg := range []struct {
		n int
		v string
	}{{1000, "base"}, {10000, "base"}, {50000, "base"}, {50000, "E"}, {50000, "F"}} {
		for rep := 1; rep <= 3; rep++ {
			full, next := flipScaleRules(cfg.n, cfg.v, false), flipScaleRules(cfg.n, cfg.v, true)
			reset, err := client.Post(server.URL+"/api/v1/sync/atomic", "application/json", bytes.NewBufferString(`{"rules":[]}`))
			if err != nil {
				t.Fatal(err)
			}
			var resetResult map[string]any
			err = json.NewDecoder(reset.Body).Decode(&resetResult)
			reset.Body.Close()
			if err != nil || reset.StatusCode != 200 || resetResult["failed"] != float64(0) || resetResult["added"] != float64(0) {
				t.Fatalf("FLIPSCALE_RESET invalid http=%d result=%v err=%v", reset.StatusCode, resetResult, err)
			}
			for _, m := range flipTries(c, flipSelector(t, c)) {
				if len(flipKeys(t, m)) != 0 {
					t.Fatal("FLIPSCALE_RESET nonempty trie")
				}
			}
			t.Logf("FLIPSCALE_RESET n=%d variant=%s rep=%d empty=1 http=200", cfg.n, cfg.v, rep)
			for op := 1; op <= 5; op++ {
				var body any
				path := "/api/v1/sync/atomic"
				wantRules := full
				required := []string{"1", "3a", "flip", "5b", "6"}
				flipStage := "flip"
				if op == 3 {
					wantRules = next
				}
				if op <= 3 {
					body = map[string]any{"rules": wantRules}
				} else {
					path = "/api/v1/rules/commit"
					wantRules = next
					v := next[0]
					if op == 4 {
						v.Action, v.RateLimit = "rate_limit", 1000000
					}
					body = map[string]any{"groups": []CommitGroup{cut55Group(t, h, v, v)}}
					required = []string{"c-3", "c-6", "c-7", "c-Rc", "c-9"}
					flipStage = "c-7"
				}
				beforeSel := flipSelector(t, c)
				var before [4]map[string]bool
				if op == 3 {
					for i, m := range flipTries(c, beforeSel) {
						before[i] = flipKeys(t, m)
					}
				}
				var mu sync.Mutex
				stages := map[string]time.Time{}
				order := []string{}
				statsStart := make(chan struct{})
				statsDone := make(chan struct{})
				var signal sync.Once
				var statsMS float64
				var statsErr error
				hook := func(stage string) {
					mu.Lock()
					stages[stage] = time.Now()
					order = append(order, stage)
					mu.Unlock()
					signal.Do(func() { close(statsStart) })
				}
				atomicStageTestHook = func(stage string, _ *Handlers) { hook(stage) }
				h.commitStageTestHook = hook
				go func() {
					defer close(statsDone)
					<-statsStart
					start := time.Now()
					response, err := client.Get(server.URL + "/api/v1/stats")
					if err == nil {
						_, err = io.Copy(io.Discard, response.Body)
						response.Body.Close()
						if response.StatusCode != 200 {
							err = fmt.Errorf("stats HTTP %d", response.StatusCode)
						}
					}
					statsMS = float64(time.Since(start)) / float64(time.Millisecond)
					statsErr = err
				}()
				start := time.Now()
				raw, e := json.Marshal(body)
				if e != nil {
					t.Fatal(e)
				}
				response, err := client.Post(server.URL+path, "application/json", bytes.NewReader(raw))
				var result map[string]any
				status := 0
				if err == nil {
					status = response.StatusCode
					err = json.NewDecoder(response.Body).Decode(&result)
					response.Body.Close()
				}
				end := time.Now()
				signal.Do(func() { close(statsStart) })
				<-statsDone
				atomicStageTestHook = nil
				h.commitStageTestHook = nil
				ok := err == nil && statsErr == nil && status == http.StatusOK && flipSelector(t, c) != beforeSel
				if op <= 3 {
					ok = ok && result["success"] == true && result["failed"] == float64(0) && result["added"] == float64(len(wantRules))
				} else {
					changed := false
					if groups, yes := result["groups"].([]any); yes {
						for _, v := range groups {
							if g, yes := v.(map[string]any); yes && g["result"] == "replaced" {
								changed = true
							}
						}
					}
					ok = ok && result["code"] == "committed" && changed
				}
				mu.Lock()
				for _, stage := range required {
					if stages[stage].IsZero() {
						ok = false
					}
				}
				toFlip, fromFlip := 0.0, 0.0
				if stamp := stages[flipStage]; !stamp.IsZero() {
					toFlip = float64(stamp.Sub(start)) / float64(time.Millisecond)
					fromFlip = float64(end.Sub(stamp)) / float64(time.Millisecond)
				}
				for _, stage := range order {
					t.Logf("FLIPSCALE_STAGE n=%d variant=%s op=T%d rep=%d stage=%s unix_ns=%d offset_ns=%d", cfg.n, cfg.v, op, rep, stage, stages[stage].UnixNano(), stages[stage].Sub(start).Nanoseconds())
				}
				if op >= 4 {
					t.Logf("FLIPSCALE_PRECHECK n=%d variant=%s op=T%d rep=%d request_to_c3_ms=%.3f label=precheck_possible_R0_rule_trie_catchup", cfg.n, cfg.v, op, rep, float64(stages["c-3"].Sub(start))/float64(time.Millisecond))
				}
				mu.Unlock()
				slot := flipSelector(t, c)
				changedPrefixes := 0
				for i, m := range flipTries(c, slot) {
					keys := flipKeys(t, m)
					countOK := len(keys) == cfg.n
					ok = ok && countOK
					if op == 3 {
						for k := range keys {
							if !before[i][k] {
								changedPrefixes++
							}
						}
					}
					t.Logf("FLIPSCALE_TRIE n=%d variant=%s op=T%d rep=%d side=%d count=%d expected=%d pass=%d", cfg.n, cfg.v, op, rep, i, len(keys), cfg.n, flipBool(countOK))
				}
				cidrCount := len(flipKeys(t, c.Maps[[]string{"cidr_blacklist", "cidr_blist_b"}[slot]]))
				exactCount := len(flipKeys(t, c.Maps[[]string{"blacklist", "blacklist_b"}[slot]]))
				exactWant := 0
				if cfg.v == "E" {
					exactWant = 100000
				} else if cfg.v == "F" {
					exactWant = 400000
				}
				ok = ok && cidrCount == 2*cfg.n && exactCount == exactWant
				if op == 3 {
					ok = ok && changedPrefixes == 2*cfg.n
				}
				httpMS := float64(end.Sub(start)) / float64(time.Millisecond)
				if cfg.n == 50000 && cfg.v == "base" {
					max50000 = max(max50000, httpMS)
				}
				samples++
				if ok {
					valid++
				}
				all = append(all, flipScaleReading{cfg.n, rep, cfg.v, fmt.Sprint("T", op), httpMS, toFlip, fromFlip, statsMS})
				t.Logf("FLIPSCALE_ROWS n=%d variant=%s op=T%d rep=%d cidr=%d exact=%d T3_changed_prefixes=%d", cfg.n, cfg.v, op, rep, cidrCount, exactCount, changedPrefixes)
				t.Logf("FLIPSCALE_SAMPLE n=%d variant=%s op=T%d rep=%d http_ms=%.3f req_to_flip_ms=%.3f flip_to_reply_ms=%.3f stats_blocked_ms=%.3f ok=%d", cfg.n, cfg.v, op, rep, httpMS, toFlip, fromFlip, statsMS, flipBool(ok))
				if !ok {
					t.Fatalf("FLIPSCALE_VALIDITY n=%d op=T%d rep=%d http=%d err=%v stats=%v result=%v pass=0", cfg.n, op, rep, status, err, statsErr, result)
				}
			}
		}
	}
	for _, cfg := range []struct {
		n int
		v string
	}{{1000, "base"}, {10000, "base"}, {50000, "base"}, {50000, "E"}, {50000, "F"}} {
		for op := 1; op <= 5; op++ {
			var values []float64
			for _, s := range all {
				if s.N == cfg.n && s.Variant == cfg.v && s.Op == fmt.Sprint("T", op) {
					values = append(values, s.HTTP)
				}
			}
			if len(values) != 3 {
				t.Fatal("FLIPSCALE_EXEC missing sample")
			}
			for _, part := range []string{"request_to_flip", "flip_to_reply", "stats_roundtrip"} {
				var times []float64
				for _, sample := range all {
					if sample.N == cfg.n && sample.Variant == cfg.v && sample.Op == fmt.Sprint("T", op) {
						value := sample.ToFlip
						if part == "flip_to_reply" {
							value = sample.FromFlip
						}
						if part == "stats_roundtrip" {
							value = sample.Stats
						}
						times = append(times, value)
					}
				}
				sort.Float64s(times)
				t.Logf("FLIPSCALE_SEGMENT_SUMMARY n=%d variant=%s op=T%d segment=%s samples=3 p50_ms=%.3f max_ms=%.3f", cfg.n, cfg.v, op, part, times[1], times[2])
			}
			sort.Float64s(values)
			t.Logf("FLIPSCALE_SUMMARY n=%d variant=%s op=T%d samples=3 p50_ms=%.3f max_ms=%.3f", cfg.n, cfg.v, op, values[1], values[2])
			t.Logf("FLIPSCALE_VARIANT_MAX variant=%s n=%d op=T%d max_ms=%.3f", cfg.v, cfg.n, op, values[2])
			if cfg.n == 50000 && ((cfg.v == "base" && op == 2) || (cfg.v == "F" && op <= 2)) {
				limit := 5000.0
				if op == 1 {
					limit = 10000
				}
				t.Logf("FLIPSCALE_TARGET variant=%s n=50000 op=T%d max_ms=%.3f limit_ms=%.0f met=%d", cfg.v, op, values[2], limit, flipBool(values[2] <= limit))
			}
		}
	}
	t.Logf("FLIPSCALE_VALID samples=%d valid=%d expected=75", samples, valid)
	t.Logf("FLIPSCALE_VERDICT max_ms_at_50000=%.3f limit_ms=10000 pass=%d", max50000, flipBool(max50000 < 10000))
	if samples != 75 || valid != 75 {
		t.Error("FLIPSCALE_REDLINE pass=0")
	}
}
func flipBool(v bool) int {
	if v {
		return 1
	}
	return 0
}
