//go:build linux && integration

package bpf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"net/netip"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/eval"
)

func matrixGroups(rules []api.Rule) []api.CommitGroup {
	by := map[string][]api.Rule{}
	for _, r := range rules {
		k := string(matrixKey(r))
		by[k] = append(by[k], r)
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var groups []api.CommitGroup
	for _, k := range keys {
		groups = append(groups, api.CommitGroup{Key: json.RawMessage(k), Rules: by[k]})
	}
	return groups
}
func matrixInstall(t *testing.T, h *api.Handlers, c *ebpf.Collection, rules []api.Rule, op string, target uint64) {
	t.Helper()
	_, before := cut53APISelectors(t, c)
	if before == target {
		if _, e := h.DoAtomicSync(nil); e != nil {
			t.Fatal(e)
		}
	}
	if op == "atomic" {
		r, e := h.DoAtomicSync(rules)
		if e != nil || r.Failed != 0 || r.Added != len(rules) {
			t.Fatalf("MATRIX_INSTALL op=%s added=%d failed=%d err=%v", op, r.Added, r.Failed, e)
		}
	} else {
		r, e := h.DoCommitRules(matrixGroups(rules))
		if e != nil || r.Code != "committed" {
			t.Fatalf("MATRIX_INSTALL op=%s result=%+v err=%v", op, r, e)
		}
	}
	_, after := cut53APISelectors(t, c)
	if after != target {
		t.Fatalf("MATRIX_SELECTOR op=%s want=%d got=%d", op, target, after)
	}
}
func matrixQuiet() func() {
	w := log.Writer()
	log.SetOutput(io.Discard)
	return func() { log.SetOutput(w) }
}
func matrixCounter(t *testing.T, c *ebpf.Collection, id uint32) api.LogicalRuleCounters {
	t.Helper()
	n, e := api.ReadLogicalRuleCounters(c.Maps["id_counts"], id)
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func matrixCheck(t *testing.T, c *ebpf.Collection, name string, p matrixProbe) bool {
	t.Helper()
	want := uint32(2)
	if p.Want.ActionCode == api.ActionDrop {
		want = 1
	}
	var before api.LogicalRuleCounters
	if p.Want.LogicalID != 0 {
		before = matrixCounter(t, c, p.Want.LogicalID)
	}
	got, _, e := c.Programs["xdp_firewall_main"].Test(p.Frame)
	if e != nil {
		t.Fatalf("MATRIX_FIXTURE TEST_RUN error=%v", e)
	}
	winner := true
	if p.Want.LogicalID != 0 {
		after := matrixCounter(t, c, p.Want.LogicalID)
		drop := uint64(0)
		if want == 1 {
			drop = 1
		}
		winner = after.Match-before.Match == 1 && after.Drop-before.Drop == drop
	}
	ok := got == want && winner
	if !ok {
		t.Errorf("MATRIX_CHECK cell=%s probe=%s-%s bpf=%d want=%d winner=%d winner_ok=%v pass=0", name, p.Class, p.Name, got, want, p.Want.LogicalID, winner)
	}
	return ok
}
func matrixSnapshots(t *testing.T, c *ebpf.Collection, rules []api.Rule) map[uint32]api.LogicalRuleCounters {
	out := map[uint32]api.LogicalRuleCounters{}
	for _, r := range rules {
		out[r.LogicalID] = matrixCounter(t, c, r.LogicalID)
	}
	return out
}
func matrixAllCounters(t *testing.T, c *ebpf.Collection, before, expected map[uint32]api.LogicalRuleCounters) {
	t.Helper()
	for id, b := range before {
		a := matrixCounter(t, c, id)
		want := expected[id]
		if a.Match-b.Match != want.Match || a.Drop-b.Drop != want.Drop {
			t.Errorf("MATRIX_ID logical_id=%d delta_match=%d delta_drop=%d want=%+v pass=0", id, a.Match-b.Match, a.Drop-b.Drop, want)
		}
	}
}
func matrixAccount(m map[uint32]api.LogicalRuleCounters, d eval.B1Decision) {
	if d.LogicalID == 0 {
		return
	}
	v := m[d.LogicalID]
	v.Match++
	if d.ActionCode == api.ActionDrop {
		v.Drop++
	}
	m[d.LogicalID] = v
}
func TestMatchMatrixELF(t *testing.T) {
	defer matrixQuiet()()
	cells, rules := matrixModel(t)
	assemblies, packets, mismatches := 0, 0, 0
	for _, op := range []string{"atomic", "commit"} {
		for target := uint64(0); target < 2; target++ {
			t.Run(fmt.Sprintf("%s/%d", op, target), func(t *testing.T) {
				h, c := cut53APIFixture(t)
				t.Log("MATRIX_FIXTURE loaded=1 receipt=kernel")
				matrixInstall(t, h, c, rules, op, target)
				before := matrixSnapshots(t, c, rules)
				expected := map[uint32]api.LogicalRuleCounters{}
				bad := map[string]int{}
				n := 0
				for _, cell := range cells {
					for _, p := range cell.Probes {
						if !matrixCheck(t, c, cell.Name, p) {
							mismatches++
							bad[cell.Kind+"/"+cell.Family]++
							bad["protocol/"+cell.Rule.Protocol]++
						}
						matrixAccount(expected, p.Want)
						n++
					}
				}
				matrixAllCounters(t, c, before, expected)
				for _, key := range []string{"cidr/v4", "cidr/v6", "exact/v4", "exact/v6", "protocol/tcp", "protocol/udp"} {
					t.Logf("MATRIX_CONTROL assembly=%s/%d group=%s mismatches=%d", op, target, key, bad[key])
				}
				if n != 4128 {
					t.Fatal("MATRIX_EXEC probe count")
				}
				assemblies++
				packets += n
				t.Logf("MATRIX_ASSEMBLY op=%s target=%d cells=624 packets=%d id_checks=624", op, target, n)
			})
		}
	}
	if assemblies != 4 || packets != 16512 {
		t.Fatal("MATRIX_EXEC assembly quota")
	}
	t.Logf("MATRIX_VERDICT assemblies=%d cells_per_assembly=624 packets=%d mismatches=%d", assemblies, packets, mismatches)
}
func matrixHTTP(t *testing.T, h *api.Handlers, entry string, rules []api.Rule) (int, map[string]any) {
	t.Helper()
	r := gin.New()
	r.POST("/atomic", h.AtomicSync)
	r.POST("/commit", h.CommitRules)
	var body any = map[string]any{"rules": rules}
	if entry == "commit" {
		body = map[string]any{"groups": matrixGroups(rules)}
	}
	raw, e := json.Marshal(body)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/"+entry, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	var decoded map[string]any
	if e = json.Unmarshal(w.Body.Bytes(), &decoded); e != nil {
		t.Fatal(e)
	}
	return w.Code, decoded
}
func matrixKBase(kind string, v6 bool, id uint32) (api.Rule, eval.B1Packet) {
	b := matrixBlock(2000+int(id)%500, v6)
	pfx := matrixPrefix(b, 24)
	if v6 {
		pfx = matrixPrefix(b, 56)
	}
	src := pfx.Addr().Next()
	dst := matrixBlock(3000+int(id)%500, v6).Addr().Next()
	p := matrixPacket(src, dst, 6)
	r := api.Rule{ID: fmt.Sprint("K-", id), LogicalID: id, Protocol: "tcp", Action: "drop", TTL: matrixText("64")}
	if kind == "cidr" {
		r.SrcCIDR = pfx.String()
	} else {
		r.SrcIP = src.String()
	}
	return r, p
}
func TestMatchMatrixConditionsELF(t *testing.T) {
	defer matrixQuiet()()
	tables := matrixTables(t)
	checks, rejections, accepted, assemblies := 0, 0, 0, 0
	for _, kind := range []string{"exact", "cidr"} {
		for _, v6 := range []bool{false, true} {
			for _, op := range []string{"atomic", "commit"} {
				for target := uint64(0); target < 2; target++ {
					t.Run(fmt.Sprintf("%s/v6=%v/%s/%d", kind, v6, op, target), func(t *testing.T) {
						h, c := cut53APIFixture(t)
						base, p := matrixKBase(kind, v6, 2001)
						clone := func(id uint32) api.Rule { r := base; r.ID = fmt.Sprint("K-", id); r.LogicalID = id; return r }
						run := func(name string, rules []api.Rule, probes []eval.B1Packet, winners []uint32) {
							t.Helper()
							if _, e := h.DoAtomicSync(nil); e != nil {
								t.Fatal(e)
							}
							matrixInstall(t, h, c, rules, op, target)
							rs := matrixRuleset(t, tables, rules)
							localBad := 0
							before := matrixSnapshots(t, c, rules)
							expected := map[uint32]api.LogicalRuleCounters{}
							for i, p := range probes {
								d, e := eval.EvaluateB1Cut54(tables, rs, p)
								if e != nil || d.LogicalID != winners[i] {
									t.Fatalf("MATRIX_K_MODEL %s predicted=%d want=%d err=%v", name, d.LogicalID, winners[i], e)
								}
								if !matrixCheck(t, c, name+"/"+kind+fmt.Sprint("/v6=", v6), matrixProbe{Name: fmt.Sprint(i), Class: "K", P: p, Frame: matrixFrame(p), Want: d}) {
									localBad++
								}
								matrixAccount(expected, d)
								checks++
							}
							matrixAllCounters(t, c, before, expected)
							t.Logf("MATRIX_K_CONTROL cell=%s kind=%s v6=%v probes=%d mismatches=%d", name, kind, v6, len(probes), localBad)
						}
						a, b := clone(2001), clone(2002)
						a.Action, a.RateLimit = "rate_limit", 1000000
						b.DSCP = matrixText("10")
						run("K1-strict", []api.Rule{a, b}, []eval.B1Packet{p}, []uint32{2002})
						b.DSCP = nil
						run("K1-tie", []api.Rule{b, a}, []eval.B1Packet{p}, []uint32{2001})
						candidates := []api.Rule{}
						probes := []eval.B1Packet{}
						winners := []uint32{}
						for k := 0; k < 4; k++ {
							r := clone(uint32(2010 + k))
							r.TTL = matrixText(fmt.Sprintf("%d,64", 60+k))
							if k%2 == 1 {
								r.Action, r.RateLimit = "rate_limit", 1000000
							}
							candidates = append(candidates, r)
							q := p
							q.TTL = byte(60 + k)
							probes = append(probes, q)
							winners = append(winners, r.LogicalID)
						}
						probes = append(probes, p)
						winners = append(winners, 2010)
						run("K2", candidates, probes, winners)
						narrow, broad := clone(2020), clone(2021)
						narrow.DstPort = p.Dport
						narrow.TTL = matrixText("63")
						broad.TTL = nil
						run("K3-fallback", []api.Rule{narrow, broad}, []eval.B1Packet{p}, []uint32{2021})
						run("K3-miss", []api.Rule{narrow}, []eval.B1Packet{p}, []uint32{0})
						for _, piece := range []bool{false, true} {
							rules := append([]api.Rule(nil), candidates...)
							name := "K4-four"
							if piece {
								name = "K4-pieces"
								rules = []api.Rule{clone(2030), clone(2031)}
								rules[0].PktLen = matrixText("96,100,104")
								rules[1].PktLen = matrixText("108,112,116")
							}
							run(name, rules, []eval.B1Packet{p}, []uint32{rules[0].LogicalID})
							accepted++
							extra := clone(2040)
							extra.TTL = matrixText("65")
							over := append(append([]api.Rule(nil), rules...), extra)
							for _, entry := range []string{"atomic", "commit"} {
								status, body := matrixHTTP(t, h, entry, over)
								code := "condition_capacity"
								if entry == "atomic" {
									code = "condition_group_invalid"
								}
								if status != 409 || body["code"] != code {
									t.Errorf("MATRIX_K_CAPACITY cell=%s entry=%s http=%d code=%v pass=0", name, entry, status, body["code"])
								}
								rejections++
								d, e := eval.EvaluateB1Cut54(tables, matrixRuleset(t, tables, rules), p)
								if e != nil {
									t.Fatal(e)
								}
								matrixCheck(t, c, name+"-preserved", matrixProbe{Class: "K", Frame: matrixFrame(p), Want: d})
							}
						}
						for _, action := range []string{"drop", "rate_limit"} {
							exact, cidr := clone(2050), clone(2051)
							exact.SrcIP = p.Src.String()
							exact.SrcCIDR = ""
							cidr.SrcIP = ""
							cidr.SrcCIDR = matrixPrefix(matrixBlock(2000+2001%500, v6), 24).String()
							if v6 {
								cidr.SrcCIDR = matrixPrefix(matrixBlock(2000+2001%500, v6), 56).String()
							}
							exact.Action = action
							if action == "rate_limit" {
								exact.RateLimit = 1000000
							}
							run("K5-"+action, []api.Rule{exact, cidr}, []eval.B1Packet{p}, []uint32{2050})
						}
						assemblies++
					})
				}
			}
		}
	}
	if checks != 208 || rejections != 64 || accepted != 32 || assemblies != 16 {
		t.Fatalf("MATRIX_K_EXEC checks=%d rejections=%d accepted=%d assemblies=%d", checks, rejections, accepted, assemblies)
	}
	t.Logf("MATRIX_K assemblies=%d checks=%d capacity_accepted=%d capacity_rejected=%d mismatches=%d", assemblies, checks, accepted, rejections, map[bool]int{false: 0, true: 1}[t.Failed()])
}

func TestMatchMatrixRejectELF(t *testing.T) {
	defer matrixQuiet()()
	h, c := cut53APIFixture(t)
	tables := matrixTables(t)
	baseline := api.Rule{ID: "R-baseline", LogicalID: 9000, SrcIP: "10.240.0.1", Protocol: "tcp", Action: "drop"}
	legal := api.Rule{ID: "R-legal", LogicalID: 9001, SrcIP: "10.241.0.1", Protocol: "tcp", Action: "drop"}
	rows := [][]api.Rule{
		{{ID: "R-icmp-port", LogicalID: 9101, SrcIP: "10.244.0.1", Protocol: "icmp", SrcPort: 12345, Action: "drop"}},
		{{ID: "R-udp-flags", LogicalID: 9102, SrcIP: "10.244.16.1", Protocol: "udp", TcpFlags: "SYN", Action: "drop"}},
		{{ID: "R-v6-fragment", LogicalID: 9103, SrcIP: "2001:db8:fa00::1", Protocol: "tcp", Fragment: matrixText("nofrag"), Action: "drop"}},
		{{ID: "R-mixed", LogicalID: 9104, SrcIP: "10.244.48.1", SrcCIDR: "10.244.48.0/24", Protocol: "tcp", Action: "drop"}},
		{{ID: "R-empty", LogicalID: 9105, Protocol: "all", Action: "drop"}},
		{{ID: "R-parent", LogicalID: 9106, SrcCIDR: "10.244.80.0/24", Protocol: "tcp", Action: "drop"}, {ID: "R-child", LogicalID: 9107, SrcCIDR: "10.244.80.0/26", Protocol: "tcp", Action: "drop"}},
	}
	batch, partial := 0, 0
	for i, row := range rows {
		for _, entry := range []string{"atomic", "commit"} {
			t.Run(fmt.Sprintf("R-%d/%s", i+1, entry), func(t *testing.T) {
				matrixInstall(t, h, c, []api.Rule{baseline}, "atomic", 0)
				bp := matrixPacket(netip.MustParseAddr(baseline.SrcIP), netip.MustParseAddr("10.242.0.1"), 6)
				bd, err := eval.EvaluateB1Cut54(tables, matrixRuleset(t, tables, []api.Rule{baseline}), bp)
				if err != nil || !matrixCheck(t, c, fmt.Sprintf("R-%d/before", i+1), matrixProbe{Class: "R", Frame: matrixFrame(bp), Want: bd}) {
					t.Fatalf("MATRIX_REJECT baseline witness err=%v", err)
				}
				t.Logf("MATRIX_REJECT_BASELINE R-%d %s packets=1 mismatches=0", i+1, entry)
				oldSlot, oldRule := cut53APISelectors(t, c)
				input := append(append([]api.Rule(nil), row...), legal)
				raw, _ := json.Marshal(input)
				keys := []json.RawMessage{}
				for _, rule := range input {
					keys = append(keys, matrixKey(rule))
				}
				keyJSON, _ := json.Marshal(keys)
				t.Logf("MATRIX_REJECT_INPUT R-%d %s rules=%s keys=%s", i+1, entry, raw, keyJSON)
				status, body := matrixHTTP(t, h, entry, input)
				shape := "batch"
				if status == 200 {
					shape = "per-rule"
				}
				code, _ := body["code"].(string)
				if code == "" {
					code = "none"
				}
				t.Logf("MATRIX_REJECT R-%d %s http=%d code=%s shape=%s", i+1, entry, status, code, shape)
				wantPartial := entry == "atomic" && (i == 0 || i == 3 || i == 4)
				expectedCode := "validation_rejected"
				expectedHTTP := 400
				if entry == "atomic" {
					expectedHTTP = 409
					expectedCode = "condition_group_invalid"
				}
				if i == 5 {
					expectedHTTP, expectedCode = 409, "cidr_overlap"
				}
				if wantPartial {
					expectedHTTP, expectedCode = 200, "none"
				}
				if (shape == "per-rule") != wantPartial {
					t.Fatalf("MATRIX_REJECT_SHAPE R-%d %s want_partial=%v actual=%s pass=0", i+1, entry, wantPartial, shape)
				}
				t.Logf("MATRIX_REJECT_CODE R-%d %s expected_http=%d expected_code=%s observed_http=%d observed_code=%s", i+1, entry, expectedHTTP, expectedCode, status, code)
				published := []api.Rule{baseline}
				if wantPartial {
					partial++
					published = []api.Rule{legal}
					rejectedJSON, _ := json.Marshal(body["rejected"])
					rejected, ok := body["rejected"].([]any)
					if !ok || len(rejected) != 1 || body["failed"] != float64(1) || body["added"] != float64(1) || body["success"] != true {
						t.Fatalf("MATRIX_REJECT R-%d invalid per-rule body=%v rejected=%s", i+1, body, rejectedJSON)
					}
					r, ok := rejected[0].(map[string]any)
					reason, reasonOK := r["reason"].(string)
					_, hasIndex := r["index"]
					if !ok || r["id"] != row[0].ID || !reasonOK || reason == "" || hasIndex {
						t.Fatalf("MATRIX_REJECT invalid original rejected identity/reason or unexpected index rejected=%s", rejectedJSON)
					}
				} else {
					batch++
					if status < 400 || code == "none" {
						t.Fatal("MATRIX_REJECT batch missing status/code")
					}
					a, b := cut53APISelectors(t, c)
					if a != oldSlot || b != oldRule {
						t.Fatal("MATRIX_REJECT batch published")
					}
				}
				// Check both the old baseline and accepted companion, plus exact live IDs.
				rs := matrixRuleset(t, tables, published)
				for _, r := range []api.Rule{baseline, legal} {
					p := matrixPacket(netip.MustParseAddr(r.SrcIP), netip.MustParseAddr("10.242.0.1"), 6)
					d, e := eval.EvaluateB1Cut54(tables, rs, p)
					if e != nil {
						t.Fatal(e)
					}
					matrixCheck(t, c, fmt.Sprintf("R-%d/%s", i+1, entry), matrixProbe{Class: "R", Frame: matrixFrame(p), Want: d})
				}
				router := gin.New()
				router.GET("/rules", h.ListRules)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest("GET", "/rules?limit=100", nil))
				var list struct {
					Rules []api.Rule `json:"rules"`
				}
				if e := json.Unmarshal(w.Body.Bytes(), &list); e != nil || w.Code != 200 || len(list.Rules) != 1 || list.Rules[0].ID != published[0].ID {
					t.Fatalf("MATRIX_REJECT published subset got=%s err=%v", w.Body.String(), e)
				}
			})
		}
	}
	if batch != 9 || partial != 3 {
		t.Fatal("MATRIX_REJECT quotas")
	}
	t.Logf("MATRIX_REJECT_VERDICT rows=6 entries=12 batch=%d per_rule=%d unchanged_or_subset=12 mismatches=%d", batch, partial, map[bool]int{false: 0, true: 1}[t.Failed()])
}
func TestMatchMatrixCharactersELF(t *testing.T) {
	defer matrixQuiet()()
	h, c := cut53APIFixture(t)
	tables := matrixTables(t)
	lines := 0
	v4 := netip.MustParseAddr("10.250.0.1")
	v6 := netip.MustParseAddr("2001:db8:fb00::1")
	mapped := netip.MustParseAddr("::ffff:10.250.0.1")
	r := api.Rule{ID: "X1", LogicalID: 9500, SrcIP: v4.String(), Protocol: "tcp", Action: "drop"}
	record := func(name string, r api.Rule, packets []eval.B1Packet) {
		t.Helper()
		if _, e := h.DoAtomicSync(nil); e != nil {
			t.Fatal(e)
		}
		result, e := h.DoAtomicSync([]api.Rule{r})
		accepted := e == nil && result.Added == 1 && result.Failed == 0
		rs := matrixRuleset(t, tables, []api.Rule{r})
		for i, p := range packets {
			got, _, err := c.Programs["xdp_firewall_main"].Test(matrixFrame(p))
			if err != nil {
				t.Fatal(err)
			}
			d, err := eval.EvaluateB1Cut54(tables, rs, p)
			oracle := "error"
			if err == nil {
				oracle = "PASS"
				if d.ActionCode == api.ActionDrop {
					oracle = "DROP"
				}
			}
			t.Logf("MATRIX_CHARACTER %s-%d bpf=%d oracle=%s accepted=%v", name, i, got, oracle, accepted)
			lines++
		}
	}
	record("X1", r, []eval.B1Packet{matrixPacket(mapped, v6, 6)})
	for _, kind := range []string{"exact", "cidr"} {
		r.ID = "X2-" + kind
		r.LogicalID++
		r.DstIP = v6.String()
		if kind == "cidr" {
			r.SrcIP, r.DstIP = "", ""
			r.SrcCIDR, r.DstCIDR = "10.250.0.0/24", "2001:db8:fb00::/64"
		}
		record("X2-"+kind, r, []eval.B1Packet{matrixPacket(v4, netip.MustParseAddr("10.251.0.1"), 6), matrixPacket(netip.MustParseAddr("2001:db8:fa00::1"), v6, 6), matrixPacket(mapped, v6, 6)})
	}
	if lines != 7 {
		t.Fatal("MATRIX_CHARACTER count")
	}
	t.Logf("MATRIX_CHARACTER_COUNT lines=%d comparisons=0", lines)
}
