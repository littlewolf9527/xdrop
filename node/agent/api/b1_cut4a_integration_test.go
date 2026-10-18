//go:build linux && integration

package api

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func cut4Input(cidr bool) Rule {
	r := Rule{ID: "r", LogicalID: 17, SrcIP: "192.0.2.1", Action: "drop", Protocol: "tcp"}
	if cidr {
		r.SrcIP = ""
		r.SrcCIDR = "192.0.2.0/24"
	}
	return r
}

func cut4Table(h *Handlers, cidr bool) (*ebpf.Map, []byte) {
	if cidr {
		return p7ActiveCIDR(h), cidrRuleKeyToBytes(h.cidrRules["r"].Key)
	}
	return p7ActiveBlacklist(h), ruleKeyToBytes(h.rules["r"].Key)
}
func cut4StoredID(h *Handlers, cidr bool) uint32 {
	if cidr {
		return h.cidrRules["r"].LogicalID
	}
	return h.rules["r"].LogicalID
}
func cut4SetStoredID(h *Handlers, cidr bool, id uint32) {
	if cidr {
		s := h.cidrRules["r"]
		s.LogicalID = id
		h.cidrRules["r"] = s
	} else {
		s := h.rules["r"]
		s.LogicalID = id
		h.rules["r"] = s
	}
}

func TestB1Cut4AListCounters(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		for _, paged := range []bool{false, true} {
			t.Run(fmt.Sprintf("cidr=%v/paged=%v", isCIDR, paged), func(t *testing.T) {
				h, router, _ := b7ELF(t)
				input := cut4Input(isCIDR)
				input.LogicalID = 17
				result, e := h.DoAtomicSync([]Rule{input})
				if e != nil || result.Added != 1 || cut4StoredID(h, isCIDR) != 17 {
					t.Fatalf("atomic metadata=%+v %v", result, e)
				}
				table, key := cut4Table(h, isCIDR)
				wire := b7Read(t, table, key)
				binary.LittleEndian.PutUint64(wire[8:16], 9001)
				binary.LittleEndian.PutUint64(wire[16:24], 7001)
				cpus, e := ebpf.PossibleCPU()
				if e != nil {
					t.Fatal(e)
				}
				slots := make([]LogicalRuleCounters, cpus)
				var match, drop uint64
				for i := range slots {
					slots[i] = LogicalRuleCounters{Match: uint64(i + 11), Drop: uint64(i + 3)}
					match += slots[i].Match
					drop += slots[i].Drop
				}
				if match == 9001 || drop == 7001 {
					t.Fatal("counter sources must differ")
				}
				if e := h.idCounts.Update(uint32(17), slots, ebpf.UpdateAny); e != nil {
					t.Fatal(e)
				}
				path := "/api/v1/rules"
				if paged {
					path += "?page=1&limit=1"
				}
				check := func(wantMatch, wantDrop uint64) {
					t.Helper()
					h.lastRuleDropCount["r"] = 0
					h.lastRuleStatsTime["r"] = time.Now().Add(-time.Second).UnixNano()
					w := jiaCall(t, router, "GET", path, "")
					var got struct{ Rules []Rule }
					if e := json.Unmarshal(w.Body.Bytes(), &got); e != nil || w.Code != 200 || len(got.Rules) != 1 {
						t.Fatalf("list=%d %s %v", w.Code, w.Body.String(), e)
					}
					r := got.Rules[0]
					if r.LogicalID != 17 || r.Stats == nil || r.Stats.MatchCount != wantMatch || r.Stats.DropCount != wantDrop {
						t.Fatalf("stats=%+v want=%d/%d id=%d", r.Stats, wantMatch, wantDrop, r.LogicalID)
					}
					if h.lastRuleDropCount["r"] != wantDrop {
						t.Fatal("PPS used other counter source")
					}
					if wantDrop > 0 && (r.Stats.DropPPS <= float64(wantDrop)*0.5 || r.Stats.DropPPS > float64(wantDrop)*1.1) {
						t.Fatalf("PPS=%v want near %d", r.Stats.DropPPS, wantDrop)
					}
					if wantDrop == 0 && r.Stats.DropPPS != 0 {
						t.Fatal("missing/error source PPS nonzero")
					}
				}
				wire[28] = RuleHasConditions
				if e := table.Update(key, wire, ebpf.UpdateExist); e != nil {
					t.Fatal(e)
				}
				check(match, drop)
				wire[28] = 0
				if e := table.Update(key, wire, ebpf.UpdateExist); e != nil {
					t.Fatal(e)
				}
				check(match, drop)
				wire[28] = RuleHasConditions
				if e := table.Update(key, wire, ebpf.UpdateExist); e != nil {
					t.Fatal(e)
				}
				if e := h.idCounts.Delete(uint32(17)); e != nil {
					t.Fatal(e)
				}
				check(0, 0)
				// A closed map is a genuine lookup error, distinct from an absent key.
				if e := h.idCounts.Close(); e != nil {
					t.Fatal(e)
				}
				check(0, 0)
				t.Logf("dispatch flag1=%d/%d flag0=logical missing=0/0 lookup_error=0/0 pps_source=selected", match, drop)
			})
		}
	}
}

func TestB1Cut4AStoredListRoundTrip(t *testing.T) {
	h, router := jiaHandler(t)
	for _, isCIDR := range []bool{false, true} {
		for _, field := range cut4Fields {
			for _, raw := range []string{"null", `""`, `"64"`} {
				r := cut4Input(isCIDR)
				r.LogicalID = 23
				json.Unmarshal([]byte(`{"`+field+`":`+raw+`}`), &r)
				// Deliberately bypass entry rejection to test the storage-to-list carriers.
				if isCIDR {
					h.rules = map[string]StoredRule{}
					h.cidrRules = map[string]StoredCIDRRule{"r": ruleToStoredCIDR(CIDRRuleKey{}, r.SrcCIDR, "", r)}
				} else {
					h.cidrRules = map[string]StoredCIDRRule{}
					h.rules = map[string]StoredRule{"r": ruleToStored(RuleKey{}, r)}
				}
				for _, path := range []string{"/api/v1/rules", "/api/v1/rules?page=1"} {
					w := jiaCall(t, router, "GET", path, "")
					var got struct{ Rules []Rule }
					json.Unmarshal(w.Body.Bytes(), &got)
					if w.Code != 200 || len(got.Rules) != 1 {
						t.Fatal(w.Body.String())
					}
					cut4AssertMetadata(t, got.Rules[0], field, raw, 23)
				}
			}
		}
	}
}

func TestB1Cut4ANodeRejection(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		for _, field := range cut4Fields {
			for _, op := range []string{"ATOMIC"} {
				t.Run(fmt.Sprintf("cidr=%v/%s/%s", isCIDR, field, op), func(t *testing.T) {
					h, router := jiaHandler(t)
					seed := cut4Input(isCIDR)
					seed.ID = "old"
					b7Code(t, cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, seed, seed)}), 200, "committed")
					bad := cut4Input(isCIDR)
					bad.LogicalID = 17
					json.Unmarshal([]byte(`{"`+field+`":""}`), &bad)
					if op == "PUT" {
						bad.ID = "old"
					}
					before := []map[string]string{b7Snapshot(t, p7ActiveBlacklist(h)), b7Snapshot(t, p7ActiveCIDR(h)), b7Snapshot(t, h.configA), b7Snapshot(t, h.configB), b7Snapshot(t, h.activeConfig)}
					good := cut4Input(isCIDR)
					good.LogicalID = 29
					// A rejected earlier item must not occupy the exact same tuple as good.
					if isCIDR {
						good.SrcCIDR = "198.51.100.0/24"
						bad.SrcCIDR = good.SrcCIDR
					} else {
						good.SrcIP = "198.51.100.1"
						bad.SrcIP = good.SrcIP
					}
					good.ID = "good"
					bad.ID = "bad"
					if op == "PUT" {
						bad.ID = "old"
					}
					b, _ := json.Marshal(bad)
					path, method := "/api/v1/rules", op
					if op == "PUT" {
						path += "/old"
					}
					if op == "BATCH" || op == "ATOMIC" {
						method = "POST"
						g, _ := json.Marshal(good)
						b = []byte(`{"rules":[` + string(b) + `,` + string(g) + `]}`)
						path += "/batch"
						if op == "ATOMIC" {
							path = "/api/v1/sync/atomic"
						}
					}
					w := jiaCall(t, router, method, path, string(b))
					want := "condition_group_required"
					if op == "ATOMIC" {
						want = "condition_group_invalid"
					}
					b7Code(t, w, 409, want)
					after := []map[string]string{b7Snapshot(t, p7ActiveBlacklist(h)), b7Snapshot(t, p7ActiveCIDR(h)), b7Snapshot(t, h.configA), b7Snapshot(t, h.configB), b7Snapshot(t, h.activeConfig)}
					if !reflect.DeepEqual(before, after) || len(h.rules)+len(h.cidrRules) != 1 {
						t.Fatal("condition rejection wrote state")
					}
					if op == "ATOMIC" {
						var got struct {
							Conflicts     []atomicConditionConflict
							Added, Failed int
						}
						if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
							t.Fatal(err)
						}
						if got.Added != 0 || got.Failed != 1 || len(got.Conflicts) != 2 || got.Conflicts[0].ID != "bad" || got.Conflicts[1].ID != "good" {
							t.Fatalf("I6 complete group conflicts: %s", w.Body.String())
						}
						if _, err := h.prepareAtomicRule(bad); err == nil || got.Conflicts[0].Reason != err.Error() {
							t.Fatalf("I6 validation reason source: %s", w.Body.String())
						}
					}

				})
			}
		}
	}
}
