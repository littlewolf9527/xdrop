package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

// Like dingWritableGolden, this is a finite register. Historical p3-p5 fixtures
// remain readable but cannot be overwritten by cut53P3Golden.
var cut56WritableGolden = map[string]bool{
	"atomic_address_family_p9": true,
	"commit_address_family_p9": true,
	"anomaly_full_p8":          true,
	"anomaly_commit_p8":        true,
	"anomaly_rejected_p8":      true,
}

const cut56BoundedError = "anomaly rule requires a bounded target (src/dst IP must not be empty/wildcard, CIDR must not be /0)"
const cut56IPv6Error = "bad_fragment not supported for IPv6 target"
const cut56ZeroRateError = "rate_limit must be > 0 for rate_limit action"

func cut56Rule(isCIDR bool) Rule {
	r := cut53Pure(isCIDR, "j8", 5617)
	r.Action, r.RateLimit, r.MatchAnomaly = "rate_limit", 7, 4
	return r
}
func cut56Body(t *testing.T, w *httptest.ResponseRecorder, status int, code string) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != status || (code != "" && body["code"] != code) {
		t.Fatalf("CUT56_ENTRY status=%d code=%v want=%d/%s body=%s", w.Code, body["code"], status, code, w.Body.String())
	}
	return body
}
func cut56Row(t *testing.T, row ConditionValue, r Rule) {
	t.Helper()
	if row.Active != 1 {
		t.Fatalf("CUT56_ROW active=%d want=1", row.Active)
	}
	if row.Action[0] != ActionRateLimit {
		t.Fatalf("CUT56_ROW action=%d want=2", row.Action[0])
	}
	if row.Rate[0] != r.RateLimit {
		t.Fatalf("CUT56_ROW rate=%d want=%d", row.Rate[0], r.RateLimit)
	}
	if row.RuleID[0] != r.LogicalID {
		t.Fatalf("CUT56_ROW logical_id=%d want=%d", row.RuleID[0], r.LogicalID)
	}
	for k := 1; k < 4; k++ {
		if row.Action[k] != 0 || row.Rate[k] != 0 || row.RuleID[k] != 0 {
			t.Fatalf("CUT56_ROW unused candidate=%d not zero", k)
		}
	}
}

func TestCut56AcceptancePreflight(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprint(isCIDR), func(t *testing.T) {
			r := cut56Rule(isCIDR)
			t.Run("full", func(t *testing.T) {
				h := cut53MemoryHandler(t)
				before := cut53State(h)
				groups, err := h.preflightAtomicConditions([]Rule{r})
				if err != nil {
					t.Fatalf("CUT56_FULL_ACCEPT anomaly rate_limit rejected: %v", err)
				}
				g := groups[0]
				if g == nil || !g.Condition || len(g.Members) != 1 {
					t.Fatal("CUT56_FULL_ACCEPT missing condition group/member")
				}
				cut56Row(t, g.Row, r)
				if g.Members[0].Value.Pad2[0] != RuleHasConditions {
					t.Fatal("CUT56_ROW full rule flag must be 1")
				}
				if before != cut53State(h) {
					t.Fatal("CUT56_FULL_ACCEPT preflight mutated state")
				}
				t.Logf("CUT56_FULL_PREFLIGHT cidr=%v accepted=1 fields=4 flag=1 unchanged=1", isCIDR)
			})
			t.Run("commit", func(t *testing.T) {
				f := cut55Memory(t)
				w := cut55HTTP(t, f.h, []CommitGroup{cut55Group(t, f.h, r, r)})
				if w.Code != 200 {
					t.Fatalf("CUT56_COMMIT_ACCEPT anomaly rate_limit rejected: %d %s", w.Code, w.Body.String())
				}
				cut56Body(t, w, 200, "committed")
				cut53P3Golden(t, "anomaly_commit_p8", fmt.Sprintf("cidr=%v", isCIDR), w)
				kind := mirrorExact
				condition := mirrorCondition
				if isCIDR {
					kind = mirrorCIDR
					condition = mirrorCIDRCondition
				}
				for side := 0; side < 2; side++ {
					rows := f.tables[side][condition].rows
					if len(rows) != 1 || len(f.tables[side][kind].rows) != 1 {
						t.Fatal("CUT56_ROW commit must install exactly one rule and condition row per side")
					}
					for key, raw := range rows {
						var row ConditionValue
						if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &row); err != nil {
							t.Fatal(err)
						}
						cut56Row(t, row, r)
						if raw := f.tables[side][kind].rows[key]; len(raw) != 32 || raw[28] != RuleHasConditions {
							t.Fatal("CUT56_ROW commit rule flag must be 1")
						}
					}
					var count uint64
					if err := f.configs[side].Lookup(uint32(ConfigAnomalyRuleCount), &count); err != nil || count != 0 {
						t.Fatalf("CUT56_K16 count=%d err=%v", count, err)
					}
				}
				t.Logf("CUT56_COMMIT_MEMORY cidr=%v accepted=1 sides=2 fields=4 flag=1 k16=0", isCIDR)
			})
		})
	}
}

func TestCut56ProtocolContract(t *testing.T) {
	if SyncProtocol != 11 {
		t.Fatalf("CUT56_PROTOCOL protocol=%d want=11", SyncProtocol)
	}
	w := httptest.NewRecorder()
	router := cut53MemoryRouter(cut53MemoryHandler(t))
	router.GET("/", (&Handlers{}).Welcome)
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	body := cut56Body(t, w, 200, "")
	if body["sync_protocol"] != float64(11) || body["version"] != Version || body["name"] != "XDrop Agent" || len(body) != 3 {
		t.Fatalf("CUT56_PROTOCOL body=%v", body)
	}
	t.Logf("CUT56_PROTOCOL value=%d fields=3", SyncProtocol)
}

func TestCut56ANDTruthTable(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		for _, entry := range []string{"full", "commit"} {
			r := cut56Rule(isCIDR)
			r.Action, r.RateLimit, r.TcpFlags = "drop", 0, "SYN"
			f := cut55Memory(t)
			var row ConditionValue
			if entry == "full" {
				groups, err := f.h.preflightAtomicConditions([]Rule{r})
				if err != nil {
					t.Fatal(err)
				}
				row = groups[0].Row
			} else {
				plan, err := f.h.preflightCommit([]CommitGroup{cut55Group(t, f.h, r, r)})
				if err != nil {
					t.Fatal(err)
				}
				if err := binary.Read(bytes.NewReader(plan.Groups[0].Condition), binary.LittleEndian, &row); err != nil {
					t.Fatal(err)
				}
			}
			for _, flags := range []bool{true, false} {
				for _, anomaly := range []bool{true, false} {
					fv, av := uint8(2), uint8(0)
					if !flags {
						fv = 16
					}
					if anomaly {
						av = 4
					}
					flagsBits := (row.Tab[2][fv/2] >> ((fv & 1) * 4)) & 15
					anomalyBits := (row.Tab[5][av/2] >> ((av & 1) * 4)) & 15
					hit := row.Active&flagsBits&anomalyBits != 0
					if hit != (flags && anomaly) {
						t.Fatalf("CUT56_AND flags=%v anomaly=%v hit=%v want=%v", flags, anomaly, hit, flags && anomaly)
					}
					if row.TCPReq != 1 {
						t.Fatal("CUT56_AND tcp_flags must require valid TCP")
					}
					t.Logf("CUT56_AND_ROW cidr=%v entry=%s flags=%v anomaly=%v hit=%v", isCIDR, entry, flags, anomaly, hit)
				}
			}
		}
	}
}

func TestCut56EntryRejections(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		for _, invalid := range []string{"unbounded", "ipv6", "zero_rate"} {
			for _, entry := range []string{"full", "commit"} {
				t.Run(fmt.Sprintf("cidr=%v/%s/%s", isCIDR, invalid, entry), func(t *testing.T) {
					r := cut56Rule(isCIDR)
					reason := cut56BoundedError
					switch invalid {
					case "unbounded":
						r.SrcIP = ""
						if isCIDR {
							r.SrcCIDR = "0.0.0.0/0"
						}
					case "ipv6":
						r.MatchAnomaly = 1
						reason = cut56IPv6Error
						if isCIDR {
							r.SrcCIDR = "2001:db8::/64"
						} else {
							r.SrcIP = "2001:db8::1"
						}
					case "zero_rate":
						r.RateLimit = 0
						reason = cut56ZeroRateError
					}
					f := cut55Memory(t)
					before := cut53State(f.h)
					maps := cut55Snapshot(f, 0) + cut55Snapshot(f, 1)
					var w *httptest.ResponseRecorder
					var body map[string]any
					if entry == "full" {
						w = cut53Request(t, cut53MemoryRouter(f.h), "POST", "/atomic", map[string]any{"rules": []Rule{r}})
						body = cut56Body(t, w, 409, "condition_group_invalid")
						conflicts := body["conflicts"].([]any)
						if len(conflicts) != 1 || conflicts[0].(map[string]any)["reason"] != reason {
							t.Fatalf("CUT56_REJECT full exact reason=%v want=%s", conflicts, reason)
						}
					} else {
						w = cut55HTTP(t, f.h, []CommitGroup{cut55Group(t, f.h, r, r)})
						body = cut56Body(t, w, 400, "validation_rejected")
						groups := body["groups"].([]any)
						if body["error"] != reason || len(groups) != 1 || groups[0].(map[string]any)["error"] != reason {
							t.Fatalf("CUT56_REJECT commit exact reason=%v want=%s", body, reason)
						}
					}
					if before != cut53State(f.h) || maps != cut55Snapshot(f, 0)+cut55Snapshot(f, 1) || f.receipts != 0 {
						t.Fatal("CUT56_REJECT changed state/maps/receipts")
					}
					if invalid != "zero_rate" {
						cut53P3Golden(t, "anomaly_rejected_p8", fmt.Sprintf("cidr=%v/%s/%s", isCIDR, invalid, entry), w)
					}
					t.Logf("CUT56_REJECT cidr=%v input=%s entry=%s status=%d exact_reason=1 unchanged=1", isCIDR, invalid, entry, w.Code)
				})
			}
		}
	}
}
