package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This source reader is deliberately independent of the Python translator and
// oracle. It reads only the five frozen source files, then uses production
// normalization and readback constructors. The ONLY excluded object field is
// stats. Unknown fields are errors, never silently dropped.
type p7Intent struct {
	Want           map[string]Rule
	Absent         []string
	WhitelistEmpty bool
	Whole          bool
	Exemptions     []string
}
type p7SourceStep struct {
	Name, Method, Path, Fault            string
	Body                                 json.RawMessage
	Expect, ExpectP3, ExpectP4, ExpectP6 string
}
type p7SourceScene struct {
	Name  string
	Steps []p7SourceStep
}

func p7SourceRules(t *testing.T, step p7SourceStep) ([]json.RawMessage, []json.RawMessage) {
	t.Helper()
	var body struct {
		Rules  []json.RawMessage
		Groups []struct {
			Key   json.RawMessage
			Rules []json.RawMessage
		}
	}
	switch {
	case step.Method == "DELETE":
		return nil, nil
	case step.Path == "/api/v1/rules/commit":
		if err := json.Unmarshal(step.Body, &body); err != nil {
			t.Fatal(err)
		}
		var rules, empty []json.RawMessage
		for _, g := range body.Groups {
			rules = append(rules, g.Rules...)
			if len(g.Rules) == 0 {
				empty = append(empty, g.Key)
			}
		}
		return rules, empty
	case step.Method == "RESTART" || step.Path == "/api/v1/sync/atomic" || strings.HasSuffix(step.Path, "/batch"):
		if err := json.Unmarshal(step.Body, &body); err != nil {
			t.Fatal(err)
		}
		return body.Rules, nil
	default:
		return []json.RawMessage{step.Body}, nil
	}
}

func p7NormalizeSource(t *testing.T, raw json.RawMessage) Rule {
	t.Helper()
	var r Rule
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		t.Fatalf("frozen rule contains unsupported fields: %v", err)
	}
	if r.ID == "" || r.Comment != "" {
		t.Fatal("future source boundary: automatic id/comment needs explicit policy")
	}
	h := &Handlers{}
	p, err := h.prepareAtomicRule(r)
	if err != nil {
		t.Fatalf("source requires a new explicit exemption: %v", err)
	}
	if p.IsCIDR {
		return h.storedCIDRRuleToRule(r.ID, ruleToStoredCIDR(p.CIDR, p.Rule.SrcCIDR, p.Rule.DstCIDR, p.Rule))
	}
	return h.storedRuleToRule(r.ID, ruleToStored(p.Exact, p.Rule))
}

func TestAPIFinalIntentSources(t *testing.T) {
	files := []string{"scenarios.json", "scenarios_p3.json", "scenarios_p4.json", "scenarios_commit_p5.json", "scenarios_p6.json"}
	intents := map[string]p7Intent{}
	skipped, exemptions := 0, 0
	remap := strings.NewReplacer("192.0.2.", "10.10.2.", "198.51.100.", "10.20.100.", "203.0.113.", "10.30.113.", "2001:db8:", "fd00:db8:")
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join("..", "sync", "cut5a_replay", file))
		if err != nil {
			t.Fatal(err)
		}
		var scenes []p7SourceScene
		if err = json.Unmarshal([]byte(remap.Replace(string(data))), &scenes); err != nil {
			t.Fatal(err)
		}
		for _, scene := range scenes {
			// Facts from earlier successful FROZEN source steps, never predicted output.
			prior := map[string]Rule{}
			for _, step := range scene.Steps {
				cell := strings.TrimSuffix(file, ".json") + "/" + scene.Name + "/" + step.Name
				tag := step.Expect
				switch file {
				case "scenarios_p3.json":
					if step.ExpectP3 != "" {
						tag = step.ExpectP3
					}
				case "scenarios_p4.json", "scenarios_commit_p5.json":
					if step.ExpectP3 != "" {
						tag = step.ExpectP3
					}
					if step.ExpectP4 != "" {
						tag = step.ExpectP4
					}
				case "scenarios_p6.json":
					if step.ExpectP6 != "" {
						tag = step.ExpectP6
					}
				}
				selected := step.Method == "RESTART"
				switch tag {
				case "success", "updated", "committed", "deferred", "unchanged", "partial_rejection":
					selected = true
				}
				if !selected || (step.Method != "POST" && step.Method != "PUT" && step.Method != "DELETE" && step.Method != "RESTART") {
					skipped++
					continue
				}
				intent := p7Intent{Want: map[string]Rule{}, Absent: []string{}, Exemptions: []string{}, WhitelistEmpty: step.Method == "RESTART", Whole: step.Method == "RESTART"}
				if step.Method == "DELETE" {
					ids := []string{step.Path[strings.LastIndex(step.Path, "/")+1:]}
					if strings.HasSuffix(step.Path, "/batch") {
						var b struct{ IDs []string }
						if err := json.Unmarshal(step.Body, &b); err != nil {
							t.Fatal(err)
						}
						ids = b.IDs
					}
					intent.Absent = append(intent.Absent, ids...)
					for _, id := range ids {
						delete(prior, id)
					}
				} else {
					rules, empty := p7SourceRules(t, step)
					for _, key := range empty {
						var identity groupIdentity
						if err := json.Unmarshal(key, &identity); err != nil {
							t.Fatal(err)
						}
						for id, r := range prior {
							g, err := (&Handlers{}).classifyRuleKey(r)
							if err != nil {
								t.Fatal(err)
							}
							if g == identity {
								intent.Absent = append(intent.Absent, id)
								delete(prior, id)
							}
						}
					}
					next := map[string]Rule{}
					for _, raw := range rules {
						var header struct {
							ID        string
							LogicalID uint32 `json:"logical_id"`
							Enabled   *bool
						}
						if err := json.Unmarshal(raw, &header); err != nil {
							t.Fatal(err)
						}
						enabled := header.Enabled == nil || *header.Enabled
						if step.Method != "RESTART" && header.Enabled != nil {
							t.Fatal("future source boundary: enabled on non-restart")
						}
						if !enabled || header.LogicalID == 0 {
							if _, exists := prior[header.ID]; exists {
								t.Fatalf("%s zero/disabled source replaces existing ID: unresolved source exemption", cell)
							}
							intent.Absent = append(intent.Absent, header.ID)
							intent.Exemptions = append(intent.Exemptions, "protocol 4 logical_id=0/new id or restart disabled: absent")
							continue
						}
						// The only partial-capacity source shape has the already-installed first
						// member plus one new ID at capacity 1. Check those source facts explicitly.
						if tag == "partial_rejection" && step.Fault == "capacity_one" {
							if _, exists := prior[header.ID]; !exists {
								if len(prior) != 1 {
									t.Fatalf("%s ambiguous capacity prestate", cell)
								}
								intent.Absent = append(intent.Absent, header.ID)
								intent.Exemptions = append(intent.Exemptions, "protocol 4 partial batch: capacity 1 held by prior successful source member; new id absent")
								continue
							}
						}
						if header.Enabled != nil {
							var obj map[string]json.RawMessage
							json.Unmarshal(raw, &obj)
							delete(obj, "enabled")
							raw, _ = json.Marshal(obj)
						}
						r := p7NormalizeSource(t, raw)
						intent.Want[r.ID] = r
						next[r.ID] = r
					}
					if step.Method == "RESTART" || step.Path == "/api/v1/sync/atomic" {
						prior = next
					} else {
						for id, r := range next {
							prior[id] = r
						}
					}
				}
				// A key-move declares old-empty and new-populated groups in one commit.
				// The whole-object equality proves the new key; the consumer also rejects
				// duplicate IDs, so an old-key duplicate cannot hide in a map projection.
				absent := intent.Absent[:0]
				for _, id := range intent.Absent {
					if _, moved := intent.Want[id]; !moved {
						absent = append(absent, id)
					}
				}
				intent.Absent = absent
				exemptions += len(intent.Exemptions)
				for _, rule := range intent.Exemptions {
					fmt.Printf("CLOSEOUT_INTENT_EXEMPT cell=%s rule=%s\n", cell, rule)
				}
				intents[cell] = intent
			}
		}
	}
	if out := os.Getenv("XDROP_CLOSEOUT_INTENTS_OUT"); out != "" {
		data, err := json.MarshalIndent(intents, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(out, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Printf("CLOSEOUT_INTENT_SOURCE selected=%d unselected=%d exemptions=%d files=%d\n", len(intents), skipped, exemptions, len(files))
}
