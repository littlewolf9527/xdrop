package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/node/agent/condexpr"
)

type ctlCut1Case struct {
	Name, Kind string
	Input      json.RawMessage
	Existing   []json.RawMessage
	Incoming   json.RawMessage
}
type ctlCut1Member struct {
	Rule
	Kind    string          `json:"kind"`
	Key     json.RawMessage `json:"group_key"`
	CondKey string          `json:"cond_key"`
}
type ctlCut1Verdict struct {
	Name      string          `json:"name"`
	Verdict   string          `json:"verdict"`
	Members   []ctlCut1Member `json:"members,omitempty"`
	Whitelist *WhitelistEntry `json:"whitelist,omitempty"`
}

func ctlCut1Path(file string) string {
	return filepath.Join("../../../controller/core/parity/testdata", file)
}
func ctlCut1Decode(t *testing.T, raw json.RawMessage, i int) Rule {
	t.Helper()
	var r Rule
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	r.ID = fmt.Sprintf("ctlcut1-%d", i)
	r.LogicalID = uint32(i + 1)
	return r
}
func ctlCut1MemberFromNode(t *testing.T, h *Handlers, r Rule) ctlCut1Member {
	t.Helper()
	p, err := h.prepareAtomicRule(r)
	if err != nil {
		t.Fatal(err)
	}
	g, err := h.classifyRuleKey(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	r = p.Rule
	r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR = g.SrcIP, g.DstIP, g.SrcCIDR, g.DstCIDR
	r.SrcPort, r.DstPort, r.Protocol = g.SrcPort, g.DstPort, g.Protocol
	n, err := condexpr.Compile(conditionInput(p.Rule))
	if err != nil {
		t.Fatal(err)
	}
	return ctlCut1Member{Rule: r, Kind: g.Kind, Key: b, CondKey: n.CondKey()}
}

// A panic is evidence of acceptance only when the stack proves Phase 2 map I/O.
func ctlCut1Whitelist(t *testing.T, in WhitelistEntry) (accepted, ioReached bool) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			stack := string(debug.Stack())
			if !strings.Contains(stack, ".clearMap(") || !strings.Contains(stack, ".DoWhitelistAtomicSync(") {
				t.Fatalf("unexpected panic before map I/O: %v\n%s", p, stack)
			}
			accepted, ioReached = true, true
		}
	}()
	h := newWLValidationHandlers()
	err := h.DoWhitelistAtomicSync([]SyncWhitelistEntry{{ID: "ctlcut1-wl", SrcIP: in.SrcIP, DstIP: in.DstIP, SrcPort: in.SrcPort, DstPort: in.DstPort, Protocol: in.Protocol}})
	if _, bad := err.(*wlSyncValidationError); bad {
		return false, false
	}
	return true, true
}
func ctlCut1Observe(t *testing.T, c ctlCut1Case) ctlCut1Verdict {
	t.Helper()
	v := ctlCut1Verdict{Name: c.Name, Verdict: "reject"}
	if c.Kind == "whitelist" {
		var in WhitelistEntry
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatal(err)
		}
		if ok, _ := ctlCut1Whitelist(t, in); !ok {
			return v
		}
		k, err := newWLValidationHandlers().whitelistToKey(in)
		if err != nil {
			t.Fatal(err)
		}
		v.Verdict = "accept"
		v.Whitelist = &WhitelistEntry{SrcIP: ipAddrToString(k.SrcIP), DstIP: ipAddrToString(k.DstIP), SrcPort: ntohs(k.SrcPort), DstPort: ntohs(k.DstPort), Protocol: protocolToString(k.Protocol)}
		return v
	}
	f := cut55Memory(t)
	if c.Kind == "rule" {
		if strings.HasPrefix(c.Name, "P-num-") {
			var raw map[string]any
			if err := json.Unmarshal(c.Input, &raw); err != nil {
				t.Fatal(err)
			}
			raw["id"], raw["logical_id"] = "ctlcut1-0", 1
			w := cut53Request(t, cut53MemoryRouter(f.h), "POST", "/atomic", map[string]any{"rules": []any{raw}})
			if w.Code != 400 {
				t.Fatalf("wide numeric input must be rejected by binding: %d %s", w.Code, w.Body.String())
			}
			return v
		}
		r := ctlCut1Decode(t, c.Input, 0)
		w := prefixABAtomicHTTP(t, f, []Rule{r})
		var result struct {
			Failed   int `json:"failed"`
			Rejected []struct {
				ID string `json:"id"`
			} `json:"rejected"`
		}
		if w.Code != 200 {
			return v
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Failed > 0 {
			return v
		}
		for _, rejected := range result.Rejected {
			if rejected.ID == r.ID {
				return v
			}
		}
		m := ctlCut1MemberFromNode(t, f.h, r)
		fresh := cut55Memory(t)
		proof := cut55HTTP(t, fresh.h, []CommitGroup{{Key: m.Key, Rules: []Rule{m.Rule}}})
		if proof.Code != 200 {
			t.Fatalf("canonical member commit proof: %d %s", proof.Code, proof.Body.String())
		}
		v.Verdict = "accept"
		v.Members = []ctlCut1Member{m}
		return v
	}
	raw := append(append([]json.RawMessage{}, c.Existing...), c.Incoming)
	items := make([]Rule, len(raw))
	members := make([]ctlCut1Member, len(raw))
	for i, r := range raw {
		items[i] = ctlCut1Decode(t, r, i)
		members[i] = ctlCut1MemberFromNode(t, f.h, items[i])
		items[i] = members[i].Rule
	}
	if c.Kind == "group" {
		seen := map[string]bool{}
		for _, m := range members {
			if seen[m.CondKey] {
				t.Fatal("capacity corpus has duplicate conditions")
			}
			seen[m.CondKey] = true
		}
		w := cut55HTTP(t, f.h, []CommitGroup{{Key: members[0].Key, Rules: items}})
		if w.Code != 200 {
			return v
		}
	} else {
		for i, r := range items {
			w := cut55HTTP(t, f.h, []CommitGroup{{Key: members[i].Key, Rules: []Rule{r}}})
			if i < len(c.Existing) && w.Code != 200 {
				t.Fatalf("existing commit: %d %s", w.Code, w.Body.String())
			}
			if w.Code != 200 {
				return v
			}
		}
	}
	v.Verdict = "accept"
	v.Members = members
	return v
}
func ctlCut1Same(got, want []byte) error {
	if !bytes.Equal(got, want) {
		return fmt.Errorf("live node verdict bytes differ from golden")
	}
	return nil
}
func TestCtlCut1NodeGolden(t *testing.T) {
	data, err := os.ReadFile(ctlCut1Path("corpus_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []ctlCut1Case
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	verdicts := make([]ctlCut1Verdict, len(cases))
	for i, c := range cases {
		i, c := i, c
		t.Run(c.Name, func(t *testing.T) { verdicts[i] = ctlCut1Observe(t, c) })
	}
	t.Run("P-wl-control-bad", func(t *testing.T) {
		ok, io := ctlCut1Whitelist(t, WhitelistEntry{Protocol: "gre", DstPort: 80})
		if ok || io {
			t.Fatal("last validation must reject before map I/O")
		}
	})
	t.Run("P-wl-control-good", func(t *testing.T) {
		ok, io := ctlCut1Whitelist(t, WhitelistEntry{SrcIP: "10.20.0.1", Protocol: "tcp", DstPort: 80})
		if !ok || !io {
			t.Fatal("good entry did not reach map I/O")
		}
	})
	encoded, err := json.MarshalIndent(verdicts, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if t.Failed() {
		return
	}
	if os.Getenv("XDROP_CTLCUT1_PARITY_WRITE") == "1" {
		if err = os.WriteFile(ctlCut1Path("node_verdicts_v1.json"), encoded, 0644); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("P-node-golden", func(t *testing.T) {
		want, err := os.ReadFile(ctlCut1Path("node_verdicts_v1.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err = ctlCut1Same(encoded, want); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("P-selfcheck", func(t *testing.T) {
		copy := append([]byte(nil), encoded...)
		copy = bytes.Replace(copy, []byte(`"verdict": "accept"`), []byte(`"verdict": "reject"`), 1)
		if err := ctlCut1Same(encoded, copy); err == nil {
			t.Fatal("node comparator missed changed verdict")
		}
	})
}
