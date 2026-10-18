package parity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type corpusCase struct {
	Name, Kind string
	Input      json.RawMessage
	Existing   []json.RawMessage
	Incoming   json.RawMessage
	Tags       []string
}
type member struct {
	store.Match
	Kind    string          `json:"kind"`
	Key     json.RawMessage `json:"group_key"`
	CondKey string          `json:"cond_key"`
}
type verdict struct {
	Name      string                `json:"name"`
	Verdict   string                `json:"verdict"`
	Members   []member              `json:"members,omitempty"`
	Whitelist *rules.WhitelistInput `json:"whitelist,omitempty"`
}

func corpus(t *testing.T) ([]corpusCase, []verdict) {
	t.Helper()
	read := func(name string, dest any) {
		data, e := os.ReadFile(filepath.Join("testdata", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(data, dest); e != nil {
			t.Fatal(e)
		}
	}
	var cases []corpusCase
	var gold []verdict
	read("corpus_v1.json", &cases)
	read("node_verdicts_v1.json", &gold)
	if len(cases) != len(gold) {
		t.Fatalf("corpus=%d golden=%d", len(cases), len(gold))
	}
	return cases, gold
}
func sameVerdict(got, want verdict) error {
	if got.Name != want.Name || got.Verdict != want.Verdict {
		return fmt.Errorf("verdict: got %s want %s", got.Verdict, want.Verdict)
	}
	if got.Verdict == "reject" {
		return nil
	}
	if !reflect.DeepEqual(got.Whitelist, want.Whitelist) {
		return fmt.Errorf("whitelist identity differs: got %+v want %+v", got.Whitelist, want.Whitelist)
	}
	if len(got.Members) != len(want.Members) {
		return fmt.Errorf("member count differs")
	}
	for i, g := range got.Members {
		w := want.Members[i]
		var gk, wk any
		if e := json.Unmarshal(g.Key, &gk); e != nil {
			return e
		}
		if e := json.Unmarshal(w.Key, &wk); e != nil {
			return e
		}
		if !reflect.DeepEqual(gk, wk) {
			return fmt.Errorf("member %d group key differs: %s != %s", i, g.Key, w.Key)
		}
		if w.Action == "drop" {
			w.RateLimit = 0
		}
		if g.Kind != w.Kind || g.CondKey != w.CondKey || !reflect.DeepEqual(g.Match, w.Match) {
			return fmt.Errorf("member %d differs: got %+v want %+v", i, g, w)
		}
	}
	return nil
}
func observe(t *testing.T, c corpusCase) verdict {
	t.Helper()
	db, e := store.Open(filepath.Join(t.TempDir(), "parity.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	svc := rules.New(db, nil)
	actor := rules.Actor{Kind: rules.UI}
	v := verdict{Name: c.Name, Verdict: "reject"}
	if c.Kind == "whitelist" {
		var in rules.WhitelistInput
		if e := json.Unmarshal(c.Input, &in); e != nil {
			t.Fatal(e)
		}
		result, e := svc.CreateWhitelist(actor, in)
		if e != nil {
			return v
		}
		rows, e := svc.ListWhitelist()
		if e != nil || len(rows) != 1 || rows[0].ID != result.Whitelist.ID {
			t.Fatalf("whitelist persisted rows: %+v %v", rows, e)
		}
		w := rows[0]
		v.Verdict = "accept"
		v.Whitelist = &rules.WhitelistInput{SrcIP: w.SrcIP, DstIP: w.DstIP, SrcPort: w.SrcPort, DstPort: w.DstPort, Protocol: w.Protocol}
		return v
	}
	inputs := append(append([]json.RawMessage{}, c.Existing...), c.Incoming)
	if c.Kind == "rule" {
		inputs = []json.RawMessage{c.Input}
	}
	for i, raw := range inputs {
		var p rules.RulePatch
		if e := json.Unmarshal(raw, &p); e != nil {
			t.Fatal(e)
		}
		created, e := svc.Create(actor, "", p)
		if e != nil {
			if i < len(c.Existing) {
				t.Fatalf("existing[%d]: %v", i, e)
			}
			v.Members = nil
			return v
		}
		r, err := store.Get(db, created.Rule.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Enabled {
			t.Fatal("parity must use enabled rules")
		}
		v.Members = append(v.Members, member{Match: r.Match, Kind: r.Kind, Key: json.RawMessage(r.GroupKey), CondKey: r.CondKey})
	}
	v.Verdict = "accept"
	return v
}
func TestCtlCut1Parity(t *testing.T) {
	cases, gold := corpus(t)
	for i, c := range cases {
		i, c := i, c
		t.Run(c.Name, func(t *testing.T) {
			if err := sameVerdict(observe(t, c), gold[i]); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestCtlCut1Apparatus(t *testing.T) {
	cases, gold := corpus(t)
	t.Run("P-count", func(t *testing.T) {
		if len(cases) < 106 {
			t.Fatalf("only %d cases", len(cases))
		}
		required := strings.Fields(`P-af-mapped-src-dotted
P-af-mapped-dst-dotted
P-af-mapped-src-hex
P-af-mapped-dst-hex
P-af-mapped-src-expanded
P-af-mapped-dst-expanded
P-af-mapped-src-uppercase
P-af-mapped-dst-uppercase
P-af-mapped-cidr-src-120
P-af-mapped-cidr-dst-120
P-af-mapped-cidr-src-96
P-af-mapped-cidr-dst-96
P-af-mapped-cidr-src-104
P-af-mapped-cidr-dst-104
P-af-mapped-cidr-src-32
P-af-mapped-cidr-dst-32
P-af-mapped-cidr-src-0120
P-af-mapped-cidr-dst-0120
P-af-mapped-cidr-src-096
P-af-mapped-cidr-dst-096
P-af-mapped-cidr-src-95
P-af-mapped-cidr-dst-95
P-af-mixed-exact
P-af-mixed-cidr
P-af-mixed-default
P-af-literal-v6
P-af-literal-v4
P-af-nonliteral-zero
P-af-positive-default-v6
P-af-positive-unmapped
P-af-positive-nat64
P-af-positive-compatible
P-anom-01
P-anom-02
P-anom-04
P-anom-08
P-anom-0f
P-anom-10
P-anom-v6-01
P-anom-v6-08
P-anom-v6-02
P-anom-v6-04
P-anom-unbounded-protocol
P-anom-unbounded-default
P-anom-rate
P-anom-flags
P-anom-08-port
P-anom-09-port
P-d2-nonfirst-port
P-d2-last-flags
P-d2-nonfirst-icmp
P-d2-frag-port
P-d2-fragment-v6
P-d2-fragment-protocol
P-act-drop-rate
P-act-zero-rate
P-act-uppercase
P-act-default
P-proto-TCP
P-proto-6
P-proto-gre
P-proto-GRE
P-proto-all
P-cidr-hostbits
P-cidr-uppercase
P-cidr-bad-mask
P-cidr-bare
P-cidr-same-end
P-cidr-cross-v4
P-cidr-cross-v6
P-num-port
P-num-anomaly
P-num-rate
P-flags-empty-mask
P-combo-empty
P-combo-zeros
P-combo-length
P-expr-full
P-expr-empty
P-expr-leading-zero
P-expr-dscp
P-expr-normalize
P-expr-flags
P-expr-contradiction
P-expr-icmp-protocol
P-expr-icmpv6
P-cap-count-4
P-cap-count-5
P-cap-split-3
P-cap-split-4
P-cap-split-5
P-cap-single-8
P-cap-single-9
P-cap-two-ttl
P-ovl-nested
P-ovl-cross
P-ovl-same
P-ovl-family
P-wl-mapped-src
P-wl-mapped-dst
P-wl-mixed
P-wl-empty
P-wl-gre-port
P-wl-v4
P-wl-v6
P-wl-wild-port`)
		seen, tags := map[string]bool{}, map[string]bool{}
		for i, c := range cases {
			if seen[c.Name] || gold[i].Name != c.Name {
				t.Fatal("duplicate or misaligned case", c.Name)
			}
			seen[c.Name] = true
			for _, tag := range c.Tags {
				tags[tag] = true
			}
			b, _ := json.Marshal(c)
			var tree any
			if e := json.Unmarshal(b, &tree); e != nil {
				t.Fatal(e)
			}
			var inspect func(any)
			inspect = func(v any) {
				switch x := v.(type) {
				case map[string]any:
					for _, v := range x {
						inspect(v)
					}
				case []any:
					for _, v := range x {
						inspect(v)
					}
				case string:
					if x == "" {
						t.Fatal("explicit empty field in corpus", c.Name)
					}
				}
			}
			inspect(tree)
		}
		for _, name := range required {
			if !seen[name] {
				t.Fatal("missing required coverage", name)
			}
		}
		for _, tag := range []string{"drift:a", "drift:b", "drift:c", "drift:d", "drift:e", "drift:f"} {
			if !tags[tag] {
				t.Fatal("missing", tag)
			}
		}
		for _, prefix := range []string{"P-af-", "P-anom-", "P-d2-", "P-act-", "P-proto-", "P-cidr-", "P-num-", "P-flags-", "P-combo-", "P-expr-", "P-cap-", "P-ovl-", "P-wl-"} {
			found := false
			for name := range seen {
				found = found || strings.HasPrefix(name, prefix)
			}
			if !found {
				t.Fatal("missing family", prefix)
			}
		}
	})
	for _, kind := range []string{"verdict", "member-port", "cond-key", "whitelist-port"} {
		kind := kind
		t.Run("P-selfcheck/"+kind, func(t *testing.T) {
			name := "P-proto-all"
			if kind == "whitelist-port" {
				name = "P-wl-v4"
			}
			for i, c := range cases {
				if c.Name == name {
					got := observe(t, c)
					data, _ := json.Marshal(gold[i])
					var copy verdict
					if e := json.Unmarshal(data, &copy); e != nil {
						t.Fatal(e)
					}
					if e := sameVerdict(got, copy); e != nil {
						t.Fatal("positive control", e)
					}
					switch kind {
					case "verdict":
						copy.Verdict = "reject"
					case "member-port":
						copy.Members[0].DstPort = 81
					case "cond-key":
						copy.Members[0].CondKey = "changed"
					case "whitelist-port":
						copy.Whitelist.DstPort = 81
					}
					if e := sameVerdict(got, copy); e == nil {
						t.Fatal("comparison did not detect corruption")
					}
					return
				}
			}
			t.Fatal("missing selfcheck witness")
		})
	}
}
