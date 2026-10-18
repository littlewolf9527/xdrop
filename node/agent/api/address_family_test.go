package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func afRule(src, dst string, prefix bool) Rule {
	r := Rule{ID: "bad", LogicalID: 901, Protocol: "tcp", Action: "drop"}
	if prefix {
		r.SrcCIDR, r.DstCIDR = src, dst
	} else {
		r.SrcIP, r.DstIP = src, dst
	}
	return r
}

func afReject(t *testing.T, r Rule, reason string, good Rule) {
	t.Helper()
	f := cut55Memory(t)
	w := prefixABAtomicHTTP(t, f, []Rule{r, good})
	var body struct {
		Added, Failed int
		Rejected      []AtomicSyncRejection
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 200 || body.Added != 1 || body.Failed != 1 || len(body.Rejected) != 1 || body.Rejected[0].ID != r.ID || body.Rejected[0].Reason != reason {
		t.Fatalf("AF per-item rejection status=%d body=%s error=%v; want=%q", w.Code, w.Body.String(), err, reason)
	}
	if len(f.h.rules) != 1 || len(f.h.cidrRules) != 0 || f.h.rules[good.ID].LogicalID != good.LogicalID {
		t.Fatal("AF rejected rule published or good member lost")
	}
	for _, trie := range append(f.tries[:], f.triesB[:]...) {
		if len(trie.rows) != 0 {
			t.Fatal("AF rejected prefix reserved/published")
		}
	}
	cut53P3Golden(t, "atomic_address_family_p9", t.Name(), w)
}

func TestAFE1(t *testing.T) {
	for i, raw := range []string{"::ffff:192.0.2.1", "::FFFF:c000:201", "0:0:0:0:0:ffff:c000:201", "::ffff:0.0.0.0"} {
		for _, side := range []string{"src", "dst"} {
			t.Run(fmt.Sprintf("%s/%d", side, i), func(t *testing.T) {
				r := afRule(raw, "", false)
				if side == "dst" {
					r.SrcIP, r.DstIP = "", raw
				}
				v4 := "192.0.2.1"
				if i == 3 {
					v4 = "0.0.0.0"
				}
				afReject(t, r, "invalid "+side+"_ip: IPv4-mapped IPv6 address "+raw+"; write the IPv4 address "+v4, cut55Rule("good", 902, "198.51.100.1"))
			})
		}
	}
}

func TestAFE2(t *testing.T) {
	inputs := []struct{ raw, rewrite string }{
		{"::ffff:192.0.2.0/120", "192.0.2.0/24"}, {"::ffff:0:0/96", "0.0.0.0/0"},
		{"::ffff:a00:0/104", "10.0.0.0/8"}, {"::ffff:192.0.2.129/32", ""},
		{"::ffff:192.0.2.0/0120", "192.0.2.0/24"}, {"::ffff:0:0/096", "0.0.0.0/0"},
		{"::ffff:0:0/95", ""}, {"::ffff:0:0/0", ""},
	}
	for i, in := range inputs {
		for _, side := range []string{"src", "dst"} {
			t.Run(fmt.Sprintf("%s/%d", side, i), func(t *testing.T) {
				r := afRule(in.raw, "", true)
				if side == "dst" {
					r.SrcCIDR, r.DstCIDR = "", in.raw
				}
				reason := "invalid " + side + "_cidr: IPv4-mapped IPv6 prefix " + in.raw
				if in.rewrite != "" {
					reason += "; write the IPv4 prefix " + in.rewrite
				}
				afReject(t, r, reason, cut55Rule("good", 902, "198.51.100.1"))
			})
		}
	}
}

func TestAFE3(t *testing.T) {
	for _, kind := range []string{"exact+TTL", "CIDR+TTL"} {
		t.Run(kind, func(t *testing.T) {
			r := afRule("::ffff:192.0.2.1", "", false)
			reason := "invalid src_ip: IPv4-mapped IPv6 address ::ffff:192.0.2.1; write the IPv4 address 192.0.2.1"
			if kind == "CIDR+TTL" {
				r = afRule("::ffff:192.0.2.0/120", "", true)
				reason = "invalid src_cidr: IPv4-mapped IPv6 prefix ::ffff:192.0.2.0/120; write the IPv4 prefix 192.0.2.0/24"
			}
			r.TTL = cut4BString("64")
			good := cut55Rule("good", 902, "198.51.100.1")
			good.TTL = cut4BString("32")
			afReject(t, r, reason, good)
		})
	}
}

func TestAFE4(t *testing.T) {
	afReject(t, afRule("::ffff:192.0.2.1", "", false), "invalid src_ip: IPv4-mapped IPv6 address ::ffff:192.0.2.1; write the IPv4 address 192.0.2.1", cut55Rule("good", 902, "192.0.2.1"))
}

func TestAFE5(t *testing.T) {
	for name, r := range map[string]Rule{
		"exact":      afRule("192.0.2.1", "2001:db8::1", false),
		"CIDR":       afRule("192.0.2.0/24", "2001:db8::/32", true),
		"v4-default": afRule("0.0.0.0/0", "2001:db8::/32", true),
		"reverse":    afRule("2001:db8::1", "192.0.2.1", false),
	} {
		t.Run(name, func(t *testing.T) {
			reason := "address family mismatch: src is IPv4, dst is IPv6"
			if name == "reverse" {
				reason = "address family mismatch: src is IPv6, dst is IPv4"
			}
			afReject(t, r, reason, cut55Rule("good", 902, "198.51.100.1"))
		})
	}
}

func TestAFE6(t *testing.T) {
	controls := []Rule{
		afRule("::/0", "", true), afRule("::fffe:0:0/95", "", true), afRule("::ffff:0:0:0/96", "", true),
		afRule("::192.0.2.1", "", false), afRule("64:ff9b::/96", "", true),
		afRule("0.0.0.0", "2001:db8::1", false), afRule("::", "192.0.2.1", false),
		afRule("192.0.2.1", "198.51.100.1", false), afRule("2001:db8::1", "2001:db8::2", false),
		afRule("192.0.2.0/24", "198.51.100.0/24", true), afRule("2001:db8:1::/64", "2001:db8:2::/64", true),
		afRule("192.0.2.1", "::", false), afRule("2001:db8::1", "0.0.0.0", false),
	}
	for i, r := range controls {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := cut55Memory(t)
			g, err := f.h.classifyRuleKey(r)
			if err != nil {
				t.Fatal(err)
			}
			p, err := f.h.prepareAtomicRule(r)
			if err != nil {
				t.Fatal(err)
			}
			again, err := f.h.classifyRuleKey(p.Rule)
			if err != nil || !reflect.DeepEqual(g, again) {
				t.Fatalf("AF canonical idempotence: %v", err)
			}
			w := prefixABAtomicHTTP(t, f, []Rule{r})
			if w.Code != 200 || len(f.h.rules)+len(f.h.cidrRules) != 1 {
				t.Fatalf("AF positive rejected: %d %s", w.Code, w.Body.String())
			}
			gb, _ := json.Marshal(g)
			t.Logf("AF_KEY cell=%d exact=%s cidr=%s identity=%s", i, hex.EncodeToString(cut55Bytes(p.Exact)), hex.EncodeToString(cut55Bytes(p.CIDR)), gb)
			if !p.IsCIDR {
				key, err := f.h.whitelistToKey(WhitelistEntry{SrcIP: r.SrcIP, DstIP: r.DstIP, Protocol: r.Protocol})
				if err != nil || key != p.Exact {
					t.Fatalf("AF whitelist positive differs: %v", err)
				}
			}
		})
	}
}

func afCommitState(f *cut55Fixture) string {
	state := fmt.Sprint(cut55Snapshot(f, 0), cut55Snapshot(f, 1), f.h.activeRuleSlot.Load(), f.h.activeSlot, f.receipts, cut53State(f.h))
	for _, tables := range f.tables {
		for _, table := range tables {
			state += fmt.Sprint(table.writes, table.deletes)
		}
	}
	for _, table := range append(f.configs[:], f.selector) {
		state += fmt.Sprint(table.rows, table.writes, table.deletes)
	}
	for _, trie := range append(f.tries[:], f.triesB[:]...) {
		state += fmt.Sprint(trie.rows)
	}
	return state
}

func TestAFE7(t *testing.T) {
	for _, name := range []string{"mapped-exact", "mapped-CIDR", "mixed-exact", "mixed-CIDR", "delete-exact", "delete-CIDR"} {
		t.Run(name, func(t *testing.T) {
			f := cut55Memory(t)
			seed := cut55Rule("seed", 900, "198.51.100.1")
			cut55Commit(t, f.h, cut55Group(t, f.h, seed, seed))
			r := afRule("192.0.2.1", "2001:db8::1", false)
			if strings.Contains(name, "CIDR") {
				r = afRule("192.0.2.0/24", "2001:db8::/32", true)
			}
			keyRule := r
			if strings.HasPrefix(name, "mixed") {
				keyRule.DstIP, keyRule.DstCIDR = "", ""
			}
			if strings.HasPrefix(name, "mapped") {
				r.DstIP, r.DstCIDR, keyRule.DstIP, keyRule.DstCIDR = "", "", "", ""
				if r.SrcCIDR != "" {
					r.SrcCIDR = "::ffff:192.0.2.0/120"
				} else {
					r.SrcIP = "::ffff:192.0.2.1"
				}
			}
			key := groupIdentity{Kind: "exact", SrcIP: keyRule.SrcIP, DstIP: keyRule.DstIP, SrcCIDR: keyRule.SrcCIDR, DstCIDR: keyRule.DstCIDR, Protocol: "tcp"}
			if r.SrcCIDR != "" {
				key.Kind = "cidr"
			}
			raw, _ := json.Marshal(key)
			group := CommitGroup{Key: raw, Rules: []Rule{r}}
			if strings.HasPrefix(name, "delete") {
				group.Rules = []Rule{}
			}
			before := afCommitState(f)
			w := cut55HTTP(t, f.h, []CommitGroup{group})
			var body CommitResult
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 400 || body.Code != "validation_rejected" || len(body.Groups) != 1 {
				t.Fatalf("AF commit accepted: %d %s %v", w.Code, w.Body.String(), err)
			}
			if after := afCommitState(f); after != before {
				t.Fatal("AF commit rejection wrote state/selectors/receipts")
			}
			cut53P3Golden(t, "commit_address_family_p9", t.Name(), w)
		})
	}
}

func TestAFE8(t *testing.T) {
	for name, entry := range map[string]WhitelistEntry{
		"src":   {ID: "w", SrcIP: "::ffff:192.0.2.1", Protocol: "tcp"},
		"dst":   {ID: "w", DstIP: "::ffff:192.0.2.1", Protocol: "tcp"},
		"mixed": {ID: "w", SrcIP: "192.0.2.1", DstIP: "2001:db8::1", Protocol: "tcp"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newWLValidationHandlers()
			if _, err := h.whitelistToKey(entry); err == nil {
				t.Fatal("AF whitelist invalid address reached publication")
			}
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.POST("/whitelist", h.SyncWhitelistHandler)
			w := cut53Request(t, router, "POST", "/whitelist", map[string]any{"entries": []WhitelistEntry{entry}})
			if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid whitelist entry w: ") {
				t.Fatalf("AF whitelist status=%d body=%s", w.Code, w.Body.String())
			}
			cut53P3Golden(t, "whitelist_address_family_p9", t.Name(), w)
		})
	}
}

func TestAFE11(t *testing.T) {
	if SyncProtocol != 11 {
		t.Fatalf("AF protocol=%d want=11", SyncProtocol)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/", (&Handlers{}).Welcome)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"sync_protocol":11`) {
		t.Fatal(w.Body.String())
	}
}

func TestAFE13Syntax(t *testing.T) {
	// Complete HTTP bytes observed on the pure 5d1b164 baseline.
	wants := map[string]string{
		"exact/src":     `{"added":0,"cidr_rules":0,"failed":1,"rejected":[{"id":"bad","reason":"invalid src_ip: invalid"}],"rules":0,"success":true}`,
		"exact/dst":     `{"added":0,"cidr_rules":0,"failed":1,"rejected":[{"id":"bad","reason":"invalid dst_ip: invalid"}],"rules":0,"success":true}`,
		"CIDR/src":      `{"added":0,"cidr_rules":0,"failed":1,"rejected":[{"id":"bad","reason":"invalid src_cidr: invalid CIDR: bad-prefix"}],"rules":0,"success":true}`,
		"CIDR/dst":      `{"added":0,"cidr_rules":0,"failed":1,"rejected":[{"id":"bad","reason":"invalid dst_cidr: invalid CIDR: bad-prefix"}],"rules":0,"success":true}`,
		"whitelist/src": `{"error":"invalid whitelist entry bad: invalid src_ip: invalid"}`,
		"whitelist/dst": `{"error":"invalid whitelist entry bad: invalid dst_ip: invalid"}`,
	}
	for _, kind := range []string{"exact", "CIDR", "whitelist"} {
		for _, side := range []string{"src", "dst"} {
			t.Run(kind+"/"+side, func(t *testing.T) {
				src, dst := "::ffff:192.0.2.1", "invalid"
				if kind == "CIDR" {
					src, dst = "::ffff:192.0.2.0/120", "bad-prefix"
				}
				if side == "src" {
					src, dst = dst, src
				}
				var w *httptest.ResponseRecorder
				status := 200
				if kind == "whitelist" {
					gin.SetMode(gin.TestMode)
					router := gin.New()
					router.POST("/whitelist", newWLValidationHandlers().SyncWhitelistHandler)
					w = cut53Request(t, router, "POST", "/whitelist", map[string]any{"entries": []WhitelistEntry{{ID: "bad", SrcIP: src, DstIP: dst, Protocol: "tcp"}}})
					status = 400
				} else {
					w = prefixABAtomicHTTP(t, cut55Memory(t), []Rule{afRule(src, dst, kind == "CIDR")})
				}
				if w.Code != status || w.Body.String() != wants[kind+"/"+side] {
					t.Fatalf("AF syntax precedence status=%d body=%s", w.Code, w.Body.String())
				}
				t.Logf("AF_SYNTAX key=%s status=%d body=%q", kind+"/"+side, w.Code, w.Body.String())
			})
		}
	}
}

func TestAFE14RejectedOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "mapped-first"
		if reverse {
			name = "ordinary-first"
		}
		t.Run(name, func(t *testing.T) {
			rules := []Rule{afRule("::ffff:192.0.2.1", "", false), cut55Rule("ordinary", 0, "198.51.100.1"), cut55Rule("good", 903, "192.0.2.2")}
			want := []AtomicSyncRejection{{ID: "bad", Reason: "invalid src_ip: IPv4-mapped IPv6 address ::ffff:192.0.2.1; write the IPv4 address 192.0.2.1"}, {ID: "ordinary", Reason: "logical_id must be nonzero"}}
			if reverse {
				rules[0], rules[1], want[0], want[1] = rules[1], rules[0], want[1], want[0]
			}
			f := cut55Memory(t)
			w := prefixABAtomicHTTP(t, f, rules)
			var body struct {
				Added, Failed int
				Rejected      []AtomicSyncRejection
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 200 || body.Added != 1 || body.Failed != 2 || !reflect.DeepEqual(body.Rejected, want) || len(f.h.rules) != 1 || f.h.rules["good"].LogicalID != 903 {
				t.Fatalf("AF rejection order status=%d body=%s error=%v", w.Code, w.Body.String(), err)
			}
			t.Logf("AF_REJECTED_ORDER %s body=%s", name, w.Body.String())
		})
	}
}
