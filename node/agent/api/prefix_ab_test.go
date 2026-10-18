package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"
)

func prefixABAtomicHTTP(t *testing.T, f *cut55Fixture, rules []Rule) *httptest.ResponseRecorder {
	t.Helper()
	f.bindConfig()
	// R0 succeeds; defer R5c because the native fixture has no kernel
	// logical-state maps. The real handler still determines response bytes.
	f.h.quiescenceConfirmed = false
	calls := 0
	f.h.quiescer = cut5ReceiptFunc(func() error {
		calls++
		if calls == 1 {
			return nil
		}
		return fmt.Errorf("native atomic R5c deferred")
	})
	return cut53Request(t, cut53MemoryRouter(f.h), "POST", "/atomic", map[string]any{"rules": rules})
}

func prefixABAtomicBody(t *testing.T, w *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	var got, want any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(body), &want); err != nil {
		t.Fatal(err)
	}
	if w.Code != status || !reflect.DeepEqual(got, want) {
		t.Fatalf("status=%d body=%s; want status=%d body=%s", w.Code, w.Body.String(), status, body)
	}
}

func TestPrefixABAtomicShadowDelete(t *testing.T) {
	for _, name := range []string{"delete_failure", "no_fault", "same_prefix", "empty_shadow"} {
		t.Run(name, func(t *testing.T) {
			f := cut55Memory(t)
			p := Rule{ID: "p", LogicalID: 93, SrcCIDR: "10.93.0.0/24", Protocol: "tcp", Action: "drop"}
			q := Rule{ID: "q", LogicalID: 94, SrcCIDR: "10.94.0.0/24", Protocol: "tcp", Action: "drop"}
			if name != "empty_shadow" {
				result := cut55Commit(t, f.h, cut55Group(t, f.h, p, p))
				if result.Receipt != "confirmed" || len(f.tries[0].rows) != 1 || !reflect.DeepEqual(f.tries[0].rows, f.triesB[0].rows) {
					t.Fatal("confirmed commit must install P in both prefix copies")
				}
			}
			if name == "same_prefix" {
				q.SrcCIDR = p.SrcCIDR
			}
			oldSlot, oldConfig := int(f.h.activeRuleSlot.Load()), f.h.activeSlot
			oldPolicy, oldRule := cut55Snapshot(f, oldSlot), f.h.cidrRules[p.ID]
			shadow := f.triesB[0]
			if oldSlot == 1 {
				shadow = f.tries[0]
			}
			shadow.failDelete = name != "no_fault"
			w := prefixABAtomicHTTP(t, f, []Rule{q})
			if name == "delete_failure" {
				prefixABAtomicBody(t, w, 500, `{"added":1,"error":"trie delete","failed":1}`)
				if int(f.h.activeRuleSlot.Load()) != oldSlot || f.h.activeSlot != oldConfig || cut55Snapshot(f, oldSlot) != oldPolicy || len(f.h.cidrRules) != 1 || !reflect.DeepEqual(f.h.cidrRules[p.ID], oldRule) || f.h.logicalOwners[p.LogicalID] != p.ID {
					t.Fatal("failed shadow Delete must preserve old selectors, active policy and logical owner")
				}
				if len(f.tries[0].rows) != 1 || !reflect.DeepEqual(f.tries[0].rows, f.triesB[0].rows) {
					t.Fatal("failed first Delete must leave both prefix copies at P")
				}
				return
			}
			prefixABAtomicBody(t, w, 200, `{"success":true,"added":1,"failed":0,"rules":0,"cidr_rules":1,"rejected":[]}`)
			if int(f.h.activeRuleSlot.Load()) != 1-oldSlot || len(f.h.cidrRules) != 1 || f.h.cidrRules[q.ID].SrcCIDR != q.SrcCIDR || len(shadow.rows) != 1 {
				t.Fatal("successful atomic must publish Q in the new active copy")
			}
		})
	}
	t.Log("CLOSEOUT_ATOMIC_DELETE_HANDLER failure=1 no_fault=1 no_delete_controls=2 old_policy=1")
}

func TestPrefixABAtomicLogicalMemberCounts(t *testing.T) {
	f := cut55Memory(t)
	var rules []Rule
	for i := 0; i < 4; i++ {
		ttl := []string{"32", "64"}[i%2]
		r := Rule{ID: fmt.Sprintf("member%d", i), LogicalID: uint32(93 + i), Protocol: "tcp", Action: "drop", TTL: &ttl}
		if i < 2 {
			r.SrcIP = "10.93.0.1"
		} else {
			r.SrcCIDR = "10.93.0.0/24"
		}
		rules = append(rules, r)
	}
	w := prefixABAtomicHTTP(t, f, rules)
	prefixABAtomicBody(t, w, 200, `{"success":true,"added":4,"failed":0,"rules":2,"cidr_rules":2,"rejected":[]}`)
	slot := int(f.h.activeRuleSlot.Load())
	if len(f.h.rules) != 2 || len(f.h.cidrRules) != 2 || len(f.tables[slot][mirrorExact].rows) != 1 || len(f.tables[slot][mirrorCIDR].rows) != 1 {
		t.Fatal("two members per group must remain two stored IDs in one physical key row")
	}
	t.Log("CLOSEOUT_ATOMIC_COUNTS added=4 rules=2 cidr_rules=2 exact_rows=1 cidr_rows=1")
}

func TestPrefixABCapacity(t *testing.T) {
	for kind := 0; kind < 4; kind++ {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			f := cut55Memory(t)
			f.h.commitTrieCapacity[kind] = 2
			var old, next []Rule
			var seed, replace []CommitGroup
			for i := 0; i < 4; i++ {
				prefix := fmt.Sprintf("10.93.%d.0/24", i)
				if kind >= 2 {
					prefix = fmt.Sprintf("fd00:93:%x::/64", i)
				}
				r := Rule{ID: fmt.Sprint("p", i), LogicalID: uint32(900 + i), Protocol: "tcp", Action: "drop"}
				if kind%2 == 0 {
					r.SrcCIDR = prefix
				} else {
					r.DstCIDR = prefix
				}
				if i < 2 {
					old = append(old, r)
					seed = append(seed, cut55Group(t, f.h, r, r))
					replace = append(replace, cut55Group(t, f.h, r))
				} else {
					next = append(next, r)
					replace = append(replace, cut55Group(t, f.h, r, r))
				}
			}
			cut55Commit(t, f.h, seed...)
			if len(f.tries[kind].rows) != 2 || len(f.triesB[kind].rows) != 2 {
				t.Fatal("capacity precondition: both old copies must contain 2 prefixes")
			}
			w := cut55HTTP(t, f.h, replace)
			if w.Code != 200 {
				t.Fatalf("CLOSEOUT_WITNESS AB-4 new_set_capacity: status=%d body=%s", w.Code, w.Body.String())
			}
			if len(f.tries[kind].rows) != 2 || !reflect.DeepEqual(f.tries[kind].rows, f.triesB[kind].rows) || len(f.h.cidrRules) != 2 {
				t.Fatal("replacement must contain exactly the 2 new prefixes in both copies")
			}
			for _, r := range next {
				if f.h.cidrRules[r.ID].LogicalID != r.LogicalID {
					t.Fatal("new rule identity missing")
				}
			}
			_, err := f.h.DoCommitRules([]CommitGroup{cut55Group(t, f.h, old[0], old[0])})
			if err == nil || err.Code != "table_full" || err.Groups[0].Excess != 1 {
				t.Fatalf("over-capacity positive control=%+v", err)
			}
		})
	}
	t.Log("CLOSEOUT_PREFIX_CAPACITY families=4 old=2 new=2 union=4 capacity=2 status=200 over_capacity_controls=4")
}
