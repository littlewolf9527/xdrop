//go:build linux && integration

package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

// These behavior/guard tests deliberately use only APIs present in eb42610.
// The recorder forwards every mutation to the real, private ELF trie map.
type td075CountingTrie struct {
	trie *ebpf.Map
	puts map[string]int
}

func (w *td075CountingTrie) Put(key, value interface{}) error {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, key); err != nil {
		return fmt.Errorf("record trie key: %w", err)
	}
	w.puts[buf.String()]++
	return w.trie.Put(key, value)
}
func (w *td075CountingTrie) Delete(key interface{}) error   { return w.trie.Delete(key) }
func (w *td075CountingTrie) KeySize() uint32                { return w.trie.KeySize() }
func (w *td075CountingTrie) NextKey(k, v interface{}) error { return w.trie.NextKey(k, v) }
func (w *td075CountingTrie) Lookup(k, v interface{}) error  { return w.trie.Lookup(k, v) }

// The active generation is copied, so in-place changes cannot alias the oracle.
type td075State struct {
	slot, ruleSlot              int
	rules                       map[string]StoredRule
	cidrRules                   map[string]StoredCIDRRule
	refs                        map[string]int64
	ids                         map[string]uint32
	active, exact, cidr, config map[string]string
	tries                       [8]map[string]string
}

func td075Snapshot(t *testing.T, h *Handlers, tries []*ebpf.Map) td075State {
	t.Helper()
	s := td075State{slot: h.activeSlot, ruleSlot: int(h.activeRuleSlot.Load()), rules: maps.Clone(h.rules), cidrRules: maps.Clone(h.cidrRules), refs: yiCIDRRefs(h), ids: map[string]uint32{}, active: b7Snapshot(t, h.activeConfig), exact: b7Snapshot(t, p7ActiveBlacklist(h)), cidr: b7Snapshot(t, p7ActiveCIDR(h)), config: b7Snapshot(t, h.activeMap())}
	for _, prefix := range h.cidrMgr.ListSrcCIDRs() {
		id, ok := h.cidrMgr.GetSrcID(prefix)
		if !ok {
			t.Fatal("src live identity disappeared")
		}
		s.ids["src:"+prefix] = id
	}
	for _, prefix := range h.cidrMgr.ListDstCIDRs() {
		id, ok := h.cidrMgr.GetDstID(prefix)
		if !ok {
			t.Fatal("dst live identity disappeared")
		}
		s.ids["dst:"+prefix] = id
	}
	for i, m := range tries {
		s.tries[i] = b7Snapshot(t, m)
	}
	return s
}
func td075Unchanged(t *testing.T, before td075State, h *Handlers, tries []*ebpf.Map) {
	t.Helper()
	after := td075Snapshot(t, h, tries)
	if before.slot != after.slot || before.ruleSlot != after.ruleSlot || !reflect.DeepEqual(before.active, after.active) {
		t.Error("rejection changed active generation selectors")
	}
	if !reflect.DeepEqual(before.rules, after.rules) || !reflect.DeepEqual(before.cidrRules, after.cidrRules) {
		t.Error("rejection changed in-memory rule tables")
	}
	if !reflect.DeepEqual(before.refs, after.refs) || !reflect.DeepEqual(before.ids, after.ids) {
		t.Errorf("rejection leaked/changed live CIDR IDs or references: before=%v after=%v", before.refs, after.refs)
	}
	if !reflect.DeepEqual(before.exact, after.exact) || !reflect.DeepEqual(before.cidr, after.cidr) || !reflect.DeepEqual(before.config, after.config) {
		t.Error("rejection changed active rule maps/config")
	}
	if !reflect.DeepEqual(before.tries, after.tries) {
		t.Error("rejection changed one of four trie snapshots")
	}
}

type td075Response struct {
	Code, Error, Direction string
	Conflicts              []struct {
		ID    string
		Index *int
	}
	Prefixes          []string
	Added, Failed     *int
	WithdrawalPending *bool `json:"withdrawal_pending"`
	Rejected          []AtomicSyncRejection
}

func td075Body(t *testing.T, w *httptest.ResponseRecorder) td075Response {
	t.Helper()
	var body td075Response
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}
func td075Overlap(t *testing.T, w *httptest.ResponseRecorder, direction string, prefixes [2]string, ids [2]string, indices [2]int, added int) {
	t.Helper()
	body := td075Body(t, w)
	if w.Code != 409 || body.Code != "cidr_overlap" {
		t.Fatalf("overlap status/code: got=%d/%s want=409/cidr_overlap body=%s", w.Code, body.Code, w.Body.String())
	}
	if body.Direction != direction || !reflect.DeepEqual(body.Prefixes, prefixes[:]) {
		t.Fatalf("overlap direction/container order: %s", w.Body.String())
	}
	if body.Added == nil || *body.Added != added || body.Failed == nil || *body.Failed != 1 || body.WithdrawalPending != nil {
		t.Fatalf("overlap counts/withdrawal state: %s", w.Body.String())
	}
	if len(body.Conflicts) != 2 {
		t.Fatalf("overlap conflicts length: %s", w.Body.String())
	}
	labels := [2]string{}
	for i, id := range ids {
		identity := body.Conflicts[i]
		if identity.ID != id {
			t.Fatalf("original conflict identity[%d]: %s", i, w.Body.String())
		}
		if id == "" {
			if identity.Index == nil || *identity.Index != indices[i] {
				t.Fatalf("first accepted empty-ID index[%d]: %s", i, w.Body.String())
			}
			labels[i] = fmt.Sprintf("rule at index %d (empty ID)", indices[i])
		} else {
			if identity.Index != nil {
				t.Fatalf("unexpected index for named rule: %s", w.Body.String())
			}
			labels[i] = fmt.Sprintf("rule ID %q", id)
		}
	}
	want := fmt.Sprintf("%s_cidr overlap: %s (%s) contains %s (%s) (strict containment); batch not published", direction, labels[0], prefixes[0], labels[1], prefixes[1])
	if body.Error != want {
		t.Fatalf("overlap error text=%q want=%q", body.Error, want)
	}
}
func td075Success(t *testing.T, w *httptest.ResponseRecorder, added, failed int) td075Response {
	t.Helper()
	body := td075Body(t, w)
	if w.Code != 200 || body.Added == nil || *body.Added != added || body.Failed == nil || *body.Failed != failed || body.WithdrawalPending != nil {
		t.Fatalf("accepted batch status/counts: got=%d body=%s want=200 added=%d failed=%d", w.Code, w.Body.String(), added, failed)
	}
	return body
}
func td075Drop443(t *testing.T, p *ebpf.Program) {
	t.Helper()
	packet := b7Packet()
	copy(packet[26:30], []byte{10, 0, 1, 42})
	copy(packet[30:34], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint16(packet[36:38], 443)
	packet[46] = 0x50 // A valid TCP header; no anomaly-dependent result.
	got, _, err := p.Test(packet)
	if err != nil || got != 1 {
		t.Fatalf("retained parent protection dport443: verdict=%d want=DROP err=%v", got, err)
	}
}

func TestTD075I1(t *testing.T) {
	h, r, p := b7ELF(t)
	tries := yiELFTries(t, p)
	writers := make([]*td075CountingTrie, 8)
	for i, m := range tries {
		writers[i] = &td075CountingTrie{trie: m, puts: map[string]int{}}
	}
	h.cidrMgr = cidr.NewManager(writers[0], writers[1], writers[2], writers[3], writers[4], writers[5], writers[6], writers[7])
	old := Rule{LogicalID: 542001, ID: "parent", SrcCIDR: "10.0.0.0/16", Action: "drop"}
	td075Success(t, yiAtomicCall(t, r, []Rule{old}), 1, 0)
	if len(writers[4].puts) != 1 || len(b7Snapshot(t, tries[4])) != 1 {
		t.Fatal("counting trie positive control did not observe seed publication")
	}
	for _, w := range writers {
		w.puts = map[string]int{}
	}
	td075Drop443(t, p)
	before := td075Snapshot(t, h, tries)
	w := yiAtomicCall(t, r, []Rule{old, {LogicalID: 542002, ID: "child", SrcCIDR: "10.0.1.0/24", Protocol: "tcp", DstPort: 80, Action: "drop"}})
	td075Overlap(t, w, "src", [2]string{"10.0.0.0/16", "10.0.1.0/24"}, [2]string{"parent", "child"}, [2]int{0, 1}, 2)
	key := make([]byte, 8)
	binary.LittleEndian.PutUint32(key, 24)
	copy(key[4:], []byte{10, 0, 1, 0})
	if n := writers[0].puts[string(key)]; n != 0 {
		t.Errorf("new-prefix Put count=%d want=0", n)
	}
	total := 0
	for _, writer := range writers {
		for _, n := range writer.puts {
			total += n
		}
	}
	if total != 0 {
		t.Errorf("rejected batch trie Put total=%d want=0", total)
	}
	td075Unchanged(t, before, h, tries)
	td075Drop443(t, p)
	t.Logf("TD075_I1 status=409 new_prefix_puts=%d total_puts=%d before_drop=1 after_drop=1", writers[0].puts[string(key)], total)
}

func TestTD075I2(t *testing.T) {
	for _, both := range []bool{false, true} {
		t.Run(fmt.Sprintf("both=%v", both), func(t *testing.T) {
			h, r, p := b7ELF(t)
			tries := yiELFTries(t, p)
			before := td075Snapshot(t, h, tries)
			rules := []Rule{{LogicalID: 542003, ID: "parent", DstCIDR: "10.0.0.0/16", Action: "drop"}, {LogicalID: 542004, ID: "child", DstCIDR: "10.0.1.0/24", Action: "drop"}}
			direction := "dst"
			if both {
				direction = "src"
				rules[0].SrcCIDR = rules[0].DstCIDR
				rules[1].SrcCIDR = rules[1].DstCIDR
			}
			td075Overlap(t, yiAtomicCall(t, r, rules), direction, [2]string{"10.0.0.0/16", "10.0.1.0/24"}, [2]string{"parent", "child"}, [2]int{0, 1}, 2)
			td075Unchanged(t, before, h, tries)
		})
	}
}
func TestTD075I3(t *testing.T) {
	h, r, p := b7ELF(t)
	tries := yiELFTries(t, p)
	before := td075Snapshot(t, h, tries)
	rules := []Rule{{LogicalID: 542005, ID: "child", SrcCIDR: "2001:db8:1::/48", Action: "drop"}, {LogicalID: 542006, ID: "parent", SrcCIDR: "2001:db8::/32", Action: "drop"}}
	td075Overlap(t, yiAtomicCall(t, r, rules), "src", [2]string{"2001:db8::/32", "2001:db8:1::/48"}, [2]string{"parent", "child"}, [2]int{1, 0}, 2)
	td075Unchanged(t, before, h, tries)
}
func TestTD075I4(t *testing.T) {
	for _, emptyParent := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty_parent=%v", emptyParent), func(t *testing.T) {
			h, r, p := b7ELF(t)
			tries := yiELFTries(t, p)
			before := td075Snapshot(t, h, tries)
			rules := []Rule{{LogicalID: 542007, ID: "child", SrcCIDR: "10.0.1.42/24", Action: "drop"}, {LogicalID: 542008, ID: "parent", SrcCIDR: "10.0.2.7/16", Action: "drop"}, {LogicalID: 542009, ID: "later-parent", SrcCIDR: "10.0.3.9/16", Protocol: "tcp", DstPort: 81, Action: "drop"}}
			if emptyParent {
				rules[1].ID = ""
			} else {
				rules[0].ID = ""
			}
			td075Overlap(t, yiAtomicCall(t, r, rules), "src", [2]string{"10.0.0.0/16", "10.0.1.0/24"}, [2]string{rules[1].ID, rules[0].ID}, [2]int{1, 0}, 3)
			td075Unchanged(t, before, h, tries)
		})
	}
}
func TestTD075I5(t *testing.T) {
	h, r, p := b7ELF(t)
	tries := yiELFTries(t, p)
	td075Success(t, yiAtomicCall(t, r, []Rule{{LogicalID: 542010, ID: "old", SrcCIDR: "10.0.0.0/16", Action: "drop"}, {LogicalID: 542011, ID: "exact-old", SrcIP: "192.0.2.1", Action: "drop"}}), 2, 0)
	before := td075Snapshot(t, h, tries)
	rules := []Rule{{LogicalID: 542012, ID: "reserve-both", SrcCIDR: "172.16.0.0/24", DstCIDR: "192.168.0.0/24", Action: "drop"}, {LogicalID: 542013, ID: "new-parent", SrcCIDR: "10.0.0.0/16", Action: "drop"}, {LogicalID: 542014, ID: "new-child", SrcCIDR: "10.0.1.0/24", Action: "drop"}, {LogicalID: 542015, ID: "exact-new", SrcIP: "198.51.100.1", Action: "drop"}}
	result, err := h.DoAtomicSync(rules)
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("direct sync must return overlap error: result=%+v err=%v", result, err)
	}
	if result.Added != 4 || result.Failed != 1 {
		t.Fatalf("direct overlap counts=%+v", result)
	}
	td075Unchanged(t, before, h, tries)
}

func TestTD075G1(t *testing.T) {
	h, r, _ := b7ELF(t)
	td075Success(t, yiAtomicCall(t, r, []Rule{{LogicalID: 542016, ID: "old", SrcCIDR: "10.0.0.0/16", Action: "drop"}}), 1, 0)
	slot, ruleSlot := h.activeSlot, int(h.activeRuleSlot.Load())
	td075Success(t, yiAtomicCall(t, r, []Rule{{LogicalID: 542017, ID: "new", SrcCIDR: "10.0.1.0/24", Action: "drop"}}), 1, 0)
	if h.activeSlot == slot || int(h.activeRuleSlot.Load()) == ruleSlot || len(h.cidrRules) != 1 || h.cidrRules["new"].SrcCIDR != "10.0.1.0/24" {
		t.Fatal("legal old-parent replacement did not flip to new child")
	}
	if _, ok := h.cidrMgr.GetSrcID("10.0.0.0/16"); ok {
		t.Fatal("old parent remains live after legal replacement")
	}
}
func TestTD075G2(t *testing.T) {
	h, r, _ := b7ELF(t)
	rules := []Rule{{LogicalID: 542018, ID: "first", SrcCIDR: "10.0.1.0/24", Protocol: "tcp", DstPort: 80, Action: "drop"}, {LogicalID: 542019, ID: "second", SrcCIDR: "10.0.1.42/24", Protocol: "tcp", DstPort: 443, Action: "drop"}}
	td075Success(t, yiAtomicCall(t, r, rules), 2, 0)
	if len(h.cidrRules) != 2 || yiCIDRRefs(h)["srcV4Refs:10.0.1.0/24"] != 2 {
		t.Fatal("shared canonical prefix lost a rule/reference")
	}
}
func TestTD075G3(t *testing.T) {
	h, r, _ := b7ELF(t)
	rules := []Rule{{LogicalID: 542020, ID: "bad", SrcCIDR: "10.0.0.0/16", Action: "invalid"}, {LogicalID: 542021, ID: "good", SrcCIDR: "10.0.1.0/24", Action: "drop"}}
	body := td075Success(t, yiAtomicCall(t, r, rules), 1, 1)
	if len(body.Rejected) != 1 || body.Rejected[0].ID != "bad" || !strings.Contains(body.Rejected[0].Reason, "action") {
		t.Fatalf("rejected item identity/reason=%+v", body.Rejected)
	}
	if len(h.cidrRules) != 1 || h.cidrRules["good"].SrcCIDR != "10.0.1.0/24" {
		t.Fatal("accepted remainder not published")
	}
}
func TestTD075G4(t *testing.T) {
	for _, kind := range []string{"condition_group_invalid", "duplicate_id", "shadow_error"} {
		t.Run(kind, func(t *testing.T) {
			h, r, p := b7ELF(t)
			tries := yiELFTries(t, p)
			before := td075Snapshot(t, h, tries)
			rules := []Rule{{LogicalID: 542022, ID: "parent", SrcCIDR: "10.0.0.0/16", Action: "drop"}, {LogicalID: 542023, ID: "child", SrcCIDR: "10.0.1.0/24", Action: "drop"}, {LogicalID: 542024, ID: "duplicate", SrcCIDR: "10.0.1.0/24", Action: "drop"}}
			if kind == "condition_group_invalid" {
				// J5 witness：组成员逻辑 ID 0 ⇒ 整组无效，先于前缀嵌套检查。
				rules[1].LogicalID = 0
				rules[2].LogicalID = 0
			}
			wantStatus := 409
			wantCode := kind
			if kind == "duplicate_id" {
				rules[2].ID = rules[0].ID
			}
			if kind == "shadow_error" {
				// Ruling #1: preserve the shadow-write failure witness with
				// distinct pure keys. The original request is the I6 case above.
				rules[2].Protocol = "tcp"
				wantStatus = 500
				wantCode = ""
				if err := h.shadowCidrBlacklist().Freeze(); err != nil {
					t.Fatal(err)
				}
			}
			w := yiAtomicCall(t, r, rules)
			body := td075Body(t, w)
			if w.Code != wantStatus || body.Code != wantCode {
				t.Fatalf("earlier abort priority: got=%d/%s want=%d/%s body=%s", w.Code, body.Code, wantStatus, wantCode, w.Body.String())
			}
			if kind == "shadow_error" && !strings.Contains(body.Error, "write shadow CIDR") {
				t.Fatalf("wrong earlier failure: %s", w.Body.String())
			}
			if kind == "condition_group_invalid" && (len(body.Conflicts) != 2 || body.Conflicts[0].ID != "child" || body.Conflicts[1].ID != "duplicate") {
				t.Fatalf("I6 must identify both same-key members: %s", w.Body.String())
			}
			if kind == "condition_group_invalid" {
				t.Logf("CUT54_TD075_G4_BRANCH status=%d code=%s conflicts=%s/%s logical_ids=%d/%d/%d", w.Code, body.Code, body.Conflicts[0].ID, body.Conflicts[1].ID, rules[0].LogicalID, rules[1].LogicalID, rules[2].LogicalID)
			}
			td075Unchanged(t, before, h, tries)
		})
	}
}
func TestTD075G5(t *testing.T) {
	h, r, _ := b7ELF(t)
	rules := []Rule{{LogicalID: 542025, ID: "source", SrcCIDR: "10.0.0.0/16", Action: "drop"}, {LogicalID: 542026, ID: "destination", DstCIDR: "10.0.1.0/24", Action: "drop"}}
	td075Success(t, yiAtomicCall(t, r, rules), 2, 0)
	if len(h.cidrRules) != 2 || len(h.cidrMgr.ListSrcCIDRs()) != 1 || len(h.cidrMgr.ListDstCIDRs()) != 1 {
		t.Fatal("independent directions were not both published")
	}
}
