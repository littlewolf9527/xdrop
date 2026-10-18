package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

type cut53DebtTrie struct {
	*cut55Trie
	puts, deletes int
}

func (f *cut53DebtTrie) Put(interface{}, interface{}) error { f.puts++; return nil }
func (f *cut53DebtTrie) Delete(interface{}) error {
	f.deletes++
	return fmt.Errorf("cut53 withdrawal fault")
}

func cut53PendingManager(t *testing.T) (*cidr.Manager, *cut53DebtTrie) {
	t.Helper()
	f := &cut53DebtTrie{cut55Trie: newFakeTrie()}
	m := cidr.NewManager(f, newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie())
	if _, err := m.ReserveSrcID("10.93.0.0/24"); err != nil {
		t.Fatal(err)
	}
	// Actual stale content plus an unknown flag; any deletion would fail visibly.
	for key, id := range m.Snapshot([2][]string{})[0] {
		f.rows[key] = id
	}
	if err := m.ReleaseSrcID("10.93.0.0/24"); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func cut53EmptyGroupCall(t *testing.T, h *Handlers) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.POST("/sync", h.AtomicSync)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/sync", strings.NewReader(`{"rules":[{"id":""},{"id":""}]}`)))
	var result struct {
		Code              string
		Conflicts         []atomicConditionConflict
		WithdrawalPending *bool `json:"withdrawal_pending"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code != 409 || result.Code != "condition_group_invalid" || result.WithdrawalPending != nil || len(result.Conflicts) != 2 {
		t.Fatalf("I6 empty-ID group response: %d %s", w.Code, w.Body.String())
	}
	for i, c := range result.Conflicts {
		if c.ID != "" || c.Index == nil || *c.Index != i || c.Reason != "rule field combination is not recognized; XDP would never match it" {
			t.Fatalf("I6 empty-ID conflict %d: %+v", i, c)
		}
	}
	return w
}

func TestCut53EmptyIDsConditionGroupZeroWrite(t *testing.T) {
	m, trie := cut53PendingManager(t)
	h := &Handlers{cidrMgr: m, rules: map[string]StoredRule{"sentinel": {Action: "drop", LogicalID: 7}}, pendingLogicalIDs: map[uint32]bool{8: true}, logicalRetireThreshold: 1}
	before := fmt.Sprintf("%#v %#v %#v", m, h.rules, h.pendingLogicalIDs)
	trieBefore := *trie
	cut53EmptyGroupCall(t, h)
	if before != fmt.Sprintf("%#v %#v %#v", m, h.rules, h.pendingLogicalIDs) || !reflect.DeepEqual(trieBefore, *trie) {
		t.Fatal("I6 touched unknown trie or rule state during rejection")
	}
	if h.logicalPayments != 0 || h.logicalPaymentFailures != 0 {
		t.Fatal("I6 triggered logical payment")
	}
	// Nil BPF/config maps make any attempted kernel operation fail this test.
	t.Log("CUT53_EMPTY_IDS I6=409 conflicts=2 withdrawal_calls=0 business_writes=0 payments=0")
}

func TestCut53InvalidGroupNeverPays(t *testing.T) {
	h := cut53MemoryHandler(t)
	h.pendingLogicalIDs[90] = true
	h.logicalRetireThreshold = 1
	receipts := 0
	h.quiescer = cut53Receipt(func() error { receipts++; return fmt.Errorf("payment witness") })
	r := cut53Pure(false, "node-only-zero", 0)
	r.TTL = cut4BString("64")
	if _, err := h.prepareAtomicRule(r); err != nil {
		t.Fatal(err)
	}
	w := cut53Request(t, cut53MemoryRouter(h), "POST", "/atomic", map[string]any{"rules": []Rule{r}})
	if w.Code != 409 || !strings.Contains(w.Body.String(), "condition_group_invalid") {
		t.Fatalf("I6 node-only failure=%d %s", w.Code, w.Body.String())
	}
	if receipts != 0 || h.logicalPaymentFailures != 0 || !h.pendingLogicalIDs[90] {
		t.Fatalf("I6 invalid group paid existing debt: receipts=%d failures=%d", receipts, h.logicalPaymentFailures)
	}
	t.Log("CUT53_INVALID_NO_PAYMENT node_validation_passed=1 receipt_calls=0")
}
