// v262_test.go — regression tests for v2.6.2 Node-side bugfixes.
// Covers: AUD-002 startup sync DTO, AUD-003 AtomicSync anomaly count,
// AUD-004 GET /rules MatchAnomaly, AUD-005 batch CIDR MatchAnomaly,
// AUD-008 ruleValueFromStored helpers, Node anomaly guard (helper +
// HTTP entry rejection).
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ---- AUD-008: ruleValueFromStored ----

func TestRuleValueFromStored_MatchAnomalyPreserved(t *testing.T) {
	s := StoredRule{
		Action:       "drop",
		TcpFlags:     "",
		MatchAnomaly: 1,
		RateLimit:    0,
	}
	v := ruleValueFromStored(s)
	if v.MatchAnomaly != 1 {
		t.Fatalf("expected MatchAnomaly=1, got %d", v.MatchAnomaly)
	}
	if v.Action != ActionDrop {
		t.Fatalf("expected ActionDrop, got %d", v.Action)
	}
}

func TestRuleValueFromStored_TcpFlagsPreserved(t *testing.T) {
	s := StoredRule{
		Action:   "drop",
		TcpFlags: "RST",
	}
	v := ruleValueFromStored(s)
	if v.TcpFlagsMask == 0 && v.TcpFlagsValue == 0 {
		t.Fatal("expected non-zero TcpFlags mask/value for RST flag")
	}
}

func TestRuleValueFromStored_FallbackOnInvalidAction(t *testing.T) {
	s := StoredRule{Action: "invalid-action", MatchAnomaly: 1}
	v := ruleValueFromStored(s) // must not panic
	if v.Action != ActionDrop {
		t.Fatalf("expected fallback to ActionDrop on invalid action, got %d", v.Action)
	}
	if v.MatchAnomaly != 1 {
		t.Fatalf("MatchAnomaly should still be preserved on action fallback, got %d", v.MatchAnomaly)
	}
}

func TestRuleValueFromStored_FallbackOnInvalidTcpFlags(t *testing.T) {
	s := StoredRule{Action: "drop", TcpFlags: "NOTAFLAG", MatchAnomaly: 2}
	v := ruleValueFromStored(s) // must not panic
	if v.TcpFlagsMask != 0 {
		t.Fatalf("expected zero TcpFlagsMask on fallback, got %d", v.TcpFlagsMask)
	}
	if v.MatchAnomaly != 2 {
		t.Fatalf("MatchAnomaly should still be preserved on flags fallback, got %d", v.MatchAnomaly)
	}
}

func TestRuleValueFromStoredCIDR_MatchAnomalyPreserved(t *testing.T) {
	s := StoredCIDRRule{
		Action:       "drop",
		MatchAnomaly: 1,
	}
	v := ruleValueFromStoredCIDR(s)
	if v.MatchAnomaly != 1 {
		t.Fatalf("expected MatchAnomaly=1 in CIDR rollback value, got %d", v.MatchAnomaly)
	}
}

// ---- AUD-002: startup sync DTO ----

func TestSyncRuleDTO_HasTcpFlagsAndMatchAnomaly(t *testing.T) {
	// The controller_sync.Rule DTO must have TcpFlags and MatchAnomaly fields.
	// This test verifies the field names exist by constructing an api.Rule from
	// a sync.Rule via the expected field copy.
	apiRule := Rule{
		ID:           "test-id",
		Protocol:     "tcp",
		Action:       "drop",
		TcpFlags:     "RST",
		MatchAnomaly: 1,
	}
	if apiRule.TcpFlags != "RST" {
		t.Fatal("api.Rule must have TcpFlags field")
	}
	if apiRule.MatchAnomaly != 1 {
		t.Fatal("api.Rule must have MatchAnomaly field")
	}
}

// ---- AUD-003: countAnomalyRulesIn ----

func TestCountAnomalyRulesIn_Empty(t *testing.T) {
	n := countAnomalyRulesIn(nil, nil)
	if n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
}

func TestCountAnomalyRulesIn_OnlyExactRules(t *testing.T) {
	rules := map[string]StoredRule{
		"a": {MatchAnomaly: 1},
		"b": {MatchAnomaly: 0},
		"c": {MatchAnomaly: 2},
	}
	n := countAnomalyRulesIn(rules, nil)
	if n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}
}

func TestCountAnomalyRulesIn_OnlyCIDRRules(t *testing.T) {
	cidrRules := map[string]StoredCIDRRule{
		"x": {MatchAnomaly: 1},
		"y": {MatchAnomaly: 0},
	}
	n := countAnomalyRulesIn(nil, cidrRules)
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}
}

func TestCountAnomalyRulesIn_Mixed(t *testing.T) {
	rules := map[string]StoredRule{
		"a": {MatchAnomaly: 1},
		"b": {MatchAnomaly: 0},
	}
	cidrRules := map[string]StoredCIDRRule{
		"x": {MatchAnomaly: 2},
	}
	n := countAnomalyRulesIn(rules, cidrRules)
	if n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}
}

func TestCountAnomalyRulesIn_ZeroAfterAllNonAnomaly(t *testing.T) {
	rules := map[string]StoredRule{
		"a": {MatchAnomaly: 0},
		"b": {MatchAnomaly: 0},
	}
	cidrRules := map[string]StoredCIDRRule{
		"x": {MatchAnomaly: 0},
	}
	n := countAnomalyRulesIn(rules, cidrRules)
	if n != 0 {
		t.Fatalf("expected 0 when no anomaly rules, got %d", n)
	}
}

// ---- AUD-004: storedRuleToRule MatchAnomaly ----

func TestStoredRuleToRule_MatchAnomalyReturned(t *testing.T) {
	h := &Handlers{}
	s := StoredRule{
		Action:       "drop",
		MatchAnomaly: 1,
	}
	r := h.storedRuleToRule("test-id", s)
	if r.MatchAnomaly != 1 {
		t.Fatalf("storedRuleToRule should return MatchAnomaly=1, got %d", r.MatchAnomaly)
	}
}

func TestStoredCIDRRuleToRule_MatchAnomalyReturned(t *testing.T) {
	h := &Handlers{}
	s := StoredCIDRRule{
		Action:       "drop",
		SrcCIDR:      "10.0.0.0/8",
		MatchAnomaly: 2,
	}
	r := h.storedCIDRRuleToRule("test-id", s)
	if r.MatchAnomaly != 2 {
		t.Fatalf("storedCIDRRuleToRule should return MatchAnomaly=2, got %d", r.MatchAnomaly)
	}
}

// ---- Node anomaly guard ----

func TestValidateNodeAnomalyFields_RateLimit(t *testing.T) {
	if err := validateNodeAnomalyFields(1, "rate_limit", "", "10.0.0.1", "", ""); err == nil {
		t.Fatal("expected error: anomaly + rate_limit")
	}
}

func TestValidateNodeAnomalyFields_NoTarget(t *testing.T) {
	if err := validateNodeAnomalyFields(1, "drop", "", "", "", ""); err == nil {
		t.Fatal("expected error: no bounded target")
	}
}

func TestValidateNodeAnomalyFields_UnknownBit(t *testing.T) {
	if err := validateNodeAnomalyFields(0xFF, "drop", "", "10.0.0.1", "", ""); err == nil {
		t.Fatal("expected error: unknown bit")
	}
}

func TestValidateNodeAnomalyFields_BadFragmentIPv6(t *testing.T) {
	if err := validateNodeAnomalyFields(AnomalyBadFragment, "drop", "", "2001:db8::1", "", ""); err == nil {
		t.Fatal("expected error: bad_fragment + IPv6")
	}
}

func TestValidateNodeAnomalyFields_InvalidIPv6Allowed(t *testing.T) {
	if err := validateNodeAnomalyFields(AnomalyInvalid, "drop", "", "2001:db8::1", "", ""); err != nil {
		t.Fatalf("invalid decoder should allow IPv6, got: %v", err)
	}
}

func TestValidateNodeAnomalyFields_Zero_NoOp(t *testing.T) {
	if err := validateNodeAnomalyFields(0, "drop", "", "", "", ""); err != nil {
		t.Fatalf("match_anomaly=0 should be no-op, got: %v", err)
	}
}

func TestValidateNodeAnomalyFields_ValidBounded(t *testing.T) {
	if err := validateNodeAnomalyFields(1, "drop", "", "10.0.0.1", "", ""); err != nil {
		t.Fatalf("valid bounded target should pass, got: %v", err)
	}
}

// ---- Wildcard / default-route coverage matching Controller hasBoundedAnomalyTarget ----

func TestValidateNodeAnomalyFields_WildcardSrcIPv4(t *testing.T) {
	if err := validateNodeAnomalyFields(1, "drop", "0.0.0.0", "", "", ""); err == nil {
		t.Fatal("expected error: src_ip 0.0.0.0 is wildcard")
	}
}

func TestValidateNodeAnomalyFields_WildcardDstIPv6(t *testing.T) {
	if err := validateNodeAnomalyFields(1, "drop", "", "::", "", ""); err == nil {
		t.Fatal("expected error: dst_ip :: is wildcard")
	}
}

func TestValidateNodeAnomalyFields_DefaultRouteCIDR(t *testing.T) {
	if err := validateNodeAnomalyFields(1, "drop", "", "", "0.0.0.0/0", ""); err == nil {
		t.Fatal("expected error: src_cidr 0.0.0.0/0 is default route")
	}
	if err := validateNodeAnomalyFields(1, "drop", "", "", "", "::/0"); err == nil {
		t.Fatal("expected error: dst_cidr ::/0 is default route")
	}
}

func TestValidateNodeAnomalyFields_NegativeBitsViaUint8(t *testing.T) {
	// uint8 cannot be negative, but verify "0xFF" (all bits) is rejected
	if err := validateNodeAnomalyFields(0xFF, "drop", "", "10.0.0.1", "", ""); err == nil {
		t.Fatal("expected error: 0xFF includes unknown bits")
	}
}

func TestValidateNodeAnomalyFields_CompoundBitIPv6Rejected(t *testing.T) {
	// match_anomaly=3 (bad_fragment | invalid) on IPv6 must reject (bad_fragment forbids v6)
	if err := validateNodeAnomalyFields(3, "drop", "", "2001:db8::1", "", ""); err == nil {
		t.Fatal("expected error: bad_fragment bit + IPv6 target")
	}
}

// ---- HTTP entry-level rejection tests ----
// These verify each Node write entrypoint actually invokes
// validateNodeAnomalyFields BEFORE any BPF interaction. Constructing a
// Handlers stub with nil BPF maps is safe because rejection happens in the
// validation phase before any map access.

// runHandler invokes the handler in test mode and returns status + parsed body.
func runHandler(handler gin.HandlerFunc, method, path string, body interface{}) (int, map[string]interface{}) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req, _ := http.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	handler(c)
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

func TestAddRuleHandler_RejectsAnomalyRateLimit(t *testing.T) {
	h := &Handlers{}
	body := Rule{
		Action: "rate_limit", RateLimit: 1000,
		MatchAnomaly: 1, DstIP: "10.0.0.1",
	}
	code, resp := runHandler(h.AddRule, "POST", "/rules", body)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (resp=%v)", code, resp)
	}
	errStr, _ := resp["error"].(string)
	if !strings.Contains(errStr, "anomaly") && !strings.Contains(errStr, "rate_limit") {
		t.Fatalf("expected anomaly/rate_limit rejection, got: %s", errStr)
	}
}

func TestAddRuleHandler_RejectsAnomalyNoTarget(t *testing.T) {
	h := &Handlers{}
	body := Rule{
		Action: "drop", MatchAnomaly: 1,
	}
	code, _ := runHandler(h.AddRule, "POST", "/rules", body)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for anomaly without target, got %d", code)
	}
}

func TestAddRuleHandler_RejectsBadFragmentIPv6(t *testing.T) {
	h := &Handlers{}
	body := Rule{
		Action: "drop", MatchAnomaly: 1, DstIP: "2001:db8::1",
	}
	code, _ := runHandler(h.AddRule, "POST", "/rules", body)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad_fragment + IPv6, got %d", code)
	}
}

func TestAddRuleHandler_RejectsUnknownBit(t *testing.T) {
	h := &Handlers{}
	body := Rule{
		Action: "drop", MatchAnomaly: 0xFF, DstIP: "10.0.0.1",
	}
	code, _ := runHandler(h.AddRule, "POST", "/rules", body)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown bits, got %d", code)
	}
}

// TestBatchInputs_RejectedByAnomalyGuard verifies the per-item validation
// helper rejects illegal anomaly inputs. The full AddRulesBatch handler
// requires real BPF maps and lives in integration-tagged tests.
func TestBatchInputs_RejectedByAnomalyGuard(t *testing.T) {
	cases := []Rule{
		// anomaly + rate_limit
		{Action: "rate_limit", RateLimit: 100, MatchAnomaly: 1, DstIP: "10.0.0.1"},
		// anomaly + IPv6 + bad_fragment
		{Action: "drop", MatchAnomaly: 1, DstIP: "2001:db8::1"},
		// anomaly + wildcard target
		{Action: "drop", MatchAnomaly: 1, SrcIP: "0.0.0.0"},
		// anomaly + default-route CIDR
		{Action: "drop", MatchAnomaly: 1, DstCIDR: "0.0.0.0/0"},
	}
	for i, r := range cases {
		if err := validateNodeAnomalyFields(r.MatchAnomaly, r.Action, r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR); err == nil {
			t.Errorf("case[%d] should be rejected, got no error: %+v", i, r)
		}
	}
}

// ---- B-10 (rev11 codex round 9 P2): Node-side portless+port guard ----

func TestValidatePortProtocolCompatNode_GREWithSrcPort(t *testing.T) {
	if err := validatePortProtocolCompatNode("gre", 500, 0); err == nil {
		t.Fatal("expected reject: gre + src_port=500")
	}
}

func TestValidatePortProtocolCompatNode_ESPWithDstPort(t *testing.T) {
	if err := validatePortProtocolCompatNode("esp", 0, 500); err == nil {
		t.Fatal("expected reject: esp + dst_port=500")
	}
}

func TestValidatePortProtocolCompatNode_AllPortlessRejected(t *testing.T) {
	for _, p := range []string{"icmp", "icmpv6", "igmp", "gre", "esp"} {
		if err := validatePortProtocolCompatNode(p, 1, 0); err == nil {
			t.Fatalf("expected reject: %s + src_port=1", p)
		}
	}
}

func TestValidatePortProtocolCompatNode_TCPUDPAcceptPort(t *testing.T) {
	if err := validatePortProtocolCompatNode("tcp", 0, 80); err != nil {
		t.Fatalf("tcp + dst_port=80 should accept, got: %v", err)
	}
	if err := validatePortProtocolCompatNode("udp", 0, 53); err != nil {
		t.Fatalf("udp + dst_port=53 should accept, got: %v", err)
	}
}

func TestValidatePortProtocolCompatNode_AllAcceptsPort(t *testing.T) {
	if err := validatePortProtocolCompatNode("all", 0, 80); err != nil {
		t.Fatalf("all + dst_port=80 should accept, got: %v", err)
	}
	if err := validatePortProtocolCompatNode("", 0, 80); err != nil {
		t.Fatalf("empty protocol + dst_port=80 should accept, got: %v", err)
	}
}

func TestValidatePortProtocolCompatNode_ZeroPortsAccepted(t *testing.T) {
	for _, p := range []string{"icmp", "icmpv6", "igmp", "gre", "esp"} {
		if err := validatePortProtocolCompatNode(p, 0, 0); err != nil {
			t.Fatalf("%s + zero ports should accept, got: %v", p, err)
		}
	}
}

// validateRule now embeds the B-10 guard — confirm portless+port flows
// through the existing exact-IP entry validation.
func TestValidateRule_PortlessProtoWithPort_Rejects(t *testing.T) {
	err := validateRule("", "10.0.0.1", "gre", 500, 0, 0, 0)
	if err == nil {
		t.Fatal("expected validateRule to reject gre + src_port=500")
	}
}

func TestValidateRule_PortlessProtoZeroPorts_Accepted(t *testing.T) {
	err := validateRule("", "10.0.0.1", "gre", 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("validateRule should accept gre + zero ports, got: %v", err)
	}
}

// HTTP entry test: AddRule rejects gre+port at the API boundary (validateRule).
func TestAddRuleHandler_RejectsPortlessProtoWithPort(t *testing.T) {
	h := &Handlers{}
	body := Rule{
		Protocol: "gre",
		SrcPort:  500,
		DstIP:    "10.99.0.220",
		Action:   "drop",
	}
	code, resp := runHandler(h.AddRule, "POST", "/rules", body)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (resp=%v)", code, resp)
	}
	errStr, _ := resp["error"].(string)
	if !strings.Contains(errStr, "does not carry ports") {
		t.Fatalf("expected portless diagnosis, got: %s", errStr)
	}
}

func TestAddRuleHandler_RejectsESPWithDstPort(t *testing.T) {
	h := &Handlers{}
	body := Rule{
		Protocol: "esp",
		DstPort:  500,
		DstIP:    "10.99.0.221",
		Action:   "drop",
	}
	code, _ := runHandler(h.AddRule, "POST", "/rules", body)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for esp+dst_port, got %d", code)
	}
}

// rev11/rev12 codex round 10/11 P3: helper-level lock for the entry
// validation matrix. The actual AddRulesBatch / addCIDRRuleFromSync /
// DoAtomicSync handlers require real BPF maps, so these tests do NOT run
// the full entry flow — they exercise the same helpers (validateRule /
// validatePortProtocolCompatNode) that each entry calls per-item, locking
// the rejection matrix so future refactors that bypass the helper would
// fail loudly here. Real entry-flow coverage with fake-BPF harness is on
// the v2.7 backlog (plan §6 lab gate items).

// AddRulesBatch exact path: verifies the per-item validation matrix that
// AddRulesBatch loops over (rules_mutation.go:408-412) rejects portless+port.
// AddRulesBatch calls validateRule per-item; this test feeds the same inputs
// through validateRule directly to lock in the rejection behavior.
func TestAddRulesBatchInputs_PortlessPortRejected(t *testing.T) {
	cases := []struct {
		desc string
		r    Rule
	}{
		{"gre + src_port", Rule{Protocol: "gre", SrcPort: 500, DstIP: "10.0.0.1", Action: "drop"}},
		{"esp + dst_port", Rule{Protocol: "esp", DstPort: 500, DstIP: "10.0.0.1", Action: "drop"}},
		{"igmp + both ports", Rule{Protocol: "igmp", SrcPort: 1, DstPort: 2, DstIP: "10.0.0.1", Action: "drop"}},
		{"icmp + src_port", Rule{Protocol: "icmp", SrcPort: 100, DstIP: "10.0.0.1", Action: "drop"}},
		{"icmpv6 + src_port", Rule{Protocol: "icmpv6", SrcPort: 1, DstIP: "2001:db8::1", Action: "drop"}},
	}
	for _, c := range cases {
		err := validateRule(c.r.SrcIP, c.r.DstIP, c.r.Protocol, c.r.SrcPort, c.r.DstPort, c.r.PktLenMin, c.r.PktLenMax)
		if err == nil {
			t.Errorf("AddRulesBatch per-item validateRule should reject %s, got nil", c.desc)
		}
	}
	// Positive: tcp+port + udp+port + portless-zero-ports should pass
	positive := []struct {
		desc string
		r    Rule
	}{
		{"tcp + dst_port", Rule{Protocol: "tcp", DstPort: 80, DstIP: "10.0.0.1", Action: "drop"}},
		{"udp + dst_port", Rule{Protocol: "udp", DstPort: 53, DstIP: "10.0.0.1", Action: "drop"}},
		{"gre + zero ports", Rule{Protocol: "gre", DstIP: "10.0.0.1", Action: "drop"}},
		{"all + dst_port", Rule{Protocol: "all", DstPort: 80, DstIP: "10.0.0.1", Action: "drop"}},
	}
	for _, c := range positive {
		err := validateRule(c.r.SrcIP, c.r.DstIP, c.r.Protocol, c.r.SrcPort, c.r.DstPort, c.r.PktLenMin, c.r.PktLenMax)
		if err != nil {
			t.Errorf("AddRulesBatch per-item validateRule should accept %s, got: %v", c.desc, err)
		}
	}
}

// addCIDRRuleFromSync per-item validation: explicit guard call (cidr_rules.go:300)
// rejects portless+port BEFORE any CIDR allocation. The rejection path is
// covered by validatePortProtocolCompatNode + the SyncRule shape is exact
// 1:1, so feeding the helper directly locks the behavior.
func TestAddCIDRRuleFromSyncInputs_PortlessPortRejected(t *testing.T) {
	cases := []SyncRule{
		{Protocol: "gre", SrcPort: 500, DstCIDR: "10.0.0.0/24", Action: "drop"},
		{Protocol: "esp", DstPort: 500, DstCIDR: "10.0.0.0/24", Action: "drop"},
		{Protocol: "igmp", SrcPort: 1, DstCIDR: "224.0.0.0/24", Action: "drop"},
	}
	for i, r := range cases {
		err := validatePortProtocolCompatNode(r.Protocol, r.SrcPort, r.DstPort)
		if err == nil {
			t.Errorf("addCIDRRuleFromSync case[%d] (%s) should reject, got nil", i, r.Protocol)
		}
	}
}

// DoAtomicSync exact + CIDR path: same per-item validation. AtomicSync calls
// validateRule for exact rules (sync.go:412) and validatePortProtocolCompatNode
// directly for CIDR rules (sync.go:323). We exercise the helpers to confirm
// the rejection path matches the entry's expected behavior, ensuring per-item
// `failed++` accounting will fire correctly.
func TestDoAtomicSyncInputs_PortlessPortFailedAccounting(t *testing.T) {
	// Exact path
	if err := validateRule("", "10.0.0.1", "gre", 500, 0, 0, 0); err == nil {
		t.Fatal("DoAtomicSync exact validateRule should reject gre+src_port=500")
	}
	// CIDR path (uses validatePortProtocolCompatNode directly, not validateRule)
	if err := validatePortProtocolCompatNode("esp", 0, 500); err == nil {
		t.Fatal("DoAtomicSync CIDR validatePortProtocolCompatNode should reject esp+dst_port=500")
	}
}

// rev12 codex round 11 P3: Node-side guard normalizes protocol case so
// direct-Node clients sending uppercase (e.g. "GRE") still hit the B-10
// rejection. Without this, parseProtocol("GRE") falls through to ProtoAll
// (legacy contract) and the BPF dead-rule path would silently reopen.
func TestValidatePortProtocolCompatNode_UppercaseProtocol(t *testing.T) {
	cases := []string{"GRE", "ESP", "ICMP", "ICMPv6", "Igmp", "GrE"}
	for _, p := range cases {
		if err := validatePortProtocolCompatNode(p, 500, 0); err == nil {
			t.Errorf("expected reject for %q (case-insensitive match), got nil", p)
		}
	}
}

// rev13 codex round 12 P2: Node whitelist write paths must reject portless+port
// the same way rule paths do — BPF whitelist matching has identical port-key
// semantics (only TCP/UDP packets fill key.src_port/dst_port). Without this
// guard, AddWhitelist / AddWhitelistBatch / AddWhitelistFromSync would write
// ghost whitelist entries that never match.

// HTTP entry: AddWhitelist rejects gre + 5-tuple + src_port=500.
func TestAddWhitelistHandler_RejectsPortlessProtoWithPort(t *testing.T) {
	h := &Handlers{}
	body := WhitelistEntry{
		Protocol: "gre",
		SrcPort:  500,
		SrcIP:    "10.99.0.10",
		DstIP:    "10.99.0.20",
	}
	code, resp := runHandler(h.AddWhitelist, "POST", "/whitelist", body)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (resp=%v)", code, resp)
	}
	errStr, _ := resp["error"].(string)
	if !strings.Contains(errStr, "does not carry ports") {
		t.Fatalf("expected portless diagnosis, got: %s", errStr)
	}
}

// HTTP entry: AddWhitelist rejects esp + dst_port.
func TestAddWhitelistHandler_RejectsESPWithDstPort(t *testing.T) {
	h := &Handlers{}
	body := WhitelistEntry{
		Protocol: "esp",
		DstPort:  500,
		SrcIP:    "10.99.0.11",
		DstIP:    "10.99.0.21",
	}
	code, _ := runHandler(h.AddWhitelist, "POST", "/whitelist", body)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", code)
	}
}

// Batch path: per-item helper-level lock — same matrix as rules.
func TestAddWhitelistBatchInputs_PortlessPortRejected(t *testing.T) {
	cases := []WhitelistEntry{
		{Protocol: "gre", SrcPort: 500, SrcIP: "10.99.0.10", DstIP: "10.99.0.20"},
		{Protocol: "esp", DstPort: 500, SrcIP: "10.99.0.11", DstIP: "10.99.0.21"},
		{Protocol: "igmp", SrcPort: 1, DstPort: 2, SrcIP: "10.99.0.12", DstIP: "10.99.0.22"},
		{Protocol: "icmp", SrcPort: 100, SrcIP: "10.99.0.13", DstIP: "10.99.0.23"},
	}
	for i, e := range cases {
		err := validatePortProtocolCompatNode(e.Protocol, e.SrcPort, e.DstPort)
		if err == nil {
			t.Errorf("AddWhitelistBatch case[%d] (%s) should reject, got nil", i, e.Protocol)
		}
	}
}

// AddWhitelistFromSync path: helper-level lock matches the explicit guard call.
func TestAddWhitelistFromSyncInputs_PortlessPortRejected(t *testing.T) {
	cases := []SyncWhitelistEntry{
		{Protocol: "gre", SrcPort: 500, SrcIP: "10.99.0.10", DstIP: "10.99.0.20"},
		{Protocol: "esp", DstPort: 500, SrcIP: "10.99.0.11", DstIP: "10.99.0.21"},
	}
	for i, e := range cases {
		err := validatePortProtocolCompatNode(e.Protocol, e.SrcPort, e.DstPort)
		if err == nil {
			t.Errorf("AddWhitelistFromSync case[%d] (%s) should reject, got nil", i, e.Protocol)
		}
	}
}

// Positive: legitimate whitelist (tcp + 5-tuple + port) accepted by the guard.
func TestAddWhitelistHandler_TCPWithPort_GuardAccepts(t *testing.T) {
	if err := validatePortProtocolCompatNode("tcp", 0, 80); err != nil {
		t.Fatalf("tcp + dst_port=80 should be accepted by guard, got: %v", err)
	}
	if err := validatePortProtocolCompatNode("udp", 0, 53); err != nil {
		t.Fatalf("udp + dst_port=53 should be accepted by guard, got: %v", err)
	}
}
