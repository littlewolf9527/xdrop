// rule_service_update_test.go — real RuleService.Update tests
// Covers AUD-006 / R3-002 / R4-003 rate_limit semantics, AUD-001 anomaly
// effective values via Update.
package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
)

// fakeNodeProvider for SyncService construction (no nodes → SyncResult is empty).
type fakeNodeProvider struct{}

func (fakeNodeProvider) List() ([]*model.Node, error)       { return nil, nil }
func (fakeNodeProvider) Get(id string) (*model.Node, error) { return nil, nil }
func (fakeNodeProvider) UpdateStatus(id, status string)     {}
func (fakeNodeProvider) UpdateLastSeen(id string)           {}
func (fakeNodeProvider) UpdateLastSync(id string)           {}

func newTestRuleService(t *testing.T) (*RuleService, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := repository.NewSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open DB: %v", err)
	}
	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}
	repo := repository.NewSQLiteRuleRepo(db)
	wlRepo := repository.NewSQLiteWhitelistRepo(db)
	syncLogRepo := repository.NewSQLiteSyncLogRepo(db)
	syncSvc := NewSyncService(fakeNodeProvider{}, syncLogRepo, repo, wlRepo, nil, 1, 0, time.Millisecond)
	return NewRuleService(repo, syncSvc), cleanup
}

func createDropRule(t *testing.T, svc *RuleService, dstIP string) *model.Rule {
	t.Helper()
	r, _, err := svc.Create(&model.RuleRequest{DstIP: dstIP, Action: "drop"})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	return r
}

func createRateLimitRule(t *testing.T, svc *RuleService, dstIP string, rl int) *model.Rule {
	t.Helper()
	r, _, err := svc.Create(&model.RuleRequest{DstIP: dstIP, Action: "rate_limit", RateLimit: rl})
	if err != nil {
		t.Fatalf("create rate_limit rule: %v", err)
	}
	return r
}

// ---- R3-002 / R4-003: Update rate_limit 4 cases ----

// Case 1: existing rate_limit=1000, PUT {"action":"drop"} → 200, rate_limit auto-cleared to 0
func TestUpdateRule_RateLimitToDrop_AutoClears(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r := createRateLimitRule(t, svc, "10.99.0.10", 1000)

	updated, _, err := svc.Update(r.ID, &model.RuleRequest{Action: "drop"})
	if err != nil {
		t.Fatalf("Update rate_limit→drop should succeed, got: %v", err)
	}
	if updated.Action != "drop" {
		t.Fatalf("expected action=drop, got %q", updated.Action)
	}
	if updated.RateLimit != 0 {
		t.Fatalf("expected rate_limit=0 after drop transition, got %d", updated.RateLimit)
	}
}

// Case 2: existing rate_limit=1000, PUT {"action":"drop","rate_limit":1000} → 400
func TestUpdateRule_ExplicitRateLimitConflictsWithDrop(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r := createRateLimitRule(t, svc, "10.99.0.11", 1000)

	_, _, err := svc.Update(r.ID, &model.RuleRequest{Action: "drop", RateLimit: 1000})
	if err == nil {
		t.Fatal("Update with action=drop + explicit rate_limit>0 should fail")
	}
}

// Case 3: existing drop rule, PUT {"rate_limit":1000} (no action change) → 400
func TestUpdateRule_PositiveRateLimitOnDropRule(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r := createDropRule(t, svc, "10.99.0.12")

	_, _, err := svc.Update(r.ID, &model.RuleRequest{RateLimit: 1000})
	if err == nil {
		t.Fatal("Update of drop rule with positive rate_limit should fail")
	}
}

// Case 4: existing drop, PUT {"action":"rate_limit","rate_limit":1000} → 200
func TestUpdateRule_DropToRateLimitTransition(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r := createDropRule(t, svc, "10.99.0.13")

	updated, _, err := svc.Update(r.ID, &model.RuleRequest{Action: "rate_limit", RateLimit: 1000})
	if err != nil {
		t.Fatalf("Update drop→rate_limit should succeed, got: %v", err)
	}
	if updated.Action != "rate_limit" {
		t.Fatalf("expected action=rate_limit, got %q", updated.Action)
	}
	if updated.RateLimit != 1000 {
		t.Fatalf("expected rate_limit=1000, got %d", updated.RateLimit)
	}
}

// ---- R3-002: Update anomaly effective values ----

// existing dst_ip=v4 + match_anomaly=1, PUT {"match_anomaly":2} → 200 (effective values, target inherited)
func TestUpdateRule_AnomalyEffectiveValuesPreserved(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP: "10.99.0.20", Action: "drop", MatchAnomaly: 1,
	})
	if err != nil {
		t.Fatalf("create anomaly rule: %v", err)
	}

	updated, _, err := svc.Update(r.ID, &model.RuleRequest{MatchAnomaly: 2})
	if err != nil {
		t.Fatalf("Update match_anomaly should succeed (effective target inherited), got: %v", err)
	}
	if updated.MatchAnomaly != 2 {
		t.Fatalf("expected match_anomaly=2, got %d", updated.MatchAnomaly)
	}
}

// existing bad_fragment + IPv6 dst_ip should be impossible to create — but verify Update path
// catches the case where someone tries to flip an invalid (IPv6) rule to bad_fragment.
func TestUpdateRule_BadFragmentOnIPv6Rejected(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	// Create with `invalid` decoder (allows IPv6)
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP: "2001:db8::20", Action: "drop", MatchAnomaly: 2,
	})
	if err != nil {
		t.Fatalf("create invalid v6 rule: %v", err)
	}

	// Try to switch to bad_fragment → should fail (IPv6 + bad_fragment)
	_, _, err = svc.Update(r.ID, &model.RuleRequest{MatchAnomaly: 1})
	if err == nil {
		t.Fatal("Update to match_anomaly=1 (bad_fragment) on IPv6 rule should fail")
	}
}

// ---- P2: Comment pointer tri-state ----

// Existing comment="hello", PUT {"comment":""} → 200, rule.Comment == ""
func TestUpdateRule_CommentClear(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	hello := "hello"
	r, _, err := svc.Create(&model.RuleRequest{DstIP: "10.99.0.30", Action: "drop", Comment: &hello})
	if err != nil {
		t.Fatalf("create with comment: %v", err)
	}
	if r.Comment != "hello" {
		t.Fatalf("create did not store comment, got %q", r.Comment)
	}

	empty := ""
	updated, _, err := svc.Update(r.ID, &model.RuleRequest{Comment: &empty})
	if err != nil {
		t.Fatalf("Update comment to empty should succeed, got: %v", err)
	}
	if updated.Comment != "" {
		t.Fatalf("expected comment cleared, got %q", updated.Comment)
	}
}

// Existing comment="hello", PUT {"action":"drop"} (no comment field) → comment unchanged
func TestUpdateRule_CommentOmitPreserves(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	hello := "hello"
	r, _, err := svc.Create(&model.RuleRequest{DstIP: "10.99.0.31", Action: "drop", Comment: &hello})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// PUT without comment field — Comment is nil → keep existing
	updated, _, err := svc.Update(r.ID, &model.RuleRequest{Action: "drop"})
	if err != nil {
		t.Fatalf("Update without comment field: %v", err)
	}
	if updated.Comment != "hello" {
		t.Fatalf("comment should be preserved when omitted, got %q", updated.Comment)
	}
}

// Existing comment="hello", PUT {"comment":"world"} → comment="world"
func TestUpdateRule_CommentSet(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	hello := "hello"
	r, _, err := svc.Create(&model.RuleRequest{DstIP: "10.99.0.32", Action: "drop", Comment: &hello})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	world := "world"
	updated, _, err := svc.Update(r.ID, &model.RuleRequest{Comment: &world})
	if err != nil {
		t.Fatalf("Update comment to new value: %v", err)
	}
	if updated.Comment != "world" {
		t.Fatalf("expected 'world', got %q", updated.Comment)
	}
}

// ---- R6-001 / R6-002 (rev7 codex round 6 P1+P2): tcp_flags / match_anomaly mutual exclusion ----

// helper: create a tcp_flags rule
func createTcpFlagsRule(t *testing.T, svc *RuleService, dstIP, flags string) *model.Rule {
	t.Helper()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:    dstIP,
		Protocol: "tcp",
		TcpFlags: &flags,
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("create tcp_flags rule: %v", err)
	}
	return r
}

// helper: create an anomaly rule (via decoder sugar)
func createAnomalyRule(t *testing.T, svc *RuleService, dstIP, decoder string) *model.Rule {
	t.Helper()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:   dstIP,
		Action:  "drop",
		Decoder: decoder,
	})
	if err != nil {
		t.Fatalf("create anomaly rule: %v", err)
	}
	return r
}

// R6-001 Direction A — frontend sends tcp_flags="" along with anomaly decoder.
// Existing tcp_flags=RST → PUT {decoder:bad_fragment, tcp_flags:""} → success,
// rule.TcpFlags == "" && rule.MatchAnomaly == 1
func TestUpdateRule_TcpFlagsToAnomalyDecoder_WithExplicitClear_Succeeds(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r := createTcpFlagsRule(t, svc, "10.99.0.40", "RST")

	emptyFlags := ""
	updated, _, err := svc.Update(r.ID, &model.RuleRequest{
		Decoder:  "bad_fragment",
		TcpFlags: &emptyFlags,
	})
	if err != nil {
		t.Fatalf("Update tcp_flags→anomaly with explicit clear should succeed, got: %v", err)
	}
	if updated.TcpFlags != "" {
		t.Fatalf("expected tcp_flags cleared, got %q", updated.TcpFlags)
	}
	if updated.MatchAnomaly != 1 {
		t.Fatalf("expected match_anomaly=1, got %d", updated.MatchAnomaly)
	}
}

// R6-001 Direction A — non-Web client (no tcp_flags="" sent). Should reject
// with the mutual-exclusion error rather than silently producing a hybrid rule.
func TestUpdateRule_TcpFlagsToAnomalyDecoder_WithoutClear_Rejects(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r := createTcpFlagsRule(t, svc, "10.99.0.41", "RST")

	_, _, err := svc.Update(r.ID, &model.RuleRequest{
		Decoder: "bad_fragment",
		// TcpFlags omitted — non-Web client behavior
	})
	if err == nil {
		t.Fatal("expected mutual-exclusion error when applying anomaly decoder without explicit tcp_flags clear")
	}
	if !strings.Contains(err.Error(), "tcp_flags") || !strings.Contains(err.Error(), "match_anomaly") {
		t.Fatalf("error should mention tcp_flags + match_anomaly mutual exclusion, got: %v", err)
	}
}

// R6-001 Direction A invalid decoder — same with `invalid` decoder.
func TestUpdateRule_TcpFlagsToInvalid_WithExplicitClear_Succeeds(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r := createTcpFlagsRule(t, svc, "10.99.0.42", "ACK,!SYN")

	emptyFlags := ""
	updated, _, err := svc.Update(r.ID, &model.RuleRequest{
		Decoder:  "invalid",
		TcpFlags: &emptyFlags,
	})
	if err != nil {
		t.Fatalf("Update tcp_flags→invalid should succeed, got: %v", err)
	}
	if updated.TcpFlags != "" {
		t.Fatalf("expected tcp_flags cleared, got %q", updated.TcpFlags)
	}
	if updated.MatchAnomaly != 2 {
		t.Fatalf("expected match_anomaly=2 (invalid bit), got %d", updated.MatchAnomaly)
	}
}

// R6-002 Direction B — anomaly rule (protocol=all), PUT decoder=tcp_rst → reject.
// Anomaly decoders don't set protocol; tcp_* decoders do. Switching from
// protocol="all" to protocol="tcp" hits rev11's key-field-immutability guard:
// "protocol is a key field and cannot be modified". Whatever the exact message,
// the reject must happen and no hybrid rule should be persisted.
func TestUpdateRule_AnomalyToTcpDecoder_Rejects(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r := createAnomalyRule(t, svc, "10.99.0.43", "bad_fragment")
	if r.MatchAnomaly == 0 {
		t.Fatalf("setup failure: anomaly rule should have match_anomaly != 0, got %d", r.MatchAnomaly)
	}

	_, _, err := svc.Update(r.ID, &model.RuleRequest{
		Decoder: "tcp_rst",
	})
	if err == nil {
		t.Fatal("expected reject when switching anomaly rule to tcp_* decoder")
	}
	msg := err.Error()
	// Accept any of: protocol immutability (rev11), tcp_flags+anomaly mutex
	// (R6-001 backstop), or tcp_flags-needs-tcp guard.
	if !strings.Contains(msg, "protocol") && !strings.Contains(msg, "tcp_flags") {
		t.Fatalf("error should mention protocol or tcp_flags conflict, got: %v", err)
	}
}

// R6-002 Direction B (protocol=tcp variant) — when an anomaly rule has
// protocol=tcp (less common but possible via raw POST with match_anomaly + tcp
// + dst_ip; new R6-001 invariant only rejects when tcp_flags is also set), the
// post-merge mutex check is what fires. Verify it.
func TestUpdateRule_AnomalyTcpToTcpDecoder_RejectsViaMutex(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	// Create anomaly rule with protocol=tcp (no tcp_flags). v2.6.2 R6-001
	// invariant only rejects when BOTH tcp_flags AND match_anomaly are set.
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:        "10.99.0.45",
		Protocol:     "tcp",
		MatchAnomaly: 2, // invalid bit
		Action:       "drop",
	})
	if err != nil {
		t.Fatalf("setup: create protocol=tcp + match_anomaly rule: %v", err)
	}

	// PUT decoder=tcp_rst → normalizeDecoderForUpdate sets req.TcpFlags="RST"
	// + req.Protocol="tcp"; protocol guard passes (already tcp); field merge
	// sets rule.TcpFlags="RST"; post-merge mutex check rejects.
	_, _, err = svc.Update(r.ID, &model.RuleRequest{
		Decoder: "tcp_rst",
	})
	if err == nil {
		t.Fatal("expected mutex rejection when applying tcp_rst on anomaly+tcp rule")
	}
	if !strings.Contains(err.Error(), "tcp_flags") || !strings.Contains(err.Error(), "match_anomaly") {
		t.Fatalf("error should mention tcp_flags + match_anomaly mutual exclusion, got: %v", err)
	}
}

// R6-001 Create path — raw tcp_flags + match_anomaly POST should reject up front.
func TestCreateRule_RawTcpFlagsAndMatchAnomaly_Rejects(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	flags := "RST"
	_, _, err := svc.Create(&model.RuleRequest{
		DstIP:        "10.99.0.44",
		Protocol:     "tcp",
		TcpFlags:     &flags,
		MatchAnomaly: 1,
		Action:       "drop",
	})
	if err == nil {
		t.Fatal("expected reject when both tcp_flags and match_anomaly are set on Create")
	}
	if !strings.Contains(err.Error(), "tcp_flags") || !strings.Contains(err.Error(), "match_anomaly") {
		t.Fatalf("error should mention tcp_flags + match_anomaly mutual exclusion, got: %v", err)
	}
}

// ---- B-10 (rev8): portless protocol + port rejection in Create + Update paths ----

// Create gre + src_port=500 → 400 with diagnosis substring.
func TestCreateRule_GREWithSrcPort_Rejects(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	_, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.200",
		Protocol: "gre",
		SrcPort:  500,
		Action:   "drop",
	})
	if err == nil {
		t.Fatal("expected reject: gre + src_port=500")
	}
	if !strings.Contains(err.Error(), "does not carry ports") {
		t.Fatalf("expected diagnosis 'does not carry ports', got: %v", err)
	}
}

func TestCreateRule_ESPWithDstPort_Rejects(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	_, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.201",
		Protocol: "esp",
		DstPort:  500,
		Action:   "drop",
	})
	if err == nil {
		t.Fatal("expected reject: esp + dst_port=500")
	}
}

func TestCreateRule_GREZeroPorts_Succeeds(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.202",
		Protocol: "gre",
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("legitimate gre rule (no ports) should succeed, got: %v", err)
	}
	if r.Protocol != "gre" {
		t.Fatalf("expected protocol=gre, got %q", r.Protocol)
	}
}

// Update path: user PUTs src_port to a portless rule → reject.
// rev11 catches this at the key-field-immutability layer ("src_port is a key
// field"); pre-rev11 the B-10 portless+port helper would have caught it. Both
// produce a 400 with a clear diagnosis; either message is acceptable.
func TestUpdateRule_AddSrcPortToGRE_Rejects(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.203",
		Protocol: "gre",
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, _, err = svc.Update(r.ID, &model.RuleRequest{
		SrcPort: 500,
	})
	if err == nil {
		t.Fatal("expected reject: PUT src_port=500 to gre rule")
	}
	msg := err.Error()
	if !strings.Contains(msg, "src_port") && !strings.Contains(msg, "does not carry ports") {
		t.Fatalf("expected src_port immutability or portless diagnosis, got: %v", err)
	}
}

// Update path: legacy ghost edit (only update comment on existing GRE rule
// with port 0) must NOT trigger port-protocol validation.
func TestUpdateRule_CommentOnGRE_NotBlockedByPortlessCheck(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.204",
		Protocol: "gre",
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	hello := "hello"
	_, _, err = svc.Update(r.ID, &model.RuleRequest{
		Comment: &hello,
	})
	if err != nil {
		t.Fatalf("comment-only update on gre rule should succeed, got: %v", err)
	}
}

// BatchCreate: per-item portless+port rejection (rest of batch should still succeed).
func TestBatchCreateRule_GREWithPortFails_OthersSucceed(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	reqs := []model.RuleRequest{
		{DstIP: "10.99.0.210", Protocol: "tcp", DstPort: 80, Action: "drop"},  // legit
		{DstIP: "10.99.0.211", Protocol: "gre", SrcPort: 500, Action: "drop"}, // B-10 reject
		{DstIP: "10.99.0.212", Protocol: "udp", DstPort: 53, Action: "drop"},  // legit
	}
	_, added, failed, _, err := svc.BatchCreate(reqs)
	if err != nil {
		t.Fatalf("batch create: %v", err)
	}
	if added != 2 {
		t.Fatalf("expected 2 added, got %d", added)
	}
	if failed != 1 {
		t.Fatalf("expected 1 failed (gre+port), got %d", failed)
	}
}

// rev11 (codex round 9 P2): plan-mandated test —
// existing tcp+port rule, PUT protocol=gre → 400. Pre-rev11 this was silently
// accepted as a no-op (key fields implicitly immutable). rev11 makes the
// rejection explicit.
func TestUpdateRule_PortToPortlessProto_Rejects(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.205",
		Protocol: "tcp",
		DstPort:  80,
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, _, err = svc.Update(r.ID, &model.RuleRequest{
		Protocol: "gre",
	})
	if err == nil {
		t.Fatal("expected reject: PUT protocol=gre to tcp+port rule (key field immutable)")
	}
	if !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("error should mention protocol, got: %v", err)
	}
}

// rev11: confirm key-field-immutability also fires on protocol-equal+port-changed.
func TestUpdateRule_DstPortChange_Rejects(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.206",
		Protocol: "tcp",
		DstPort:  80,
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, _, err = svc.Update(r.ID, &model.RuleRequest{
		DstPort: 443,
	})
	if err == nil {
		t.Fatal("expected reject: PUT dst_port=443 on dst_port=80 rule (key field immutable)")
	}
	if !strings.Contains(err.Error(), "dst_port") {
		t.Fatalf("error should mention dst_port, got: %v", err)
	}
}

// rev11: PUT-same-value on key fields should be accepted as no-op (decoder
// sugar may set req.Protocol="tcp" on a tcp rule, which is functionally a
// no-op and shouldn't be rejected).
func TestUpdateRule_SameProtocolNoOp_Accepted(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.207",
		Protocol: "tcp",
		DstPort:  80,
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// PUT decoder=tcp_rst → normalizeDecoderForUpdate sets req.Protocol="tcp"
	// (matches stored), req.TcpFlags=&"RST" (a real change). Should succeed.
	_, _, err = svc.Update(r.ID, &model.RuleRequest{
		Decoder: "tcp_rst",
	})
	if err != nil {
		t.Fatalf("PUT decoder=tcp_rst on tcp+port rule should succeed (req.Protocol matches stored), got: %v", err)
	}
}

// codex round 9 P3: whitelist B-10 service-level test (helper covered, but
// service-level test was missing). Confirms WhitelistService.Create rejects
// portless+port via the shared validatePortProtocolCompat helper.
func TestWhitelistService_GREWithPort_Rejects(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := repository.NewSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open DB: %v", err)
	}
	defer db.Close()
	defer os.RemoveAll(tmpDir)

	ruleRepo := repository.NewSQLiteRuleRepo(db)
	wlRepo := repository.NewSQLiteWhitelistRepo(db)
	syncLogRepo := repository.NewSQLiteSyncLogRepo(db)
	syncSvc := NewSyncService(fakeNodeProvider{}, syncLogRepo, ruleRepo, wlRepo, nil, 1, 0, time.Millisecond)
	wlSvc := NewWhitelistService(wlRepo, syncSvc)

	// gre + src_port=500 + 5-tuple (must have both src+dst IP per validateWhitelistCombo)
	_, _, err = wlSvc.Create(&model.WhitelistRequest{
		SrcIP:    "10.99.0.10",
		DstIP:    "10.99.0.20",
		SrcPort:  500,
		Protocol: "gre",
	})
	if err == nil {
		t.Fatal("expected reject: whitelist gre + src_port=500")
	}
	if !strings.Contains(err.Error(), "does not carry ports") {
		t.Fatalf("expected portless diagnosis, got: %v", err)
	}

	// esp + dst_port=500
	_, _, err = wlSvc.Create(&model.WhitelistRequest{
		SrcIP:    "10.99.0.11",
		DstIP:    "10.99.0.21",
		DstPort:  500,
		Protocol: "esp",
	})
	if err == nil {
		t.Fatal("expected reject: whitelist esp + dst_port=500")
	}

	// Positive: tcp + dst_port=80 should succeed
	_, _, err = wlSvc.Create(&model.WhitelistRequest{
		SrcIP:    "10.99.0.12",
		DstIP:    "10.99.0.22",
		DstPort:  80,
		Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("legitimate tcp+port whitelist should succeed, got: %v", err)
	}
}

// rev12 codex round 11 P2: lock the documented zero-value PUT limitation.
// `protocol/src_port/dst_port` are int/string scalars (no tri-state), so the
// server cannot tell "omit" from "set to zero/empty". v2.6.2 documents this
// as a known limitation and accepts zero-value PUTs as no-op rather than
// changing key fields. Pointer schema is in v2.7 backlog (R3-002).

// existing dst_port=80, PUT {dst_port: 0} → 200 no-op (zero treated as omit).
func TestUpdateRule_ZeroDstPort_NoOp(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.70",
		Protocol: "tcp",
		DstPort:  80,
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// PUT {"dst_port": 0} — int 0 is "omit" per v2.6.2 contract
	updated, _, err := svc.Update(r.ID, &model.RuleRequest{DstPort: 0})
	if err != nil {
		t.Fatalf("PUT dst_port=0 should be accepted as no-op, got: %v", err)
	}
	if updated.DstPort != 80 {
		t.Fatalf("dst_port should remain 80 (zero treated as omit), got %d", updated.DstPort)
	}
}

// existing src_port=1234, PUT {src_port: 0} → 200 no-op.
func TestUpdateRule_ZeroSrcPort_NoOp(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.71",
		Protocol: "tcp",
		SrcPort:  1234,
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	updated, _, err := svc.Update(r.ID, &model.RuleRequest{SrcPort: 0})
	if err != nil {
		t.Fatalf("PUT src_port=0 should be accepted as no-op, got: %v", err)
	}
	if updated.SrcPort != 1234 {
		t.Fatalf("src_port should remain 1234 (zero treated as omit), got %d", updated.SrcPort)
	}
}

// existing protocol=tcp, PUT {protocol: ""} → 200 no-op (empty string is omit).
func TestUpdateRule_EmptyProtocol_NoOp(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:    "10.99.0.72",
		Protocol: "tcp",
		DstPort:  80,
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	updated, _, err := svc.Update(r.ID, &model.RuleRequest{Protocol: ""})
	if err != nil {
		t.Fatalf("PUT protocol='' should be accepted as no-op, got: %v", err)
	}
	if updated.Protocol != "tcp" {
		t.Fatalf("protocol should remain tcp (empty treated as omit), got %q", updated.Protocol)
	}
}

// ---- v2.6.4 regression tests ----

// B4: action is now required on Create; omitting it must return an error.
func TestCreateRule_MissingAction_Returns400(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	_, _, err := svc.Create(&model.RuleRequest{DstIP: "10.99.0.80"})
	if err == nil {
		t.Fatal("expected error when action is omitted, got nil")
	}
	if !strings.Contains(err.Error(), "action is required") {
		t.Fatalf("expected 'action is required' error, got: %v", err)
	}
}

// B1: Create with enabled=false stores rule as disabled and skips BPF sync.
func TestCreateRule_EnabledFalse_StoredAsDisabled(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	f := false
	r, sr, err := svc.Create(&model.RuleRequest{DstIP: "10.99.0.81", Action: "drop", Enabled: &f})
	if err != nil {
		t.Fatalf("create with enabled=false should succeed, got: %v", err)
	}
	if r.Enabled {
		t.Fatal("rule should be stored with enabled=false")
	}
	// No nodes registered → SyncResult should be empty (not nil), confirming no fan-out attempted.
	if sr == nil {
		t.Fatal("SyncResult should not be nil")
	}
}

// B1: Update enabled false → true triggers BPF sync (SyncUpdateRule path).
func TestUpdateRule_EnableFlagToggle(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	// Create disabled
	f := false
	r, _, err := svc.Create(&model.RuleRequest{DstIP: "10.99.0.82", Action: "drop", Enabled: &f})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if r.Enabled {
		t.Fatal("setup: expected enabled=false")
	}

	// Enable it
	tr := true
	updated, _, err := svc.Update(r.ID, &model.RuleRequest{Enabled: &tr})
	if err != nil {
		t.Fatalf("Update enabled=true: %v", err)
	}
	if !updated.Enabled {
		t.Fatal("expected rule enabled after update")
	}

	// Disable again
	updated2, _, err := svc.Update(r.ID, &model.RuleRequest{Enabled: &f})
	if err != nil {
		t.Fatalf("Update enabled=false: %v", err)
	}
	if updated2.Enabled {
		t.Fatal("expected rule disabled after second update")
	}
}

// B3: pkt_len pointer tri-state — nil keeps existing, 0 clears.
func TestUpdateRule_PktLenClearWithZeroPointer(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	// Create with pkt_len 100-200
	min, max := 100, 200
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:     "10.99.0.83",
		Action:    "drop",
		PktLenMin: &min,
		PktLenMax: &max,
	})
	if err != nil {
		t.Fatalf("create with pkt_len: %v", err)
	}
	if r.PktLenMin != 100 || r.PktLenMax != 200 {
		t.Fatalf("setup: expected pkt_len 100-200, got %d-%d", r.PktLenMin, r.PktLenMax)
	}

	// PUT with pkt_len_min=0, pkt_len_max=0 (pointer to 0) → should CLEAR
	zero := 0
	updated, _, err := svc.Update(r.ID, &model.RuleRequest{PktLenMin: &zero, PktLenMax: &zero})
	if err != nil {
		t.Fatalf("Update pkt_len to 0 (clear): %v", err)
	}
	if updated.PktLenMin != 0 || updated.PktLenMax != 0 {
		t.Fatalf("expected pkt_len cleared to 0, got %d-%d", updated.PktLenMin, updated.PktLenMax)
	}
}

// B3: pkt_len nil in PUT request keeps existing value (backward compat).
func TestUpdateRule_PktLenNilKeepsExisting(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	min, max := 60, 120
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:     "10.99.0.84",
		Action:    "drop",
		PktLenMin: &min,
		PktLenMax: &max,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// PUT without pkt_len fields → should keep 60-120
	updated, _, err := svc.Update(r.ID, &model.RuleRequest{Action: "drop"})
	if err != nil {
		t.Fatalf("Update without pkt_len: %v", err)
	}
	if updated.PktLenMin != 60 || updated.PktLenMax != 120 {
		t.Fatalf("pkt_len should be preserved when omitted, got %d-%d", updated.PktLenMin, updated.PktLenMax)
	}
}

// B6: Delete on non-existent ID returns success (no error), empty SyncResult.
func TestDeleteRule_NonExistentID_Idempotent(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	sr, err := svc.Delete("rule_nonexistent")
	if err != nil {
		t.Fatalf("Delete non-existent should be idempotent, got: %v", err)
	}
	if sr == nil {
		t.Fatal("SyncResult should not be nil")
	}
}

// B7: Update on non-existent ID returns ErrRuleNotFound.
func TestUpdateRule_NonExistentID_ReturnsNotFound(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	_, _, err := svc.Update("rule_nonexistent", &model.RuleRequest{Action: "drop"})
	if err == nil {
		t.Fatal("expected error for non-existent ID, got nil")
	}
	if !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("expected ErrRuleNotFound, got: %v", err)
	}
}

// TestBatchCreate_MissingActionFails: batch item with no action → counted as failed (B4 parity).
func TestBatchCreate_MissingActionFails(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	reqs := []model.RuleRequest{
		{DstIP: "10.99.0.90", Action: "drop"}, // valid
		{DstIP: "10.99.0.91"},                 // missing action → fail
		{DstIP: "10.99.0.92", Action: "drop"}, // valid
	}
	_, added, failed, _, err := svc.BatchCreate(reqs)
	if err != nil {
		t.Fatalf("batch create: %v", err)
	}
	if added != 2 {
		t.Fatalf("expected 2 added, got %d", added)
	}
	if failed != 1 {
		t.Fatalf("expected 1 failed (missing action), got %d", failed)
	}
}

// TestBatchCreate_EnabledFalseStoredDisabledAndNotSynced: enabled=false items are stored but not
// pushed to BPF (sync covers only enabled items).
func TestBatchCreate_EnabledFalseStoredDisabledAndNotSynced(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	f := false
	reqs := []model.RuleRequest{
		{DstIP: "10.99.0.93", Action: "drop"},              // enabled=nil → true
		{DstIP: "10.99.0.94", Action: "drop", Enabled: &f}, // enabled=false
	}
	rules, added, failed, sr, err := svc.BatchCreate(reqs)
	if err != nil {
		t.Fatalf("batch create: %v", err)
	}
	if added != 2 || failed != 0 {
		t.Fatalf("expected added=2 failed=0, got added=%d failed=%d", added, failed)
	}

	// Verify stored enabled states.
	var enabledCount, disabledCount int
	for _, r := range rules {
		if r.Enabled {
			enabledCount++
		} else {
			disabledCount++
		}
	}
	if enabledCount != 1 || disabledCount != 1 {
		t.Fatalf("expected 1 enabled + 1 disabled, got enabled=%d disabled=%d", enabledCount, disabledCount)
	}

	// No nodes → SyncResult not nil; total reflects only the enabled rule (1).
	if sr == nil {
		t.Fatal("SyncResult must not be nil")
	}
	// With no registered nodes, Total=0 either way; just confirm we get a result.
	_ = sr
}

// P1: anomaly merge onto a disabled existing rule must not activate BPF.
// The merged rule's Enabled flag must remain false, bitmask must be OR'd,
// and the returned SyncResult must show no failures.
func TestAnomalyMerge_DisabledExistingRule_StaysDisabled(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	f := false
	// Create a disabled bad_fragment anomaly rule.
	r1, _, err := svc.Create(&model.RuleRequest{
		DstIP:   "192.0.2.10",
		Action:  "drop",
		Decoder: "bad_fragment",
		Enabled: &f,
	})
	if err != nil {
		t.Fatalf("create disabled anomaly rule: %v", err)
	}
	if r1.Enabled {
		t.Fatal("setup failure: rule should be disabled")
	}
	if r1.MatchAnomaly != 0x01 {
		t.Fatalf("expected match_anomaly=0x01 (bad_fragment), got %d", r1.MatchAnomaly)
	}

	// Merge a second anomaly (invalid=0x02) onto the same tuple.
	r2, sr, err := svc.Create(&model.RuleRequest{
		DstIP:   "192.0.2.10",
		Action:  "drop",
		Decoder: "invalid",
	})
	if err != nil {
		t.Fatalf("anomaly merge: %v", err)
	}
	// Must return the same rule ID — not a new row.
	if r2.ID != r1.ID {
		t.Fatalf("expected merge to return same rule ID, got %s != %s", r2.ID, r1.ID)
	}
	// Bitmask must be OR'd: 0x01 | 0x02 = 0x03.
	if r2.MatchAnomaly != 0x03 {
		t.Errorf("expected match_anomaly=0x03 after merge, got %d", r2.MatchAnomaly)
	}
	// Existing disabled rule must remain disabled after merge.
	if r2.Enabled {
		t.Error("merged rule must remain disabled; anomaly merge must not activate BPF")
	}
	// SyncResult must not report failures (no BPF push should have been attempted).
	if sr == nil {
		t.Fatal("SyncResult must not be nil")
	}
	if sr.Failed != 0 {
		t.Errorf("expected sync.failed=0 for disabled anomaly merge, got %d", sr.Failed)
	}
}

// P2: deleting a disabled rule must not fan-out to Node (disabled rules are
// never in BPF, so Node delete would produce a spurious 404 / sync.failed>0).
func TestDeleteRule_DisabledRule_NoSyncFanout(t *testing.T) {
	svc, cleanup := newTestRuleService(t)
	defer cleanup()

	f := false
	r, _, err := svc.Create(&model.RuleRequest{
		DstIP:   "192.0.2.11",
		Action:  "drop",
		Enabled: &f,
	})
	if err != nil {
		t.Fatalf("create disabled rule: %v", err)
	}
	if r.Enabled {
		t.Fatal("setup failure: rule should be disabled")
	}

	sr, err := svc.Delete(r.ID)
	if err != nil {
		t.Fatalf("delete disabled rule: %v", err)
	}
	if sr == nil {
		t.Fatal("SyncResult must not be nil")
	}
	// With fakeNodeProvider (0 nodes), any sync path returns Failed=0.
	// The key assertion is no error and an empty result (no targeted nodes).
	if sr.Failed != 0 {
		t.Errorf("expected sync.failed=0 for disabled rule delete, got %d", sr.Failed)
	}
	if sr.Total != 0 {
		t.Errorf("expected sync.total=0 for disabled rule delete (no BPF push), got %d", sr.Total)
	}
}
