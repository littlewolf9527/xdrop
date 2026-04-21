// anomaly_merge_test.go — v2.6.1 Phase 4 B5 Controller-side anomaly merge
// unit tests, covering proposal §7.2.1 committed 方案 a.
//
// Tests run against a real SQLite repo (t.TempDir() database) + a stub
// SyncService so that Create flow exercises the full merge path end-to-end
// (GetByTuple → tryAnomalyMerge → repo.Update → SyncUpdateRule).
//
// Covers:
//   - P4-UT-28 TestAnomalyUpsertMergeSameAction
//   - P4-UT-29 TestAnomalyConflictDifferentAction
//   - P4-UT-30 TestAnomalyConflictWithNonAnomalyRule
//   - P4-UT-31 (partial) anomaly merge idempotency
//   - Merge for CIDR path (not explicitly numbered in proposal §13)
//
// See proposal §7.2.1 / §7.8 / §13.4.3.
package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/client"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
)

// emptyNodeProvider returns no nodes — syncs become no-ops.
type emptyNodeProvider struct{}

func (emptyNodeProvider) List() ([]*model.Node, error)        { return nil, nil }
func (emptyNodeProvider) Get(id string) (*model.Node, error)  { return nil, nil }
func (emptyNodeProvider) UpdateStatus(id, status string)      {}
func (emptyNodeProvider) UpdateLastSeen(id string)            {}
func (emptyNodeProvider) UpdateLastSync(id string)            {}

// newAnomalyTestService builds a RuleService backed by a fresh SQLite repo
// in a temp dir. The SyncService is wired to an empty node provider so
// syncs are no-ops — we're testing the service-layer merge logic, not
// remote sync.
func newAnomalyTestService(t *testing.T) *RuleService {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "anomaly_merge.db")
	db, err := repository.NewSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	repo := repository.NewSQLiteRuleRepo(db)
	// WhitelistRepo / SyncLogRepo are needed by SyncService but not exercised
	// when NodeProvider.List returns empty. Pass nil-equivalent.
	wlRepo := repository.NewSQLiteWhitelistRepo(db)
	logRepo := repository.NewSQLiteSyncLogRepo(db)
	nc := client.NewNodeClient(2*time.Second)
	sync := NewSyncService(emptyNodeProvider{}, logRepo, repo, wlRepo, nc, 1, 0, 1*time.Second)

	return NewRuleService(repo, sync)
}

func TestAnomalyUpsertMergeSameAction(t *testing.T) {
	// P4-UT-28: same tuple + same action + different anomaly decoders → merge.
	s := newAnomalyTestService(t)

	// First rule: bad_fragment (0x01) drop on 10.99.0.3.
	r1, _, err := s.Create(&model.RuleRequest{
		Decoder: "bad_fragment",
		DstIP:   "10.99.0.3",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("create bad_fragment: %v", err)
	}
	if r1.MatchAnomaly != int(AnomalyBadFragment) {
		t.Fatalf("first rule MatchAnomaly = %d, want %d", r1.MatchAnomaly, AnomalyBadFragment)
	}

	// Second rule: invalid (0x02) drop on same tuple → merge.
	r2, _, err := s.Create(&model.RuleRequest{
		Decoder: "invalid",
		DstIP:   "10.99.0.3",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("expected merge success, got error: %v", err)
	}
	if r2.ID != r1.ID {
		t.Errorf("merge returned different rule ID: got %q want %q (expected upsert on existing)", r2.ID, r1.ID)
	}
	if r2.MatchAnomaly != int(AnomalyBadFragment|AnomalyInvalid) {
		t.Errorf("merged MatchAnomaly = 0x%x, want 0x%x (bad_fragment|invalid=0x03)",
			r2.MatchAnomaly, AnomalyBadFragment|AnomalyInvalid)
	}

	// Verify persisted state.
	fetched, err := s.Get(r1.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fetched.MatchAnomaly != int(AnomalyBadFragment|AnomalyInvalid) {
		t.Errorf("persisted MatchAnomaly = 0x%x, want 0x%x", fetched.MatchAnomaly, AnomalyBadFragment|AnomalyInvalid)
	}

	// And only one rule exists (no duplicate).
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 rule after merge, got %d", len(all))
	}
}

func TestAnomalyConflictDifferentAction(t *testing.T) {
	// P4-UT-29 (updated v2.6.1 post-codex round 9): originally this test
	// verified "two anomaly rules on the same tuple with different actions
	// → 409 no-merge". Post-round-9, the Controller rejects rate_limit on
	// anomaly rules entirely (only drop is allowed for anomaly in v2.6.1),
	// so "two anomaly rules with different actions" is structurally
	// impossible. We now exercise the blocking path at the decoder
	// normalization layer — this IS the new guard that prevents the
	// "different-action anomaly rule" scenario from existing in the first
	// place.
	s := newAnomalyTestService(t)

	_, _, err := s.Create(&model.RuleRequest{
		Decoder: "bad_fragment",
		DstIP:   "10.99.0.3",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Attempting to add a second anomaly rule on the same tuple with a
	// non-drop action must fail — the normalizeDecoder rate_limit guard
	// fires before merge logic runs.
	_, _, err = s.Create(&model.RuleRequest{
		Decoder:   "invalid",
		DstIP:     "10.99.0.3",
		Action:    "rate_limit",
		RateLimit: 1000,
	})
	if err == nil {
		t.Fatal("expected rate_limit-on-anomaly rejection, got nil")
	}
	t.Logf("got expected rejection: %v", err)
}

func TestAnomalyConflictWithNonAnomalyRule(t *testing.T) {
	// P4-UT-30: existing non-anomaly rule + incoming anomaly → 409.
	s := newAnomalyTestService(t)

	// Create non-anomaly rule first.
	_, _, err := s.Create(&model.RuleRequest{
		DstIP:  "10.99.0.3",
		Action: "drop",
	})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Try to add anomaly rule on same tuple.
	_, _, err = s.Create(&model.RuleRequest{
		Decoder: "bad_fragment",
		DstIP:   "10.99.0.3",
		Action:  "drop",
	})
	if err == nil {
		t.Fatal("expected conflict error (non-anomaly + anomaly), got nil")
	}
	t.Logf("got expected non-anomaly conflict: %v", err)
}

func TestAnomalyMergeIdempotent(t *testing.T) {
	// Posting the SAME decoder twice on the same tuple → merge is a no-op
	// but should NOT error (idempotent).
	s := newAnomalyTestService(t)

	r1, _, err := s.Create(&model.RuleRequest{
		Decoder: "bad_fragment",
		DstIP:   "10.99.0.3",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	r2, _, err := s.Create(&model.RuleRequest{
		Decoder: "bad_fragment",
		DstIP:   "10.99.0.3",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("idempotent merge should succeed, got: %v", err)
	}
	if r2.ID != r1.ID {
		t.Errorf("idempotent merge returned different rule ID: %q vs %q", r2.ID, r1.ID)
	}
	if r2.MatchAnomaly != int(AnomalyBadFragment) {
		t.Errorf("idempotent merge changed MatchAnomaly: 0x%x", r2.MatchAnomaly)
	}
}

func TestAnomalyMergeOnCIDR(t *testing.T) {
	// P4-UT-34: merge also works on CIDR tuples.
	s := newAnomalyTestService(t)

	_, _, err := s.Create(&model.RuleRequest{
		Decoder: "bad_fragment",
		DstCIDR: "10.99.0.0/24",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("first CIDR create: %v", err)
	}

	r2, _, err := s.Create(&model.RuleRequest{
		Decoder: "invalid",
		DstCIDR: "10.99.0.0/24",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("CIDR merge should succeed: %v", err)
	}
	if r2.MatchAnomaly != int(AnomalyBadFragment|AnomalyInvalid) {
		t.Errorf("CIDR merged MatchAnomaly = 0x%x, want 0x%x",
			r2.MatchAnomaly, AnomalyBadFragment|AnomalyInvalid)
	}

	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("CIDR merge should produce 1 rule, got %d", len(all))
	}
}

func TestAnomalyMergeDedupCIDRvsSingleIP(t *testing.T) {
	// Verify CIDR and single-IP tuples are treated as DISTINCT for merge
	// purposes — the same "decoder" posted once with dst_ip and once with
	// dst_cidr should create two separate rules, not merge.
	s := newAnomalyTestService(t)

	r1, _, err := s.Create(&model.RuleRequest{
		Decoder: "bad_fragment",
		DstIP:   "10.99.0.3",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("create dst_ip: %v", err)
	}

	r2, _, err := s.Create(&model.RuleRequest{
		Decoder: "bad_fragment",
		DstCIDR: "10.99.0.0/24",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("create dst_cidr: %v", err)
	}

	if r1.ID == r2.ID {
		t.Errorf("dst_ip and dst_cidr tuples should be distinct rules; got same ID %q", r1.ID)
	}

	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 rules (exact + CIDR), got %d", len(all))
	}
}

func TestAnomalyPutReplacesNotMerge(t *testing.T) {
	// P4-UT-31 (proposal §13.4.3): PUT replaces match_anomaly, does NOT merge.
	// This is the "explicit" API — user wants the exact value they sent.
	// Create-path merge is for convenience; Update-path is for precision.
	s := newAnomalyTestService(t)

	// Start with anomaly=0x03 rule (bad_fragment | invalid).
	r1, _, err := s.Create(&model.RuleRequest{
		Decoder: "bad_fragment",
		DstIP:   "10.99.0.3",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("create bad_fragment: %v", err)
	}
	_, _, err = s.Create(&model.RuleRequest{
		Decoder: "invalid",
		DstIP:   "10.99.0.3",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("merge invalid: %v", err)
	}
	verifyAnomaly(t, s, r1.ID, int(AnomalyBadFragment|AnomalyInvalid), "pre-PUT baseline")

	// PUT decoder:bad_fragment → match_anomaly should REPLACE to 0x01 (not merge).
	_, _, err = s.Update(r1.ID, &model.RuleRequest{
		Decoder: "bad_fragment",
		Action:  "drop",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	verifyAnomaly(t, s, r1.ID, int(AnomalyBadFragment),
		"PUT bad_fragment should REPLACE 0x03 with 0x01 (not OR-merge to 0x03)")
}

// verifyAnomaly fetches rule by ID and asserts its MatchAnomaly value.
func verifyAnomaly(t *testing.T, s *RuleService, id string, want int, context string) {
	t.Helper()
	r, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get %s: %v", id, err)
	}
	if r.MatchAnomaly != want {
		t.Errorf("%s: MatchAnomaly = 0x%x, want 0x%x", context, r.MatchAnomaly, want)
	}
}

func TestAnomalyPutIPv6ScopeGuard(t *testing.T) {
	// Update-path IPv6 scope guard: the relaxed "no explicit target"
	// in normalizeDecoderForUpdate MUST still reject bad_fragment when
	// the existing rule's target is IPv6. Rationale: the scope guard's
	// purpose is to reject combinations xdrop can't actually detect in
	// BPF (IPv6 bad_fragment is deferred to v1.4 — see proposal §7.4.1).
	// Update doesn't get to sneak past the guard just because the target
	// is implicit.
	s := newAnomalyTestService(t)

	// Create a benign rule on an IPv6 target — non-anomaly, so this is
	// allowed.
	r, _, err := s.Create(&model.RuleRequest{
		Protocol: "tcp",
		DstIP:    "2001:db8::1",
		Action:   "drop",
	})
	if err != nil {
		t.Fatalf("create v6 base rule: %v", err)
	}

	// Now PUT decoder:bad_fragment on it — must be rejected by scope guard,
	// NOT silently accepted.
	_, _, err = s.Update(r.ID, &model.RuleRequest{
		Decoder: "bad_fragment",
		Action:  "drop",
	})
	if err == nil {
		t.Fatal("expected IPv6 scope guard to reject PUT decoder:bad_fragment on v6 target; got nil")
	}
	// Reuse the round-6 audit's stable diagnosis substring so the test
	// breaks if someone accidentally loosens the Update-path guard.
	if !containsString(err.Error(), "not supported for IPv6") {
		t.Errorf("expected 'not supported for IPv6' in diagnosis; got: %v", err)
	}

	// Verify rule MatchAnomaly wasn't mutated by the failed update.
	fetched, err := s.Get(r.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fetched.MatchAnomaly != 0 {
		t.Errorf("failed PUT should not mutate MatchAnomaly; got 0x%x", fetched.MatchAnomaly)
	}
}

// containsString is a tiny helper to avoid pulling in strings.Contains
// visibility through a lint in the test-only path. Standard strings pkg
// is already imported elsewhere but keeping the helper local makes
// regexp-free substring assertions obvious.
func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) &&
		(haystack == needle ||
			(len(needle) > 0 && indexOf(haystack, needle) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestAnomalyNonAnomalyDuplicatePreservesLegacyError(t *testing.T) {
	// When both rules are non-anomaly, the legacy "rule already exists"
	// behavior must still fire (the merge path should only activate for
	// anomaly-carrying requests).
	s := newAnomalyTestService(t)

	_, _, err := s.Create(&model.RuleRequest{
		DstIP:  "10.99.0.3",
		Action: "drop",
	})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	_, _, err = s.Create(&model.RuleRequest{
		DstIP:  "10.99.0.3",
		Action: "drop",
	})
	if err == nil {
		t.Fatal("expected 'rule already exists' for duplicate non-anomaly rule")
	}
	t.Logf("got expected legacy duplicate error: %v", err)
}
