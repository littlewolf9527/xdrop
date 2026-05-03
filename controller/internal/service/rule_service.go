package service

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
)

// ErrRuleNotFound is returned by Update when the target rule does not exist.
// Callers can use errors.Is(err, ErrRuleNotFound) to distinguish from other errors
// and return a 404 response instead of a generic 400.
var ErrRuleNotFound = errors.New("rule not found")

// RuleService is the rule management service.
type RuleService struct {
	repo        repository.RuleRepository
	syncService *SyncService
}

// NewRuleService creates a new RuleService.
func NewRuleService(repo repository.RuleRepository, syncService *SyncService) *RuleService {
	return &RuleService{
		repo:        repo,
		syncService: syncService,
	}
}

// Create creates a new rule.
func (s *RuleService) Create(req *model.RuleRequest) (*model.Rule, *SyncResult, error) {
	// Phase 2 decoder sugar normalization (before any other validation so
	// downstream validators see the expanded predicate fields).
	if err := normalizeDecoder(req); err != nil {
		return nil, nil, err
	}

	// Validate — B4: action is required; no silent default.
	if req.Action == "" {
		return nil, nil, fmt.Errorf("action is required: specify \"drop\" or \"rate_limit\"")
	}
	if req.Action != "drop" && req.Action != "rate_limit" {
		return nil, nil, fmt.Errorf("invalid action: %s", req.Action)
	}
	if req.Action == "rate_limit" && req.RateLimit <= 0 {
		return nil, nil, fmt.Errorf("rate_limit must be > 0 for rate_limit action")
	}
	// B-1: IP format validation + IPv4-mapped normalize (before CIDR/anomaly checks)
	if err := validateIPFields(req); err != nil {
		return nil, nil, err
	}

	// AUD-006: scalar bounds (Create path: drop+rate_limit>0 is also rejected)
	if err := validateRuleScalarBounds(req); err != nil {
		return nil, nil, err
	}

	// Validate protocol
	if err := validateProtocol(req.Protocol); err != nil {
		return nil, nil, err
	}

	// B-10: portless protocols (icmp/icmpv6/igmp/gre/esp) cannot carry ports;
	// reject up front to avoid silent BPF dead rules.
	if err := validatePortProtocolCompat(req.Protocol, req.SrcPort, req.DstPort); err != nil {
		return nil, nil, err
	}

	// Validate packet length rule
	if err := validatePktLenRule(req); err != nil {
		return nil, nil, err
	}

	// Validate CIDR rule (normalizes req.SrcCIDR / req.DstCIDR to network address)
	// Must run before anomaly validation so hasBoundedAnomalyTarget sees normalized CIDRs.
	isCIDR := req.SrcCIDR != "" || req.DstCIDR != ""
	if isCIDR {
		if err := validateCIDRRule(req); err != nil {
			return nil, nil, err
		}
		// Overlap detection
		if err := s.checkCIDROverlap(req.SrcCIDR, req.DstCIDR); err != nil {
			return nil, nil, err
		}
	}

	// AUD-001: anomaly invariants — run after IP normalize (validateIPFields above)
	// and CIDR normalize (validateCIDRRule above) so hasBoundedAnomalyTarget sees
	// canonical strings.
	if err := validateAnomalyFields(req); err != nil {
		return nil, nil, err
	}

	// R6-001: tcp_flags and match_anomaly are mutually exclusive at the data
	// plane (anomaly_verify is a separate XDP program with its own combo
	// lookup; mixing fields produces a hybrid rule that no path actually
	// matches). Reject up front rather than letting it through.
	if derefString(req.TcpFlags) != "" && req.MatchAnomaly != 0 {
		return nil, nil, fmt.Errorf("rule cannot have both tcp_flags and match_anomaly: clear one before setting the other")
	}

	// Check for duplicates. v2.6.1 Phase 4 B5 (proposal §7.2.1 committed
	// 方案 a Controller merge): if the incoming request is an anomaly rule
	// (MatchAnomaly != 0) AND an existing rule with the same 5-tuple is
	// also anomaly-specialized AND has the same action, merge the anomaly
	// bitmask into the existing rule instead of rejecting. This lets
	// xSight push `decoder:bad_fragment` + `decoder:invalid` for the same
	// target without the client having to merge them.
	protocol := req.Protocol
	if protocol == "" {
		protocol = "all"
	}
	var existing *model.Rule
	var lookupErr error
	if isCIDR {
		existing, lookupErr = s.repo.GetByCIDRTuple(req.SrcCIDR, req.DstCIDR, req.SrcPort, req.DstPort, protocol)
	} else {
		existing, lookupErr = s.repo.GetByTuple(req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, protocol)
	}
	if lookupErr != nil {
		return nil, nil, lookupErr
	}
	if existing != nil {
		merged, mergeResult, mergeErr := s.tryAnomalyMerge(existing, req)
		if mergeErr != nil {
			return nil, nil, mergeErr
		}
		if merged != nil {
			// Merge succeeded — Update() + sync happened inside.
			return merged, mergeResult, nil
		}
		// merged == nil && err == nil means "not a merge candidate, proceed
		// to Create" — but the tuple already has a rule, so Create will
		// conflict via UNIQUE constraint. Return the legacy 409 message to
		// preserve backward-compatible error text.
		if isCIDR {
			return nil, nil, fmt.Errorf("CIDR rule already exists")
		}
		return nil, nil, fmt.Errorf("rule already exists")
	}

	// Compute expiry time
	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid expires_in: %s", req.ExpiresIn)
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}

	// Build rule — B1: respect Enabled *bool (default true when nil).
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	rule := &model.Rule{
		ID:           "rule_" + uuid.New().String()[:8],
		Name:         req.Name,
		SrcIP:        req.SrcIP,
		DstIP:        req.DstIP,
		SrcCIDR:      req.SrcCIDR,
		DstCIDR:      req.DstCIDR,
		SrcPort:      req.SrcPort,
		DstPort:      req.DstPort,
		Protocol:     protocol,
		Action:       req.Action,
		RateLimit:    req.RateLimit,
		PktLenMin:    derefInt(req.PktLenMin),
		PktLenMax:    derefInt(req.PktLenMax),
		TcpFlags:     derefString(req.TcpFlags),
		MatchAnomaly: req.MatchAnomaly, // v2.6 Phase 4
		Source:       req.Source,
		Comment:      derefString(req.Comment),
		Enabled:      enabled,
		CreatedAt:    time.Now(),
		ExpiresAt:    expiresAt,
		UpdatedAt:    time.Now(),
	}

	if rule.Source == "" {
		rule.Source = "api"
	}

	if err := s.repo.Create(rule); err != nil {
		return nil, nil, err
	}

	// Only sync to BPF when the rule is enabled.
	var syncResult *SyncResult
	if rule.Enabled {
		syncResult = s.syncService.SyncAddRule(rule)
	} else {
		syncResult = &SyncResult{}
	}

	return rule, syncResult, nil
}

// tryAnomalyMerge implements v2.6.1 Phase 4 B5 Controller-side anomaly merge
// (proposal §7.2.1 committed 方案 a). Given an existing rule on the same
// 5-tuple and an incoming request, decides between:
//
//   - (merged, result, nil)  — both are anomaly rules with same action → merged
//     via OR'd match_anomaly bitmask. Calls repo.Update + SyncUpdateRule.
//   - (nil, nil, 409 err)    — conflict (different action OR existing non-anomaly
//     AND incoming anomaly, etc.). Caller should return this error verbatim.
//   - (nil, nil, nil)        — not a merge candidate (both non-anomaly, or
//     incoming non-anomaly). Caller falls through to the legacy "rule already
//     exists" path.
//
// Merge rules (from §7.2.1):
//   - incoming MatchAnomaly == 0 → not a merge candidate (nil, nil, nil)
//   - incoming anomaly + existing non-anomaly → 409
//   - incoming anomaly + existing anomaly + different action → 409
//   - incoming anomaly + existing anomaly + same action → merge (OR bits)
func (s *RuleService) tryAnomalyMerge(existing *model.Rule, req *model.RuleRequest) (*model.Rule, *SyncResult, error) {
	// Only anomaly-carrying requests participate in merge.
	if req.MatchAnomaly == 0 {
		return nil, nil, nil
	}
	// Existing rule is not anomaly-specialized — refuse (proposal §7.2.1).
	if existing.MatchAnomaly == 0 {
		return nil, nil, fmt.Errorf(
			"rule already exists at this tuple without match_anomaly; refusing to merge anomaly bits onto a non-anomaly rule (delete the existing rule or use a different tuple)")
	}
	// Action mismatch — refuse; caller must resolve explicitly.
	if existing.Action != req.Action {
		return nil, nil, fmt.Errorf(
			"anomaly rule already exists at this tuple with action %q; refusing to merge with conflicting action %q",
			existing.Action, req.Action)
	}
	// Idempotent: if all the bits are already set, this is a no-op merge.
	// Still return the existing rule so the caller's API response looks like
	// a successful POST (201 with rule body), not a 409.
	before := existing.MatchAnomaly
	existing.MatchAnomaly |= req.MatchAnomaly
	if existing.MatchAnomaly == before {
		// Nothing changed — caller treats as successful "no-op merge" and
		// returns the existing rule. No need to re-sync.
		return existing, &SyncResult{}, nil
	}

	existing.UpdatedAt = time.Now()
	if err := s.repo.Update(existing); err != nil {
		// Revert the bitmask mutation on the in-memory rule so the caller
		// doesn't report a bogus merged state.
		existing.MatchAnomaly = before
		return nil, nil, fmt.Errorf("anomaly merge update failed: %w", err)
	}

	// Propagate the merged rule to all nodes only if the existing rule is enabled.
	// A disabled rule was never written to BPF, so merging bits into it must not
	// activate it on the data plane.
	var syncResult *SyncResult
	if existing.Enabled {
		syncResult = s.syncService.SyncUpdateRule(existing)
	} else {
		syncResult = &SyncResult{}
	}
	return existing, syncResult, nil
}

// Get retrieves a rule by ID.
func (s *RuleService) Get(id string) (*model.Rule, error) {
	return s.repo.Get(id)
}

// List returns all rules.
func (s *RuleService) List() ([]*model.Rule, error) {
	return s.repo.List()
}

// ListPaginated returns a paginated list of rules.
func (s *RuleService) ListPaginated(params repository.PaginationParams) ([]*model.Rule, *repository.PaginationResult, error) {
	return s.repo.ListPaginated(params)
}

// ListEnabled returns all enabled rules.
func (s *RuleService) ListEnabled() ([]*model.Rule, error) {
	return s.repo.ListEnabled()
}

// Update updates an existing rule.
func (s *RuleService) Update(id string, req *model.RuleRequest) (*model.Rule, *SyncResult, error) {
	// Fetch existing rule FIRST so decoder normalization (Update-path variant)
	// can seed the IPv6 scope guard with the rule's actual target.
	// B7: map sql.ErrNoRows → ErrRuleNotFound so the handler can return 404.
	rule, err := s.repo.Get(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, fmt.Errorf("%w", ErrRuleNotFound)
		}
		return nil, nil, err
	}

	// Phase 2/4 decoder sugar normalization (Update-path). Relaxes the
	// "anomaly decoder requires explicit target" gate because the existing
	// rule already has a tuple — but still runs IPv6 scope guard and
	// protocol/tcp_flags mutex checks.
	if err := normalizeDecoderForUpdate(req, rule); err != nil {
		return nil, nil, err
	}

	// CIDR key fields cannot be modified (delete and recreate instead)
	if req.SrcCIDR != "" || req.DstCIDR != "" {
		return nil, nil, fmt.Errorf("CIDR key fields (src_cidr, dst_cidr) cannot be modified; delete and recreate the rule instead")
	}
	// B-1: validate IP format before the "key fields cannot be modified" check so
	// the caller gets a useful diagnosis instead of "cannot be modified" for garbage input.
	if err := validateIPFields(req); err != nil {
		return nil, nil, err
	}
	// IP key fields cannot be modified either
	if req.SrcIP != "" || req.DstIP != "" {
		return nil, nil, fmt.Errorf("IP key fields (src_ip, dst_ip) cannot be modified; delete and recreate the rule instead")
	}

	// rev11 / codex round 9 P2: protocol and src_port/dst_port are also key
	// fields and cannot be modified. Previously these were implicitly
	// immutable (the field merge below never assigned them to the stored
	// rule), but client requests like `PUT protocol=gre` were silently
	// accepted as no-ops. Reject explicitly so callers get clear feedback
	// and so plan's `TestUpdateRule_PortToPortlessProto_Reject` matches.
	// This also obviates the B-10 effective-value validation for Update —
	// since key fields can't change, the existing rule's stored
	// (protocol, ports) was already validated at Create time.
	if req.Protocol != "" {
		// normalizeDecoderForUpdate sets req.Protocol when a tcp_* decoder is
		// applied, but it ALWAYS sets it to "tcp" for tcp_* decoders; if the
		// rule's existing protocol matches that's a no-op via decoder sugar.
		// Reject only when the request would change the protocol.
		if req.Protocol != rule.Protocol {
			return nil, nil, fmt.Errorf("protocol is a key field and cannot be modified (current: %s, requested: %s); delete and recreate the rule instead", rule.Protocol, req.Protocol)
		}
	}
	if req.SrcPort != 0 && req.SrcPort != rule.SrcPort {
		return nil, nil, fmt.Errorf("src_port is a key field and cannot be modified (current: %d, requested: %d); delete and recreate the rule instead", rule.SrcPort, req.SrcPort)
	}
	if req.DstPort != 0 && req.DstPort != rule.DstPort {
		return nil, nil, fmt.Errorf("dst_port is a key field and cannot be modified (current: %d, requested: %d); delete and recreate the rule instead", rule.DstPort, req.DstPort)
	}

	// AUD-006: scalar bounds on updatable fields
	if err := validateRuleScalarBounds(req); err != nil {
		return nil, nil, err
	}

	// AUD-001: anomaly invariants using effective values (existing rule provides target)
	if err := validateAnomalyFieldsForUpdate(req, rule); err != nil {
		return nil, nil, err
	}

	// Validate packet length rule using effective values.
	// B3: pkt_len is pointer tri-state — nil means "keep existing", non-nil (incl. 0) means "set".
	tempReq := &model.RuleRequest{
		SrcIP:    rule.SrcIP,
		DstIP:    rule.DstIP,
		SrcPort:  rule.SrcPort,
		DstPort:  rule.DstPort,
		Protocol: rule.Protocol,
	}
	if req.PktLenMin != nil {
		tempReq.PktLenMin = req.PktLenMin
	} else {
		tempReq.PktLenMin = intPtr(rule.PktLenMin)
	}
	if req.PktLenMax != nil {
		tempReq.PktLenMax = req.PktLenMax
	} else {
		tempReq.PktLenMax = intPtr(rule.PktLenMax)
	}
	if err := validatePktLenRule(tempReq); err != nil {
		return nil, nil, err
	}

	// Validate action value
	if req.Action != "" && req.Action != "drop" && req.Action != "rate_limit" {
		return nil, nil, fmt.Errorf("invalid action: %q (valid: drop, rate_limit)", req.Action)
	}

	// Validate action/rate_limit consistency
	effectiveAction := rule.Action
	if req.Action != "" {
		effectiveAction = req.Action
	}
	effectiveRateLimit := rule.RateLimit
	if req.RateLimit > 0 {
		effectiveRateLimit = req.RateLimit
	}
	if effectiveAction == "rate_limit" && effectiveRateLimit <= 0 {
		return nil, nil, fmt.Errorf("rate_limit must be > 0 for rate_limit action")
	}
	// AUD-006 / R4-003: explicit positive rate_limit with effective drop is a conflict
	if req.RateLimit > 0 && effectiveAction == "drop" {
		return nil, nil, fmt.Errorf("rate_limit > 0 conflicts with action=drop; remove rate_limit or change action to rate_limit")
	}

	// Apply field updates
	if req.Name != "" {
		rule.Name = req.Name
	}
	if req.Action != "" {
		rule.Action = req.Action
	}
	// AUD-006 / R3-002: auto-clear rate_limit when action transitions to drop
	if effectiveAction == "drop" {
		rule.RateLimit = 0
	} else if req.RateLimit > 0 {
		rule.RateLimit = req.RateLimit
	}
	// B3: pointer tri-state — nil=omit (keep), non-nil (including 0) = set.
	if req.PktLenMin != nil {
		rule.PktLenMin = *req.PktLenMin
	}
	if req.PktLenMax != nil {
		rule.PktLenMax = *req.PktLenMax
	}
	// tcp_flags: pointer tri-state — nil=omit (keep existing), ""=clear, "SYN"=set
	// Validate against the PERSISTED protocol, not the request protocol (AUD-R2-01)
	if req.TcpFlags != nil {
		if *req.TcpFlags != "" {
			if rule.Protocol != "tcp" {
				return nil, nil, fmt.Errorf("tcp_flags can only be used with protocol=tcp (current rule protocol: %s)", rule.Protocol)
			}
			normalized, err := validateAndNormalizeTcpFlags(*req.TcpFlags)
			if err != nil {
				return nil, nil, err
			}
			rule.TcpFlags = normalized
		} else {
			rule.TcpFlags = "" // explicit clear
		}
	}
	// v2.6.1 Phase 4 B5 (proposal §13.4.3 P4-UT-31): PUT **replaces** the
	// match_anomaly bitmask rather than merging it. Merge semantics are
	// Create-path only (§7.2.1); PUT is the explicit "I want this exact
	// value" API. req.MatchAnomaly is set by normalizeDecoder (when Decoder
	// field provided) or directly by the caller.
	//
	// Note: MatchAnomaly=0 in the request is ambiguous (0 = not set, or
	// 0 = user wants to clear anomaly specialization?). For now we only
	// apply when non-zero — matches tcp_flags's tri-state pattern loosely
	// but not exactly. Explicit clear will land with a pointer-based
	// tri-state if a user ever needs it; v2.6.1 scope stops here.
	if req.MatchAnomaly != 0 {
		rule.MatchAnomaly = req.MatchAnomaly
	}
	// B1: Enabled pointer tri-state — nil = keep existing value.
	prevEnabled := rule.Enabled
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}

	// B-9: Comment is pointer tri-state — nil means "keep existing", non-nil
	// (including "") means "set to this value", so explicit clear works.
	if req.Comment != nil {
		rule.Comment = *req.Comment
	}

	// R6-001 / R6-002: tcp_flags and match_anomaly are mutually exclusive at the
	// data plane. Catches both edit directions:
	//   A. existing tcp_flags rule + decoder=bad_fragment: req.TcpFlags must be
	//      explicitly cleared (frontend sends tcp_flags=""), or this rejects
	//   B. existing anomaly rule + decoder=tcp_rst: match_anomaly's int schema
	//      can't be explicit-cleared via PUT, so we reject here. Frontend
	//      should disable tcp_* decoders for anomaly rows + hint
	//      "delete and recreate to switch type"
	if rule.TcpFlags != "" && rule.MatchAnomaly != 0 {
		return nil, nil, fmt.Errorf("rule cannot have both tcp_flags and match_anomaly: clear one before setting the other (set tcp_flags=\"\" in the request, or for anomaly→tcp_flags switch, delete and recreate the rule)")
	}

	rule.UpdatedAt = time.Now()

	if err := s.repo.Update(rule); err != nil {
		return nil, nil, err
	}

	// Sync to BPF based on enabled state transition.
	var syncResult *SyncResult
	switch {
	case prevEnabled && rule.Enabled:
		// enabled → enabled: update in place.
		syncResult = s.syncService.SyncUpdateRule(rule)
	case !prevEnabled && rule.Enabled:
		// disabled → enabled: rule was never in BPF, use add (not update/delete+add).
		syncResult = s.syncService.SyncAddRule(rule)
	case prevEnabled && !rule.Enabled:
		// enabled → disabled: remove from BPF.
		syncResult = s.syncService.SyncDeleteRule(rule.ID)
	default:
		// disabled → disabled: no BPF change needed.
		syncResult = &SyncResult{}
	}

	return rule, syncResult, nil
}

// Delete removes a rule by ID.
// B6: idempotent — if the rule does not exist in DB we skip the Node fan-out
// and return success, matching Batch DELETE behaviour.
// P2: only fan-out SyncDeleteRule when the rule was enabled; a disabled rule
// was never written to BPF so Node delete would produce a spurious 404.
func (s *RuleService) Delete(id string) (*SyncResult, error) {
	// Read the rule first to capture its enabled state before deletion.
	rule, err := s.repo.Get(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &SyncResult{}, nil // idempotent
		}
		return nil, err
	}
	wasEnabled := rule.Enabled

	found, err := s.repo.Delete(id)
	if err != nil {
		return nil, err
	}
	if !found {
		// Raced with another delete — no BPF state to clean up.
		return &SyncResult{}, nil
	}

	if !wasEnabled {
		// Rule was never in BPF; skip Node fan-out.
		return &SyncResult{}, nil
	}

	syncResult := s.syncService.SyncDeleteRule(id)
	return syncResult, nil
}

// DeleteExpired removes all expired rules.
func (s *RuleService) DeleteExpired() (int, error) {
	return s.repo.DeleteExpired()
}

// BatchCreate creates multiple rules in a transaction with batch sync.
func (s *RuleService) BatchCreate(reqs []model.RuleRequest) ([]*model.Rule, int, int, *SyncResult, error) {
	var rules []*model.Rule
	failed := 0

	// Track pending CIDRs within this batch for intra-batch overlap detection
	var pendingSrcCIDRs, pendingDstCIDRs []string
	// Track seen rule keys within this batch for intra-batch duplicate detection
	seenKeys := make(map[string]bool)

	for _, req := range reqs {
		// Phase 2 decoder sugar (per-item; failure increments `failed` per the
		// existing partial-success semantics, matches proposal §5.4 P2-UT-10).
		if err := normalizeDecoder(&req); err != nil {
			failed++
			continue
		}

		// Validate — B4: action is required in batch too; missing action is a per-item failure.
		if req.Action == "" {
			failed++
			continue
		}
		if req.Action != "drop" && req.Action != "rate_limit" {
			failed++
			continue
		}
		if req.Action == "rate_limit" && req.RateLimit <= 0 {
			failed++
			continue
		}

		// B-1: IP format validation + normalize
		if err := validateIPFields(&req); err != nil {
			failed++
			continue
		}

		// AUD-006: scalar bounds
		if err := validateRuleScalarBounds(&req); err != nil {
			failed++
			continue
		}

		// Validate protocol
		if err := validateProtocol(req.Protocol); err != nil {
			failed++
			continue
		}

		// B-10: portless protocol + port → BPF dead rule. Reject up front.
		if err := validatePortProtocolCompat(req.Protocol, req.SrcPort, req.DstPort); err != nil {
			failed++
			continue
		}

		// Validate packet length rule
		if err := validatePktLenRule(&req); err != nil {
			failed++
			continue
		}

		// Validate CIDR rule (normalizes CIDRs — must run before anomaly check)
		if req.SrcCIDR != "" || req.DstCIDR != "" {
			if err := validateCIDRRule(&req); err != nil {
				failed++
				continue
			}
			// Check overlap against DB
			if err := s.checkCIDROverlap(req.SrcCIDR, req.DstCIDR); err != nil {
				failed++
				continue
			}
			// Check overlap against pending items in this batch
			if req.SrcCIDR != "" {
				if conflict := findCIDROverlap(req.SrcCIDR, pendingSrcCIDRs); conflict != "" {
					failed++
					continue
				}
			}
			if req.DstCIDR != "" {
				if conflict := findCIDROverlap(req.DstCIDR, pendingDstCIDRs); conflict != "" {
					failed++
					continue
				}
			}
		}

		// AUD-001: anomaly invariants — after IP and CIDR normalize
		if err := validateAnomalyFields(&req); err != nil {
			failed++
			continue
		}

		// R6-001: tcp_flags + match_anomaly are mutually exclusive (see Create path)
		if derefString(req.TcpFlags) != "" && req.MatchAnomaly != 0 {
			failed++
			continue
		}

		protocol := req.Protocol
		if protocol == "" {
			protocol = "all"
		}

		// Duplicate precheck (same as Create()) to avoid transaction abort
		isCIDR := req.SrcCIDR != "" || req.DstCIDR != ""
		if isCIDR {
			exists, err := s.repo.CIDRExists(req.SrcCIDR, req.DstCIDR, req.SrcPort, req.DstPort, protocol)
			if err != nil {
				failed++
				continue
			}
			if exists {
				failed++
				continue
			}
		} else {
			exists, err := s.repo.Exists(req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, protocol)
			if err != nil {
				failed++
				continue
			}
			if exists {
				failed++
				continue
			}
		}

		// Intra-batch duplicate detection
		var batchKey string
		if isCIDR {
			batchKey = fmt.Sprintf("cidr:%s:%s:%d:%d:%s", req.SrcCIDR, req.DstCIDR, req.SrcPort, req.DstPort, protocol)
		} else {
			batchKey = fmt.Sprintf("ip:%s:%s:%d:%d:%s", req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, protocol)
		}
		if seenKeys[batchKey] {
			failed++
			continue
		}
		seenKeys[batchKey] = true

		// Compute expiry time
		var expiresAt *time.Time
		if req.ExpiresIn != "" {
			d, err := time.ParseDuration(req.ExpiresIn)
			if err == nil {
				t := time.Now().Add(d)
				expiresAt = &t
			}
		}

		// B1: respect Enabled *bool per item (nil defaults to true).
		itemEnabled := true
		if req.Enabled != nil {
			itemEnabled = *req.Enabled
		}
		rule := &model.Rule{
			ID:           "rule_" + uuid.New().String()[:8],
			Name:         req.Name,
			SrcIP:        req.SrcIP,
			DstIP:        req.DstIP,
			SrcCIDR:      req.SrcCIDR,
			DstCIDR:      req.DstCIDR,
			SrcPort:      req.SrcPort,
			DstPort:      req.DstPort,
			Protocol:     protocol,
			Action:       req.Action,
			RateLimit:    req.RateLimit,
			PktLenMin:    derefInt(req.PktLenMin),
			PktLenMax:    derefInt(req.PktLenMax),
			TcpFlags:     derefString(req.TcpFlags),
			MatchAnomaly: req.MatchAnomaly, // v2.6 Phase 4
			Source:       req.Source,
			Comment:      derefString(req.Comment),
			Enabled:      itemEnabled,
			CreatedAt:    time.Now(),
			ExpiresAt:    expiresAt,
			UpdatedAt:    time.Now(),
		}
		if rule.Source == "" {
			rule.Source = "api"
		}

		// Track pending CIDRs for intra-batch overlap detection
		if req.SrcCIDR != "" {
			pendingSrcCIDRs = append(pendingSrcCIDRs, req.SrcCIDR)
		}
		if req.DstCIDR != "" {
			pendingDstCIDRs = append(pendingDstCIDRs, req.DstCIDR)
		}

		rules = append(rules, rule)
	}

	// Transactional batch insert
	if len(rules) > 0 {
		if err := s.repo.BatchCreate(rules); err != nil {
			return nil, 0, len(reqs), nil, err
		}
	}

	// Sync only enabled rules to BPF (disabled rules are stored in DB but not
	// pushed to the data plane until explicitly enabled via PUT).
	var enabledRules []*model.Rule
	for _, r := range rules {
		if r.Enabled {
			enabledRules = append(enabledRules, r)
		}
	}
	var syncResult *SyncResult
	if len(enabledRules) > 0 {
		syncResult = s.syncService.SyncAddRulesBatch(enabledRules)
	} else {
		syncResult = &SyncResult{}
	}

	return rules, len(rules), failed, syncResult, nil
}

// BatchDelete removes multiple rules by ID.
func (s *RuleService) BatchDelete(ids []string) (int, int, *SyncResult, error) {
	if len(ids) == 0 {
		// rev9 codex round 8 P3: keep `sync` always-present in handler response
		// (B-2 contract). Return an empty SyncResult instead of nil so
		// syncToResponse() emits the field with zero counters.
		return 0, 0, &SyncResult{}, nil
	}

	// 1. Delete from local database first (transactional)
	if err := s.repo.BatchDelete(ids); err != nil {
		return 0, len(ids), nil, err
	}

	// 2. Full sync to all nodes to ensure consistency
	syncResult := s.syncService.FullSyncToAllNodes()

	return len(ids), 0, syncResult, nil
}

// checkCIDROverlap checks whether the new CIDR overlaps (contains or is contained by) any existing CIDR.
func (s *RuleService) checkCIDROverlap(srcCIDR, dstCIDR string) error {
	if srcCIDR != "" {
		existing, err := s.repo.ListSrcCIDRs()
		if err != nil {
			return fmt.Errorf("failed to list src CIDRs: %w", err)
		}
		if conflict := findCIDROverlap(srcCIDR, existing); conflict != "" {
			return fmt.Errorf("src_cidr overlap: %s conflicts with existing %s", srcCIDR, conflict)
		}
	}
	if dstCIDR != "" {
		existing, err := s.repo.ListDstCIDRs()
		if err != nil {
			return fmt.Errorf("failed to list dst CIDRs: %w", err)
		}
		if conflict := findCIDROverlap(dstCIDR, existing); conflict != "" {
			return fmt.Errorf("dst_cidr overlap: %s conflicts with existing %s", dstCIDR, conflict)
		}
	}
	return nil
}

// findCIDROverlap checks whether newCIDR overlaps with any CIDR in existing.
// Returns the conflicting CIDR string, or an empty string if no conflict.
func findCIDROverlap(newCIDR string, existing []string) string {
	_, newNet, err := net.ParseCIDR(newCIDR)
	if err != nil {
		return ""
	}
	newOnes, _ := newNet.Mask.Size()

	for _, e := range existing {
		if e == newCIDR {
			continue // exact duplicates are handled by CIDRExists
		}
		_, existNet, err := net.ParseCIDR(e)
		if err != nil {
			continue
		}
		existOnes, _ := existNet.Mask.Size()

		// Check containment: larger prefix contains smaller prefix
		if newOnes >= existOnes && existNet.Contains(newNet.IP) {
			return e // existing network contains new network
		}
		if existOnes >= newOnes && newNet.Contains(existNet.IP) {
			return e // new network contains existing network
		}
	}
	return ""
}

// validProtocols is the set of protocol values supported by the BPF datapath.
// v2.6 Phase 1: added gre / esp / igmp (IANA protocol numbers 47 / 50 / 2).
var validProtocols = map[string]bool{
	"all":    true,
	"tcp":    true,
	"udp":    true,
	"icmp":   true,
	"icmpv6": true,
	"igmp":   true,
	"gre":    true,
	"esp":    true,
	"":       true,
}

// portlessProtocols are L4 protocols that don't carry source/destination
// ports. The BPF datapath (xdrop.c parse_l4) only fills key.src_port /
// key.dst_port for PROTO_TCP and PROTO_UDP — every other protocol leaves
// the key ports at 0. Storing a rule with src_port=500 + protocol=gre
// makes the rule a permanent BPF lookup miss (rule key port=500 ≠ packet
// key port=0). B-10 rejects such ghost rules at the API boundary.
//
// "all" is NOT portless — it's a wildcard that may match TCP/UDP traffic,
// so the data plane will fill ports for those packets. Allowing port on
// "all" preserves the existing semantics.
var portlessProtocols = map[string]bool{
	"icmp":   true,
	"icmpv6": true,
	"igmp":   true,
	"gre":    true,
	"esp":    true,
}

// validatePortProtocolCompat rejects port values when the protocol cannot
// carry them. Empty protocol and "all" are allowed with ports (legacy
// wildcard semantics; see portlessProtocols comment).
func validatePortProtocolCompat(protocol string, srcPort, dstPort int) error {
	if !portlessProtocols[protocol] {
		return nil
	}
	if srcPort == 0 && dstPort == 0 {
		return nil
	}
	return fmt.Errorf(
		"protocol=%s does not carry ports (src_port/dst_port must be 0); got src_port=%d dst_port=%d",
		protocol, srcPort, dstPort)
}

// validateProtocol rejects protocol values outside the supported set.
func validateProtocol(protocol string) error {
	if !validProtocols[protocol] {
		return fmt.Errorf("invalid protocol %q: allowed values are all, tcp, udp, icmp, icmpv6, igmp, gre, esp", protocol)
	}
	return nil
}

// validateCIDRRule validates a CIDR rule:
// - at least one CIDR must be non-empty
// - CIDR format must be valid
// - exact IP and CIDR cannot be specified together
func validateCIDRRule(req *model.RuleRequest) error {
	if req.SrcCIDR == "" && req.DstCIDR == "" {
		return fmt.Errorf("at least one of src_cidr or dst_cidr must be specified")
	}
	// v1: reject any mix of exact IP and CIDR fields (even across opposite sides)
	// This matches the Node API which rejects hasCIDR && hasExactIP
	hasExactIP := req.SrcIP != "" || req.DstIP != ""
	if hasExactIP {
		return fmt.Errorf("cannot mix exact IP and CIDR fields in the same rule")
	}
	if req.SrcCIDR != "" {
		if _, _, err := net.ParseCIDR(req.SrcCIDR); err != nil {
			return fmt.Errorf("invalid src_cidr: %s", req.SrcCIDR)
		}
		// Normalize to network address
		_, network, _ := net.ParseCIDR(req.SrcCIDR)
		req.SrcCIDR = network.String()
	}
	if req.DstCIDR != "" {
		if _, _, err := net.ParseCIDR(req.DstCIDR); err != nil {
			return fmt.Errorf("invalid dst_cidr: %s", req.DstCIDR)
		}
		// Normalize to network address
		_, network, _ := net.ParseCIDR(req.DstCIDR)
		req.DstCIDR = network.String()
	}
	return nil
}

// validatePktLenRule validates packet length constraints.
// Pure length-only rules are not allowed: at least one 5-tuple field must be specified.
func validatePktLenRule(req *model.RuleRequest) error {
	pktMin := derefInt(req.PktLenMin)
	pktMax := derefInt(req.PktLenMax)
	hasLengthFilter := pktMin > 0 || pktMax > 0
	has5Tuple := req.SrcIP != "" || req.DstIP != "" ||
		req.SrcCIDR != "" || req.DstCIDR != "" ||
		req.SrcPort != 0 || req.DstPort != 0 ||
		(req.Protocol != "" && req.Protocol != "all")

	if hasLengthFilter && !has5Tuple {
		return fmt.Errorf("pure length rules not allowed: must specify at least one of src_ip, dst_ip, src_port, dst_port, or protocol")
	}

	if pktMin > 0 && pktMax > 0 && pktMin > pktMax {
		return fmt.Errorf("invalid length range: min (%d) > max (%d)", pktMin, pktMax)
	}

	// tcp_flags validation: syntax check + protocol=tcp requirement
	if req.TcpFlags != nil && *req.TcpFlags != "" {
		if req.Protocol != "tcp" {
			return fmt.Errorf("tcp_flags can only be used with protocol=tcp")
		}
		normalized, err := validateAndNormalizeTcpFlags(*req.TcpFlags)
		if err != nil {
			return err
		}
		req.TcpFlags = &normalized
	}

	return nil
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func intPtr(v int) *int { return &v }

// validateRuleScalarBounds checks that numeric fields fit Node-side types
// (uint16 for ports/pkt_len, uint32 for rate_limit) and rejects nonsensical
// combinations such as action=drop with a positive rate_limit. AUD-006.
func validateRuleScalarBounds(req *model.RuleRequest) error {
	if req.SrcPort < 0 || req.SrcPort > 65535 {
		return fmt.Errorf("src_port out of range [0,65535]: %d", req.SrcPort)
	}
	if req.DstPort < 0 || req.DstPort > 65535 {
		return fmt.Errorf("dst_port out of range [0,65535]: %d", req.DstPort)
	}
	if req.PktLenMin != nil {
		if v := *req.PktLenMin; v < 0 || v > 65535 {
			return fmt.Errorf("pkt_len_min out of range [0,65535]: %d", v)
		}
	}
	if req.PktLenMax != nil {
		if v := *req.PktLenMax; v < 0 || v > 65535 {
			return fmt.Errorf("pkt_len_max out of range [0,65535]: %d", v)
		}
	}
	if req.RateLimit < 0 {
		return fmt.Errorf("rate_limit must be non-negative: %d", req.RateLimit)
	}
	if req.RateLimit > math.MaxUint32 {
		return fmt.Errorf("rate_limit exceeds uint32 max: %d", req.RateLimit)
	}
	// action=drop with a positive rate_limit is a contradictory/redundant field.
	if req.Action == "drop" && req.RateLimit > 0 {
		return fmt.Errorf("rate_limit must be 0 when action=drop (got %d)", req.RateLimit)
	}
	return nil
}

// validateWhitelistScalarBounds checks port ranges for whitelist entries. AUD-006.
func validateWhitelistScalarBounds(req *model.WhitelistRequest) error {
	if req.SrcPort < 0 || req.SrcPort > 65535 {
		return fmt.Errorf("src_port out of range [0,65535]: %d", req.SrcPort)
	}
	if req.DstPort < 0 || req.DstPort > 65535 {
		return fmt.Errorf("dst_port out of range [0,65535]: %d", req.DstPort)
	}
	return nil
}

// validateAndNormalizeIPField validates and optionally normalizes a single IP
// string. Accepts empty string (means "any"). Rejects non-IP values (e.g.
// CIDR notation) with a diagnostic. IPv4-mapped IPv6 addresses are normalized
// to their IPv4 form to match Node ruleToKey behaviour. B-1.
func validateAndNormalizeIPField(field, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", fmt.Errorf("%s %q is not a valid IP address (for CIDR ranges use %s_cidr)", field, value, field[:3])
	}
	// Normalize IPv4-mapped IPv6 (e.g. ::ffff:1.2.3.4) → plain IPv4 to match
	// Node-side ip.To4() behaviour and avoid display format drift.
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String(), nil
	}
	return ip.String(), nil
}

// validateIPFields validates and normalizes src_ip / dst_ip on a RuleRequest. B-1.
func validateIPFields(req *model.RuleRequest) error {
	normalized, err := validateAndNormalizeIPField("src_ip", req.SrcIP)
	if err != nil {
		return err
	}
	req.SrcIP = normalized

	normalized, err = validateAndNormalizeIPField("dst_ip", req.DstIP)
	if err != nil {
		return err
	}
	req.DstIP = normalized
	return nil
}

// validateWhitelistIPFields validates src_ip / dst_ip on a WhitelistRequest. B-1.
func validateWhitelistIPFields(req *model.WhitelistRequest) error {
	normalized, err := validateAndNormalizeIPField("src_ip", req.SrcIP)
	if err != nil {
		return err
	}
	req.SrcIP = normalized

	normalized, err = validateAndNormalizeIPField("dst_ip", req.DstIP)
	if err != nil {
		return err
	}
	req.DstIP = normalized
	return nil
}

// validateAndNormalizeTcpFlags validates tcp_flags syntax and returns canonical form.
var validTcpFlags = map[string]bool{
	"FIN": true, "SYN": true, "RST": true, "PSH": true,
	"ACK": true, "URG": true, "ECE": true, "CWR": true,
}

func validateAndNormalizeTcpFlags(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	seen := make(map[string]bool)
	// Fixed canonical order (matches Node-side tcpFlagsToString)
	canonicalOrder := []string{"CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"}
	setFlags := make(map[string]bool)   // flags that must be 1
	clearFlags := make(map[string]bool) // flags that must be 0

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := strings.ToUpper(part)
		negate := false
		if strings.HasPrefix(name, "!") {
			negate = true
			name = name[1:]
		}
		if !validTcpFlags[name] {
			return "", fmt.Errorf("unknown TCP flag %q; valid: SYN, ACK, FIN, RST, PSH, URG, ECE, CWR", part)
		}
		if seen[name] {
			continue // deduplicate
		}
		seen[name] = true
		if negate {
			if setFlags[name] {
				return "", fmt.Errorf("contradictory TCP flags: both %s and !%s specified", name, name)
			}
			clearFlags[name] = true
		} else {
			if clearFlags[name] {
				return "", fmt.Errorf("contradictory TCP flags: both %s and !%s specified", name, name)
			}
			setFlags[name] = true
		}
	}

	// Emit in canonical order
	var parts []string
	for _, name := range canonicalOrder {
		if setFlags[name] {
			parts = append(parts, name)
		} else if clearFlags[name] {
			parts = append(parts, "!"+name)
		}
	}
	return strings.Join(parts, ","), nil
}
