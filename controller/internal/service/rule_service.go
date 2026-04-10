package service

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
)

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
	// Validate
	if req.Action == "" {
		req.Action = "drop"
	}
	if req.Action != "drop" && req.Action != "rate_limit" {
		return nil, nil, fmt.Errorf("invalid action: %s", req.Action)
	}
	if req.Action == "rate_limit" && req.RateLimit <= 0 {
		return nil, nil, fmt.Errorf("rate_limit must be > 0 for rate_limit action")
	}

	// Validate protocol
	if err := validateProtocol(req.Protocol); err != nil {
		return nil, nil, err
	}

	// Validate packet length rule
	if err := validatePktLenRule(req); err != nil {
		return nil, nil, err
	}

	// Validate CIDR rule
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

	// Check for duplicates
	protocol := req.Protocol
	if protocol == "" {
		protocol = "all"
	}
	if isCIDR {
		exists, err := s.repo.CIDRExists(req.SrcCIDR, req.DstCIDR, req.SrcPort, req.DstPort, protocol)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			return nil, nil, fmt.Errorf("CIDR rule already exists")
		}
	} else {
		exists, err := s.repo.Exists(req.SrcIP, req.DstIP, req.SrcPort, req.DstPort, protocol)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			return nil, nil, fmt.Errorf("rule already exists")
		}
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

	// Build rule
	rule := &model.Rule{
		ID:        "rule_" + uuid.New().String()[:8],
		Name:      req.Name,
		SrcIP:     req.SrcIP,
		DstIP:     req.DstIP,
		SrcCIDR:   req.SrcCIDR,
		DstCIDR:   req.DstCIDR,
		SrcPort:   req.SrcPort,
		DstPort:   req.DstPort,
		Protocol:  protocol,
		Action:    req.Action,
		RateLimit: req.RateLimit,
		PktLenMin: req.PktLenMin,
		PktLenMax: req.PktLenMax,
		TcpFlags:  derefString(req.TcpFlags),
		Source:    req.Source,
		Comment:   req.Comment,
		Enabled:   true,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		UpdatedAt: time.Now(),
	}

	if rule.Source == "" {
		rule.Source = "api"
	}

	if err := s.repo.Create(rule); err != nil {
		return nil, nil, err
	}

	// Sync to nodes (waits for completion)
	syncResult := s.syncService.SyncAddRule(rule)

	return rule, syncResult, nil
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
	rule, err := s.repo.Get(id)
	if err != nil {
		return nil, nil, err
	}

	// CIDR key fields cannot be modified (delete and recreate instead)
	if req.SrcCIDR != "" || req.DstCIDR != "" {
		return nil, nil, fmt.Errorf("CIDR key fields (src_cidr, dst_cidr) cannot be modified; delete and recreate the rule instead")
	}
	// IP key fields cannot be modified either
	if req.SrcIP != "" || req.DstIP != "" {
		return nil, nil, fmt.Errorf("IP key fields (src_ip, dst_ip) cannot be modified; delete and recreate the rule instead")
	}

	// Validate packet length rule using updated values
	tempReq := &model.RuleRequest{
		SrcIP:     rule.SrcIP,
		DstIP:     rule.DstIP,
		SrcPort:   rule.SrcPort,
		DstPort:   rule.DstPort,
		Protocol:  rule.Protocol,
		PktLenMin: req.PktLenMin,
		PktLenMax: req.PktLenMax,
	}
	// If length not specified in the request, keep existing values
	if req.PktLenMin == 0 && req.PktLenMax == 0 {
		tempReq.PktLenMin = rule.PktLenMin
		tempReq.PktLenMax = rule.PktLenMax
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

	// Apply field updates
	if req.Name != "" {
		rule.Name = req.Name
	}
	if req.Action != "" {
		rule.Action = req.Action
	}
	if req.RateLimit > 0 {
		rule.RateLimit = req.RateLimit
	}
	if req.PktLenMin > 0 || req.PktLenMax > 0 {
		rule.PktLenMin = req.PktLenMin
		rule.PktLenMax = req.PktLenMax
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
	if req.Comment != "" {
		rule.Comment = req.Comment
	}

	rule.UpdatedAt = time.Now()

	if err := s.repo.Update(rule); err != nil {
		return nil, nil, err
	}

	// Sync update to nodes (delete then re-add)
	syncResult := s.syncService.SyncUpdateRule(rule)

	return rule, syncResult, nil
}

// Delete removes a rule by ID.
func (s *RuleService) Delete(id string) (*SyncResult, error) {
	if err := s.repo.Delete(id); err != nil {
		return nil, err
	}

	// Sync deletion to nodes
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
		// Validate
		if req.Action == "" {
			req.Action = "drop"
		}
		if req.Action != "drop" && req.Action != "rate_limit" {
			failed++
			continue
		}
		if req.Action == "rate_limit" && req.RateLimit <= 0 {
			failed++
			continue
		}

		// Validate protocol
		if err := validateProtocol(req.Protocol); err != nil {
			failed++
			continue
		}

		// Validate packet length rule
		if err := validatePktLenRule(&req); err != nil {
			failed++
			continue
		}

		// Validate CIDR rule
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

		rule := &model.Rule{
			ID:        "rule_" + uuid.New().String()[:8],
			Name:      req.Name,
			SrcIP:     req.SrcIP,
			DstIP:     req.DstIP,
			SrcCIDR:   req.SrcCIDR,
			DstCIDR:   req.DstCIDR,
			SrcPort:   req.SrcPort,
			DstPort:   req.DstPort,
			Protocol:  protocol,
			Action:    req.Action,
			RateLimit: req.RateLimit,
			PktLenMin: req.PktLenMin,
			PktLenMax: req.PktLenMax,
			TcpFlags:  derefString(req.TcpFlags),
			Source:    req.Source,
			Comment:   req.Comment,
			Enabled:   true,
			CreatedAt: time.Now(),
			ExpiresAt: expiresAt,
			UpdatedAt: time.Now(),
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

	// Sync via node batch API (fast, lossless)
	syncResult := s.syncService.SyncAddRulesBatch(rules)

	return rules, len(rules), failed, syncResult, nil
}

// BatchDelete removes multiple rules by ID.
func (s *RuleService) BatchDelete(ids []string) (int, int, *SyncResult, error) {
	if len(ids) == 0 {
		return 0, 0, nil, nil
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
var validProtocols = map[string]bool{
	"all": true, "tcp": true, "udp": true, "icmp": true, "icmpv6": true, "": true,
}

// validateProtocol rejects protocol values outside the supported set.
func validateProtocol(protocol string) error {
	if !validProtocols[protocol] {
		return fmt.Errorf("invalid protocol %q: allowed values are all, tcp, udp, icmp, icmpv6", protocol)
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
	hasLengthFilter := req.PktLenMin > 0 || req.PktLenMax > 0
	has5Tuple := req.SrcIP != "" || req.DstIP != "" ||
		req.SrcCIDR != "" || req.DstCIDR != "" ||
		req.SrcPort != 0 || req.DstPort != 0 ||
		(req.Protocol != "" && req.Protocol != "all")

	if hasLengthFilter && !has5Tuple {
		return fmt.Errorf("pure length rules not allowed: must specify at least one of src_ip, dst_ip, src_port, dst_port, or protocol")
	}

	if req.PktLenMin > 0 && req.PktLenMax > 0 && req.PktLenMin > req.PktLenMax {
		return fmt.Errorf("invalid length range: min (%d) > max (%d)", req.PktLenMin, req.PktLenMax)
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
