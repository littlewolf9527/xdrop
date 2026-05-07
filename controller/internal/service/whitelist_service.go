package service

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
)

// WhitelistService manages whitelist entries.
type WhitelistService struct {
	repo        repository.WhitelistRepository
	syncService *SyncService
}

// NewWhitelistService creates a new WhitelistService.
func NewWhitelistService(repo repository.WhitelistRepository, syncService *SyncService) *WhitelistService {
	return &WhitelistService{
		repo:        repo,
		syncService: syncService,
	}
}

// normalizeWhitelistProtocol normalizes protocol to a canonical value.
// "" and "all" both map to protocol byte 0 on the Node, so treat them as the same key.
func normalizeWhitelistProtocol(proto string) string {
	if proto == "all" {
		return ""
	}
	return proto
}

// validateWhitelistCombo validates whitelist combo for Phase 8 (31-combo).
// Any non-empty five-tuple subset is valid except:
//   - completely empty (at least one field required)
//   - protocol="all" alone (would whitelist all traffic)
//   - portless protocol with port fields
func validateWhitelistCombo(req *model.WhitelistRequest) error {
	proto := normalizeWhitelistProtocol(req.Protocol)

	hasAnyField := req.SrcIP != "" || req.DstIP != "" ||
		req.SrcPort != 0 || req.DstPort != 0 || proto != ""
	if !hasAnyField {
		return fmt.Errorf("whitelist entry must have at least one field set")
	}

	// Reject protocol=all alone (no IP, no port) — would whitelist all traffic
	if req.Protocol == "all" && req.SrcIP == "" && req.DstIP == "" && req.SrcPort == 0 && req.DstPort == 0 {
		return fmt.Errorf("whitelist with protocol=all and no other fields would allow all traffic")
	}

	// All other non-empty subsets are valid in Phase 8
	return nil
}

// Create adds a new whitelist entry.
func (s *WhitelistService) Create(req *model.WhitelistRequest) (*model.Whitelist, *SyncResult, error) {
	// B-1: IP format validation + normalize
	if err := validateWhitelistIPFields(req); err != nil {
		return nil, nil, err
	}
	// AUD-006: scalar bounds
	if err := validateWhitelistScalarBounds(req); err != nil {
		return nil, nil, err
	}
	if err := validateProtocol(req.Protocol); err != nil {
		return nil, nil, err
	}
	// B-10: portless protocols cannot carry ports — same BPF reason as rules.
	if err := validatePortProtocolCompat(req.Protocol, req.SrcPort, req.DstPort); err != nil {
		return nil, nil, err
	}
	if err := validateWhitelistCombo(req); err != nil {
		return nil, nil, err
	}

	// Normalize protocol before persistence and duplicate check
	normalizedProtocol := normalizeWhitelistProtocol(req.Protocol)

	entry := &model.Whitelist{
		ID:        "wl_" + uuid.New().String()[:8],
		Name:      req.Name,
		SrcIP:     req.SrcIP,
		DstIP:     req.DstIP,
		SrcPort:   req.SrcPort,
		DstPort:   req.DstPort,
		Protocol:  normalizedProtocol,
		Comment:   req.Comment,
		CreatedAt: time.Now(),
	}

	if err := s.repo.Create(entry); err != nil {
		return nil, nil, err
	}

	syncResult := s.syncService.SyncAddWhitelist(entry)

	return entry, syncResult, nil
}

// Get retrieves a whitelist entry by ID.
func (s *WhitelistService) Get(id string) (*model.Whitelist, error) {
	return s.repo.Get(id)
}

// List returns all whitelist entries.
func (s *WhitelistService) List() ([]*model.Whitelist, error) {
	return s.repo.List()
}

// Delete removes a whitelist entry by ID.
func (s *WhitelistService) Delete(id string) (*SyncResult, error) {
	if err := s.repo.Delete(id); err != nil {
		return nil, err
	}

	// Sync deletion to nodes
	syncResult := s.syncService.SyncDeleteWhitelist(id)

	return syncResult, nil
}
