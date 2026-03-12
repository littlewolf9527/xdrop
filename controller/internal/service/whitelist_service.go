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

// validateWhitelistCombo validates that the whitelist combo is supported by BPF datapath.
// BPF only supports: exact 5-tuple, src_ip-only, dst_ip-only.
func validateWhitelistCombo(req *model.WhitelistRequest) error {
	hasIP := req.SrcIP != "" || req.DstIP != ""
	hasPortOrProto := req.SrcPort != 0 || req.DstPort != 0 ||
		(req.Protocol != "" && req.Protocol != "all")
	hasBothIPs := req.SrcIP != "" && req.DstIP != ""

	if !hasIP && hasPortOrProto {
		return fmt.Errorf("whitelist with port/protocol but no IP is not supported; BPF whitelist only matches: exact 5-tuple, src_ip-only, or dst_ip-only")
	}
	if hasIP && !hasBothIPs && hasPortOrProto {
		return fmt.Errorf("whitelist with port/protocol requires both src_ip and dst_ip (exact 5-tuple)")
	}
	return nil
}

// Create adds a new whitelist entry.
func (s *WhitelistService) Create(req *model.WhitelistRequest) (*model.Whitelist, *SyncResult, error) {
	if err := validateProtocol(req.Protocol); err != nil {
		return nil, nil, err
	}
	if err := validateWhitelistCombo(req); err != nil {
		return nil, nil, err
	}

	entry := &model.Whitelist{
		ID:        "wl_" + uuid.New().String()[:8],
		Name:      req.Name,
		SrcIP:     req.SrcIP,
		DstIP:     req.DstIP,
		SrcPort:   req.SrcPort,
		DstPort:   req.DstPort,
		Protocol:  req.Protocol,
		Comment:   req.Comment,
		CreatedAt: time.Now(),
	}

	if err := s.repo.Create(entry); err != nil {
		return nil, nil, err
	}

	// Sync to nodes (waits for completion)
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
