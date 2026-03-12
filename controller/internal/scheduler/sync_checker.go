package scheduler

import (
	"log/slog"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/client"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

// SyncChecker periodically verifies that controller and node rules are in sync
type SyncChecker struct {
	nodeProvider service.NodeProvider
	ruleRepo     repository.RuleRepository
	wlRepo       repository.WhitelistRepository
	nodeClient   *client.NodeClient
	syncService  *service.SyncService
	interval     time.Duration
	stopCh       chan struct{}
}

// NewSyncChecker creates a new sync checker
func NewSyncChecker(
	nodeProvider service.NodeProvider,
	ruleRepo repository.RuleRepository,
	wlRepo repository.WhitelistRepository,
	nodeClient *client.NodeClient,
	syncService *service.SyncService,
	interval time.Duration,
) *SyncChecker {
	return &SyncChecker{
		nodeProvider: nodeProvider,
		ruleRepo:     ruleRepo,
		wlRepo:       wlRepo,
		nodeClient:   nodeClient,
		syncService:  syncService,
		interval:     interval,
		stopCh:       make(chan struct{}),
	}
}

// Start begins the periodic sync check loop
func (s *SyncChecker) Start() {
	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		slog.Info("Sync checker started", "interval", s.interval)

		for {
			select {
			case <-ticker.C:
				s.check()
			case <-s.stopCh:
				slog.Info("Sync checker stopped")
				return
			}
		}
	}()
}

// Stop halts the sync check loop
func (s *SyncChecker) Stop() {
	close(s.stopCh)
}

// check inspects the sync state of all online nodes
func (s *SyncChecker) check() {
	nodes, err := s.nodeProvider.List()
	if err != nil {
		slog.Error("Sync checker: failed to list nodes", "error", err)
		return
	}

	// Get the number of rules in the controller
	controllerRules, err := s.ruleRepo.ListEnabled()
	if err != nil {
		slog.Error("Sync checker: failed to list rules", "error", err)
		return
	}
	controllerCount := len(controllerRules)

	wlEntries, err := s.wlRepo.List()
	if err != nil {
		slog.Error("Sync checker: failed to list whitelist", "error", err)
		return
	}

	for _, node := range nodes {
		if node.Status == model.NodeStatusOffline {
			continue
		}

		go s.checkNode(node, controllerRules, wlEntries, controllerCount, len(wlEntries))
	}
}

// checkNode inspects the sync state of a single node
func (s *SyncChecker) checkNode(node *model.Node, rules []*model.Rule, whitelist []*model.Whitelist, controllerRuleCount int, controllerWlCount int) {
	// Fetch statistics from the node
	stats, err := s.nodeClient.GetStats(node.Endpoint, node.ApiKey)
	if err != nil {
		slog.Warn("Sync checker: failed to get node stats", "node", node.Name, "error", err)
		return
	}

	// Parse rules_count
	var nodeRuleCount int
	if rc, ok := stats["rules_count"].(float64); ok {
		nodeRuleCount = int(rc)
	} else if rc, ok := stats["rules_count"].(int); ok {
		nodeRuleCount = rc
	}

	// Parse whitelist_count
	var nodeWlCount int
	if wc, ok := stats["whitelist_count"].(float64); ok {
		nodeWlCount = int(wc)
	} else if wc, ok := stats["whitelist_count"].(int); ok {
		nodeWlCount = wc
	}

	// If rule or whitelist counts differ, trigger DiffSync (falls back to FullSync on failure)
	if nodeRuleCount != controllerRuleCount || nodeWlCount != controllerWlCount {
		slog.Warn("Sync checker: count mismatch, triggering diff sync",
			"node", node.Name,
			"controller_rules", controllerRuleCount,
			"node_rules", nodeRuleCount,
			"controller_whitelist", controllerWlCount,
			"node_whitelist", nodeWlCount,
		)

		err := s.syncService.DiffSyncToNode(node, rules, whitelist)
		if err != nil {
			slog.Error("Sync checker: diff sync failed", "node", node.Name, "error", err)
		} else {
			slog.Info("Sync checker: diff sync completed", "node", node.Name,
				"rules", controllerRuleCount, "whitelist", controllerWlCount)
		}
	}
}
