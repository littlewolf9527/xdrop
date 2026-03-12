package service

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/client"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
)

// NodeProvider is the interface for listing and updating nodes.
type NodeProvider interface {
	List() ([]*model.Node, error)
	Get(id string) (*model.Node, error)
	UpdateStatus(id string, status string)
	UpdateLastSeen(id string)
	UpdateLastSync(id string)
}

// SyncService manages rule synchronization to nodes.
type SyncService struct {
	nodeProvider  NodeProvider
	syncLogRepo   repository.SyncLogRepository
	ruleRepo      repository.RuleRepository
	wlRepo        repository.WhitelistRepository
	nodeClient    *client.NodeClient
	concurrent    int
	retryCount    int
	retryInterval time.Duration
	mu            sync.Mutex
}

// NewSyncService creates a new SyncService.
func NewSyncService(
	nodeProvider NodeProvider,
	syncLogRepo repository.SyncLogRepository,
	ruleRepo repository.RuleRepository,
	wlRepo repository.WhitelistRepository,
	nodeClient *client.NodeClient,
	concurrent int,
	retryCount int,
	retryInterval time.Duration,
) *SyncService {
	return &SyncService{
		nodeProvider:  nodeProvider,
		syncLogRepo:   syncLogRepo,
		ruleRepo:      ruleRepo,
		wlRepo:        wlRepo,
		nodeClient:    nodeClient,
		concurrent:    concurrent,
		retryCount:    retryCount,
		retryInterval: retryInterval,
	}
}

// SyncResult summarizes the outcome of a sync operation across all nodes.
type SyncResult struct {
	Total   int              `json:"total"`   // nodes targeted
	Success int              `json:"success"` // nodes succeeded
	Failed  int              `json:"failed"`  // nodes failed
	Errors  map[string]string `json:"errors,omitempty"` // node_name -> error
}

func newSyncResult() *SyncResult {
	return &SyncResult{Errors: make(map[string]string)}
}

// SyncAddRule syncs a new rule to all nodes (with retry).
func (s *SyncService) SyncAddRule(rule *model.Rule) *SyncResult {
	result := newSyncResult()
	nodes, err := s.nodeProvider.List()
	if err != nil {
		slog.Error("Failed to list nodes", "error", err)
		return result
	}

	sem := make(chan struct{}, s.concurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, node := range nodes {
		if node.Status == model.NodeStatusOffline {
			continue
		}
		result.Total++

		wg.Add(1)
		sem <- struct{}{}

		go func(n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()

			nodeRule := rule.ToNodeRule()

			var resp *client.Response
			var err error
			for attempt := 0; attempt <= s.retryCount; attempt++ {
				if attempt > 0 {
					time.Sleep(s.retryInterval)
					slog.Debug("Retrying add rule", "node", n.Name, "attempt", attempt)
				}
				resp, err = s.nodeClient.AddRule(n.Endpoint, n.ApiKey, nodeRule)
				if err == nil && resp.Success {
					break
				}
			}

			status := "success"
			errMsg := ""
			if err != nil {
				status = "failed"
				errMsg = err.Error()
				slog.Warn("Sync add rule failed", "node", n.Name, "error", err)
			} else if !resp.Success {
				status = "failed"
				errMsg = resp.Error
				slog.Warn("Node rejected rule", "node", n.Name, "error", resp.Error)
			}

			mu.Lock()
			if status == "success" {
				result.Success++
			} else {
				result.Failed++
				result.Errors[n.Name] = errMsg
			}
			mu.Unlock()

			s.syncLogRepo.Log(n.ID, "add_rule", rule.ID, status, errMsg)
		}(node)
	}

	wg.Wait()
	return result
}

// SyncAddRulesBatch syncs multiple rules to all nodes using the node batch API.
func (s *SyncService) SyncAddRulesBatch(rules []*model.Rule) *SyncResult {
	result := newSyncResult()
	if len(rules) == 0 {
		return result
	}

	nodes, err := s.nodeProvider.List()
	if err != nil {
		slog.Error("Failed to list nodes", "error", err)
		return result
	}

	var nodeRules []map[string]interface{}
	for _, r := range rules {
		nodeRules = append(nodeRules, r.ToNodeRule())
	}

	sem := make(chan struct{}, s.concurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, node := range nodes {
		if node.Status == model.NodeStatusOffline {
			continue
		}
		result.Total++

		wg.Add(1)
		sem <- struct{}{}

		go func(n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()

			var resp *client.Response
			var err error
			for attempt := 0; attempt <= s.retryCount; attempt++ {
				if attempt > 0 {
					time.Sleep(s.retryInterval)
				}
				resp, err = s.nodeClient.AddRulesBatch(n.Endpoint, n.ApiKey, nodeRules)
				if err == nil && resp.Success && resp.Failed == 0 {
					break
				}
			}

			status := "success"
			errMsg := ""
			if err != nil {
				status = "failed"
				errMsg = err.Error()
				slog.Warn("Batch sync add rules failed", "node", n.Name, "error", err)
			} else if !resp.Success {
				status = "failed"
				errMsg = resp.Error
			} else if resp.Failed > 0 {
				status = "partial"
				errMsg = fmt.Sprintf("added %d, failed %d", resp.Added, resp.Failed)
				slog.Warn("Batch sync add rules partial failure", "node", n.Name, "added", resp.Added, "failed", resp.Failed)
			}

			mu.Lock()
			if status == "success" {
				result.Success++
			} else {
				result.Failed++
				result.Errors[n.Name] = errMsg
			}
			mu.Unlock()

			s.syncLogRepo.Log(n.ID, "batch_add_rules", "", status, errMsg)
		}(node)
	}

	wg.Wait()
	return result
}

// SyncDeleteRulesBatch batch-deletes rules from all nodes using controller IDs.
func (s *SyncService) SyncDeleteRulesBatch(controllerRuleIDs []string) *SyncResult {
	result := newSyncResult()
	if len(controllerRuleIDs) == 0 {
		return result
	}

	nodes, err := s.nodeProvider.List()
	if err != nil {
		slog.Error("Failed to list nodes", "error", err)
		return result
	}

	sem := make(chan struct{}, s.concurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, node := range nodes {
		if node.Status == model.NodeStatusOffline {
			continue
		}
		result.Total++

		wg.Add(1)
		sem <- struct{}{}

		go func(n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()

			// Batch delete using controller IDs directly
			var resp *client.Response
			var err error
			for attempt := 0; attempt <= s.retryCount; attempt++ {
				if attempt > 0 {
					time.Sleep(s.retryInterval)
				}
				resp, err = s.nodeClient.DeleteRulesBatch(n.Endpoint, n.ApiKey, controllerRuleIDs)
				if err == nil && resp != nil && resp.Failed == 0 {
					break
				}
			}

			status := "success"
			errMsg := ""
			if err != nil {
				status = "failed"
				errMsg = err.Error()
			} else if resp != nil && resp.Failed > 0 {
				status = "partial"
				errMsg = fmt.Sprintf("deleted %d, failed %d", resp.Deleted, resp.Failed)
				slog.Warn("Batch sync delete rules partial failure", "node", n.Name, "deleted", resp.Deleted, "failed", resp.Failed)
			}

			mu.Lock()
			if status == "success" {
				result.Success++
			} else {
				result.Failed++
				result.Errors[n.Name] = errMsg
			}
			mu.Unlock()

			s.syncLogRepo.Log(n.ID, "batch_delete_rules", "", status, errMsg)
		}(node)
	}

	wg.Wait()
	return result
}

// SyncDeleteRule deletes a rule from all nodes using the controller ID.
func (s *SyncService) SyncDeleteRule(controllerRuleID string) *SyncResult {
	result := newSyncResult()
	nodes, err := s.nodeProvider.List()
	if err != nil {
		slog.Error("Failed to list nodes", "error", err)
		return result
	}

	sem := make(chan struct{}, s.concurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, node := range nodes {
		if node.Status == model.NodeStatusOffline {
			continue
		}
		result.Total++

		wg.Add(1)
		sem <- struct{}{}

		go func(n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()

			var err error
			for attempt := 0; attempt <= s.retryCount; attempt++ {
				if attempt > 0 {
					time.Sleep(s.retryInterval)
				}
				_, err = s.nodeClient.DeleteRule(n.Endpoint, n.ApiKey, controllerRuleID)
				if err == nil {
					break
				}
			}

			status := "success"
			errMsg := ""
			if err != nil {
				status = "failed"
				errMsg = err.Error()
				slog.Warn("Sync delete rule failed", "node", n.Name, "error", err)
			}

			mu.Lock()
			if status == "success" {
				result.Success++
			} else {
				result.Failed++
				result.Errors[n.Name] = errMsg
			}
			mu.Unlock()

			s.syncLogRepo.Log(n.ID, "delete_rule", controllerRuleID, status, errMsg)
		}(node)
	}

	wg.Wait()
	return result
}

// SyncAddWhitelist syncs a new whitelist entry to all nodes (with retry).
func (s *SyncService) SyncAddWhitelist(entry *model.Whitelist) *SyncResult {
	result := newSyncResult()
	nodes, err := s.nodeProvider.List()
	if err != nil {
		slog.Error("Failed to list nodes", "error", err)
		return result
	}

	sem := make(chan struct{}, s.concurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, node := range nodes {
		if node.Status == model.NodeStatusOffline {
			continue
		}
		result.Total++

		wg.Add(1)
		sem <- struct{}{}

		go func(n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()

			nodeEntry := entry.ToNodeWhitelist()

			var resp *client.Response
			var err error
			for attempt := 0; attempt <= s.retryCount; attempt++ {
				if attempt > 0 {
					time.Sleep(s.retryInterval)
				}
				resp, err = s.nodeClient.AddWhitelist(n.Endpoint, n.ApiKey, nodeEntry)
				if err == nil && resp.Success {
					break
				}
			}

			status := "success"
			errMsg := ""
			if err != nil {
				status = "failed"
				errMsg = err.Error()
			} else if !resp.Success {
				status = "failed"
				errMsg = resp.Error
			}

			mu.Lock()
			if status == "success" {
				result.Success++
			} else {
				result.Failed++
				result.Errors[n.Name] = errMsg
			}
			mu.Unlock()

			s.syncLogRepo.Log(n.ID, "add_whitelist", entry.ID, status, errMsg)
		}(node)
	}

	wg.Wait()
	return result
}

// SyncDeleteWhitelist deletes a whitelist entry from all nodes using the controller ID.
func (s *SyncService) SyncDeleteWhitelist(controllerWlID string) *SyncResult {
	result := newSyncResult()
	nodes, err := s.nodeProvider.List()
	if err != nil {
		slog.Error("Failed to list nodes", "error", err)
		return result
	}

	sem := make(chan struct{}, s.concurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, node := range nodes {
		if node.Status == model.NodeStatusOffline {
			continue
		}
		result.Total++

		wg.Add(1)
		sem <- struct{}{}

		go func(n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()

			var err error
			for attempt := 0; attempt <= s.retryCount; attempt++ {
				if attempt > 0 {
					time.Sleep(s.retryInterval)
				}
				_, err = s.nodeClient.DeleteWhitelist(n.Endpoint, n.ApiKey, controllerWlID)
				if err == nil {
					break
				}
			}

			status := "success"
			errMsg := ""
			if err != nil {
				status = "failed"
				errMsg = err.Error()
			}

			mu.Lock()
			if status == "success" {
				result.Success++
			} else {
				result.Failed++
				result.Errors[n.Name] = errMsg
			}
			mu.Unlock()

			s.syncLogRepo.Log(n.ID, "delete_whitelist", controllerWlID, status, errMsg)
		}(node)
	}

	wg.Wait()
	return result
}

// SyncUpdateRule syncs a rule update to all nodes (delete then re-add).
func (s *SyncService) SyncUpdateRule(rule *model.Rule) *SyncResult {
	delResult := s.SyncDeleteRule(rule.ID)
	addResult := s.SyncAddRule(rule)
	return mergeSyncResults(delResult, addResult)
}

// mergeSyncResults combines two SyncResults into one.
func mergeSyncResults(a, b *SyncResult) *SyncResult {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	merged := newSyncResult()
	merged.Total = a.Total + b.Total
	merged.Success = a.Success + b.Success
	merged.Failed = a.Failed + b.Failed
	for k, v := range a.Errors {
		merged.Errors[k] = v
	}
	for k, v := range b.Errors {
		if existing, ok := merged.Errors[k]; ok {
			merged.Errors[k] = existing + "; " + v
		} else {
			merged.Errors[k] = v
		}
	}
	return merged
}

// FullSyncToAllNodes performs a full sync to all online nodes (clear node state and re-add all controller rules).
func (s *SyncService) FullSyncToAllNodes() *SyncResult {
	result := newSyncResult()
	nodes, err := s.nodeProvider.List()
	if err != nil {
		slog.Error("Failed to list nodes", "error", err)
		return result
	}

	// Fetch all rules and whitelist entries
	rules, err := s.ruleRepo.ListEnabled()
	if err != nil {
		slog.Error("Failed to list rules for full sync", "error", err)
		return result
	}

	whitelist, err := s.wlRepo.List()
	if err != nil {
		slog.Error("Failed to list whitelist for full sync", "error", err)
		return result
	}

	slog.Info("Starting full sync to all nodes", "nodes", len(nodes), "rules", len(rules), "whitelist", len(whitelist))

	sem := make(chan struct{}, s.concurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, node := range nodes {
		if node.Status == model.NodeStatusOffline {
			continue
		}
		result.Total++

		wg.Add(1)
		sem <- struct{}{}

		go func(n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()

			err := s.FullSyncToNode(n, rules, whitelist)
			mu.Lock()
			if err != nil {
				slog.Warn("Full sync to node failed", "node", n.Name, "error", err)
				result.Failed++
				result.Errors[n.Name] = err.Error()
			} else {
				slog.Info("Full sync to node completed", "node", n.Name, "rules", len(rules))
				result.Success++
			}
			mu.Unlock()
		}(node)
	}

	wg.Wait()
	slog.Info("Full sync to all nodes completed")
	return result
}

// FullSyncToNode performs a full sync of rules to the specified node.
// Phase 4.2: sync whitelist first (batch API), then AtomicSync blacklist rules; fall back to legacy FullSync on failure.
func (s *SyncService) FullSyncToNode(node *model.Node, rules []*model.Rule, whitelist []*model.Whitelist) error {
	s.nodeProvider.UpdateStatus(node.ID, model.NodeStatusSyncing)

	// Convert rule format
	var nodeRules []map[string]interface{}
	for _, r := range rules {
		nodeRules = append(nodeRules, r.ToNodeRule())
	}

	var nodeWhitelist []map[string]interface{}
	for _, w := range whitelist {
		nodeWhitelist = append(nodeWhitelist, w.ToNodeWhitelist())
	}

	// Step 1: Sync whitelist first (independent of AtomicSync, via batch API)
	var wlErr error
	if wlErr = s.syncWhitelistToNode(node, nodeWhitelist); wlErr != nil {
		slog.Warn("Whitelist sync failed, continuing with rule sync", "node", node.Name, "error", wlErr)
	}

	// Step 2: Attempt AtomicSync (zero-gap swap)
	resp, err := s.nodeClient.AtomicSync(node.Endpoint, node.ApiKey, nodeRules)
	if err != nil || (resp != nil && resp.Failed > 0) {
		// AtomicSync failed (old node may return 404 for /sync/atomic, partial failure, or other error)
		// Fall back to legacy FullSync
		if err != nil {
			slog.Warn("AtomicSync failed, falling back to legacy FullSync", "node", node.Name, "error", err)
		} else {
			slog.Warn("AtomicSync partial failure, falling back to legacy FullSync", "node", node.Name, "failed", resp.Failed)
		}
		err = s.nodeClient.FullSync(node.Endpoint, node.ApiKey, nodeRules, nodeWhitelist)
		if err != nil {
			s.nodeProvider.UpdateStatus(node.ID, model.NodeStatusOffline)
			s.syncLogRepo.Log(node.ID, "full_sync", "", "failed", err.Error())
			return err
		}
		// Legacy FullSync includes whitelist, so whitelist error is resolved
		wlErr = nil
	}

	// If whitelist sync failed but rule sync succeeded, report partial failure
	if wlErr != nil {
		s.nodeProvider.UpdateStatus(node.ID, model.NodeStatusOnline)
		s.nodeProvider.UpdateLastSync(node.ID)
		s.syncLogRepo.Log(node.ID, "full_sync", "", "partial", fmt.Sprintf("whitelist sync failed: %v", wlErr))
		slog.Warn("Full sync partial: rules OK, whitelist failed", "node", node.Name, "error", wlErr)
		return fmt.Errorf("whitelist sync failed: %w", wlErr)
	}

	s.nodeProvider.UpdateStatus(node.ID, model.NodeStatusOnline)
	s.nodeProvider.UpdateLastSync(node.ID)
	s.syncLogRepo.Log(node.ID, "full_sync", "", "success", "")

	slog.Info("Full sync completed", "node", node.Name, "rules", len(rules))
	return nil
}

// syncWhitelistToNode syncs whitelist entries to a node (batch delete + batch add).
func (s *SyncService) syncWhitelistToNode(node *model.Node, nodeWhitelist []map[string]interface{}) error {
	// Get existing whitelist IDs from the node
	wlIDs, err := s.nodeClient.GetWhitelistIDs(node.Endpoint, node.ApiKey)
	if err != nil {
		return fmt.Errorf("failed to get existing whitelist IDs: %w", err)
	}

	// Batch-delete existing whitelist entries
	if len(wlIDs) > 0 {
		if _, err := s.nodeClient.DeleteWhitelistBatch(node.Endpoint, node.ApiKey, wlIDs); err != nil {
			return fmt.Errorf("failed to delete existing whitelist: %w", err)
		}
	}

	// Batch-add new whitelist entries
	if len(nodeWhitelist) > 0 {
		resp, err := s.nodeClient.AddWhitelistBatch(node.Endpoint, node.ApiKey, nodeWhitelist)
		if err != nil {
			return fmt.Errorf("failed to add whitelist batch: %w", err)
		}
		if resp.Failed > 0 {
			return fmt.Errorf("whitelist sync partially failed: %d/%d entries failed", resp.Failed, len(nodeWhitelist))
		}
	}

	return nil
}

// DiffSyncToNode performs a diff sync to the specified node, falling back to FullSync on failure.
func (s *SyncService) DiffSyncToNode(node *model.Node, rules []*model.Rule, whitelist []*model.Whitelist) error {
	s.nodeProvider.UpdateStatus(node.ID, model.NodeStatusSyncing)

	// Convert rule format
	var nodeRules []map[string]interface{}
	for _, r := range rules {
		nodeRules = append(nodeRules, r.ToNodeRule())
	}

	var nodeWhitelist []map[string]interface{}
	for _, w := range whitelist {
		nodeWhitelist = append(nodeWhitelist, w.ToNodeWhitelist())
	}

	// Attempt DiffSync
	err := s.nodeClient.DiffSync(node.Endpoint, node.ApiKey, nodeRules, nodeWhitelist)
	if err != nil {
		slog.Warn("Diff sync failed, falling back to full sync", "node", node.Name, "error", err)
		s.syncLogRepo.Log(node.ID, "diff_sync", "", "failed", err.Error())

		// Fall back to FullSync
		err = s.nodeClient.FullSync(node.Endpoint, node.ApiKey, nodeRules, nodeWhitelist)
		if err != nil {
			s.nodeProvider.UpdateStatus(node.ID, model.NodeStatusOffline)
			s.syncLogRepo.Log(node.ID, "full_sync_fallback", "", "failed", err.Error())
			return err
		}
		s.syncLogRepo.Log(node.ID, "full_sync_fallback", "", "success", "")
	} else {
		s.syncLogRepo.Log(node.ID, "diff_sync", "", "success", "")
	}

	s.nodeProvider.UpdateStatus(node.ID, model.NodeStatusOnline)
	s.nodeProvider.UpdateLastSync(node.ID)

	slog.Info("Diff sync completed", "node", node.Name, "rules", len(rules))
	return nil
}

// DiffSyncToAllNodes performs a diff sync to all online nodes.
func (s *SyncService) DiffSyncToAllNodes() {
	nodes, err := s.nodeProvider.List()
	if err != nil {
		slog.Error("Failed to list nodes", "error", err)
		return
	}

	rules, err := s.ruleRepo.ListEnabled()
	if err != nil {
		slog.Error("Failed to list rules for diff sync", "error", err)
		return
	}

	whitelist, err := s.wlRepo.List()
	if err != nil {
		slog.Error("Failed to list whitelist for diff sync", "error", err)
		return
	}

	slog.Info("Starting diff sync to all nodes", "nodes", len(nodes), "rules", len(rules), "whitelist", len(whitelist))

	sem := make(chan struct{}, s.concurrent)
	var wg sync.WaitGroup

	for _, node := range nodes {
		if node.Status == model.NodeStatusOffline {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()

			err := s.DiffSyncToNode(n, rules, whitelist)
			if err != nil {
				slog.Warn("Diff sync to node failed", "node", n.Name, "error", err)
			}
		}(node)
	}

	wg.Wait()
	slog.Info("Diff sync to all nodes completed")
}
