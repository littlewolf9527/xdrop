package service

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/littlewolf9527/xdrop/controller/internal/client"
	"github.com/littlewolf9527/xdrop/controller/internal/config"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
)

// ErrNodeReadOnly is returned when node management is in read-only mode.
var ErrNodeReadOnly = errors.New("node management is read-only; configure nodes in config.yaml")

// NodeService manages nodes using in-memory storage.
type NodeService struct {
	nodes       map[string]*model.Node // in-memory store
	mu          sync.RWMutex
	ruleRepo    repository.RuleRepository
	wlRepo      repository.WhitelistRepository
	syncService *SyncService
	nodeClient  *client.NodeClient
}

// NewNodeService creates a new NodeService.
func NewNodeService(
	ruleRepo repository.RuleRepository,
	wlRepo repository.WhitelistRepository,
	syncService *SyncService,
	nodeClient *client.NodeClient,
) *NodeService {
	return &NodeService{
		nodes:       make(map[string]*model.Node),
		ruleRepo:    ruleRepo,
		wlRepo:      wlRepo,
		syncService: syncService,
		nodeClient:  nodeClient,
	}
}

// SetSyncService sets the sync service (used to break circular dependency).
func (s *NodeService) SetSyncService(syncService *SyncService) {
	s.syncService = syncService
}

// InitFromConfig initializes nodes from the configuration file.
func (s *NodeService) InitFromConfig(nodeCfgs []config.NodeConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, cfg := range nodeCfgs {
		if cfg.Name == "" || cfg.Endpoint == "" {
			continue
		}

		node := &model.Node{
			ID:        "node_" + uuid.New().String()[:8],
			Name:      cfg.Name,
			Endpoint:  cfg.Endpoint,
			ApiKey:    cfg.APIKey,
			Status:    model.NodeStatusUnknown,
			CreatedAt: time.Now(),
		}

		s.nodes[node.ID] = node
		slog.Info("Node loaded from config", "name", node.Name, "endpoint", node.Endpoint)
	}

	slog.Info("Nodes initialized from config", "count", len(s.nodes))
}

// Register registers a node (disabled — returns read-only error).
func (s *NodeService) Register(req *model.NodeRequest) (*model.Node, error) {
	return nil, ErrNodeReadOnly
}

// Get returns a node by ID (returns a copy to avoid shared-pointer races).
func (s *NodeService) Get(id string) (*model.Node, error) {
	s.mu.RLock()
	node, exists := s.nodes[id]
	if !exists {
		s.mu.RUnlock()
		return nil, fmt.Errorf("node not found: %s", id)
	}
	// Copy before releasing the lock to avoid mutating the shared object outside the lock
	copied := *node
	s.mu.RUnlock()

	// Fetch stats on the copy
	stats, err := s.nodeClient.GetStats(copied.Endpoint, copied.ApiKey)
	if err == nil {
		copied.Stats = parseNodeStats(stats)
	}

	return &copied, nil
}

// List returns all nodes (copies, to avoid shared-pointer races) with Stats populated.
func (s *NodeService) List() ([]*model.Node, error) {
	s.mu.RLock()
	nodes := make([]*model.Node, 0, len(s.nodes))
	for _, node := range s.nodes {
		copied := *node
		nodes = append(nodes, &copied)
	}
	s.mu.RUnlock()

	// Fetch stats for each node concurrently (bounded to avoid thundering herd with many nodes)
	const maxConcurrentStatsFetch = 8
	sem := make(chan struct{}, maxConcurrentStatsFetch)
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(n *model.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			stats, err := s.nodeClient.GetStats(n.Endpoint, n.ApiKey)
			if err == nil {
				n.Stats = parseNodeStats(stats)
			}
		}(node)
	}
	wg.Wait()

	return nodes, nil
}

// Delete removes a node (disabled — returns read-only error).
func (s *NodeService) Delete(id string) error {
	return ErrNodeReadOnly
}

// Update modifies a node (disabled — returns read-only error).
func (s *NodeService) Update(id, name, apiKey string) (*model.Node, error) {
	return nil, ErrNodeReadOnly
}

// UpdateStatus updates the status of a node (internal use).
func (s *NodeService) UpdateStatus(id string, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if node, exists := s.nodes[id]; exists {
		node.Status = status
	}
}

// UpdateLastSeen updates the last-seen timestamp of a node (internal use).
func (s *NodeService) UpdateLastSeen(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if node, exists := s.nodes[id]; exists {
		now := time.Now()
		node.LastSeen = &now
	}
}

// UpdateLastSync updates the last-sync timestamp of a node (internal use).
func (s *NodeService) UpdateLastSync(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if node, exists := s.nodes[id]; exists {
		now := time.Now()
		node.LastSync = &now
	}
}

// ForceSync forces a full rule sync to the specified node.
func (s *NodeService) ForceSync(id string) error {
	s.mu.RLock()
	node, exists := s.nodes[id]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("node not found: %s", id)
	}

	return s.fullSyncToNode(node)
}

// fullSyncToNode performs a full sync to the given node.
func (s *NodeService) fullSyncToNode(node *model.Node) error {
	rules, err := s.ruleRepo.ListEnabled()
	if err != nil {
		return err
	}

	whitelist, err := s.wlRepo.List()
	if err != nil {
		return err
	}

	return s.syncService.FullSyncToNode(node, rules, whitelist)
}

// GetStats retrieves statistics from a node.
func (s *NodeService) GetStats(id string) (*model.NodeStats, error) {
	s.mu.RLock()
	node, exists := s.nodes[id]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("node not found: %s", id)
	}

	stats, err := s.nodeClient.GetStats(node.Endpoint, node.ApiKey)
	if err != nil {
		return nil, err
	}

	return parseNodeStats(stats), nil
}

// AggregatedRuleStats holds aggregated rule statistics across all nodes.
type AggregatedRuleStats struct {
	MatchCount uint64  `json:"match_count"`
	DropCount  uint64  `json:"drop_count"`
	DropPPS    float64 `json:"drop_pps"`
}

// GetAggregatedRuleStats returns rule statistics aggregated across all nodes.
func (s *NodeService) GetAggregatedRuleStats() (map[string]*AggregatedRuleStats, error) {
	s.mu.RLock()
	nodes := make([]*model.Node, 0, len(s.nodes))
	for _, node := range s.nodes {
		nodes = append(nodes, node)
	}
	s.mu.RUnlock()

	// Aggregation result: rule_id -> aggregated stats
	aggregated := make(map[string]*AggregatedRuleStats)

	for _, node := range nodes {
		if node.Status != model.NodeStatusOnline {
			continue
		}

		// Fetch per-rule stats from this node
		rulesResp, err := s.nodeClient.GetRulesWithStats(node.Endpoint, node.ApiKey)
		if err != nil {
			slog.Warn("Failed to get rules stats from node", "node", node.Name, "error", err)
			continue
		}

		// Aggregate stats for each rule
		for _, rule := range rulesResp.Rules {
			if rule.Stats == nil {
				continue
			}

			if _, exists := aggregated[rule.ID]; !exists {
				aggregated[rule.ID] = &AggregatedRuleStats{}
			}

			aggregated[rule.ID].MatchCount += rule.Stats.MatchCount
			aggregated[rule.ID].DropCount += rule.Stats.DropCount
			aggregated[rule.ID].DropPPS += rule.Stats.DropPPS
		}
	}

	return aggregated, nil
}

func parseNodeStats(data map[string]interface{}) *model.NodeStats {
	stats := &model.NodeStats{}

	if v, ok := data["total_packets"].(float64); ok {
		stats.TotalPackets = uint64(v)
	}
	if v, ok := data["dropped_packets"].(float64); ok {
		stats.DroppedPackets = uint64(v)
	}
	if v, ok := data["passed_packets"].(float64); ok {
		stats.PassedPackets = uint64(v)
	}
	if v, ok := data["whitelisted_packets"].(float64); ok {
		stats.WhitelistedPackets = uint64(v)
	}
	if v, ok := data["rate_limited_packets"].(float64); ok {
		stats.RateLimitedPackets = uint64(v)
	}
	if v, ok := data["rules_count"].(float64); ok {
		stats.RulesCount = int(v)
	}
	if v, ok := data["whitelist_count"].(float64); ok {
		stats.WhitelistCount = int(v)
	}
	if v, ok := data["dropped_pps"].(float64); ok {
		stats.DroppedPPS = v
	}
	if v, ok := data["passed_pps"].(float64); ok {
		stats.PassedPPS = v
	}
	if v, ok := data["total_pps"].(float64); ok {
		stats.TotalPPS = v
	}

	// Phase 5.1: nested system stats (two-level assertion — JSON numbers decode as float64)
	if system, ok := data["system"].(map[string]interface{}); ok {
		s := &model.NodeSystemStats{}
		if v, ok := system["cpu_percent"].(float64); ok {
			s.CPUPercent = v
		}
		if v, ok := system["mem_total_mb"].(float64); ok {
			s.MemTotalMB = uint64(v)
		}
		if v, ok := system["mem_used_mb"].(float64); ok {
			s.MemUsedMB = uint64(v)
		}
		if v, ok := system["mem_percent"].(float64); ok {
			s.MemPercent = v
		}
		if v, ok := system["uptime_seconds"].(float64); ok {
			s.UptimeSeconds = uint64(v)
		}
		if v, ok := system["load_avg_1"].(float64); ok {
			s.LoadAvg1 = v
		}
		if v, ok := system["load_avg_5"].(float64); ok {
			s.LoadAvg5 = v
		}
		if v, ok := system["load_avg_15"].(float64); ok {
			s.LoadAvg15 = v
		}
		stats.System = s
	}

	// Phase 5.1: nested agent state
	if agentRaw, ok := data["agent_state"].(map[string]interface{}); ok {
		a := &model.NodeAgentState{}
		if v, ok := agentRaw["exact_rules"].(float64); ok {
			a.ExactRules = int(v)
		}
		if v, ok := agentRaw["cidr_rules"].(float64); ok {
			a.CIDRRules = int(v)
		}
		if v, ok := agentRaw["whitelist_entries"].(float64); ok {
			a.WhitelistEntries = int(v)
		}
		if v, ok := agentRaw["active_slot"].(float64); ok {
			a.ActiveSlot = int(v)
		}
		if v, ok := agentRaw["rule_map_selector"].(float64); ok {
			a.RuleMapSelector = int(v)
		}
		stats.AgentState = a
	}

	// XDP interface info
	if xdpRaw, ok := data["xdp_info"].(map[string]interface{}); ok {
		x := &model.NodeXDPInfo{}
		if v, ok := xdpRaw["mode"].(string); ok {
			x.Mode = v
		}
		if ifaces, ok := xdpRaw["interfaces"].([]interface{}); ok {
			for _, ifRaw := range ifaces {
				if ifMap, ok := ifRaw.(map[string]interface{}); ok {
					iface := model.NodeXDPInterface{}
					if v, ok := ifMap["name"].(string); ok {
						iface.Name = v
					}
					if v, ok := ifMap["role"].(string); ok {
						iface.Role = v
					}
					x.Interfaces = append(x.Interfaces, iface)
				}
			}
		}
		stats.XDPInfo = x
	}

	return stats
}
