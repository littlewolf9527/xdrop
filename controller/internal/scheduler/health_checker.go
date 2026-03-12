package scheduler

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/client"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

// HealthChecker periodically checks node health
type HealthChecker struct {
	nodeProvider service.NodeProvider
	nodeClient   *client.NodeClient
	interval     time.Duration
	stopCh       chan struct{}
	running      atomic.Bool // prevents overlapping rounds
	maxWorkers   int
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(nodeProvider service.NodeProvider, nodeClient *client.NodeClient, interval time.Duration) *HealthChecker {
	return &HealthChecker{
		nodeProvider: nodeProvider,
		nodeClient:   nodeClient,
		interval:     interval,
		stopCh:       make(chan struct{}),
		maxWorkers:   8,
	}
}

// Start begins the health check loop, running an immediate check on startup
func (h *HealthChecker) Start() {
	// Run one check immediately on startup
	go h.check()

	go func() {
		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()

		slog.Info("Health checker started", "interval", h.interval)

		for {
			select {
			case <-ticker.C:
				h.check()
			case <-h.stopCh:
				slog.Info("Health checker stopped")
				return
			}
		}
	}()
}

// Stop halts the health check loop
func (h *HealthChecker) Stop() {
	close(h.stopCh)
}

func (h *HealthChecker) check() {
	// Skip if a previous round is still running
	if !h.running.CompareAndSwap(false, true) {
		slog.Debug("Health check round skipped, previous round still running")
		return
	}
	defer h.running.Store(false)

	nodes, err := h.nodeProvider.List()
	if err != nil {
		slog.Error("Failed to list nodes", "error", err)
		return
	}

	sem := make(chan struct{}, h.maxWorkers)
	var wg sync.WaitGroup

	for _, node := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(n *model.Node) {
			defer wg.Done()
			defer func() { <-sem }()
			h.checkNode(n)
		}(node)
	}

	wg.Wait()
}

func (h *HealthChecker) checkNode(node *model.Node) {
	err := h.nodeClient.Ping(node.Endpoint, node.ApiKey)

	if err != nil {
		if node.Status != model.NodeStatusOffline {
			slog.Warn("Node offline", "name", node.Name, "endpoint", node.Endpoint, "error", err)
			h.nodeProvider.UpdateStatus(node.ID, model.NodeStatusOffline)
		}
	} else {
		if node.Status != model.NodeStatusOnline {
			slog.Info("Node online", "name", node.Name, "endpoint", node.Endpoint)
			h.nodeProvider.UpdateStatus(node.ID, model.NodeStatusOnline)
		}
		h.nodeProvider.UpdateLastSeen(node.ID)
	}
}
