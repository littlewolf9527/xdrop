package scheduler

import (
	"log/slog"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/repository"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

// ExpireCleaner removes expired rules on a schedule
type ExpireCleaner struct {
	ruleRepo repository.RuleRepository
	syncSvc  *service.SyncService
	interval time.Duration
	stopCh   chan struct{}
}

// NewExpireCleaner creates a new expire cleaner
func NewExpireCleaner(ruleRepo repository.RuleRepository, syncSvc *service.SyncService, interval time.Duration) *ExpireCleaner {
	return &ExpireCleaner{
		ruleRepo: ruleRepo,
		syncSvc:  syncSvc,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the periodic cleanup loop
func (c *ExpireCleaner) Start() {
	go func() {
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		slog.Info("Expire cleaner started", "interval", c.interval)

		for {
			select {
			case <-ticker.C:
				c.cleanup()
			case <-c.stopCh:
				slog.Info("Expire cleaner stopped")
				return
			}
		}
	}()
}

// Stop halts the cleanup loop
func (c *ExpireCleaner) Stop() {
	close(c.stopCh)
}

func (c *ExpireCleaner) cleanup() {
	// Fetch the list of expired rules first
	expiredRules, err := c.ruleRepo.ListExpired()
	if err != nil {
		slog.Error("Failed to list expired rules", "error", err)
		return
	}

	if len(expiredRules) == 0 {
		return
	}

	slog.Info("Found expired rules", "count", len(expiredRules))

	// Delete from controller DB first, then sync the deletion to nodes.
	// Rationale: if we sync first and local delete fails, the controller keeps
	// a stale rule record that no longer exists on the datapath and blocks
	// recreation via UNIQUE constraint. Deleting locally first means node
	// convergence is handled by SyncChecker / next sync cycle if SyncDeleteRule fails.
	for _, rule := range expiredRules {
		if err := c.ruleRepo.Delete(rule.ID); err != nil {
			slog.Error("Failed to delete expired rule from DB; skipping node sync", "id", rule.ID, "error", err)
			continue
		}
		c.syncSvc.SyncDeleteRule(rule.ID)
	}

	slog.Info("Expired rules cleaned and synced", "count", len(expiredRules))
}
