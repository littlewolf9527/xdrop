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

	// Delete each rule and sync the deletion to nodes
	for _, rule := range expiredRules {
		// Sync deletion to nodes first
		c.syncSvc.SyncDeleteRule(rule.ID)

		// Then remove from the local database
		if err := c.ruleRepo.Delete(rule.ID); err != nil {
			slog.Error("Failed to delete expired rule", "id", rule.ID, "error", err)
		}
	}

	slog.Info("Expired rules cleaned and synced", "count", len(expiredRules))
}
