package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

// StatsHandler handles statistics API requests.
type StatsHandler struct {
	ruleSvc *service.RuleService
	wlSvc   *service.WhitelistService
	nodeSvc *service.NodeService
}

// NewStatsHandler creates a new StatsHandler.
func NewStatsHandler(ruleSvc *service.RuleService, wlSvc *service.WhitelistService, nodeSvc *service.NodeService) *StatsHandler {
	return &StatsHandler{
		ruleSvc: ruleSvc,
		wlSvc:   wlSvc,
		nodeSvc: nodeSvc,
	}
}

// GetStats returns global aggregated statistics.
func (h *StatsHandler) GetStats(c *gin.Context) {
	rules, _ := h.ruleSvc.List()
	whitelist, _ := h.wlSvc.List()
	nodes, _ := h.nodeSvc.List() // List() already fetches per-node stats

	// Count online nodes — reuse stats already populated by List()
	onlineNodes := 0
	var totalDroppedPPS, totalPassedPPS float64

	for _, n := range nodes {
		if n.Status == "online" {
			onlineNodes++
			if n.Stats != nil {
				totalDroppedPPS += n.Stats.DroppedPPS
				totalPassedPPS += n.Stats.PassedPPS
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"rules_count":       len(rules),
		"whitelist_count":   len(whitelist),
		"nodes_count":       len(nodes),
		"online_nodes":      onlineNodes,
		"total_dropped_pps": totalDroppedPPS,
		"total_passed_pps":  totalPassedPPS,
	})
}
