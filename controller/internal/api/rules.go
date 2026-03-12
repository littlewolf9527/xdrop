package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

// RulesHandler handles rule API requests.
type RulesHandler struct {
	svc     *service.RuleService
	nodeSvc *service.NodeService
}

// NewRulesHandler creates a new RulesHandler.
func NewRulesHandler(svc *service.RuleService, nodeSvc *service.NodeService) *RulesHandler {
	return &RulesHandler{svc: svc, nodeSvc: nodeSvc}
}

// RuleWithStats is a rule augmented with aggregated cluster statistics.
type RuleWithStats struct {
	*model.Rule
	Stats *service.AggregatedRuleStats `json:"stats,omitempty"`
}

// hasPaginationParams checks if any pagination-related query param is present.
// Uses GetQuery to distinguish "not present" from "present but empty".
func hasPaginationParams(c *gin.Context) bool {
	for _, key := range []string{"page", "limit", "search", "sort", "order", "enabled", "action"} {
		if _, exists := c.GetQuery(key); exists {
			return true
		}
	}
	return false
}

// parseAndValidatePaginationParams parses and validates all pagination parameters.
// Returns 400-style error if any parameter is invalid.
func parseAndValidatePaginationParams(c *gin.Context) (repository.PaginationParams, error) {
	params := repository.PaginationParams{
		Page:  1,
		Limit: 50,
		Sort:  "created_at",
		Order: "desc",
	}

	if v, exists := c.GetQuery("page"); exists {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return params, fmt.Errorf("invalid page: must be positive integer")
		}
		params.Page = n
	}
	if v, exists := c.GetQuery("limit"); exists {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return params, fmt.Errorf("invalid limit: must be 1-1000")
		}
		params.Limit = n
	}
	if v, exists := c.GetQuery("sort"); exists {
		if v != "created_at" && v != "updated_at" {
			return params, fmt.Errorf("invalid sort: allowed values are created_at, updated_at")
		}
		params.Sort = v
	}
	if v, exists := c.GetQuery("order"); exists {
		if v != "asc" && v != "desc" {
			return params, fmt.Errorf("invalid order: allowed values are asc, desc")
		}
		params.Order = v
	}
	if v, exists := c.GetQuery("search"); exists {
		// search accepts any string; empty string means no filter
		params.Search = v
	}
	if v, exists := c.GetQuery("enabled"); exists {
		if v != "true" && v != "false" {
			return params, fmt.Errorf("invalid enabled: allowed values are true, false")
		}
		b := v == "true"
		params.Enabled = &b
	}
	if v, exists := c.GetQuery("action"); exists {
		if v != "drop" && v != "rate_limit" {
			return params, fmt.Errorf("invalid action: allowed values are drop, rate_limit")
		}
		params.Action = v
	}

	return params, nil
}

// List lists rules in paginated or full mode (with aggregated stats in full mode).
func (h *RulesHandler) List(c *gin.Context) {
	if !hasPaginationParams(c) {
		// No pagination params at all → full mode (backward compatible)
		h.listAll(c)
		return
	}

	// Any pagination param present → paginated mode
	params, err := parseAndValidatePaginationParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rules, pagination, err := h.svc.ListPaginated(params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Paginated mode: skip expensive full-cluster stats aggregation (AUD-001)
	c.JSON(http.StatusOK, gin.H{
		"rules":      rules,
		"count":      pagination.Total,
		"pagination": pagination,
	})
}

// listAll returns all rules (backward compatible with old API).
func (h *RulesHandler) listAll(c *gin.Context) {
	rules, err := h.svc.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Fetch aggregated stats
	aggregatedStats, _ := h.nodeSvc.GetAggregatedRuleStats()

	// Combine rules with stats
	result := make([]RuleWithStats, 0, len(rules))
	for _, rule := range rules {
		rws := RuleWithStats{Rule: rule}
		if stats, ok := aggregatedStats[rule.ID]; ok {
			rws.Stats = stats
		}
		result = append(result, rws)
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": result,
		"count": len(result),
	})
}

// Get retrieves a single rule by ID.
func (h *RulesHandler) Get(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.svc.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// TopRules returns top-N rules sorted by drop_pps (for dashboard chart).
// Uses aggregated cluster stats but only returns a small projection.
func (h *RulesHandler) TopRules(c *gin.Context) {
	limit := 10
	if v, exists := c.GetQuery("limit"); exists {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 50 {
			limit = n
		}
	}

	aggregatedStats, _ := h.nodeSvc.GetAggregatedRuleStats()
	if len(aggregatedStats) == 0 {
		c.JSON(http.StatusOK, gin.H{"rules": []interface{}{}})
		return
	}

	// Collect rule IDs that have drop activity
	type entry struct {
		ID   string
		Stat *service.AggregatedRuleStats
	}
	var entries []entry
	for id, stat := range aggregatedStats {
		if stat.DropPPS > 0 {
			entries = append(entries, entry{id, stat})
		}
	}

	// Sort by drop_pps descending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Stat.DropPPS > entries[j].Stat.DropPPS
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}

	// Fetch rule details for the top entries
	result := make([]RuleWithStats, 0, len(entries))
	for _, e := range entries {
		rule, err := h.svc.Get(e.ID)
		if err != nil {
			continue
		}
		result = append(result, RuleWithStats{Rule: rule, Stats: e.Stat})
	}

	c.JSON(http.StatusOK, gin.H{"rules": result})
}

// syncToResponse adds sync result fields to a gin.H response map.
func syncToResponse(resp gin.H, sr *service.SyncResult) gin.H {
	if sr != nil && sr.Failed > 0 {
		resp["sync"] = sr
	}
	return resp
}

// Create adds a new rule.
func (h *RulesHandler) Create(c *gin.Context) {
	var req model.RuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, sr, err := h.svc.Create(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, syncToResponse(gin.H{
		"success": true,
		"rule":    rule,
	}, sr))
}

// Update modifies an existing rule.
func (h *RulesHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req model.RuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, sr, err := h.svc.Update(id, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, syncToResponse(gin.H{
		"success": true,
		"rule":    rule,
	}, sr))
}

// Delete removes a rule by ID.
func (h *RulesHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	sr, err := h.svc.Delete(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, syncToResponse(gin.H{
		"success": true,
		"message": "Rule deleted",
	}, sr))
}

// BatchCreate adds multiple rules in one request.
func (h *RulesHandler) BatchCreate(c *gin.Context) {
	var req struct {
		Rules []model.RuleRequest `json:"rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rules, added, failed, sr, err := h.svc.BatchCreate(req.Rules)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, syncToResponse(gin.H{
		"success": true,
		"added":   added,
		"failed":  failed,
		"rules":   rules,
	}, sr))
}

// BatchDelete removes multiple rules by ID.
func (h *RulesHandler) BatchDelete(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	deleted, failed, sr, err := h.svc.BatchDelete(req.IDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, syncToResponse(gin.H{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
	}, sr))
}
