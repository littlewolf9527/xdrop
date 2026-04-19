// XDrop Agent - Rule list/query handlers (read-only path)
package api

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// nodeHasPaginationParams checks if any pagination-related query param is present on Node.
func nodeHasPaginationParams(c *gin.Context) bool {
	for _, key := range []string{"page", "limit", "search"} {
		if _, exists := c.GetQuery(key); exists {
			return true
		}
	}
	return false
}

// parseNodePaginationParams parses and validates Node pagination parameters.
func parseNodePaginationParams(c *gin.Context) (int, int, error) {
	page := 1
	limit := 50

	if v, exists := c.GetQuery("page"); exists {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return 0, 0, fmt.Errorf("invalid page: must be positive integer")
		}
		page = n
	}
	if v, exists := c.GetQuery("limit"); exists {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return 0, 0, fmt.Errorf("invalid limit: must be 1-1000")
		}
		limit = n
	}
	return page, limit, nil
}

// ListRules returns rules with statistics (supports pagination and full-list modes)
func (h *Handlers) ListRules(c *gin.Context) {
	// Unsupported parameter present → reject with 400
	for _, key := range []string{"sort", "order", "enabled", "action"} {
		if _, exists := c.GetQuery(key); exists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("unsupported parameter: %s (Node only supports page, limit, search)", key),
			})
			return
		}
	}

	if !nodeHasPaginationParams(c) {
		// No pagination params at all → full-list mode (backward-compatible)
		h.listAllRules(c)
		return
	}

	// Paginated mode
	page, limit, err := parseNodePaginationParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	search := c.Query("search")

	now := time.Now().UnixNano()

	// Step 1: Snapshot all rules (O(N) unavoidable)
	h.rulesMu.RLock()
	type ruleEntry struct {
		id          string
		isExact     bool
		exactStored StoredRule
		cidrStored  StoredCIDRRule
	}
	allEntries := make([]ruleEntry, 0, len(h.rules)+len(h.cidrRules))
	for id, stored := range h.rules {
		allEntries = append(allEntries, ruleEntry{id: id, isExact: true, exactStored: stored})
	}
	for id, stored := range h.cidrRules {
		allEntries = append(allEntries, ruleEntry{id: id, isExact: false, cidrStored: stored})
	}
	h.rulesMu.RUnlock()

	// Step 2: Stable sort (Go map iteration order is random; sort to guarantee consistent pagination)
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].id < allEntries[j].id
	})

	// Step 3: Search filter
	if search != "" {
		searchLower := strings.ToLower(search)
		filtered := make([]ruleEntry, 0, len(allEntries))
		for _, e := range allEntries {
			var rule Rule
			if e.isExact {
				rule = h.storedRuleToRule(e.id, e.exactStored)
			} else {
				rule = h.storedCIDRRuleToRule(e.id, e.cidrStored)
			}
			if strings.Contains(strings.ToLower(rule.SrcIP), searchLower) ||
				strings.Contains(strings.ToLower(rule.DstIP), searchLower) ||
				strings.Contains(strings.ToLower(rule.SrcCIDR), searchLower) ||
				strings.Contains(strings.ToLower(rule.DstCIDR), searchLower) ||
				strings.Contains(strings.ToLower(rule.ID), searchLower) {
				filtered = append(filtered, e)
			}
		}
		allEntries = filtered
	}

	// Step 4: Slice for pagination
	total := len(allEntries)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	pageEntries := allEntries[start:end]

	// Step 5: Read BPF stats for current page only
	type ruleWithStats struct {
		rule       Rule
		matchCount uint64
		dropCount  uint64
	}
	results := make([]ruleWithStats, 0, len(pageEntries))
	for _, e := range pageEntries {
		var rule Rule
		var matchCount, dropCount uint64
		if e.isExact {
			rule = h.storedRuleToRule(e.id, e.exactStored)
			keyBytes := ruleKeyToBytes(e.exactStored.Key)
			var valueBytes [32]byte // struct rule_value
			if err := h.activeBlacklist().Lookup(keyBytes, &valueBytes); err == nil {
				matchCount = binary.LittleEndian.Uint64(valueBytes[8:16])
				dropCount = binary.LittleEndian.Uint64(valueBytes[16:24])
			}
		} else {
			rule = h.storedCIDRRuleToRule(e.id, e.cidrStored)
			keyBytes := cidrRuleKeyToBytes(e.cidrStored.Key)
			var valueBytes [32]byte // struct rule_value
			if err := h.activeCidrBlacklist().Lookup(keyBytes, &valueBytes); err == nil {
				matchCount = binary.LittleEndian.Uint64(valueBytes[8:16])
				dropCount = binary.LittleEndian.Uint64(valueBytes[16:24])
			}
		}
		results = append(results, ruleWithStats{rule: rule, matchCount: matchCount, dropCount: dropCount})
	}

	// Step 6: Calculate PPS (per-rule timestamp to avoid cross-page pollution)
	h.rulePPSMu.Lock()
	rules := make([]Rule, 0, len(results))
	for _, r := range results {
		var dropPPS float64
		if lastTime, ok := h.lastRuleStatsTime[r.rule.ID]; ok && lastTime > 0 {
			elapsed := float64(now-lastTime) / 1e9
			if elapsed > 0 {
				if lastDrop, ok := h.lastRuleDropCount[r.rule.ID]; ok {
					if r.dropCount >= lastDrop {
						dropPPS = float64(r.dropCount-lastDrop) / elapsed
					}
				}
			}
		}
		h.lastRuleDropCount[r.rule.ID] = r.dropCount
		h.lastRuleStatsTime[r.rule.ID] = now
		r.rule.Stats = &RuleStats{
			MatchCount: r.matchCount,
			DropCount:  r.dropCount,
			DropPPS:    dropPPS,
		}
		rules = append(rules, r.rule)
	}
	h.rulePPSMu.Unlock()

	pages := 0
	if limit > 0 {
		pages = (total + limit - 1) / limit
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"count": total,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
			"total": total,
			"pages": pages,
		},
	})
}

// listAllRules returns all rules without pagination (legacy full-list mode)
func (h *Handlers) listAllRules(c *gin.Context) {
	now := time.Now().UnixNano()

	// Step 1: Quick snapshot of rules (memory only, no BPF access)
	h.rulesMu.RLock()
	snapshot := make(map[string]StoredRule, len(h.rules))
	for id, stored := range h.rules {
		snapshot[id] = stored
	}
	// Also snapshot CIDR rules (must be under same rulesMu lock)
	cidrSnapshot := make(map[string]StoredCIDRRule, len(h.cidrRules))
	for id, stored := range h.cidrRules {
		cidrSnapshot[id] = stored
	}
	h.rulesMu.RUnlock() // Release lock immediately

	// Step 2: Read BPF stats without holding rulesMu lock
	type ruleWithStats struct {
		rule       Rule
		matchCount uint64
		dropCount  uint64
	}
	results := make([]ruleWithStats, 0, len(snapshot)+len(cidrSnapshot))

	for id, stored := range snapshot {
		rule := h.storedRuleToRule(id, stored)
		var matchCount, dropCount uint64

		keyBytes := ruleKeyToBytes(stored.Key)
		var valueBytes [32]byte // struct rule_value
		if err := h.activeBlacklist().Lookup(keyBytes, &valueBytes); err == nil {
			matchCount = binary.LittleEndian.Uint64(valueBytes[8:16])
			dropCount = binary.LittleEndian.Uint64(valueBytes[16:24])
		}

		results = append(results, ruleWithStats{rule: rule, matchCount: matchCount, dropCount: dropCount})
	}

	// Read CIDR rule stats
	for id, stored := range cidrSnapshot {
		rule := h.storedCIDRRuleToRule(id, stored)
		var matchCount, dropCount uint64

		keyBytes := cidrRuleKeyToBytes(stored.Key)
		var valueBytes [32]byte // struct rule_value
		if err := h.activeCidrBlacklist().Lookup(keyBytes, &valueBytes); err == nil {
			matchCount = binary.LittleEndian.Uint64(valueBytes[8:16])
			dropCount = binary.LittleEndian.Uint64(valueBytes[16:24])
		}

		results = append(results, ruleWithStats{rule: rule, matchCount: matchCount, dropCount: dropCount})
	}

	// Step 3: Calculate incremental PPS using per-rule cached values
	h.rulePPSMu.Lock()
	rules := make([]Rule, 0, len(results))

	for _, r := range results {
		var dropPPS float64

		if lastTime, ok := h.lastRuleStatsTime[r.rule.ID]; ok && lastTime > 0 {
			elapsed := float64(now-lastTime) / 1e9 // Convert to seconds
			if elapsed > 0 {
				if lastDrop, ok := h.lastRuleDropCount[r.rule.ID]; ok {
					if r.dropCount >= lastDrop {
						dropPPS = float64(r.dropCount-lastDrop) / elapsed
					}
				}
			}
		}

		// Update cache
		h.lastRuleDropCount[r.rule.ID] = r.dropCount
		h.lastRuleStatsTime[r.rule.ID] = now

		r.rule.Stats = &RuleStats{
			MatchCount: r.matchCount,
			DropCount:  r.dropCount,
			DropPPS:    dropPPS,
		}
		rules = append(rules, r.rule)
	}

	h.rulePPSMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"count": len(rules),
	})
}
