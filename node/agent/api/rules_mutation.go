// XDrop Agent - Exact IP rule add/delete/batch handlers
// NOTE: DeleteRule and DeleteRulesBatch call cidrMgr.ReleaseSrcID/ReleaseDstID
// when removing CIDR rules. CIDR ID lifecycle therefore spans both this file (release)
// and cidr_rules.go (alloc). See cidr_rules.go for the alloc side.
package api

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AddRule adds a new rule (exact IP or CIDR)
func (h *Handlers) AddRule(c *gin.Context) {
	var req Rule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hasCIDR := req.SrcCIDR != "" || req.DstCIDR != ""
	hasExactIP := req.SrcIP != "" || req.DstIP != ""

	// Mixed exact IP + CIDR is not supported in v1
	if hasCIDR && hasExactIP {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot mix src_ip/dst_ip with src_cidr/dst_cidr; use one or the other"})
		return
	}

	// Route to CIDR path if any CIDR field is set
	if hasCIDR {
		h.addCIDRRule(c, req)
		return
	}

	// === Existing exact-IP path ===

	// Validate rule (check for pure-length rules and length range)
	if err := validateRule(req.SrcIP, req.DstIP, req.Protocol, req.SrcPort, req.DstPort, req.PktLenMin, req.PktLenMax); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	key, err := h.ruleToKey(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	action, err := parseAction(req.Action)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// rate_limit action requires rate_limit > 0, otherwise BPF falls through to PASS
	if action == ActionRateLimit && req.RateLimit <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rate_limit must be > 0 for rate_limit action"})
		return
	}

	value := RuleValue{
		Action:    action,
		RateLimit: req.RateLimit,
		PktLenMin: req.PktLenMin,
		PktLenMax: req.PktLenMax,
	}

	keyBytes := ruleKeyToBytes(key)
	valueBytes := ruleValueToBytes(value)

	// Use externally provided ID if present, otherwise generate a new one
	id := req.ID
	if id == "" {
		id = uuid.New().String()
	}

	// Double-buffer: BPF Insert + memory update + publish all inside lock
	h.syncMu.Lock()
	h.publishMu.Lock()
	h.rulesMu.Lock()
	bl := h.activeBlacklist()

	// Duplicate key check: reject if another ID already owns this key
	if existingID, ok := h.ruleKeyIndex[key]; ok && existingID != id {
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("rule key already exists under id %s", existingID)})
		return
	}

	// Check for existing rule with same ID (replacement case)
	var oldStored *StoredRule
	countDelta := int64(1)
	if old, exists := h.rules[id]; exists {
		oldCopy := old
		oldStored = &oldCopy
		countDelta = 0 // replacing, not adding
	}

	// Step 1: Insert new BPF entry (old entry still intact if different key)
	if err := bl.Insert(keyBytes, valueBytes); err != nil {
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to insert rule: %v", err)})
		return
	}

	// Step 2: Delete old BPF entry BEFORE publish (hard failure if can't clean up)
	if oldStored != nil && oldStored.Key != key {
		if err := bl.Delete(ruleKeyToBytes(oldStored.Key)); err != nil {
			// Can't delete old entry → abort replacement to avoid orphan stale entry
			if delErr := bl.Delete(keyBytes); delErr != nil {
				log.Printf("[AddRule] WARN: best-effort cleanup of new BPF entry failed during abort: %v", delErr)
			}
			h.rulesMu.Unlock()
			h.publishMu.Unlock()
			h.syncMu.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete old BPF entry during replacement: %v", err)})
			return
		}
	}

	// Step 3: Update memory state (no BPF orphan possible from here)
	if oldStored != nil {
		oldComboType := getComboType(oldStored.Key)
		if oldComboType >= 0 && oldComboType < 64 {
			h.comboRefCount[oldComboType]--
		}
		delete(h.ruleKeyIndex, oldStored.Key)
	}
	comboType := getComboType(key)
	if comboType >= 0 && comboType < 64 {
		h.comboRefCount[comboType]++
	}
	h.rules[id] = StoredRule{
		Key:       key,
		Action:    req.Action,
		RateLimit: req.RateLimit,
		PktLenMin: req.PktLenMin,
		PktLenMax: req.PktLenMax,
	}
	h.ruleKeyIndex[key] = id

	// Step 4: Publish config
	if err := h.publishConfigUpdate(countDelta, 0, 0); err != nil {
		// Strong failure: rollback memory state + BPF entries
		if delErr := bl.Delete(keyBytes); delErr != nil {
			log.Printf("[AddRule] WARN: best-effort rollback delete of new BPF entry failed: %v", delErr)
		}
		if comboType >= 0 && comboType < 64 {
			h.comboRefCount[comboType]--
		}
		delete(h.rules, id)
		delete(h.ruleKeyIndex, key)
		// Restore old state if this was a replacement
		if oldStored != nil {
			oldComboType := getComboType(oldStored.Key)
			if oldComboType >= 0 && oldComboType < 64 {
				h.comboRefCount[oldComboType]++
			}
			h.rules[id] = *oldStored
			h.ruleKeyIndex[oldStored.Key] = id
			// Re-insert old BPF entry (best-effort restore)
			if oldStored.Key != key {
				oldAction, _ := parseAction(oldStored.Action)
				oldValue := RuleValue{Action: oldAction, RateLimit: oldStored.RateLimit, PktLenMin: oldStored.PktLenMin, PktLenMax: oldStored.PktLenMax}
				if insErr := bl.Insert(ruleKeyToBytes(oldStored.Key), ruleValueToBytes(oldValue)); insErr != nil {
					log.Printf("[AddRule] WARN: best-effort rollback re-insert of old BPF entry failed: %v", insErr)
				}
			}
		}
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config publish failed"})
		return
	}

	h.rulesMu.Unlock()
	h.publishMu.Unlock()
	h.syncMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"rule_id": id,
		"message": "Rule added",
	})
}

// DeleteRule removes a rule by ID
// NOTE: For CIDR rules, this calls cidrMgr.ReleaseSrcID/ReleaseDstID.
// The corresponding alloc is in cidr_rules.go (addCIDRRule / addCIDRRuleFromSync).
func (h *Handlers) DeleteRule(c *gin.Context) {
	id := c.Param("id")

	h.syncMu.Lock()
	h.publishMu.Lock()
	h.rulesMu.Lock()
	bl := h.activeBlacklist()
	cbl := h.activeCidrBlacklist()

	// Check exact rules first, then CIDR rules
	stored, exists := h.rules[id]
	if exists {
		// === Delete exact rule ===
		keyBytes := ruleKeyToBytes(stored.Key)
		if err := bl.Delete(keyBytes); err != nil {
			h.rulesMu.Unlock()
			h.publishMu.Unlock()
			h.syncMu.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete rule: %v", err)})
			return
		}
		if stored.Action == "rate_limit" && h.rlStates != nil {
			h.rlStates.Delete(keyBytes)
		}
		comboType := getComboType(stored.Key)
		if comboType >= 0 && comboType < 64 {
			h.comboRefCount[comboType]--
		}
		delete(h.ruleKeyIndex, stored.Key)
		delete(h.rules, id)
		if err := h.publishConfigUpdate(-1, 0, 0); err != nil {
			log.Printf("[DeleteRule] WARN: config publish failed after BPF delete (safe direction): %v", err)
		}
	} else if cidrStored, cidrExists := h.cidrRules[id]; cidrExists {
		// === Delete CIDR rule ===
		keyBytes := cidrRuleKeyToBytes(cidrStored.Key)
		if err := cbl.Delete(keyBytes); err != nil {
			h.rulesMu.Unlock()
			h.publishMu.Unlock()
			h.syncMu.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete CIDR rule: %v", err)})
			return
		}
		if cidrStored.Action == "rate_limit" && h.cidrRlStates != nil {
			h.cidrRlStates.Delete(keyBytes)
		}
		comboType := getCIDRComboType(cidrStored.Key)
		if comboType >= 0 && comboType < 64 {
			h.cidrComboRefCount[comboType]--
		}
		delete(h.cidrRuleKeyIndex, cidrStored.Key)
		delete(h.cidrRules, id)
		// Release CIDR IDs (trie cleanup when ref reaches 0)
		if cidrStored.SrcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(cidrStored.SrcCIDR)
		}
		if cidrStored.DstCIDR != "" {
			h.cidrMgr.ReleaseDstID(cidrStored.DstCIDR)
		}
		if err := h.publishConfigUpdate(0, 0, -1); err != nil {
			log.Printf("[DeleteRule] WARN: CIDR config publish failed after BPF delete (safe direction): %v", err)
		}
	} else {
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	h.rulesMu.Unlock()
	h.publishMu.Unlock()
	h.syncMu.Unlock()

	// Clean up PPS cache outside lock
	h.rulePPSMu.Lock()
	delete(h.lastRuleDropCount, id)
	delete(h.lastRuleStatsTime, id)
	h.rulePPSMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Rule deleted",
	})
}

// AddRulesBatch adds multiple rules
func (h *Handlers) AddRulesBatch(c *gin.Context) {
	var req struct {
		Rules []Rule `json:"rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	added := 0
	failed := 0

	// Separate CIDR rules from exact rules — CIDR rules are processed individually
	var exactRules []Rule
	var cidrRules []Rule
	for _, r := range req.Rules {
		if r.SrcCIDR != "" || r.DstCIDR != "" {
			cidrRules = append(cidrRules, r)
		} else {
			exactRules = append(exactRules, r)
		}
	}

	// Process CIDR rules individually (typically few, complex trie logic)
	for _, r := range cidrRules {
		syncRule := SyncRule{
			ID:        r.ID,
			SrcIP:     r.SrcIP,
			DstIP:     r.DstIP,
			SrcCIDR:   r.SrcCIDR,
			DstCIDR:   r.DstCIDR,
			SrcPort:   r.SrcPort,
			DstPort:   r.DstPort,
			Protocol:  r.Protocol,
			Action:    r.Action,
			RateLimit: r.RateLimit,
			PktLenMin: r.PktLenMin,
			PktLenMax: r.PktLenMax,
		}
		if err := h.addCIDRRuleFromSync(syncRule); err != nil {
			log.Printf("[AddRulesBatch] CIDR rule %s failed: %v", r.ID, err)
			failed++
		} else {
			added++
		}
	}

	// Pre-validate and prepare exact rules
	type preparedRule struct {
		id         string
		key        RuleKey
		keyBytes   []byte
		valueBytes []byte
		action     string
		rateLimit  uint32
		pktLenMin  uint16
		pktLenMax  uint16
	}
	prepared := make([]preparedRule, 0, len(exactRules))

	// Deduplicate by ID: if same ID appears multiple times, keep only the last occurrence.
	// This prevents rollback from restoring to a batch-internal intermediate state.
	seenIDs := make(map[string]int) // id → index in prepared slice

	for _, r := range exactRules {
		// Validate rule (check for pure-length rules and length range)
		if err := validateRule(r.SrcIP, r.DstIP, r.Protocol, r.SrcPort, r.DstPort, r.PktLenMin, r.PktLenMax); err != nil {
			failed++
			continue
		}

		key, err := h.ruleToKey(r)
		if err != nil {
			failed++
			continue
		}

		action, err := parseAction(r.Action)
		if err != nil {
			failed++
			continue
		}

		// Validate rate_limit consistency
		if action == ActionRateLimit && r.RateLimit <= 0 {
			failed++
			continue
		}

		value := RuleValue{
			Action:    action,
			RateLimit: r.RateLimit,
			PktLenMin: r.PktLenMin,
			PktLenMax: r.PktLenMax,
		}

		id := r.ID
		if id == "" {
			id = uuid.New().String()
		}

		p := preparedRule{
			id:         id,
			key:        key,
			keyBytes:   ruleKeyToBytes(key),
			valueBytes: ruleValueToBytes(value),
			action:     r.Action,
			rateLimit:  r.RateLimit,
			pktLenMin:  r.PktLenMin,
			pktLenMax:  r.PktLenMax,
		}

		// If same ID already seen in this batch, replace it (keep last occurrence)
		if idx, ok := seenIDs[id]; ok {
			prepared[idx] = p
		} else {
			seenIDs[id] = len(prepared)
			prepared = append(prepared, p)
		}
	}

	// Double-buffer batch: BPF writes + memory updates inside lock, one publish at the end
	h.syncMu.Lock()
	h.publishMu.Lock()
	h.rulesMu.Lock()
	bl := h.activeBlacklist()

	type succeededItem struct {
		id            string
		key           RuleKey
		comboType     int
		keyBytes      []byte
		isReplacement bool        // true if replacing existing rule (no count delta)
		oldStored     *StoredRule // saved old state for rollback
	}
	succeeded := make([]succeededItem, 0, len(prepared))

	for _, p := range prepared {
		// Duplicate key check: reject if another ID already owns this key
		if existingID, ok := h.ruleKeyIndex[p.key]; ok && existingID != p.id {
			failed++
			continue
		}

		// Insert new BPF entry FIRST (old still intact if different key)
		if err := bl.Insert(p.keyBytes, p.valueBytes); err != nil {
			failed++
			continue
		}

		// Save old state
		var oldStored *StoredRule
		isReplacement := false
		if old, exists := h.rules[p.id]; exists {
			isReplacement = true
			oldCopy := old
			oldStored = &oldCopy
		}

		// Delete old BPF entry BEFORE memory update (hard failure to avoid orphan)
		if oldStored != nil && oldStored.Key != p.key {
			if err := bl.Delete(ruleKeyToBytes(oldStored.Key)); err != nil {
				// Can't delete old entry → abort this item, remove new entry
				if delErr := bl.Delete(p.keyBytes); delErr != nil {
					log.Printf("[AddRulesBatch] WARN: best-effort cleanup of new BPF entry failed during per-item abort: %v", delErr)
				}
				failed++
				continue
			}
		}

		// Update memory state
		if oldStored != nil {
			oldCombo := getComboType(oldStored.Key)
			if oldCombo >= 0 && oldCombo < 64 {
				h.comboRefCount[oldCombo]--
			}
			delete(h.ruleKeyIndex, oldStored.Key)
		}

		comboType := getComboType(p.key)
		if comboType >= 0 && comboType < 64 {
			h.comboRefCount[comboType]++
		}
		h.rules[p.id] = StoredRule{
			Key:       p.key,
			Action:    p.action,
			RateLimit: p.rateLimit,
			PktLenMin: p.pktLenMin,
			PktLenMax: p.pktLenMax,
		}
		h.ruleKeyIndex[p.key] = p.id
		succeeded = append(succeeded, succeededItem{id: p.id, key: p.key, comboType: comboType, keyBytes: p.keyBytes, isReplacement: isReplacement, oldStored: oldStored})
	}

	// Count only net new rules (not replacements)
	netNew := int64(0)
	for _, item := range succeeded {
		if !item.isReplacement {
			netNew++
		}
	}

	// One publish for entire batch
	if len(succeeded) > 0 {
		if err := h.publishConfigUpdate(netNew, 0, 0); err != nil {
			// Strong failure: rollback all. Delete new BPF, restore old state (including old BPF entries).
			for _, item := range succeeded {
				if delErr := bl.Delete(item.keyBytes); delErr != nil {
					log.Printf("[AddRulesBatch] WARN: best-effort rollback delete of new BPF entry failed (id=%s): %v", item.id, delErr)
				}
				if item.comboType >= 0 && item.comboType < 64 {
					h.comboRefCount[item.comboType]--
				}
				delete(h.ruleKeyIndex, item.key)
				delete(h.rules, item.id)
				// Restore old state if replacement
				if item.oldStored != nil {
					oldCombo := getComboType(item.oldStored.Key)
					if oldCombo >= 0 && oldCombo < 64 {
						h.comboRefCount[oldCombo]++
					}
					h.rules[item.id] = *item.oldStored
					h.ruleKeyIndex[item.oldStored.Key] = item.id
					// Re-insert old BPF entry if it was deleted (best-effort restore)
					if item.oldStored.Key != item.key {
						oldAction, _ := parseAction(item.oldStored.Action)
						oldValue := RuleValue{Action: oldAction, RateLimit: item.oldStored.RateLimit, PktLenMin: item.oldStored.PktLenMin, PktLenMax: item.oldStored.PktLenMax}
						if insErr := bl.Insert(ruleKeyToBytes(item.oldStored.Key), ruleValueToBytes(oldValue)); insErr != nil {
							log.Printf("[AddRulesBatch] WARN: best-effort rollback re-insert of old BPF entry failed (id=%s): %v", item.id, insErr)
						}
					}
				}
			}
			h.rulesMu.Unlock()
			h.publishMu.Unlock()
			h.syncMu.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "config publish failed"})
			return
		}
	}
	added += len(succeeded)

	h.rulesMu.Unlock()
	h.publishMu.Unlock()
	h.syncMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"added":   added,
		"failed":  failed,
	})
}

// DeleteRulesBatch removes multiple rules
// NOTE: For CIDR rules, this calls cidrMgr.ReleaseSrcID/ReleaseDstID.
// See cidr_rules.go for the corresponding alloc side.
func (h *Handlers) DeleteRulesBatch(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	deleted := 0
	failed := 0

	// Double-buffer batch delete: BPF deletes + memory updates inside lock, one publish
	h.syncMu.Lock()
	h.publishMu.Lock()
	h.rulesMu.Lock()
	bl := h.activeBlacklist()
	cbl := h.activeCidrBlacklist()

	type succeededItem struct {
		id string
	}
	var exactSucceeded []succeededItem
	var cidrSucceeded []succeededItem

	for _, id := range req.IDs {
		// Try exact rules first
		stored, exists := h.rules[id]
		if exists {
			keyBytes := ruleKeyToBytes(stored.Key)
			if err := bl.Delete(keyBytes); err != nil {
				failed++
				continue
			}

			if stored.Action == "rate_limit" && h.rlStates != nil {
				h.rlStates.Delete(keyBytes)
			}

			comboType := getComboType(stored.Key)
			if comboType >= 0 && comboType < 64 {
				h.comboRefCount[comboType]--
			}
			delete(h.ruleKeyIndex, stored.Key)
			delete(h.rules, id)
			exactSucceeded = append(exactSucceeded, succeededItem{id: id})
			continue
		}

		// Try CIDR rules
		cidrStored, cidrExists := h.cidrRules[id]
		if cidrExists {
			keyBytes := cidrRuleKeyToBytes(cidrStored.Key)
			if err := cbl.Delete(keyBytes); err != nil {
				failed++
				continue
			}

			if cidrStored.Action == "rate_limit" && h.cidrRlStates != nil {
				h.cidrRlStates.Delete(keyBytes)
			}

			comboType := getCIDRComboType(cidrStored.Key)
			if comboType >= 0 && comboType < 64 {
				h.cidrComboRefCount[comboType]--
			}
			delete(h.cidrRuleKeyIndex, cidrStored.Key)
			delete(h.cidrRules, id)
			if cidrStored.SrcCIDR != "" {
				h.cidrMgr.ReleaseSrcID(cidrStored.SrcCIDR)
			}
			if cidrStored.DstCIDR != "" {
				h.cidrMgr.ReleaseDstID(cidrStored.DstCIDR)
			}
			cidrSucceeded = append(cidrSucceeded, succeededItem{id: id})
			continue
		}

		failed++
	}

	// One publish for entire batch
	exactDelta := -int64(len(exactSucceeded))
	cidrDelta := -int64(len(cidrSucceeded))
	if len(exactSucceeded) > 0 || len(cidrSucceeded) > 0 {
		if err := h.publishConfigUpdate(exactDelta, 0, cidrDelta); err != nil {
			log.Printf("[DeleteRulesBatch] WARN: publish failed after BPF deletes (safe direction): %v", err)
		}
	}
	deleted = len(exactSucceeded) + len(cidrSucceeded)

	h.rulesMu.Unlock()
	h.publishMu.Unlock()
	h.syncMu.Unlock()

	// Clean up PPS cache outside lock
	if len(exactSucceeded) > 0 || len(cidrSucceeded) > 0 {
		h.rulePPSMu.Lock()
		for _, item := range exactSucceeded {
			delete(h.lastRuleDropCount, item.id)
			delete(h.lastRuleStatsTime, item.id)
		}
		for _, item := range cidrSucceeded {
			delete(h.lastRuleDropCount, item.id)
			delete(h.lastRuleStatsTime, item.id)
		}
		h.rulePPSMu.Unlock()
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
	})
}
