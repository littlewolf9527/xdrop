// XDrop Agent - Whitelist CRUD handlers
package api

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (h *Handlers) ListWhitelist(c *gin.Context) {
	h.wlMu.RLock()
	defer h.wlMu.RUnlock()

	entries := make([]WhitelistEntry, 0, len(h.wlEntries))
	for id, key := range h.wlEntries {
		entries = append(entries, h.keyToWhitelist(id, key))
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"count":   len(entries),
	})
}

// AddWhitelist adds a whitelist entry
// BPF whitelist only supports 3 match types: exact 5-tuple, src_ip-only, dst_ip-only.
// Entries with port/protocol fields but missing the corresponding IP are rejected
// because they would be silently ineffective in the datapath.
func (h *Handlers) AddWhitelist(c *gin.Context) {
	var req WhitelistEntry
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate: BPF whitelist only supports exact, src_ip-only, dst_ip-only
	hasIP := req.SrcIP != "" || req.DstIP != ""
	hasPortOrProto := req.SrcPort != 0 || req.DstPort != 0 ||
		(req.Protocol != "" && req.Protocol != "all")
	hasBothIPs := req.SrcIP != "" && req.DstIP != ""

	if !hasIP && hasPortOrProto {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "whitelist with port/protocol but no IP is not supported; " +
				"BPF whitelist only matches: exact 5-tuple, src_ip-only, or dst_ip-only",
		})
		return
	}
	if hasPortOrProto && !hasBothIPs {
		// Has port/proto but only one IP → not an exact match, BPF won't match
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "whitelist with port/protocol requires both src_ip and dst_ip (exact 5-tuple); " +
				"single-IP whitelist only supports IP-only matching without port/protocol",
		})
		return
	}

	key, err := h.whitelistToKey(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	keyBytes := ruleKeyToBytes(key)
	wlValue := []byte{1}

	// Use externally provided ID if present, otherwise generate a new one
	id := req.ID
	if id == "" {
		id = uuid.New().String()
	}

	h.publishMu.Lock()
	h.wlMu.Lock()

	// Duplicate key check: reject if another ID already owns this key
	if existingID, ok := h.wlKeyIndex[key]; ok && existingID != id {
		h.wlMu.Unlock()
		h.publishMu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("whitelist key already exists under id %s", existingID)})
		return
	}

	// Check for existing whitelist with same ID (replacement case)
	var oldKey *RuleKey
	wlCountDelta := int64(1)
	if existingKey, exists := h.wlEntries[id]; exists {
		keyCopy := existingKey
		oldKey = &keyCopy
		wlCountDelta = 0 // replacing, not adding
	}

	// Step 1: Insert new BPF whitelist entry (old entry still intact if different key)
	if err := h.whitelist.Insert(keyBytes, wlValue); err != nil {
		h.wlMu.Unlock()
		h.publishMu.Unlock()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to add whitelist: %v", err)})
		return
	}

	// Step 2: Delete old BPF entry BEFORE publish (hard failure to avoid orphan)
	if oldKey != nil && *oldKey != key {
		if err := h.whitelist.Delete(ruleKeyToBytes(*oldKey)); err != nil {
			if delErr := h.whitelist.Delete(keyBytes); delErr != nil {
				log.Printf("[AddWhitelist] WARN: best-effort cleanup of new BPF entry failed during abort: %v", delErr)
			}
			h.wlMu.Unlock()
			h.publishMu.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete old whitelist entry during replacement: %v", err)})
			return
		}
	}

	// Step 3: Update memory state
	if oldKey != nil {
		delete(h.wlKeyIndex, *oldKey)
	}
	h.wlEntries[id] = key
	h.wlKeyIndex[key] = id

	// Step 4: Publish config
	if err := h.publishConfigUpdate(0, wlCountDelta, 0); err != nil {
		// Strong failure: rollback memory + BPF
		if delErr := h.whitelist.Delete(keyBytes); delErr != nil {
			log.Printf("[AddWhitelist] WARN: best-effort rollback delete of new BPF entry failed: %v", delErr)
		}
		delete(h.wlEntries, id)
		delete(h.wlKeyIndex, key)
		// Restore old state if replacement
		if oldKey != nil {
			h.wlEntries[id] = *oldKey
			h.wlKeyIndex[*oldKey] = id
			// Re-insert old BPF entry if it was deleted (best-effort restore)
			if *oldKey != key {
				if insErr := h.whitelist.Insert(ruleKeyToBytes(*oldKey), wlValue); insErr != nil {
					log.Printf("[AddWhitelist] WARN: best-effort rollback re-insert of old BPF entry failed: %v", insErr)
				}
			}
		}
		h.wlMu.Unlock()
		h.publishMu.Unlock()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config publish failed"})
		return
	}

	h.wlMu.Unlock()
	h.publishMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"id":      id,
		"message": "Whitelist entry added",
	})
}

// DeleteWhitelist removes a whitelist entry
func (h *Handlers) DeleteWhitelist(c *gin.Context) {
	id := c.Param("id")

	h.publishMu.Lock()
	h.wlMu.Lock()

	key, exists := h.wlEntries[id]
	if !exists {
		h.wlMu.Unlock()
		h.publishMu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "Whitelist entry not found"})
		return
	}

	keyBytes := ruleKeyToBytes(key)
	if err := h.whitelist.Delete(keyBytes); err != nil {
		h.wlMu.Unlock()
		h.publishMu.Unlock()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete: %v", err)})
		return
	}

	delete(h.wlKeyIndex, key)
	delete(h.wlEntries, id)

	if err := h.publishConfigUpdate(0, -1, 0); err != nil {
		log.Printf("[DeleteWhitelist] WARN: publish failed after BPF delete (safe direction): %v", err)
	}

	h.wlMu.Unlock()
	h.publishMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Whitelist entry deleted",
	})
}

// AddWhitelistBatch adds multiple whitelist entries in one request.
// Follows the same lock + double-buffer pattern as AddRulesBatch.
func (h *Handlers) AddWhitelistBatch(c *gin.Context) {
	var req struct {
		Entries []WhitelistEntry `json:"entries"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	added := 0
	failed := 0

	// Pre-validate and prepare entries (before locks)
	type preparedEntry struct {
		id       string
		key      RuleKey
		keyBytes []byte
	}
	prepared := make([]preparedEntry, 0, len(req.Entries))

	// Deduplicate by ID: keep last occurrence
	seenIDs := make(map[string]int)

	for _, entry := range req.Entries {
		// Validate: BPF whitelist only supports exact, src_ip-only, dst_ip-only
		hasIP := entry.SrcIP != "" || entry.DstIP != ""
		hasPortOrProto := entry.SrcPort != 0 || entry.DstPort != 0 ||
			(entry.Protocol != "" && entry.Protocol != "all")
		hasBothIPs := entry.SrcIP != "" && entry.DstIP != ""

		if !hasIP && hasPortOrProto {
			failed++
			continue
		}
		if hasPortOrProto && !hasBothIPs {
			failed++
			continue
		}

		key, err := h.whitelistToKey(entry)
		if err != nil {
			failed++
			continue
		}

		id := entry.ID
		if id == "" {
			id = uuid.New().String()
		}

		p := preparedEntry{
			id:       id,
			key:      key,
			keyBytes: ruleKeyToBytes(key),
		}

		if idx, ok := seenIDs[id]; ok {
			prepared[idx] = p
		} else {
			seenIDs[id] = len(prepared)
			prepared = append(prepared, p)
		}
	}

	// Critical section: BPF writes + memory updates, one publish at the end
	h.publishMu.Lock()
	h.wlMu.Lock()

	type succeededItem struct {
		id            string
		key           RuleKey
		keyBytes      []byte
		isReplacement bool
		oldKey        *RuleKey
	}
	succeeded := make([]succeededItem, 0, len(prepared))
	wlValue := []byte{1}

	for _, p := range prepared {
		// Duplicate key check: reject if another ID already owns this key
		if existingID, ok := h.wlKeyIndex[p.key]; ok && existingID != p.id {
			failed++
			continue
		}

		// Insert new BPF entry
		if err := h.whitelist.Insert(p.keyBytes, wlValue); err != nil {
			failed++
			continue
		}

		// Save old state
		var oldKey *RuleKey
		isReplacement := false
		if existingKey, exists := h.wlEntries[p.id]; exists {
			isReplacement = true
			keyCopy := existingKey
			oldKey = &keyCopy
		}

		// Delete old BPF entry if key changed
		if oldKey != nil && *oldKey != p.key {
			if err := h.whitelist.Delete(ruleKeyToBytes(*oldKey)); err != nil {
				// Abort this item, remove new entry
				if delErr := h.whitelist.Delete(p.keyBytes); delErr != nil {
					log.Printf("[AddWhitelistBatch] WARN: best-effort cleanup of new BPF entry failed: %v", delErr)
				}
				failed++
				continue
			}
		}

		// Update memory state
		if oldKey != nil {
			delete(h.wlKeyIndex, *oldKey)
		}
		h.wlEntries[p.id] = p.key
		h.wlKeyIndex[p.key] = p.id
		succeeded = append(succeeded, succeededItem{id: p.id, key: p.key, keyBytes: p.keyBytes, isReplacement: isReplacement, oldKey: oldKey})
	}

	// Count net new (exclude replacements)
	netNew := int64(0)
	for _, item := range succeeded {
		if !item.isReplacement {
			netNew++
		}
	}

	// One publish for entire batch
	if len(succeeded) > 0 {
		if err := h.publishConfigUpdate(0, netNew, 0); err != nil {
			// Rollback all
			for _, item := range succeeded {
				if delErr := h.whitelist.Delete(item.keyBytes); delErr != nil {
					log.Printf("[AddWhitelistBatch] WARN: rollback delete failed (id=%s): %v", item.id, delErr)
				}
				delete(h.wlKeyIndex, item.key)
				delete(h.wlEntries, item.id)
				if item.oldKey != nil {
					h.wlEntries[item.id] = *item.oldKey
					h.wlKeyIndex[*item.oldKey] = item.id
					if *item.oldKey != item.key {
						if insErr := h.whitelist.Insert(ruleKeyToBytes(*item.oldKey), wlValue); insErr != nil {
							log.Printf("[AddWhitelistBatch] WARN: rollback re-insert failed (id=%s): %v", item.id, insErr)
						}
					}
				}
			}
			h.wlMu.Unlock()
			h.publishMu.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "config publish failed"})
			return
		}
	}
	added = len(succeeded)

	h.wlMu.Unlock()
	h.publishMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"added":   added,
		"failed":  failed,
	})
}

// DeleteWhitelistBatch removes multiple whitelist entries in one request.
func (h *Handlers) DeleteWhitelistBatch(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	deleted := 0
	failed := 0

	h.publishMu.Lock()
	h.wlMu.Lock()

	for _, id := range req.IDs {
		key, exists := h.wlEntries[id]
		if !exists {
			failed++
			continue
		}

		if err := h.whitelist.Delete(ruleKeyToBytes(key)); err != nil {
			failed++
			continue
		}

		delete(h.wlKeyIndex, key)
		delete(h.wlEntries, id)
		deleted++
	}

	// One publish for entire batch
	if deleted > 0 {
		if err := h.publishConfigUpdate(0, -int64(deleted), 0); err != nil {
			log.Printf("[DeleteWhitelistBatch] WARN: publish failed after BPF deletes (safe direction): %v", err)
		}
	}

	h.wlMu.Unlock()
	h.publishMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
	})
}
