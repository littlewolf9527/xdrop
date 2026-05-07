// XDrop Agent - Whitelist CRUD handlers (Phase 8: 31-combo bitmap-gated dual-buffer)
package api

import (
	"fmt"
	"log"
	"net/http"

	"github.com/cilium/ebpf"
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

// AddWhitelist adds or replaces a whitelist entry (Phase 8: 31-combo bitmap-gated).
// Lock order: syncMu → publishMu → wlMu.
// Bitmap ordering (safety-critical):
//   Add:     refcount++ → publish (bitmap bit set) → BPF insert
//   Replace: delete old BPF → old combo refcount-- → new combo refcount++ → publish → insert new BPF
func (h *Handlers) AddWhitelist(c *gin.Context) {
	var req WhitelistEntry
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Phase 8: replace old exact-only guard with combo-type validation
	key, err := h.whitelistToKey(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	newCombo := getComboType(key)
	if err := validateComboType(newCombo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Portless protocol guard
	if err := validatePortProtocolCompatNode(req.Protocol, req.SrcPort, req.DstPort); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id := req.ID
	if id == "" {
		id = uuid.New().String()
	}

	newKeyBytes := ruleKeyToBytes(key)
	wlValue := []byte{1}

	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	h.publishMu.Lock()
	defer h.publishMu.Unlock()
	h.wlMu.Lock()
	defer h.wlMu.Unlock()

	// Conflict: newKey already owned by different ID
	if existingID, ok := h.wlKeyIndex[key]; ok && existingID != id {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("whitelist key already exists under id %s", existingID)})
		return
	}

	// Check for same-ID replacement
	var oldKey *RuleKey
	var oldCombo int
	wlCountDelta := int64(1)
	if existingKey, exists := h.wlEntries[id]; exists {
		keyCopy := existingKey
		oldKey = &keyCopy
		oldCombo = getComboType(*oldKey)
		wlCountDelta = 0 // replacing, not adding
	}

	// Same-ID same-key: idempotent, no refcount/BPF change needed
	if oldKey != nil && *oldKey == key {
		c.JSON(http.StatusOK, gin.H{"success": true, "id": id, "message": "Whitelist entry unchanged (idempotent)"})
		return
	}

	// --- Security-first replacement: delete old BPF entry before adding new ---
	if oldKey != nil {
		if err := h.activeWhitelist().Delete(ruleKeyToBytes(*oldKey)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to delete old whitelist entry during replacement: %v", err)})
			return
		}
		h.wlComboRefCount[oldCombo]--
	}

	// Increment new combo refcount BEFORE publish (so bitmap bit is set first)
	h.wlComboRefCount[newCombo]++

	// Publish: sets new bitmap bit (and clears old if refcount=0)
	if err := h.publishConfigUpdate(0, wlCountDelta, 0); err != nil {
		// Rollback refcount changes
		h.wlComboRefCount[newCombo]--
		if oldKey != nil {
			h.wlComboRefCount[oldCombo]++
			// Best-effort re-insert old BPF entry
			if insErr := h.activeWhitelist().Update(ruleKeyToBytes(*oldKey), wlValue, ebpf.UpdateNoExist); insErr != nil {
				log.Printf("[AddWhitelist] WARN: rollback re-insert of old BPF entry failed: %v", insErr)
			}
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config publish failed"})
		return
	}

	// Insert new BPF entry (bitmap bit already set above)
	if err := h.activeWhitelist().Update(newKeyBytes, wlValue, ebpf.UpdateNoExist); err != nil {
		// Rollback: undo refcount, re-insert old if replacement, re-publish
		h.wlComboRefCount[newCombo]--
		if oldKey != nil {
			h.wlComboRefCount[oldCombo]++
			if insErr := h.activeWhitelist().Update(ruleKeyToBytes(*oldKey), wlValue, ebpf.UpdateNoExist); insErr != nil {
				log.Printf("[AddWhitelist] WARN: rollback re-insert of old BPF entry failed: %v", insErr)
			}
		}
		if pubErr := h.publishConfigUpdate(0, -wlCountDelta, 0); pubErr != nil {
			log.Printf("[AddWhitelist] WARN: rollback re-publish failed: %v", pubErr)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to add whitelist to BPF: %v", err)})
		return
	}

	// Update memory state
	if oldKey != nil {
		delete(h.wlKeyIndex, *oldKey)
	}
	h.wlEntries[id] = key
	h.wlKeyIndex[key] = id

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"id":      id,
		"message": "Whitelist entry added",
	})
}

// DeleteWhitelist removes a whitelist entry.
// Bitmap ordering: BPF delete → refcount-- → publish (bitmap bit cleared if refcount=0).
func (h *Handlers) DeleteWhitelist(c *gin.Context) {
	id := c.Param("id")

	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	h.publishMu.Lock()
	defer h.publishMu.Unlock()
	h.wlMu.Lock()
	defer h.wlMu.Unlock()

	key, exists := h.wlEntries[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Whitelist entry not found"})
		return
	}

	combo := getComboType(key)
	keyBytes := ruleKeyToBytes(key)

	// Delete BPF entry first
	if err := h.activeWhitelist().Delete(keyBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to delete: %v", err)})
		return
	}

	// Decrement refcount and update memory, then publish
	h.wlComboRefCount[combo]--
	delete(h.wlKeyIndex, key)
	delete(h.wlEntries, id)

	if err := h.publishConfigUpdate(0, -1, 0); err != nil {
		// Rollback: restore refcount, memory, and re-insert BPF entry
		h.wlComboRefCount[combo]++
		h.wlEntries[id] = key
		h.wlKeyIndex[key] = id
		if insErr := h.activeWhitelist().Update(keyBytes, []byte{1}, ebpf.UpdateNoExist); insErr != nil {
			log.Printf("[DeleteWhitelist] WARN: rollback BPF re-insert failed: %v", insErr)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config publish failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Whitelist entry deleted",
	})
}

// AddWhitelistBatch adds multiple whitelist entries atomically (all-or-nothing).
// Phase 8: 31-combo bitmap, supports replacement (same ID), combo refcount maintenance.
// Any validation failure or BPF error causes the entire batch to be rolled back.
func (h *Handlers) AddWhitelistBatch(c *gin.Context) {
	var req struct {
		Entries []WhitelistEntry `json:"entries"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	type preparedEntry struct {
		id            string
		key           RuleKey
		keyBytes      []byte
		combo         int
		isNoOp        bool // same-ID same-key: idempotent, skip BPF
		isReplacement bool
		oldKey        *RuleKey
		oldCombo      int
	}

	// --- Phase 1: Pre-validate ALL entries BEFORE acquiring locks ---
	// Fail the entire batch if any entry is invalid (all-or-nothing starts here).
	prepared := make([]preparedEntry, 0, len(req.Entries))
	seenIDsBefore := make(map[string]int) // for ID dedup: keep last

	for i, entry := range req.Entries {
		key, err := h.whitelistToKey(entry)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("entry %d: %v", i, err)})
			return
		}
		combo := getComboType(key)
		if err := validateComboType(combo); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("entry %d unsupported combo: %v", i, err)})
			return
		}
		if err := validatePortProtocolCompatNode(entry.Protocol, entry.SrcPort, entry.DstPort); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("entry %d: %v", i, err)})
			return
		}
		id := entry.ID
		if id == "" {
			id = uuid.New().String()
		}
		p := preparedEntry{id: id, key: key, keyBytes: ruleKeyToBytes(key), combo: combo}
		if idx, ok := seenIDsBefore[id]; ok {
			prepared[idx] = p // dedup: keep last
		} else {
			seenIDsBefore[id] = len(prepared)
			prepared = append(prepared, p)
		}
	}

	if len(prepared) == 0 {
		c.JSON(http.StatusOK, gin.H{"success": true, "added": 0})
		return
	}

	// --- Phase 2: Acquire locks and do lock-held validation ---
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	h.publishMu.Lock()
	defer h.publishMu.Unlock()
	h.wlMu.Lock()
	defer h.wlMu.Unlock()

	wlValue := []byte{1}
	seenKeysInBatch := make(map[RuleKey]string, len(prepared))

	for i := range prepared {
		p := &prepared[i]
		// Intra-batch key duplicate
		if ownerID, ok := seenKeysInBatch[p.key]; ok && ownerID != p.id {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("duplicate key in batch: id %s and %s map to the same BPF key", ownerID, p.id)})
			return
		}
		// Cross-existing key conflict
		if existingID, ok := h.wlKeyIndex[p.key]; ok && existingID != p.id {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("key already owned by id %s", existingID)})
			return
		}
		seenKeysInBatch[p.key] = p.id

		if existingKey, exists := h.wlEntries[p.id]; exists {
			if existingKey == p.key {
				p.isNoOp = true // same-ID same-key: idempotent
				continue
			}
			p.isReplacement = true
			keyCopy := existingKey
			p.oldKey = &keyCopy
			p.oldCombo = getComboType(existingKey)
		}
	}

	// --- Phase 3: Delete old BPF entries for replacements ---
	// On any failure, rollback deletions already done and return error.
	deletedOld := make([]preparedEntry, 0)
	for _, p := range prepared {
		if p.isNoOp || p.oldKey == nil {
			continue
		}
		if err := h.activeWhitelist().Delete(ruleKeyToBytes(*p.oldKey)); err != nil {
			// Rollback: re-insert already-deleted old entries
			for _, done := range deletedOld {
				if insErr := h.activeWhitelist().Update(ruleKeyToBytes(*done.oldKey), wlValue, ebpf.UpdateNoExist); insErr != nil {
					log.Printf("[AddWhitelistBatch] WARN: rollback of old entry failed (id=%s): %v", done.id, insErr)
				}
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to delete old entry for id %s: %v", p.id, err)})
			return
		}
		deletedOld = append(deletedOld, p)
	}

	// --- Phase 4: Update refcounts ---
	netNew := int64(0)
	for _, p := range prepared {
		if p.isNoOp {
			continue
		}
		if p.oldKey != nil {
			h.wlComboRefCount[p.oldCombo]--
		}
		h.wlComboRefCount[p.combo]++
		if !p.isReplacement {
			netNew++
		}
	}

	// --- Phase 5: Publish (bitmap + count reflect all changes) ---
	if err := h.publishConfigUpdate(0, netNew, 0); err != nil {
		// Full rollback: undo refcounts and re-insert old entries
		for _, p := range prepared {
			if p.isNoOp {
				continue
			}
			h.wlComboRefCount[p.combo]--
			if p.oldKey != nil {
				h.wlComboRefCount[p.oldCombo]++
				if insErr := h.activeWhitelist().Update(ruleKeyToBytes(*p.oldKey), wlValue, ebpf.UpdateNoExist); insErr != nil {
					log.Printf("[AddWhitelistBatch] WARN: rollback re-insert of old entry failed (id=%s): %v", p.id, insErr)
				}
			}
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config publish failed"})
		return
	}

	// --- Phase 6: Insert new BPF entries ---
	// If ANY insert fails, rollback ALL (including already-inserted) and re-insert all old entries.
	inserted := make([]preparedEntry, 0, len(prepared))
	for _, p := range prepared {
		if p.isNoOp {
			continue
		}
		if err := h.activeWhitelist().Update(p.keyBytes, wlValue, ebpf.UpdateNoExist); err != nil {
			// Rollback: delete all already-inserted, restore refcounts, re-insert old entries, re-publish
			for _, done := range inserted {
				if delErr := h.activeWhitelist().Delete(done.keyBytes); delErr != nil {
					log.Printf("[AddWhitelistBatch] WARN: rollback delete of new entry failed (id=%s): %v", done.id, delErr)
				}
			}
			for _, rp := range prepared {
				if rp.isNoOp {
					continue
				}
				h.wlComboRefCount[rp.combo]--
				if rp.oldKey != nil {
					h.wlComboRefCount[rp.oldCombo]++
					if insErr := h.activeWhitelist().Update(ruleKeyToBytes(*rp.oldKey), wlValue, ebpf.UpdateNoExist); insErr != nil {
						log.Printf("[AddWhitelistBatch] WARN: rollback re-insert of old entry failed (id=%s): %v", rp.id, insErr)
					}
				}
			}
			if pubErr := h.publishConfigUpdate(0, -netNew, 0); pubErr != nil {
				log.Printf("[AddWhitelistBatch] WARN: rollback re-publish failed: %v", pubErr)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("BPF insert failed for id %s: %v; entire batch rolled back", p.id, err)})
			return
		}
		inserted = append(inserted, p)
	}

	// --- Phase 7: Commit memory state ---
	for _, p := range prepared {
		if p.isNoOp {
			continue
		}
		if p.oldKey != nil {
			delete(h.wlKeyIndex, *p.oldKey)
		}
		h.wlEntries[p.id] = p.key
		h.wlKeyIndex[p.key] = p.id
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"added":   len(inserted),
	})
}

// DeleteWhitelistBatch removes multiple whitelist entries.
// Semantics: best-effort per-entry deletion. Missing IDs and per-entry BPF
// delete failures are counted as failed without aborting the rest. Config is
// published once for all successfully deleted entries. If publish fails, all
// deleted entries are rolled back (BPF re-insert + refcount restore).
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

	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	h.publishMu.Lock()
	defer h.publishMu.Unlock()
	h.wlMu.Lock()
	defer h.wlMu.Unlock()

	type deletedItem struct {
		id    string
		key   RuleKey
		combo int
	}
	deletedItems := make([]deletedItem, 0, len(req.IDs))
	wlValue := []byte{1}

	for _, id := range req.IDs {
		key, exists := h.wlEntries[id]
		if !exists {
			failed++
			continue
		}

		combo := getComboType(key)

		// BPF delete first
		if err := h.activeWhitelist().Delete(ruleKeyToBytes(key)); err != nil {
			failed++
			continue
		}

		h.wlComboRefCount[combo]--
		delete(h.wlKeyIndex, key)
		delete(h.wlEntries, id)
		deletedItems = append(deletedItems, deletedItem{id: id, key: key, combo: combo})
		deleted++
	}

	if deleted > 0 {
		if err := h.publishConfigUpdate(0, -int64(deleted), 0); err != nil {
			// Rollback: restore all successfully deleted entries
			for _, item := range deletedItems {
				h.wlComboRefCount[item.combo]++
				h.wlEntries[item.id] = item.key
				h.wlKeyIndex[item.key] = item.id
				if insErr := h.activeWhitelist().Update(ruleKeyToBytes(item.key), wlValue, ebpf.UpdateNoExist); insErr != nil {
					log.Printf("[DeleteWhitelistBatch] WARN: rollback BPF re-insert failed (id=%s): %v", item.id, insErr)
				}
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "config publish failed"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
	})
}
