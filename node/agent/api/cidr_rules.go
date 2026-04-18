// XDrop Agent - CIDR rule add paths (HTTP + sync recovery)
// NOTE: DeleteRule (in rules_mutation.go) also calls cidrMgr.ReleaseSrcID/ReleaseDstID
// when deleting CIDR rules. CIDR ID lifecycle therefore spans both files:
//   alloc  → cidr_rules.go (addCIDRRule / addCIDRRuleFromSync)
//   release on delete → rules_mutation.go (DeleteRule / DeleteRulesBatch)
package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

func (h *Handlers) addCIDRRule(c *gin.Context, req Rule, flagsMask, flagsValue uint8) {
	// Validate action
	action, err := parseAction(req.Action)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if action == ActionRateLimit && req.RateLimit <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rate_limit must be > 0 for rate_limit action"})
		return
	}

	// Normalize CIDRs
	var srcCIDR, dstCIDR string
	if req.SrcCIDR != "" {
		srcCIDR, err = cidr.NormalizeCIDR(req.SrcCIDR)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid src_cidr: %v", err)})
			return
		}
	}
	if req.DstCIDR != "" {
		dstCIDR, err = cidr.NormalizeCIDR(req.DstCIDR)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid dst_cidr: %v", err)})
			return
		}
	}

	// Overlap detection
	if srcCIDR != "" {
		existing := h.cidrMgr.ListSrcCIDRs()
		if conflict, _ := cidr.CheckOverlap(srcCIDR, existing); conflict != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf(
				"src_cidr overlap: %s conflicts with existing %s (strict containment); remove conflicting rule first", srcCIDR, conflict)})
			return
		}
	}
	if dstCIDR != "" {
		existing := h.cidrMgr.ListDstCIDRs()
		if conflict, _ := cidr.CheckOverlap(dstCIDR, existing); conflict != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf(
				"dst_cidr overlap: %s conflicts with existing %s (strict containment); remove conflicting rule first", dstCIDR, conflict)})
			return
		}
	}

	// Allocate CIDR IDs
	var srcID, dstID uint32
	if srcCIDR != "" {
		srcID, err = h.cidrMgr.AllocSrcID(srcCIDR)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to alloc src CIDR ID: %v", err)})
			return
		}
	}
	if dstCIDR != "" {
		dstID, err = h.cidrMgr.AllocDstID(dstCIDR)
		if err != nil {
			// Rollback src alloc
			if srcCIDR != "" {
				h.cidrMgr.ReleaseSrcID(srcCIDR)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to alloc dst CIDR ID: %v", err)})
			return
		}
	}

	// Build CIDR rule key
	ck := CIDRRuleKey{
		SrcID:    srcID,
		DstID:    dstID,
		SrcPort:  htons(req.SrcPort),
		DstPort:  htons(req.DstPort),
		Protocol: parseProtocol(req.Protocol),
	}

	if err := validateComboType(getCIDRComboType(ck)); err != nil {
		if srcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(srcCIDR)
		}
		if dstCIDR != "" {
			h.cidrMgr.ReleaseDstID(dstCIDR)
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	value := RuleValue{
		Action:        action,
		TcpFlagsMask:  flagsMask,
		TcpFlagsValue: flagsValue,
		RateLimit:     req.RateLimit,
		PktLenMin:     req.PktLenMin,
		PktLenMax:     req.PktLenMax,
	}

	keyBytes := cidrRuleKeyToBytes(ck)
	valueBytes := ruleValueToBytes(value)

	id := req.ID
	if id == "" {
		id = uuid.New().String()
	}

	// Double-buffer: BPF Insert + memory update + publish
	h.syncMu.Lock()
	h.publishMu.Lock()
	h.rulesMu.Lock()
	cbl := h.activeCidrBlacklist()

	// Duplicate key check
	if existingID, ok := h.cidrRuleKeyIndex[ck]; ok && existingID != id {
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		if srcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(srcCIDR)
		}
		if dstCIDR != "" {
			h.cidrMgr.ReleaseDstID(dstCIDR)
		}
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("CIDR rule key already exists under id %s", existingID)})
		return
	}

	// Check for existing rule with same ID (replacement)
	var oldStored *StoredCIDRRule
	countDelta := int64(1)
	if old, exists := h.cidrRules[id]; exists {
		oldCopy := old
		oldStored = &oldCopy
		countDelta = 0
	}

	// Step 1: Insert BPF entry
	if err := cbl.Insert(keyBytes, valueBytes); err != nil {
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		if srcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(srcCIDR)
		}
		if dstCIDR != "" {
			h.cidrMgr.ReleaseDstID(dstCIDR)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to insert CIDR rule: %v", err)})
		return
	}

	// Step 2: Delete old BPF entry if key changed
	if oldStored != nil && oldStored.Key != ck {
		if err := cbl.Delete(cidrRuleKeyToBytes(oldStored.Key)); err != nil {
			cbl.Delete(keyBytes) // rollback new entry
			h.rulesMu.Unlock()
			h.publishMu.Unlock()
			h.syncMu.Unlock()
			if srcCIDR != "" {
				h.cidrMgr.ReleaseSrcID(srcCIDR)
			}
			if dstCIDR != "" {
				h.cidrMgr.ReleaseDstID(dstCIDR)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete old CIDR BPF entry: %v", err)})
			return
		}
	}

	// Step 3: Update memory state (defer old CIDR ID release until after publish succeeds)
	if oldStored != nil {
		oldCombo := getCIDRComboType(oldStored.Key)
		if oldCombo >= 0 && oldCombo < 64 {
			h.cidrComboRefCount[oldCombo]--
		}
		delete(h.cidrRuleKeyIndex, oldStored.Key)
		// NOTE: old CIDR IDs are NOT released here — deferred to after publish
		// so rollback can restore oldStored.Key with the original trie IDs intact
	}

	comboType := getCIDRComboType(ck)
	if comboType >= 0 && comboType < 64 {
		h.cidrComboRefCount[comboType]++
	}
	h.cidrRules[id] = StoredCIDRRule{
		Key:       ck,
		SrcCIDR:   srcCIDR,
		DstCIDR:   dstCIDR,
		Action:    req.Action,
		RateLimit: req.RateLimit,
		PktLenMin: req.PktLenMin,
		PktLenMax: req.PktLenMax,
		TcpFlags:  req.TcpFlags,
	}
	h.cidrRuleKeyIndex[ck] = id

	// Step 4: Publish config
	if err := h.publishConfigUpdate(0, 0, countDelta); err != nil {
		// Rollback new rule
		cbl.Delete(keyBytes)
		if comboType >= 0 && comboType < 64 {
			h.cidrComboRefCount[comboType]--
		}
		delete(h.cidrRules, id)
		delete(h.cidrRuleKeyIndex, ck)
		if srcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(srcCIDR)
		}
		if dstCIDR != "" {
			h.cidrMgr.ReleaseDstID(dstCIDR)
		}
		// Restore old rule if this was a replacement
		// Old CIDR IDs were never released, so oldStored.Key still has valid trie IDs
		if oldStored != nil {
			oldKeyBytes := cidrRuleKeyToBytes(oldStored.Key)
			oldAction, _ := parseAction(oldStored.Action)
			oldFM, oldFV, _ := parseTcpFlags(oldStored.TcpFlags)
			oldValue := RuleValue{Action: oldAction, TcpFlagsMask: oldFM, TcpFlagsValue: oldFV, RateLimit: oldStored.RateLimit, PktLenMin: oldStored.PktLenMin, PktLenMax: oldStored.PktLenMax}
			cbl.Insert(oldKeyBytes, ruleValueToBytes(oldValue))
			oldCombo := getCIDRComboType(oldStored.Key)
			if oldCombo >= 0 && oldCombo < 64 {
				h.cidrComboRefCount[oldCombo]++
			}
			h.cidrRules[id] = *oldStored
			h.cidrRuleKeyIndex[oldStored.Key] = id
		}
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config publish failed"})
		return
	}

	// Publish succeeded — now safe to release old CIDR IDs
	if oldStored != nil {
		if oldStored.SrcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(oldStored.SrcCIDR)
		}
		if oldStored.DstCIDR != "" {
			h.cidrMgr.ReleaseDstID(oldStored.DstCIDR)
		}
	}

	h.rulesMu.Unlock()
	h.publishMu.Unlock()
	h.syncMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"rule_id": id,
		"message": "CIDR rule added",
	})
}

// addCIDRRuleFromSync adds a CIDR rule from Controller sync (internal, no gin.Context)
func (h *Handlers) addCIDRRuleFromSync(rule SyncRule) error {
	action, err := parseAction(rule.Action)
	if err != nil {
		return fmt.Errorf("invalid action: %w", err)
	}
	if action == ActionRateLimit && rule.RateLimit <= 0 {
		return fmt.Errorf("rate_limit must be > 0 for rate_limit action")
	}

	// Normalize CIDRs
	var srcCIDR, dstCIDR string
	if rule.SrcCIDR != "" {
		srcCIDR, err = cidr.NormalizeCIDR(rule.SrcCIDR)
		if err != nil {
			return fmt.Errorf("invalid src_cidr: %w", err)
		}
	}
	if rule.DstCIDR != "" {
		dstCIDR, err = cidr.NormalizeCIDR(rule.DstCIDR)
		if err != nil {
			return fmt.Errorf("invalid dst_cidr: %w", err)
		}
	}

	// Overlap detection
	if srcCIDR != "" {
		existing := h.cidrMgr.ListSrcCIDRs()
		if conflict, _ := cidr.CheckOverlap(srcCIDR, existing); conflict != "" {
			return fmt.Errorf("src_cidr overlap: %s conflicts with existing %s", srcCIDR, conflict)
		}
	}
	if dstCIDR != "" {
		existing := h.cidrMgr.ListDstCIDRs()
		if conflict, _ := cidr.CheckOverlap(dstCIDR, existing); conflict != "" {
			return fmt.Errorf("dst_cidr overlap: %s conflicts with existing %s", dstCIDR, conflict)
		}
	}

	// Validate tcp_flags + protocol BEFORE CIDR allocation so a rejection here
	// does not leave freshly-allocated trie IDs leaked (AUD-V240-001).
	sfm, sfv, sfErr := parseTcpFlags(rule.TcpFlags)
	if sfErr != nil {
		return fmt.Errorf("invalid tcp_flags %q: %w", rule.TcpFlags, sfErr)
	}
	if sfm != 0 && parseProtocol(rule.Protocol) != ProtoTCP {
		return fmt.Errorf("tcp_flags requires protocol=tcp, got %q", rule.Protocol)
	}

	// Allocate CIDR IDs
	var srcID, dstID uint32
	if srcCIDR != "" {
		srcID, err = h.cidrMgr.AllocSrcID(srcCIDR)
		if err != nil {
			return fmt.Errorf("failed to alloc src CIDR ID: %w", err)
		}
	}
	if dstCIDR != "" {
		dstID, err = h.cidrMgr.AllocDstID(dstCIDR)
		if err != nil {
			if srcCIDR != "" {
				h.cidrMgr.ReleaseSrcID(srcCIDR)
			}
			return fmt.Errorf("failed to alloc dst CIDR ID: %w", err)
		}
	}

	// Build CIDR rule key
	ck := CIDRRuleKey{
		SrcID:    srcID,
		DstID:    dstID,
		SrcPort:  htons(rule.SrcPort),
		DstPort:  htons(rule.DstPort),
		Protocol: parseProtocol(rule.Protocol),
	}

	if err := validateComboType(getCIDRComboType(ck)); err != nil {
		if srcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(srcCIDR)
		}
		if dstCIDR != "" {
			h.cidrMgr.ReleaseDstID(dstCIDR)
		}
		return fmt.Errorf("invalid CIDR rule: %w", err)
	}
	value := RuleValue{
		Action:        action,
		TcpFlagsMask:  sfm,
		TcpFlagsValue: sfv,
		RateLimit:     rule.RateLimit,
		PktLenMin:     rule.PktLenMin,
		PktLenMax:     rule.PktLenMax,
	}

	keyBytes := cidrRuleKeyToBytes(ck)
	valueBytes := ruleValueToBytes(value)

	id := rule.ID
	if id == "" {
		id = uuid.New().String()
	}

	// Double-buffer: BPF Insert + memory update + publish
	h.syncMu.Lock()
	h.publishMu.Lock()
	h.rulesMu.Lock()
	cbl := h.activeCidrBlacklist()

	// Duplicate key check
	if existingID, ok := h.cidrRuleKeyIndex[ck]; ok && existingID != id {
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		if srcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(srcCIDR)
		}
		if dstCIDR != "" {
			h.cidrMgr.ReleaseDstID(dstCIDR)
		}
		return fmt.Errorf("CIDR rule key already exists under id %s", existingID)
	}

	// Check for existing rule with same ID (replacement)
	var oldStored *StoredCIDRRule
	countDelta := int64(1)
	if old, exists := h.cidrRules[id]; exists {
		oldCopy := old
		oldStored = &oldCopy
		countDelta = 0
	}

	// Step 1: Insert BPF entry
	if err := cbl.Insert(keyBytes, valueBytes); err != nil {
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		if srcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(srcCIDR)
		}
		if dstCIDR != "" {
			h.cidrMgr.ReleaseDstID(dstCIDR)
		}
		return fmt.Errorf("BPF insert failed: %w", err)
	}

	// Step 2: Delete old BPF entry if key changed
	if oldStored != nil && oldStored.Key != ck {
		if err := cbl.Delete(cidrRuleKeyToBytes(oldStored.Key)); err != nil {
			cbl.Delete(keyBytes)
			h.rulesMu.Unlock()
			h.publishMu.Unlock()
			h.syncMu.Unlock()
			if srcCIDR != "" {
				h.cidrMgr.ReleaseSrcID(srcCIDR)
			}
			if dstCIDR != "" {
				h.cidrMgr.ReleaseDstID(dstCIDR)
			}
			return fmt.Errorf("failed to delete old CIDR BPF entry: %w", err)
		}
	}

	// Step 3: Update memory state (defer old CIDR ID release until after publish succeeds)
	if oldStored != nil {
		oldCombo := getCIDRComboType(oldStored.Key)
		if oldCombo >= 0 && oldCombo < 64 {
			h.cidrComboRefCount[oldCombo]--
		}
		delete(h.cidrRuleKeyIndex, oldStored.Key)
		// NOTE: old CIDR IDs are NOT released here — deferred to after publish
		// so rollback can restore oldStored.Key with the original trie IDs intact
	}

	comboType := getCIDRComboType(ck)
	if comboType >= 0 && comboType < 64 {
		h.cidrComboRefCount[comboType]++
	}
	h.cidrRules[id] = StoredCIDRRule{
		Key:       ck,
		SrcCIDR:   srcCIDR,
		DstCIDR:   dstCIDR,
		Action:    rule.Action,
		RateLimit: rule.RateLimit,
		PktLenMin: rule.PktLenMin,
		PktLenMax: rule.PktLenMax,
		TcpFlags:  rule.TcpFlags,
	}
	h.cidrRuleKeyIndex[ck] = id

	// Step 4: Publish config
	if err := h.publishConfigUpdate(0, 0, countDelta); err != nil {
		// Rollback new rule
		cbl.Delete(keyBytes)
		if comboType >= 0 && comboType < 64 {
			h.cidrComboRefCount[comboType]--
		}
		delete(h.cidrRules, id)
		delete(h.cidrRuleKeyIndex, ck)
		if srcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(srcCIDR)
		}
		if dstCIDR != "" {
			h.cidrMgr.ReleaseDstID(dstCIDR)
		}
		// Restore old rule if this was a replacement
		// Old CIDR IDs were never released, so oldStored.Key still has valid trie IDs
		if oldStored != nil {
			oldKeyBytes := cidrRuleKeyToBytes(oldStored.Key)
			oldAction, _ := parseAction(oldStored.Action)
			oldFM, oldFV, _ := parseTcpFlags(oldStored.TcpFlags)
			oldValue := RuleValue{Action: oldAction, TcpFlagsMask: oldFM, TcpFlagsValue: oldFV, RateLimit: oldStored.RateLimit, PktLenMin: oldStored.PktLenMin, PktLenMax: oldStored.PktLenMax}
			cbl.Insert(oldKeyBytes, ruleValueToBytes(oldValue))
			oldCombo := getCIDRComboType(oldStored.Key)
			if oldCombo >= 0 && oldCombo < 64 {
				h.cidrComboRefCount[oldCombo]++
			}
			h.cidrRules[id] = *oldStored
			h.cidrRuleKeyIndex[oldStored.Key] = id
		}
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		return fmt.Errorf("config publish failed: %w", err)
	}

	// Publish succeeded — now safe to release old CIDR IDs
	if oldStored != nil {
		if oldStored.SrcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(oldStored.SrcCIDR)
		}
		if oldStored.DstCIDR != "" {
			h.cidrMgr.ReleaseDstID(oldStored.DstCIDR)
		}
	}

	h.rulesMu.Unlock()
	h.publishMu.Unlock()
	h.syncMu.Unlock()
	return nil
}
