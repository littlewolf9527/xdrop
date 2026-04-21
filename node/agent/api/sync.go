// XDrop Agent - Controller sync path (AtomicSync / AddRuleFromSync / AddWhitelistFromSync)
package api

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/http"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

func (h *Handlers) AddRuleFromSync(rule SyncRule) error {
	// Detect CIDR rule and route to internal CIDR add
	if rule.SrcCIDR != "" || rule.DstCIDR != "" {
		return h.addCIDRRuleFromSync(rule)
	}

	// Convert to internal Rule format
	req := Rule{
		ID:           rule.ID,
		SrcIP:        rule.SrcIP,
		DstIP:        rule.DstIP,
		SrcPort:      rule.SrcPort,
		DstPort:      rule.DstPort,
		Protocol:     rule.Protocol,
		Action:       rule.Action,
		RateLimit:    rule.RateLimit,
		PktLenMin:    rule.PktLenMin,
		PktLenMax:    rule.PktLenMax,
		TcpFlags:     rule.TcpFlags,
		MatchAnomaly: rule.MatchAnomaly,
	}

	// Validation is done at Controller level, but do a sanity check
	if err := validateRule(req.SrcIP, req.DstIP, req.Protocol, req.SrcPort, req.DstPort, req.PktLenMin, req.PktLenMax); err != nil {
		return fmt.Errorf("invalid rule: %w", err)
	}

	key, err := h.ruleToKey(req)
	if err != nil {
		return fmt.Errorf("failed to convert rule: %w", err)
	}

	if err := validateComboType(getComboType(key)); err != nil {
		return fmt.Errorf("rule rejected: %w", err)
	}

	action, err := parseAction(req.Action)
	if err != nil {
		return fmt.Errorf("invalid action: %w", err)
	}

	// Validate rate_limit consistency
	if action == ActionRateLimit && req.RateLimit <= 0 {
		return fmt.Errorf("rate_limit must be > 0 for rate_limit action")
	}

	fm, fv, fErr := parseTcpFlags(req.TcpFlags)
	if fErr != nil {
		return fmt.Errorf("invalid tcp_flags %q: %w", req.TcpFlags, fErr)
	}
	if fm != 0 && parseProtocol(req.Protocol) != ProtoTCP {
		return fmt.Errorf("tcp_flags requires protocol=tcp")
	}
	value := RuleValue{
		Action:        action,
		TcpFlagsMask:  fm,
		TcpFlagsValue: fv,
		MatchAnomaly:  req.MatchAnomaly,
		RateLimit:     req.RateLimit,
		PktLenMin:     req.PktLenMin,
		PktLenMax:     req.PktLenMax,
	}

	keyBytes := ruleKeyToBytes(key)
	valueBytes := ruleValueToBytes(value)

	// Use provided ID or generate new one
	id := rule.ID
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
		return fmt.Errorf("rule key already exists under id %s", existingID)
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
	if err := bl.Update(keyBytes, valueBytes, ebpf.UpdateNoExist); err != nil {
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		return fmt.Errorf("BPF insert failed: %w", err)
	}

	// Step 2: Delete old BPF entry BEFORE publish (hard failure to avoid orphan)
	if oldStored != nil && oldStored.Key != key {
		if err := bl.Delete(ruleKeyToBytes(oldStored.Key)); err != nil {
			if delErr := bl.Delete(keyBytes); delErr != nil {
				log.Printf("[AddRuleFromSync] WARN: best-effort cleanup of new BPF entry failed during abort: %v", delErr)
			}
			h.rulesMu.Unlock()
			h.publishMu.Unlock()
			h.syncMu.Unlock()
			return fmt.Errorf("failed to delete old BPF entry during replacement: %w", err)
		}
	}

	// Step 3: Update memory state
	if oldStored != nil {
		oldCombo := getComboType(oldStored.Key)
		if oldCombo >= 0 && oldCombo < 64 {
			h.comboRefCount[oldCombo]--
		}
		delete(h.ruleKeyIndex, oldStored.Key)
	}
	comboType := getComboType(key)
	if comboType >= 0 && comboType < 64 {
		h.comboRefCount[comboType]++
	}
	h.rules[id] = StoredRule{
		Key:          key,
		Action:       req.Action,
		RateLimit:    req.RateLimit,
		PktLenMin:    req.PktLenMin,
		PktLenMax:    req.PktLenMax,
		TcpFlags:     req.TcpFlags,
		MatchAnomaly: req.MatchAnomaly,
	}
	h.ruleKeyIndex[key] = id

	// Step 4: Publish config
	if err := h.publishConfigUpdate(countDelta, 0, 0); err != nil {
		// Strong failure: rollback memory + BPF
		if delErr := bl.Delete(keyBytes); delErr != nil {
			log.Printf("[AddRuleFromSync] WARN: best-effort rollback delete of new BPF entry failed: %v", delErr)
		}
		if comboType >= 0 && comboType < 64 {
			h.comboRefCount[comboType]--
		}
		delete(h.ruleKeyIndex, key)
		delete(h.rules, id)
		// Restore old state if replacement
		if oldStored != nil {
			oldCombo := getComboType(oldStored.Key)
			if oldCombo >= 0 && oldCombo < 64 {
				h.comboRefCount[oldCombo]++
			}
			h.rules[id] = *oldStored
			h.ruleKeyIndex[oldStored.Key] = id
			// Re-insert old BPF entry if it was deleted (best-effort restore)
			if oldStored.Key != key {
				oldAction, _ := parseAction(oldStored.Action)
				oldFM, oldFV, _ := parseTcpFlags(oldStored.TcpFlags)
				oldValue := RuleValue{Action: oldAction, TcpFlagsMask: oldFM, TcpFlagsValue: oldFV, RateLimit: oldStored.RateLimit, PktLenMin: oldStored.PktLenMin, PktLenMax: oldStored.PktLenMax}
				if insErr := bl.Update(ruleKeyToBytes(oldStored.Key), ruleValueToBytes(oldValue), ebpf.UpdateNoExist); insErr != nil {
					log.Printf("[AddRuleFromSync] WARN: best-effort rollback re-insert of old BPF entry failed: %v", insErr)
				}
			}
		}
		h.rulesMu.Unlock()
		h.publishMu.Unlock()
		h.syncMu.Unlock()
		return fmt.Errorf("config publish failed: %w", err)
	}

	h.rulesMu.Unlock()
	h.publishMu.Unlock()
	h.syncMu.Unlock()

	return nil
}

// AtomicSync performs zero-gap full sync of blacklist rules using dual rule maps.
// POST /api/v1/sync/atomic — only syncs blacklist rules (exact + CIDR), not whitelist.
// Whitelist must be synced separately before calling this endpoint.
func (h *Handlers) AtomicSync(c *gin.Context) {
	var req struct {
		Rules []Rule `json:"rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.DoAtomicSync(req.Rules)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  err.Error(),
			"added":  result.Added,
			"failed": result.Failed,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"added":      result.Added,
		"failed":     result.Failed,
		"rules":      result.ExactRules,
		"cidr_rules": result.CIDRRules,
	})
}

// DoAtomicSync is the core atomic sync logic — callable from both the HTTP handler and SyncOnStartup.
// It acquires syncMu and publishMu internally.
func (h *Handlers) DoAtomicSync(rules []Rule) (AtomicSyncResult, error) {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()

	h.publishMu.Lock()
	defer h.publishMu.Unlock()

	shadow := h.shadowBlacklist()
	cidrShadow := h.shadowCidrBlacklist()

	// --- Step 1: Clear shadow rule maps ---
	clearMap(shadow)
	clearMap(cidrShadow)

	// --- Step 2: Write all rules to shadow maps ---
	var shadowCombo [64]int
	var shadowCidrCombo [64]int
	var shadowRuleCount int64
	var shadowCidrCount int64
	newRules := make(map[string]StoredRule)
	newCidrRules := make(map[string]StoredCIDRRule)
	newRuleKeyIndex := make(map[RuleKey]string)
	newCidrRuleKeyIndex := make(map[CIDRRuleKey]string)

	added := 0
	failed := 0

	// Save old CIDR rules — their IDs will be released AFTER the flip
	// to avoid destroying active trie entries during shadow build.
	h.rulesMu.Lock()
	oldCidrRules := h.cidrRules
	h.rulesMu.Unlock()

	for _, r := range rules {
		hasCIDR := r.SrcCIDR != "" || r.DstCIDR != ""
		hasExactIP := r.SrcIP != "" || r.DstIP != ""

		if hasCIDR && hasExactIP {
			failed++
			continue
		}

		id := r.ID
		if id == "" {
			id = uuid.New().String()
		}

		action, err := parseAction(r.Action)
		if err != nil {
			failed++
			continue
		}
		if action == ActionRateLimit && r.RateLimit <= 0 {
			failed++
			continue
		}

		if hasCIDR {
			// --- CIDR rule ---
			var srcCIDR, dstCIDR string
			if r.SrcCIDR != "" {
				srcCIDR, err = cidr.NormalizeCIDR(r.SrcCIDR)
				if err != nil {
					failed++
					continue
				}
			}
			if r.DstCIDR != "" {
				dstCIDR, err = cidr.NormalizeCIDR(r.DstCIDR)
				if err != nil {
					failed++
					continue
				}
			}

			// Validate tcp_flags + protocol BEFORE CIDR allocation so a rejection
			// here does not leave freshly-allocated trie IDs leaked (AUD-V240-001).
			cfm, cfv, cfErr := parseTcpFlags(r.TcpFlags)
			if cfErr != nil {
				failed++
				continue
			}
			if cfm != 0 && parseProtocol(r.Protocol) != ProtoTCP {
				failed++
				continue
			}

			// Allocate CIDR IDs (overlap check skipped for atomic sync — full replacement)
			var srcID, dstID uint32
			if srcCIDR != "" {
				srcID, err = h.cidrMgr.AllocSrcID(srcCIDR)
				if err != nil {
					failed++
					continue
				}
			}
			if dstCIDR != "" {
				dstID, err = h.cidrMgr.AllocDstID(dstCIDR)
				if err != nil {
					if srcCIDR != "" {
						h.cidrMgr.ReleaseSrcID(srcCIDR)
					}
					failed++
					continue
				}
			}

			ck := CIDRRuleKey{
				SrcID:    srcID,
				DstID:    dstID,
				SrcPort:  htons(r.SrcPort),
				DstPort:  htons(r.DstPort),
				Protocol: parseProtocol(r.Protocol),
			}

			if err := validateComboType(getCIDRComboType(ck)); err != nil {
				if srcCIDR != "" {
					h.cidrMgr.ReleaseSrcID(srcCIDR)
				}
				if dstCIDR != "" {
					h.cidrMgr.ReleaseDstID(dstCIDR)
				}
				log.Printf("[AtomicSync] CIDR rule %s rejected: %v", id, err)
				failed++
				continue
			}
			value := RuleValue{
				Action:        action,
				TcpFlagsMask:  cfm,
				TcpFlagsValue: cfv,
				MatchAnomaly:  r.MatchAnomaly,
				RateLimit:     r.RateLimit,
				PktLenMin:     r.PktLenMin,
				PktLenMax:     r.PktLenMax,
			}

			if err := cidrShadow.Update(cidrRuleKeyToBytes(ck), ruleValueToBytes(value), ebpf.UpdateNoExist); err != nil {
				if srcCIDR != "" {
					h.cidrMgr.ReleaseSrcID(srcCIDR)
				}
				if dstCIDR != "" {
					h.cidrMgr.ReleaseDstID(dstCIDR)
				}
				failed++
				continue
			}

			comboType := getCIDRComboType(ck)
			if comboType >= 0 && comboType < 64 {
				shadowCidrCombo[comboType]++
			}
			shadowCidrCount++
			newCidrRules[id] = StoredCIDRRule{
				Key:          ck,
				SrcCIDR:      srcCIDR,
				DstCIDR:      dstCIDR,
				Action:       r.Action,
				RateLimit:    r.RateLimit,
				PktLenMin:    r.PktLenMin,
				PktLenMax:    r.PktLenMax,
				TcpFlags:     r.TcpFlags,
				MatchAnomaly: r.MatchAnomaly,
			}
			newCidrRuleKeyIndex[ck] = id
			added++
		} else {
			// --- Exact rule ---
			if err := validateRule(r.SrcIP, r.DstIP, r.Protocol, r.SrcPort, r.DstPort, r.PktLenMin, r.PktLenMax); err != nil {
				failed++
				continue
			}

			key, err := h.ruleToKey(r)
			if err != nil {
				failed++
				continue
			}

			if err := validateComboType(getComboType(key)); err != nil {
				log.Printf("[AtomicSync] rule %s rejected: %v", id, err)
				failed++
				continue
			}

			efm, efv, efErr := parseTcpFlags(r.TcpFlags)
			if efErr != nil {
				failed++
				continue
			}
			if efm != 0 && parseProtocol(r.Protocol) != ProtoTCP {
				failed++
				continue
			}
			value := RuleValue{
				Action:        action,
				TcpFlagsMask:  efm,
				TcpFlagsValue: efv,
				MatchAnomaly:  r.MatchAnomaly,
				RateLimit:     r.RateLimit,
				PktLenMin:     r.PktLenMin,
				PktLenMax:     r.PktLenMax,
			}

			if err := shadow.Update(ruleKeyToBytes(key), ruleValueToBytes(value), ebpf.UpdateNoExist); err != nil {
				failed++
				continue
			}

			comboType := getComboType(key)
			if comboType >= 0 && comboType < 64 {
				shadowCombo[comboType]++
			}
			shadowRuleCount++
			newRules[id] = StoredRule{
				Key:          key,
				Action:       r.Action,
				RateLimit:    r.RateLimit,
				PktLenMin:    r.PktLenMin,
				PktLenMax:    r.PktLenMax,
				TcpFlags:     r.TcpFlags,
				MatchAnomaly: r.MatchAnomaly,
			}
			newRuleKeyIndex[key] = id
			added++
		}
	}

	// --- Fail-fast: abort if any rule failed (don't publish partial rule set) ---
	if failed > 0 {
		// Release any CIDR IDs we allocated for the shadow (they're orphaned now)
		for _, stored := range newCidrRules {
			if stored.SrcCIDR != "" {
				h.cidrMgr.ReleaseSrcID(stored.SrcCIDR)
			}
			if stored.DstCIDR != "" {
				h.cidrMgr.ReleaseDstID(stored.DstCIDR)
			}
		}
		// Shadow maps contain partial data but won't be read (no flip).
		// Next AtomicSync will clearMap() them before use.
		log.Printf("[AtomicSync] Aborted: %d rules failed, %d succeeded — no flip", failed, added)
		return AtomicSyncResult{Added: added, Failed: failed},
			fmt.Errorf("atomic sync aborted: %d rules failed", failed)
	}

	// --- Step 3: Build shadow config and flip ---
	// 3a. Copy active config → shadow config (preserve fast_forward, filter_ifindex, whitelist_count, etc.)
	activeConf := h.activeMap()
	shadowConf := h.shadowMap()
	for i := uint32(0); i < ConfigMapEntries; i++ {
		key := make([]byte, 4)
		binary.LittleEndian.PutUint32(key, i)
		var value [8]byte
		if err := activeConf.Lookup(key, &value); err == nil {
			// shadowConf is an ARRAY map → Update(UpdateExist) is the
			// strict §5.2 translation of the prior goebpf.Update call.
			shadowConf.Update(key, value[:], ebpf.UpdateExist)
		}
	}

	// 3b. Overwrite dynamic rule fields in shadow config
	var bitmap uint64
	for i := 0; i < 64; i++ {
		if shadowCombo[i] > 0 {
			bitmap |= 1 << uint(i)
		}
	}
	var cidrBitmap uint64
	for i := 0; i < 64; i++ {
		if shadowCidrCombo[i] > 0 {
			cidrBitmap |= 1 << uint(i)
		}
	}

	newRuleMapSel := 1 - h.activeRuleSlot

	configUpdates := []struct {
		idx uint32
		val uint64
	}{
		{ConfigRuleBitmap, bitmap},
		{ConfigBlacklistCount, uint64(shadowRuleCount)},
		{ConfigCIDRBitmap, cidrBitmap},
		{ConfigCIDRRuleCount, uint64(shadowCidrCount)},
		{ConfigRuleMapSelector, uint64(newRuleMapSel)},
	}
	for _, u := range configUpdates {
		key := make([]byte, 4)
		binary.LittleEndian.PutUint32(key, u.idx)
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, u.val)
		if err := shadowConf.Update(key, val, ebpf.UpdateExist); err != nil {
			// Release allocated CIDR IDs and abort
			for _, stored := range newCidrRules {
				if stored.SrcCIDR != "" {
					h.cidrMgr.ReleaseSrcID(stored.SrcCIDR)
				}
				if stored.DstCIDR != "" {
					h.cidrMgr.ReleaseDstID(stored.DstCIDR)
				}
			}
			log.Printf("[AtomicSync] CRITICAL: failed to update shadow config index %d: %v", u.idx, err)
			return AtomicSyncResult{Added: added, Failed: failed},
				fmt.Errorf("failed to update shadow config index %d: %w", u.idx, err)
		}
	}

	// --- Step 4: Atomic flip (switch active config slot) ---
	newSlot := 1 - h.activeSlot
	selKey := make([]byte, 4) // key = 0
	selValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(selValue, uint64(newSlot))
	if err := h.activeConfig.Update(selKey, selValue, ebpf.UpdateExist); err != nil {
		// Release newly allocated CIDR IDs (they're in shared tries and can affect LPM behavior)
		for _, stored := range newCidrRules {
			if stored.SrcCIDR != "" {
				h.cidrMgr.ReleaseSrcID(stored.SrcCIDR)
			}
			if stored.DstCIDR != "" {
				h.cidrMgr.ReleaseDstID(stored.DstCIDR)
			}
		}
		log.Printf("[AtomicSync] CRITICAL: failed to flip active config: %v", err)
		return AtomicSyncResult{Added: added, Failed: failed},
			fmt.Errorf("failed to flip config selector: %w", err)
	}
	h.activeSlot = newSlot
	h.activeRuleSlot = newRuleMapSel

	// --- Step 5: Update in-memory state ---
	h.rulesMu.Lock()
	h.rules = newRules
	h.ruleKeyIndex = newRuleKeyIndex
	h.cidrRules = newCidrRules
	h.cidrRuleKeyIndex = newCidrRuleKeyIndex
	h.comboRefCount = shadowCombo
	h.cidrComboRefCount = shadowCidrCombo
	h.rulesMu.Unlock()

	// --- Step 5b: Release old CIDR IDs (AFTER flip, so active trie entries are safe) ---
	for _, stored := range oldCidrRules {
		if stored.SrcCIDR != "" {
			h.cidrMgr.ReleaseSrcID(stored.SrcCIDR)
		}
		if stored.DstCIDR != "" {
			h.cidrMgr.ReleaseDstID(stored.DstCIDR)
		}
	}

	// Clear PPS cache (rules changed completely)
	h.rulePPSMu.Lock()
	h.lastRuleDropCount = make(map[string]uint64)
	h.lastRuleStatsTime = make(map[string]int64)
	h.rulePPSMu.Unlock()

	log.Printf("[AtomicSync] Flipped: slot=%d, ruleMapSel=%d, exact=%d, cidr=%d, failed=%d, bitmap=0x%x, cidrBitmap=0x%x",
		newSlot, newRuleMapSel, shadowRuleCount, shadowCidrCount, failed, bitmap, cidrBitmap)

	// --- Step 6: Cleanup old map (now shadow) synchronously under lock ---
	// Must be synchronous to prevent race with next DoAtomicSync reusing the same map pair.
	// Cleanup failures are logged but do not fail the overall sync (the active side
	// already holds the new authoritative state). Next DoAtomicSync will retry clearing.
	cleanupOK := true
	if err := clearMap(h.shadowBlacklist()); err != nil {
		log.Printf("[cleanupOldRuleMap] WARN: shadow blacklist cleanup failed: %v", err)
		cleanupOK = false
	}
	if err := clearMap(h.shadowCidrBlacklist()); err != nil {
		log.Printf("[cleanupOldRuleMap] WARN: shadow CIDR blacklist cleanup failed: %v", err)
		cleanupOK = false
	}
	if cleanupOK {
		log.Printf("[cleanupOldRuleMap] Old rule maps cleared")
	} else {
		log.Printf("[cleanupOldRuleMap] Cleanup completed with errors; next AtomicSync will retry")
	}

	return AtomicSyncResult{
		Added:      added,
		Failed:     failed,
		ExactRules: shadowRuleCount,
		CIDRRules:  shadowCidrCount,
	}, nil
}

// AddWhitelistFromSync adds a whitelist entry from Controller sync
func (h *Handlers) AddWhitelistFromSync(entry SyncWhitelistEntry) error {
	// Convert to internal WhitelistEntry format
	req := WhitelistEntry{
		ID:       entry.ID,
		SrcIP:    entry.SrcIP,
		DstIP:    entry.DstIP,
		SrcPort:  entry.SrcPort,
		DstPort:  entry.DstPort,
		Protocol: entry.Protocol,
	}

	// Validate: BPF whitelist only supports exact, src_ip-only, dst_ip-only
	hasIP := req.SrcIP != "" || req.DstIP != ""
	hasPortOrProto := req.SrcPort != 0 || req.DstPort != 0 ||
		(req.Protocol != "" && req.Protocol != "all")
	hasBothIPs := req.SrcIP != "" && req.DstIP != ""

	if !hasIP && hasPortOrProto {
		return fmt.Errorf("whitelist with port/protocol but no IP is not supported")
	}
	if hasIP && !hasBothIPs && hasPortOrProto {
		return fmt.Errorf("whitelist with port/protocol requires both src_ip and dst_ip (exact 5-tuple)")
	}

	key, err := h.whitelistToKey(req)
	if err != nil {
		return fmt.Errorf("failed to convert whitelist: %w", err)
	}

	keyBytes := ruleKeyToBytes(key)
	wlValue := []byte{1}

	// Use provided ID or generate new one
	id := entry.ID
	if id == "" {
		id = uuid.New().String()
	}

	h.publishMu.Lock()
	h.wlMu.Lock()

	// Duplicate key check: reject if another ID already owns this key
	if existingID, ok := h.wlKeyIndex[key]; ok && existingID != id {
		h.wlMu.Unlock()
		h.publishMu.Unlock()
		return fmt.Errorf("whitelist key already exists under id %s", existingID)
	}

	// Check for existing whitelist with same ID (replacement case)
	var oldKey *RuleKey
	wlCountDelta := int64(1)
	if existingKey, exists := h.wlEntries[id]; exists {
		keyCopy := existingKey
		oldKey = &keyCopy
		wlCountDelta = 0 // replacing, not adding
	}

	// Step 1: Insert new BPF entry (old entry still intact if different key)
	if err := h.whitelist.Update(keyBytes, wlValue, ebpf.UpdateNoExist); err != nil {
		h.wlMu.Unlock()
		h.publishMu.Unlock()
		return fmt.Errorf("failed to insert whitelist: %w", err)
	}

	// Step 2: Delete old BPF entry BEFORE publish (hard failure to avoid orphan)
	if oldKey != nil && *oldKey != key {
		if err := h.whitelist.Delete(ruleKeyToBytes(*oldKey)); err != nil {
			if delErr := h.whitelist.Delete(keyBytes); delErr != nil {
				log.Printf("[AddWhitelistFromSync] WARN: best-effort cleanup of new BPF entry failed during abort: %v", delErr)
			}
			h.wlMu.Unlock()
			h.publishMu.Unlock()
			return fmt.Errorf("failed to delete old whitelist entry during replacement: %w", err)
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
			log.Printf("[AddWhitelistFromSync] WARN: best-effort rollback delete of new BPF entry failed: %v", delErr)
		}
		delete(h.wlEntries, id)
		delete(h.wlKeyIndex, key)
		// Restore old state if replacement
		if oldKey != nil {
			h.wlEntries[id] = *oldKey
			h.wlKeyIndex[*oldKey] = id
			// Re-insert old BPF entry if it was deleted (best-effort restore)
			if *oldKey != key {
				if insErr := h.whitelist.Update(ruleKeyToBytes(*oldKey), wlValue, ebpf.UpdateNoExist); insErr != nil {
					log.Printf("[AddWhitelistFromSync] WARN: best-effort rollback re-insert of old BPF entry failed: %v", insErr)
				}
			}
		}
		h.wlMu.Unlock()
		h.publishMu.Unlock()
		return fmt.Errorf("config publish failed: %w", err)
	}

	h.wlMu.Unlock()
	h.publishMu.Unlock()

	return nil
}

// ClearAllWhitelistFromSync removes all whitelist entries from BPF and memory.
// Called before each startup-sync attempt to ensure a clean whitelist state,
// preventing partial replay residue from failed previous attempts.
//
// Returns an error if any BPF delete fails — in that case, the in-memory state
// for the failed entry is preserved (not wiped) to avoid control-plane/datapath
// divergence. The caller should treat this as a hard failure for the attempt.
func (h *Handlers) ClearAllWhitelistFromSync() error {
	h.publishMu.Lock()
	h.wlMu.Lock()

	deleted := 0
	for id, key := range h.wlEntries {
		keyBytes := ruleKeyToBytes(key)
		if err := h.whitelist.Delete(keyBytes); err != nil {
			// BPF delete failed: do NOT wipe in-memory state for this entry.
			// Publish the delta for entries successfully deleted so far, then bail.
			if deleted > 0 {
				if pubErr := h.publishConfigUpdate(0, -int64(deleted), 0); pubErr != nil {
					log.Printf("[ClearAllWhitelistFromSync] WARN: publish config failed: %v", pubErr)
				}
			}
			h.wlMu.Unlock()
			h.publishMu.Unlock()
			return fmt.Errorf("BPF delete failed for whitelist entry %s: %w", id, err)
		}
		// BPF delete succeeded — safe to wipe in-memory state for this entry
		delete(h.wlKeyIndex, key)
		delete(h.wlEntries, id)
		deleted++
	}

	if deleted > 0 {
		if err := h.publishConfigUpdate(0, -int64(deleted), 0); err != nil {
			log.Printf("[ClearAllWhitelistFromSync] ERROR: publish config failed after deleting %d entries: %v", deleted, err)
			h.wlMu.Unlock()
			h.publishMu.Unlock()
			// BPF entries are gone but config count is stale; caller must know convergence failed
			return fmt.Errorf("whitelist cleared but publishConfigUpdate failed: %w", err)
		}
		log.Printf("[ClearAllWhitelistFromSync] Cleared %d whitelist entries", deleted)
	}

	h.wlMu.Unlock()
	h.publishMu.Unlock()
	return nil
}
