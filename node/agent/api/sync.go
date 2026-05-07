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
	// Anomaly semantic guard
	if err := validateNodeAnomalyFields(req.MatchAnomaly, req.Action, req.SrcIP, req.DstIP, req.SrcCIDR, req.DstCIDR); err != nil {
		return err
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
				oldValue := ruleValueFromStored(*oldStored) // AUD-008
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

			// Validate tcp_flags + protocol + anomaly semantics BEFORE CIDR allocation
			// so a rejection here does not leave freshly-allocated trie IDs leaked.
			cfm, cfv, cfErr := parseTcpFlags(r.TcpFlags)
			if cfErr != nil {
				failed++
				continue
			}
			if cfm != 0 && parseProtocol(r.Protocol) != ProtoTCP {
				failed++
				continue
			}
			if err := validateNodeAnomalyFields(r.MatchAnomaly, r.Action, r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR); err != nil {
				log.Printf("[AtomicSync] CIDR rule %s anomaly guard rejected: %v", id, err)
				failed++
				continue
			}
			// B-10 (rev11 codex round 9 P2): portless+port guard for CIDR
			// AtomicSync path. Rejected items count toward `failed` so the
			// Controller's DiffSync dual-failure contract sees the reject.
			if err := validatePortProtocolCompatNode(r.Protocol, r.SrcPort, r.DstPort); err != nil {
				log.Printf("[AtomicSync] CIDR rule %s portless+port rejected: %v", id, err)
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
			if err := validateNodeAnomalyFields(r.MatchAnomaly, r.Action, r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR); err != nil {
				log.Printf("[AtomicSync] rule %s anomaly guard rejected: %v", id, err)
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

	// AUD-003: count anomaly rules from the NEW ruleset being installed.
	// Must NOT call countAnomalyRulesLocked() — that reads h.rules/h.cidrRules
	// (old state). We need the absolute count for the shadow config before flip.
	anomalyCount := countAnomalyRulesIn(newRules, newCidrRules)

	configUpdates := []struct {
		idx uint32
		val uint64
	}{
		{ConfigRuleBitmap, bitmap},
		{ConfigBlacklistCount, uint64(shadowRuleCount)},
		{ConfigCIDRBitmap, cidrBitmap},
		{ConfigCIDRRuleCount, uint64(shadowCidrCount)},
		{ConfigRuleMapSelector, uint64(newRuleMapSel)},
		{ConfigAnomalyRuleCount, uint64(anomalyCount)},
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

// AddWhitelistFromSync adds a whitelist entry from Controller incremental sync (DiffSync path).
// Phase 8: uses 31-combo bitmap validation, activeWhitelist(), wlComboRefCount.
// Lock order: syncMu → publishMu → wlMu.
func (h *Handlers) AddWhitelistFromSync(entry SyncWhitelistEntry) error {
	req := WhitelistEntry{
		ID:       entry.ID,
		SrcIP:    entry.SrcIP,
		DstIP:    entry.DstIP,
		SrcPort:  entry.SrcPort,
		DstPort:  entry.DstPort,
		Protocol: entry.Protocol,
	}

	// Phase 8: replace old exact-only guard with combo-type validation
	key, err := h.whitelistToKey(req)
	if err != nil {
		return fmt.Errorf("failed to convert whitelist entry: %w", err)
	}
	newCombo := getComboType(key)
	if err := validateComboType(newCombo); err != nil {
		return fmt.Errorf("unsupported whitelist combo: %w", err)
	}
	if err := validatePortProtocolCompatNode(req.Protocol, req.SrcPort, req.DstPort); err != nil {
		return err
	}

	id := entry.ID
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

	if existingID, ok := h.wlKeyIndex[key]; ok && existingID != id {
		return fmt.Errorf("whitelist key already exists under id %s", existingID)
	}

	var oldKey *RuleKey
	var oldCombo int
	wlCountDelta := int64(1)
	if existingKey, exists := h.wlEntries[id]; exists {
		// Same-ID same-key: idempotent, no-op
		if existingKey == key {
			return nil
		}
		keyCopy := existingKey
		oldKey = &keyCopy
		oldCombo = getComboType(*oldKey)
		wlCountDelta = 0
	}

	// Security-first: delete old BPF entry before adding new (always different key here)
	if oldKey != nil {
		if err := h.activeWhitelist().Delete(ruleKeyToBytes(*oldKey)); err != nil {
			return fmt.Errorf("failed to delete old whitelist entry: %w", err)
		}
		h.wlComboRefCount[oldCombo]--
	}

	// Increment new combo refcount BEFORE publish
	h.wlComboRefCount[newCombo]++

	if err := h.publishConfigUpdate(0, wlCountDelta, 0); err != nil {
		h.wlComboRefCount[newCombo]--
		if oldKey != nil {
			h.wlComboRefCount[oldCombo]++
			if insErr := h.activeWhitelist().Update(ruleKeyToBytes(*oldKey), wlValue, ebpf.UpdateNoExist); insErr != nil {
				log.Printf("[AddWhitelistFromSync] WARN: rollback re-insert of old entry failed: %v", insErr)
			}
		}
		return fmt.Errorf("config publish failed: %w", err)
	}

	if err := h.activeWhitelist().Update(newKeyBytes, wlValue, ebpf.UpdateNoExist); err != nil {
		h.wlComboRefCount[newCombo]--
		if oldKey != nil {
			h.wlComboRefCount[oldCombo]++
			if insErr := h.activeWhitelist().Update(ruleKeyToBytes(*oldKey), wlValue, ebpf.UpdateNoExist); insErr != nil {
				log.Printf("[AddWhitelistFromSync] WARN: rollback re-insert of old entry failed: %v", insErr)
			}
		}
		if pubErr := h.publishConfigUpdate(0, -wlCountDelta, 0); pubErr != nil {
			log.Printf("[AddWhitelistFromSync] WARN: rollback re-publish failed: %v", pubErr)
		}
		return fmt.Errorf("failed to insert whitelist into BPF: %w", err)
	}

	if oldKey != nil {
		delete(h.wlKeyIndex, *oldKey)
	}
	h.wlEntries[id] = key
	h.wlKeyIndex[key] = id

	return nil
}

// ClearAllWhitelistFromSync clears the active whitelist map and resets combo state.
// Used for error recovery / cleanup paths. Full sync uses DoWhitelistAtomicSync instead.
// Lock order: syncMu → publishMu → wlMu (must not be called while syncMu is held by caller).
func (h *Handlers) ClearAllWhitelistFromSync() error {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	h.publishMu.Lock()
	h.wlMu.Lock()

	deleted := 0
	for id, key := range h.wlEntries {
		combo := getComboType(key)
		keyBytes := ruleKeyToBytes(key)
		if err := h.activeWhitelist().Delete(keyBytes); err != nil {
			if deleted > 0 {
				if pubErr := h.publishConfigUpdate(0, -int64(deleted), 0); pubErr != nil {
					log.Printf("[ClearAllWhitelistFromSync] WARN: publish failed: %v", pubErr)
				}
			}
			h.wlMu.Unlock()
			h.publishMu.Unlock()
			return fmt.Errorf("BPF delete failed for whitelist entry %s: %w", id, err)
		}
		h.wlComboRefCount[combo]--
		delete(h.wlKeyIndex, key)
		delete(h.wlEntries, id)
		deleted++
	}

	// Reset all combo refcounts to zero (should already be zero after loop above)
	h.wlComboRefCount = [64]int{}

	if deleted > 0 {
		if err := h.publishConfigUpdate(0, -int64(deleted), 0); err != nil {
			log.Printf("[ClearAllWhitelistFromSync] ERROR: publish failed after clearing %d entries: %v", deleted, err)
			h.wlMu.Unlock()
			h.publishMu.Unlock()
			return fmt.Errorf("whitelist cleared but publishConfigUpdate failed: %w", err)
		}
		log.Printf("[ClearAllWhitelistFromSync] Cleared %d whitelist entries", deleted)
	}

	h.wlMu.Unlock()
	h.publishMu.Unlock()
	return nil
}

// DoWhitelistAtomicSync performs a zero-window full whitelist replacement.
// This is the ONLY entry point for full whitelist sync (Controller FullSync + startup pull-sync).
// Pattern: clear shadow → write shadow → flip selector → commit memory.
// All CRUD paths are blocked via syncMu for the entire duration.
func (h *Handlers) DoWhitelistAtomicSync(entries []SyncWhitelistEntry) error {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	h.publishMu.Lock()
	defer h.publishMu.Unlock()
	h.wlMu.Lock()
	defer h.wlMu.Unlock()

	// --- Phase 1: Pre-validate ALL entries before any shadow writes ---
	type prepared struct {
		entry SyncWhitelistEntry
		key   RuleKey
		combo int
	}

	items := make([]prepared, 0, len(entries))
	seenIDs := make(map[string]bool, len(entries))
	seenKeys := make(map[RuleKey]bool, len(entries))

	for _, e := range entries {
		if e.ID == "" {
			return &wlSyncValidationError{msg: "whitelist entry with empty ID rejected"}
		}
		if seenIDs[e.ID] {
			return &wlSyncValidationError{msg: fmt.Sprintf("duplicate whitelist ID in sync batch: %s", e.ID)}
		}
		seenIDs[e.ID] = true

		req := WhitelistEntry{
			SrcIP: e.SrcIP, DstIP: e.DstIP,
			SrcPort: e.SrcPort, DstPort: e.DstPort,
			Protocol: e.Protocol,
		}
		key, err := h.whitelistToKey(req)
		if err != nil {
			return &wlSyncValidationError{msg: fmt.Sprintf("invalid whitelist entry %s: %v", e.ID, err)}
		}
		if seenKeys[key] {
			return &wlSyncValidationError{msg: fmt.Sprintf("duplicate whitelist key in sync batch for ID %s", e.ID)}
		}
		seenKeys[key] = true

		combo := getComboType(key)
		if err := validateComboType(combo); err != nil {
			return &wlSyncValidationError{msg: fmt.Sprintf("unsupported combo for whitelist entry %s: %v", e.ID, err)}
		}
		if err := validatePortProtocolCompatNode(e.Protocol, e.SrcPort, e.DstPort); err != nil {
			return &wlSyncValidationError{msg: fmt.Sprintf("port/protocol error for whitelist entry %s: %v", e.ID, err)}
		}

		items = append(items, prepared{entry: e, key: key, combo: combo})
	}

	// --- Phase 2: Clear shadow whitelist map ---
	shadow := h.shadowWhitelist()
	if err := clearMap(shadow); err != nil {
		return fmt.Errorf("failed to clear shadow whitelist: %w", err)
	}

	// --- Phase 3: Write all entries to shadow ---
	newWlEntries := make(map[string]RuleKey, len(items))
	newWlKeyIndex := make(map[RuleKey]string, len(items))
	var newWlComboRefCount [64]int

	for _, item := range items {
		keyBytes := ruleKeyToBytes(item.key)
		if err := shadow.Update(keyBytes, []byte{1}, ebpf.UpdateNoExist); err != nil {
			return fmt.Errorf("shadow whitelist insert failed for %s: %w", item.entry.ID, err)
		}
		newWlEntries[item.entry.ID] = item.key
		newWlKeyIndex[item.key] = item.entry.ID
		newWlComboRefCount[item.combo]++
	}

	// --- Phase 4: Flip selector and publish config ---
	oldWLSlot := h.activeWLSlot
	oldWlEntries := h.wlEntries
	oldWlKeyIndex := h.wlKeyIndex
	oldWlComboRefCount := h.wlComboRefCount

	h.activeWLSlot = 1 - h.activeWLSlot
	h.wlComboRefCount = newWlComboRefCount

	if err := h.publishConfigUpdateForWLSync(uint64(len(items)), newWlComboRefCount); err != nil {
		// Rollback in-memory state (shadow map data doesn't matter — selector wasn't flipped)
		h.activeWLSlot = oldWLSlot
		h.wlComboRefCount = oldWlComboRefCount
		return fmt.Errorf("config publish failed: %w", err)
	}

	// --- Phase 5: Commit memory state (point of no return) ---
	h.wlEntries = newWlEntries
	h.wlKeyIndex = newWlKeyIndex
	// wlComboRefCount and activeWLSlot already updated in Phase 4

	log.Printf("[DoWhitelistAtomicSync] Synced %d whitelist entries, wlSlot=%d", len(items), h.activeWLSlot)

	// --- Phase 6: Cleanup old shadow (now = old active) — best-effort ---
	if err := clearMap(h.shadowWhitelist()); err != nil {
		log.Printf("[DoWhitelistAtomicSync] WARN: old shadow whitelist cleanup failed: %v", err)
	}

	_ = oldWlEntries
	_ = oldWlKeyIndex
	return nil
}

// wlSyncValidationError distinguishes validation errors (400) from I/O errors (500).
type wlSyncValidationError struct{ msg string }

func (e *wlSyncValidationError) Error() string { return e.msg }

// SyncWhitelistHandler handles POST /api/v1/sync/whitelist — full snapshot sync from Controller.
func (h *Handlers) SyncWhitelistHandler(c *gin.Context) {
	var req struct {
		Entries []SyncWhitelistEntry `json:"entries"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.DoWhitelistAtomicSync(req.Entries); err != nil {
		if _, ok := err.(*wlSyncValidationError); ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"total": len(req.Entries), "failed": 0})
}
