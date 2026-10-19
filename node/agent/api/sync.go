// XDrop Agent - Controller push path (AtomicSync / SyncWhitelistHandler)
package api

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

// AtomicSync performs zero-gap full sync of blacklist rules using dual rule maps.
// POST /api/v1/sync/atomic — only syncs blacklist rules (exact + CIDR), not whitelist.
// Whitelist must be synced separately before calling this endpoint.
func (h *Handlers) AtomicSync(c *gin.Context) {
	var req struct {
		Rules []Rule `json:"rules"`
	}
	if err := bindStrictJSON(c, &req); err != nil {
		h.ruleJSON(c, http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.DoAtomicSync(req.Rules)
	if err != nil {
		var group *atomicConditionGroupError
		if errors.As(err, &group) {
			h.ruleJSON(c, http.StatusConflict, gin.H{"code": "condition_group_invalid", "error": group.Error(), "key": group.Key, "conflicts": group.Conflicts, "added": result.Added, "failed": result.Failed})
			return
		}
		var full *logicalTableFullError
		if errors.As(err, &full) {
			h.ruleJSON(c, http.StatusConflict, gin.H{"code": "table_full", "error": full.Error(), "added": result.Added, "failed": result.Failed})
			return
		}
		if errors.Is(err, errAtomicTableFull) {
			h.ruleJSON(c, http.StatusConflict, gin.H{"code": "table_full", "error": err.Error(), "added": result.Added, "failed": result.Failed})
			return
		}
		var logical *atomicDuplicateLogicalIDError
		if errors.As(err, &logical) {
			h.ruleJSON(c, http.StatusConflict, gin.H{"code": "duplicate_logical_id", "error": err.Error(), "logical_id": logical.LogicalID, "conflicts": logical.Conflicts, "added": result.Added, "failed": result.Failed})
			return
		}
		if errors.Is(err, errQuiescence) {
			h.ruleJSON(c, http.StatusInternalServerError, gin.H{"code": "quiescence_failed", "error": err.Error(), "added": result.Added, "failed": result.Failed})
			return
		}
		var duplicateID *atomicDuplicateIDError
		if errors.As(err, &duplicateID) {
			h.ruleJSON(c, http.StatusConflict, gin.H{
				"code": "duplicate_id", "error": duplicateID.Error(),
				"conflicts": duplicateID.Conflicts, "added": result.Added, "failed": result.Failed,
			})
			return
		}
		var duplicate *atomicDuplicateKeyError
		if errors.As(err, &duplicate) {
			h.ruleJSON(c, http.StatusConflict, gin.H{
				"code": "duplicate_key", "error": duplicate.Error(),
				"conflicts": duplicate.Conflicts, "added": result.Added, "failed": result.Failed,
			})
			return
		}
		var nested *atomicNestedCIDRError
		if errors.As(err, &nested) {
			h.ruleJSON(c, http.StatusConflict, gin.H{
				"code": "cidr_overlap", "error": nested.Error(), "direction": nested.Direction,
				"conflicts": nested.Conflicts, "prefixes": nested.Prefixes,
				"added": result.Added, "failed": result.Failed,
			})
			return
		}
		h.ruleJSON(c, http.StatusInternalServerError, gin.H{
			"error":  err.Error(),
			"added":  result.Added,
			"failed": result.Failed,
		})
		return
	}

	h.rulesSynced.Store(true)
	h.ruleJSON(c, http.StatusOK, gin.H{
		"success":    true,
		"added":      result.Added,
		"failed":     result.Failed,
		"rules":      result.ExactRules,
		"cidr_rules": result.CIDRRules,
		"rejected":   result.Rejected,
	})
}

type atomicRuleIdentity struct {
	ID    string `json:"id"`
	Index *int   `json:"index,omitempty"`
}

func (r atomicRuleIdentity) String() string {
	if r.Index != nil {
		return fmt.Sprintf("rule at index %d (empty ID)", *r.Index)
	}
	return fmt.Sprintf("rule ID %q", r.ID)
}

type atomicDuplicateKeyError struct {
	Conflicts [2]atomicRuleIdentity
}

func (e *atomicDuplicateKeyError) Error() string {
	return fmt.Sprintf("duplicate key between %s and %s; batch not published", e.Conflicts[0], e.Conflicts[1])
}

type atomicDuplicateIDError struct {
	Conflicts [2]atomicRuleIdentity
}

type atomicNestedCIDRError struct {
	Direction string
	Conflicts [2]atomicRuleIdentity
	Prefixes  [2]string
}

func (e *atomicNestedCIDRError) Error() string {
	return fmt.Sprintf("%s_cidr overlap: %s (%s) contains %s (%s) (strict containment); batch not published",
		e.Direction, e.Conflicts[0], e.Prefixes[0], e.Conflicts[1], e.Prefixes[1])
}

func (e *atomicDuplicateIDError) Error() string {
	return fmt.Sprintf("duplicate ID %q at index %d and index %d; batch not published",
		e.Conflicts[0].ID, *e.Conflicts[0].Index, *e.Conflicts[1].Index)
}

// Fixed stage: shadow config 3b is complete, and no new prefix is published.
// Production leaves this nil.
var cidrBeforeAtomicPublishTestHook func(*Handlers)
var atomicMemoTestHook func(**atomicMemo)

var errAtomicTableFull = errors.New("table_full")

func atomicRowWriteError(err error) error {
	if errors.Is(err, syscall.E2BIG) {
		return fmt.Errorf("%w: %w", errAtomicTableFull, err)
	}
	return err
}

// DoAtomicSync is the core atomic sync logic — called by the HTTP full-snapshot handler.
// It acquires syncMu and publishMu internally.
func (h *Handlers) DoAtomicSync(rules []Rule) (AtomicSyncResult, error) {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()

	h.publishMu.Lock()
	defer h.publishMu.Unlock()

	memo := &atomicMemo{cidrs: make(map[string]atomicCIDRParse), prepared: make(map[int]atomicPreparation)}
	if atomicMemoTestHook != nil {
		atomicMemoTestHook(&memo)
	}

	// Preflight must precede any business mutation: duplicate IDs change no state.
	seenIDs := make(map[string]int, len(rules))
	for index, rule := range rules {
		if rule.ID == "" {
			continue // Each empty ID is generated independently during construction.
		}
		if first, exists := seenIDs[rule.ID]; exists {
			second := index
			return AtomicSyncResult{Failed: 1}, &atomicDuplicateIDError{Conflicts: [2]atomicRuleIdentity{
				{ID: rule.ID, Index: &first}, {ID: rule.ID, Index: &second},
			}}
		}
		seenIDs[rule.ID] = index
	}

	if err := checkAtomicLogicalIDs(rules); err != nil {
		return AtomicSyncResult{Failed: 1}, err
	}

	groups, err := h.preflightAtomicConditions(rules, memo)
	if err != nil {
		return AtomicSyncResult{Failed: 1}, err
	}
	logicalUsed, err := h.admitAtomicLogicalUsage(rules, memo)
	if err != nil {
		return AtomicSyncResult{Failed: 1}, err
	}
	// Payment follows all business writes and precedes unlock, including exits
	// after a published generation whose regular R5c reclamation was deferred.
	defer func() { h.rulesMu.Lock(); h.maybePayLogicalLocked(); h.rulesMu.Unlock() }()

	// R0 must precede any reuse, including Step 3a's opposite config slot.
	if !h.quiescenceConfirmed {
		if err := h.awaitQuiescence(); err != nil {
			return AtomicSyncResult{Failed: 1}, fmt.Errorf("%w: %v", errQuiescence, err)
		}
	}
	beforePrefixes := h.cidrMgr.Snapshot([2][]string{})
	shadowSlot := 1 - int(h.activeRuleSlot.Load())
	shadow := h.mirrorTable(shadowSlot, mirrorExact)
	cidrShadow := h.mirrorTable(shadowSlot, mirrorCIDR)

	// --- Step 2: Write all rules to shadow maps ---
	var shadowCombo [64]int
	var shadowCidrCombo [64]int
	var shadowRuleCount int64
	var shadowCidrCount int64
	newRules := make(map[string]StoredRule)
	newCidrRules := make(map[string]StoredCIDRRule)
	newRuleKeyIndex := make(map[RuleKey]ruleIDSet)
	newCidrRuleKeyIndex := make(map[CIDRRuleKey]ruleIDSet)
	exactPositions := make(map[RuleKey]int)
	cidrPositions := make(map[CIDRRuleKey]int)
	batchPrefixes := []struct {
		direction string
		first     map[string]int
		prefixes  []cidr.PrefixIndex
	}{
		{direction: "src", first: make(map[string]int)},
		{direction: "dst", first: make(map[string]int)},
	}
	recordPrefixes := func(src, dst string, index int) {
		for direction, prefix := range []string{src, dst} {
			if prefix == "" {
				continue
			}
			set := &batchPrefixes[direction]
			if _, exists := set.first[prefix]; exists {
				continue
			}
			set.first[prefix] = index
			set.prefixes = append(set.prefixes, cidr.PrefixIndex{Prefix: prefix, Index: index})
		}
	}
	duplicateKey := func(first, second int) error {
		e := &atomicDuplicateKeyError{}
		for i, index := range []int{first, second} {
			e.Conflicts[i].ID = rules[index].ID
			if rules[index].ID == "" {
				position := index
				e.Conflicts[i].Index = &position
			}
		}
		return e
	}

	added := 0
	rejected := make([]AtomicSyncRejection, 0)
	reject := func(index int, rule Rule, reason string) {
		item := AtomicSyncRejection{ID: rule.ID, Reason: reason}
		if rule.ID == "" {
			item.Index = &index
		}
		rejected = append(rejected, item)
	}
	// Each successful reservation has one matching borrow, including shared IDs.
	release := func(src, dst string) {
		if src != "" {
			if err := h.cidrMgr.UndoSrcReservation(src); err != nil {
				log.Printf("[AtomicSync rollback] CIDR reference release: %v", err)
			}
		}
		if dst != "" {
			if err := h.cidrMgr.UndoDstReservation(dst); err != nil {
				log.Printf("[AtomicSync rollback] CIDR reference release: %v", err)
			}
		}
	}
	abort := func(err error) (AtomicSyncResult, error) {
		h.cidrMgr.Invalidate(1 - int(h.activeRuleSlot.Load()))
		for _, stored := range newCidrRules {
			release(stored.SrcCIDR, stored.DstCIDR)
		}
		return AtomicSyncResult{Added: added, Failed: len(rejected) + 1, Rejected: rejected}, err
	}

	// Step 1 invalidates the mirror before any shadow mutation, including aborts.
	h.mirrorReady = false
	h.observeAtomicStage("1")
	have, err := h.prepareAtomicShadow(h.atomicKeepKeys(rules, groups, memo))
	if err != nil {
		return abort(err)
	}

	wantRows := newAtomicTableRows()

	// Old CIDR references remain alive until the new rule generation is active.
	h.rulesMu.Lock()
	oldCidrRules := h.cidrRules
	h.rulesMu.Unlock()

	for index, original := range rules {
		g := groups[index]
		if g != nil && g.Condition && g.Indexes[0] != index {
			continue
		}
		var members []atomicPreparedRule
		if g != nil && g.Condition {
			members = g.Members
		} else {
			prepared, err := h.prepareAtomicAt(original, index, memo)
			if err != nil {
				reject(index, original, err.Error())
				continue
			}
			if err := validateLogicalID(prepared.Rule.LogicalID); err != nil {
				reject(index, original, err.Error())
				continue
			}
			if prepared.Rule.ID == "" {
				prepared.Rule.ID = uuid.NewString()
			}
			members = []atomicPreparedRule{prepared}
		}
		first := members[0]
		value := first.Value
		conditional := g != nil && g.Condition
		if conditional {
			value.Pad2[0] = RuleHasConditions
			value.Action, value.RateLimit = g.Row.Action[0], g.Row.Rate[0]
			value.LogicalID = g.Row.RuleID[0]
		}
		if first.IsCIDR {
			// Preserve a borrow for every logical member, including shared IDs.
			var reserved []atomicPreparedRule
			undoReserved := func() {
				for _, p := range reserved {
					release(p.Rule.SrcCIDR, p.Rule.DstCIDR)
				}
			}
			for _, prepared := range members {
				r := prepared.Rule
				var srcID, dstID uint32
				if r.SrcCIDR != "" {
					var err error
					srcID, err = h.cidrMgr.ReserveSrcID(r.SrcCIDR)
					if err != nil {
						undoReserved()
						return abort(fmt.Errorf("allocate src CIDR for rule %s: %w", r.ID, err))
					}
				}
				if r.DstCIDR != "" {
					var err error
					dstID, err = h.cidrMgr.ReserveDstID(r.DstCIDR)
					if err != nil {
						release(r.SrcCIDR, "")
						undoReserved()
						return abort(fmt.Errorf("allocate dst CIDR for rule %s: %w", r.ID, err))
					}
				}
				prepared.CIDR.SrcID, prepared.CIDR.DstID = srcID, dstID
				reserved = append(reserved, prepared)
			}
			ck := reserved[0].CIDR
			for _, prepared := range reserved {
				identity, err := h.classifyRuleKey(prepared.Rule, memo)
				if prepared.CIDR != ck || err != nil || (conditional && identity != g.Key) {
					undoReserved()
					return abort(fmt.Errorf("CIDR group identity changed after reservation"))
				}
			}
			if previous, exists := cidrPositions[ck]; exists {
				undoReserved()
				return abort(duplicateKey(previous, index))
			}
			if conditional {
				if err := atomicWriteRow(h.mirrorTable(shadowSlot, mirrorCIDRCondition), have[mirrorCIDRCondition], wantRows[mirrorCIDRCondition], cidrRuleKeyToBytes(ck), conditionValueToBytes(g.Row), ebpf.UpdateNoExist); err != nil {
					undoReserved()
					return abort(atomicRowWriteError(fmt.Errorf("write shadow CIDR condition: %w", err)))
				}
				h.observeAtomicStage("2-cidr-condition")
			}
			if err := atomicWriteRow(cidrShadow, have[mirrorCIDR], wantRows[mirrorCIDR], cidrRuleKeyToBytes(ck), ruleValueToBytes(value), ebpf.UpdateNoExist); err != nil {
				undoReserved()
				return abort(atomicRowWriteError(fmt.Errorf("write shadow CIDR rule %s: %w", original.ID, err)))
			}
			if conditional {
				h.observeAtomicStage("2-cidr-rule")
			}
			shadowCidrCombo[getCIDRComboType(ck)]++
			shadowCidrCount++
			for _, prepared := range reserved {
				r := prepared.Rule
				newCidrRules[r.ID] = ruleToStoredCIDR(ck, r.SrcCIDR, r.DstCIDR, r)
				addRuleID(newCidrRuleKeyIndex, ck, r.ID)
				added++
			}
			recordPrefixes(first.Rule.SrcCIDR, first.Rule.DstCIDR, index)
			cidrPositions[ck] = index
		} else {
			key := first.Exact
			for _, prepared := range members {
				if prepared.Exact != key {
					return abort(fmt.Errorf("exact group identity changed after normalization"))
				}
			}
			if previous, exists := exactPositions[key]; exists {
				return abort(duplicateKey(previous, index))
			}
			if conditional {
				if err := atomicWriteRow(h.mirrorTable(shadowSlot, mirrorCondition), have[mirrorCondition], wantRows[mirrorCondition], ruleKeyToBytes(key), conditionValueToBytes(g.Row), ebpf.UpdateNoExist); err != nil {
					return abort(atomicRowWriteError(fmt.Errorf("write shadow exact condition: %w", err)))
				}
				h.observeAtomicStage("2-exact-condition")
			}
			if err := atomicWriteRow(shadow, have[mirrorExact], wantRows[mirrorExact], ruleKeyToBytes(key), ruleValueToBytes(value), ebpf.UpdateNoExist); err != nil {
				return abort(atomicRowWriteError(fmt.Errorf("write shadow exact rule %s: %w", original.ID, err)))
			}
			if conditional {
				h.observeAtomicStage("2-exact-rule")
			}
			shadowCombo[getComboType(key)]++
			shadowRuleCount++
			for _, prepared := range members {
				r := prepared.Rule
				newRules[r.ID] = ruleToStored(key, r)
				addRuleID(newRuleKeyIndex, key, r.ID)
				added++
			}
			exactPositions[key] = index
		}
	}

	// Only accepted prefixes participate; source conflicts take precedence.
	for _, set := range batchPrefixes {
		container, contained, found := cidr.FindNested(set.prefixes)
		if found {
			e := &atomicNestedCIDRError{Direction: set.direction}
			for i, entry := range []cidr.PrefixIndex{container, contained} {
				e.Prefixes[i] = entry.Prefix
				e.Conflicts[i].ID = rules[entry.Index].ID
				if rules[entry.Index].ID == "" {
					position := entry.Index
					e.Conflicts[i].Index = &position
				}
			}
			return abort(e)
		}
	}

	// Step 3a: copy every active config slot; either syscall error aborts.
	h.observeAtomicStage("3a")
	shadowConf, activeConf, selector := h.configPublishTables()
	for i := uint32(0); i < ConfigMapEntries; i++ {
		key := make([]byte, 4)
		binary.LittleEndian.PutUint32(key, i)
		var value [8]byte
		if err := activeConf.Lookup(key, &value); err != nil {
			return abort(fmt.Errorf("read active config index %d: %w", i, err))
		}
		if err := shadowConf.Update(key, value[:], ebpf.UpdateExist); err != nil {
			return abort(fmt.Errorf("copy shadow config index %d: %w", i, err))
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

	newRuleMapSel := 1 - int(h.activeRuleSlot.Load())

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
			return abort(fmt.Errorf("failed to update shadow config index %d: %w", u.idx, err))
		}
	}

	if cidrBeforeAtomicPublishTestHook != nil {
		cidrBeforeAtomicPublishTestHook(h)
	}
	// Apply the accepted prefix delta; unknown copies fall back to actual contents.
	wantPrefixes := h.cidrMgr.Snapshot(prefixReferences(oldCidrRules))
	if err := h.cidrMgr.Apply(newRuleMapSel, beforePrefixes, wantPrefixes); err != nil {
		return abort(err)
	}

	verifiedRows, err := h.readAtomicShadow(wantRows)
	if err != nil {
		return abort(err)
	}

	// --- Step 4: Atomic flip (switch active config slot) ---
	newSlot := 1 - h.activeSlot
	selKey := make([]byte, 4) // key = 0
	selValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(selValue, uint64(newSlot))
	if err := selector.Update(selKey, selValue, ebpf.UpdateExist); err != nil {
		return abort(fmt.Errorf("failed to flip config selector: %w", err))
	}
	h.quiescenceConfirmed = false
	h.activeSlot = newSlot
	h.activeRuleSlot.Store(int32(newRuleMapSel))
	h.ruleRowCounts = [4]int{int(shadowRuleCount), int(shadowCidrCount), 0, 0}
	h.ruleRowCountsKnown = false // Step 6 counts actual rows, including conditions.
	h.publishRuleState(len(newRules), len(newCidrRules))
	h.publishAtomicCapacity(verifiedRows, wantPrefixes, logicalUsed)
	h.observeAtomicStage("flip")

	// --- Step 5: Update in-memory state ---
	h.rulesMu.Lock()
	h.replaceLogicalOwnersLocked(newRules, newCidrRules)
	h.rules = newRules
	h.ruleKeyIndex = newRuleKeyIndex
	h.cidrRules = newCidrRules
	h.cidrRuleKeyIndex = newCidrRuleKeyIndex
	h.comboRefCount = shadowCombo
	h.cidrComboRefCount = shadowCidrCombo
	h.rulesMu.Unlock()

	// Step 5b releases memory references; old trie writes await this R5c receipt.
	for _, stored := range oldCidrRules {
		if stored.SrcCIDR != "" {
			if err := h.cidrMgr.ReleaseSrcID(stored.SrcCIDR); err != nil {
				log.Printf("[AtomicSync 5b] CIDR reference release: %v", err)
			}
		}
		if stored.DstCIDR != "" {
			if err := h.cidrMgr.ReleaseDstID(stored.DstCIDR); err != nil {
				log.Printf("[AtomicSync 5b] CIDR reference release: %v", err)
			}
		}
	}

	h.observeAtomicStage("5b")
	// Clear PPS cache (rules changed completely)
	h.rulePPSMu.Lock()
	h.lastRuleDropCount = make(map[string]uint64)
	h.lastRuleStatsTime = make(map[string]int64)
	h.rulePPSMu.Unlock()

	log.Printf("[AtomicSync] Flipped: slot=%d, ruleMapSel=%d, exact=%d, cidr=%d, failed=%d, bitmap=0x%x, cidrBitmap=0x%x",
		newSlot, newRuleMapSel, shadowRuleCount, shadowCidrCount, len(rejected), bitmap, cidrBitmap)

	result := AtomicSyncResult{Added: added, Failed: len(rejected), Rejected: rejected, ExactRules: int64(len(newRules)), CIDRRules: int64(len(newCidrRules))}
	// R5c follows both the flip and release of old CIDR references.
	if err := h.awaitQuiescence(); err != nil {
		log.Printf("[AtomicSync R5c] %v; reclamation deferred until next full sync", err)
		h.cidrMgr.Invalidate(1 - newRuleMapSel)
		return result, nil
	}

	if err := h.cidrMgr.Apply(1-newRuleMapSel, beforePrefixes, wantPrefixes); err != nil {
		log.Printf("[AtomicSync R5c] old prefix alignment deferred: %v", err)
	}

	// Step 6 reads the old maps and aligns to the verified shadow bytes; failures keep M3 pending.
	h.observeAtomicStage("6")
	h.finishAtomicMirrorLocked(verifiedRows)

	return result, nil
}

// DoWhitelistAtomicSync performs a zero-window full whitelist replacement.
// This is the ONLY entry point for full whitelist sync (Controller FullSync).
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
	if !h.quiescenceConfirmed {
		if err := h.awaitQuiescence(); err != nil {
			return fmt.Errorf("%w: %v", errQuiescence, err)
		}
	}
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
		if err := whitelistMapIO(shadow).Update(keyBytes, []byte{1}, ebpf.UpdateNoExist); err != nil {
			return fmt.Errorf("shadow whitelist insert failed for %s: %w", item.entry.ID, err)
		}
		newWlEntries[item.entry.ID] = item.key
		newWlKeyIndex[item.key] = item.entry.ID
		newWlComboRefCount[item.combo]++
	}

	// Verify every expected key/value and reject unexpected extra rows before publication.
	for _, item := range items {
		var value [1]byte
		if err := whitelistMapIO(shadow).Lookup(ruleKeyToBytes(item.key), &value); err != nil || value[0] != 1 {
			return fmt.Errorf("shadow whitelist verification failed for %s: value=%d err=%v", item.entry.ID, value[0], err)
		}
	}
	iter := whitelistMapIO(shadow).Iterate()
	key, value := make([]byte, 40), make([]byte, 1)
	count := 0
	for iter.Next(&key, &value) {
		count++
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("shadow whitelist verification iterate: %w", err)
	}
	if count != len(items) {
		return fmt.Errorf("shadow whitelist verification count: got %d want %d", count, len(items))
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
	if err := h.awaitQuiescence(); err != nil {
		log.Printf("[DoWhitelistAtomicSync R5c] %v; reclamation deferred until next full sync", err)
		return nil
	}
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
	if err := bindStrictJSON(c, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.DoWhitelistAtomicSync(req.Entries); err != nil {
		if _, ok := err.(*wlSyncValidationError); ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else if errors.Is(err, errQuiescence) {
			c.JSON(http.StatusInternalServerError, gin.H{"code": "quiescence_failed", "error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	h.whitelistSynced.Store(true)
	c.JSON(http.StatusOK, gin.H{"total": len(req.Entries), "failed": 0})
}
