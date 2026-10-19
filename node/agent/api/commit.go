package api

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/http"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
)

func commitUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// CommitRules publishes all declared groups through one selector flip.
func (h *Handlers) CommitRules(c *gin.Context) {
	var req struct {
		Groups []CommitGroup `json:"groups"`
	}
	if err := bindStrictJSON(c, &req); err != nil {
		h.ruleJSON(c, http.StatusBadRequest, gin.H{"code": mutationInvalid, "error": err.Error(), "groups": []CommitGroupResult{}})
		return
	}
	result, err := h.DoCommitRules(req.Groups)
	if err != nil {
		groups := err.Groups
		if groups == nil {
			groups = []CommitGroupResult{}
		}
		h.ruleJSON(c, err.Status, gin.H{"code": err.Code, "error": err.Message, "groups": groups})
		return
	}
	body := gin.H{"code": result.Code, "groups": result.Groups}
	if result.Receipt != "" {
		body["receipt"] = result.Receipt
	}
	h.ruleJSON(c, http.StatusOK, body)
}

func (h *Handlers) observeCommit(stage string) {
	if h.commitStageTestHook != nil {
		h.commitStageTestHook(stage)
	}
}
func (h *Handlers) commitFault(stage string) error {
	if h.commitFaultTestHook != nil {
		return h.commitFaultTestHook(stage)
	}
	return nil
}

func (h *Handlers) admitCommitLogicalLocked(p *commitPlan) *commitError {
	_, err := h.admitCommitLogicalUsageLocked(p)
	return err
}

func (h *Handlers) admitCommitLogicalUsageLocked(p *commitPlan) (int, *commitError) {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	a := h.newLogicalAdmissionLocked()
	for id := range p.LogicalIDs {
		a.reserve(id)
	}
	if a.used > h.logicalCapacity() {
		h.payAdmissionLocked(a)
	}
	if a.used > h.logicalCapacity() {
		return a.used, commitCapacityError(0, "logical_state", a.used-h.logicalCapacity())
	}
	return a.used, nil
}

type commitRows [4]map[string][]byte // nil value means delete, absent means untouched

func (h *Handlers) reserveCommitGroups(p *commitPlan, borrowed *[]commitPrefix) (commitRows, []commitPrefix, error) {
	var rows commitRows
	for i := range rows {
		rows[i] = make(map[string][]byte)
	}
	var publish []commitPrefix
	seen := make(map[commitPrefix]bool)
	for _, g := range p.Groups {
		if !g.Changed {
			continue
		}
		kind, cond := mirrorExact, mirrorCondition
		if g.Key.Kind == "cidr" {
			kind, cond = mirrorCIDR, mirrorCIDRCondition
			for i := range g.Members {
				member := &g.Members[i]
				for direction, prefix := range []string{member.Rule.SrcCIDR, member.Rule.DstCIDR} {
					if prefix == "" {
						continue
					}
					var id uint32
					var err error
					if direction == 0 {
						id, err = h.cidrMgr.ReserveSrcID(prefix)
					} else {
						id, err = h.cidrMgr.ReserveDstID(prefix)
					}
					if err != nil {
						return rows, publish, err
					}
					borrow := commitPrefix{prefix, direction == 0}
					*borrowed = append(*borrowed, borrow)
					// Step 3 may retire a prefix seen by preflight. Publish each
					// borrowed prefix; Manager decides whether its current ID needs publishing.
					if !seen[borrow] {
						seen[borrow] = true
						publish = append(publish, borrow)
					}
					if direction == 0 {
						member.CIDR.SrcID = id
					} else {
						member.CIDR.DstID = id
					}
				}
			}
			if len(g.Members) > 0 {
				g.Physical, g.Known = cidrRuleKeyToBytes(g.Members[0].CIDR), true
				for _, member := range g.Members {
					if member.CIDR != g.Members[0].CIDR {
						return rows, publish, fmt.Errorf("CIDR group key changed after reservation")
					}
				}
			}
		}
		if g.Known {
			rows[kind][string(g.Physical)] = g.Value
			rows[cond][string(g.Physical)] = g.Condition
		}
	}
	return rows, publish, nil
}

func (h *Handlers) undoCommitBorrows(borrowed []commitPrefix) {
	for i := len(borrowed) - 1; i >= 0; i-- {
		p := borrowed[i]
		var err error
		if p.Src {
			err = h.cidrMgr.UndoSrcReservation(p.Prefix)
		} else {
			err = h.cidrMgr.UndoDstReservation(p.Prefix)
		}
		if err != nil {
			log.Printf("[commit rollback] reference release: %v", err)
		}
	}
}

func (h *Handlers) dirtyCommitRows(rows commitRows) {
	for kind, entries := range rows {
		for key := range entries {
			h.markMirrorDirty(kind, []byte(key))
		}
	}
}

func (h *Handlers) oweCommitRows(rows commitRows) {
	for kind, entries := range rows {
		if h.mirrorDebt[kind] == nil {
			h.mirrorDebt[kind] = make(map[string]struct{})
		}
		for key := range entries {
			h.mirrorDebt[kind][key] = struct{}{}
		}
	}
}

// Both step 4 and step 9 use this ordering. Remove a deconditioned rule before
// deleting its condition row, then condition deletes/writes, then rule
// deletes/writes. Each individual table performs all deletes before writes.
func (h *Handlers) applyCommitRows(slot int, rows commitRows) error {
	remove := func(kind int, key string) error {
		err := h.mirrorTable(slot, kind).Delete([]byte(key))
		if err != nil && !isMapEntryMissing(err) {
			return fmt.Errorf("delete %s: %w", mirrorNames[kind], err)
		}
		return nil
	}
	for _, kind := range []int{mirrorExact, mirrorCIDR} {
		for _, key := range sortedMirrorKeys(rows[kind]) {
			value := rows[kind][key]
			if value != nil && value[ruleFlagsOffset]&RuleHasConditions == 0 && rows[kind+2][key] == nil {
				if err := remove(kind, key); err != nil {
					return err
				}
			}
		}
	}
	for _, kind := range []int{mirrorCondition, mirrorCIDRCondition, mirrorExact, mirrorCIDR} {
		for _, key := range sortedMirrorKeys(rows[kind]) {
			if rows[kind][key] == nil {
				if err := remove(kind, key); err != nil {
					return err
				}
			}
		}
		for _, key := range sortedMirrorKeys(rows[kind]) {
			value := rows[kind][key]
			if value == nil {
				continue
			}
			if err := h.mirrorTable(slot, kind).Update([]byte(key), value, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("write %s: %w", mirrorNames[kind], err)
			}
		}
	}
	return nil
}

func (h *Handlers) writeCommitConfig(p *commitPlan) error {
	shadow, active, _ := h.configPublishTables()
	for i := uint32(0); i < ConfigMapEntries; i++ {
		var value uint64
		if err := active.Lookup(i, &value); err != nil {
			return fmt.Errorf("read active config %d: %w", i, err)
		}
		if err := shadow.Update(i, value, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("copy shadow config %d: %w", i, err)
		}
	}
	var exactBitmap, cidrBitmap, exactCount, cidrCount uint64
	for i, count := range p.Combos {
		if count > 0 {
			exactBitmap |= 1 << uint(i)
			exactCount += uint64(count)
		}
	}
	for i, count := range p.CIDRCombos {
		if count > 0 {
			cidrBitmap |= 1 << uint(i)
			cidrCount += uint64(count)
		}
	}
	for _, item := range []struct {
		key   uint32
		value uint64
	}{
		{ConfigRuleBitmap, exactBitmap}, {ConfigBlacklistCount, exactCount},
		{ConfigCIDRBitmap, cidrBitmap}, {ConfigCIDRRuleCount, cidrCount},
		{ConfigRuleMapSelector, uint64(1 - h.activeRuleSlot.Load())},
	} {
		if err := shadow.Update(item.key, item.value, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("write shadow config %d: %w", item.key, err)
		}
	}
	return nil
}

// S+P already held; only memory index replacement holds R. No helper called
// here acquires R or P recursively. Preserve unrelated rows and orphan owners.
func (h *Handlers) installCommitMemory(p *commitPlan) []string {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	if h.rules == nil {
		h.rules = make(map[string]StoredRule)
	}
	if h.cidrRules == nil {
		h.cidrRules = make(map[string]StoredCIDRRule)
	}
	if h.ruleKeyIndex == nil {
		h.ruleKeyIndex = make(map[RuleKey]ruleIDSet)
	}
	if h.cidrRuleKeyIndex == nil {
		h.cidrRuleKeyIndex = make(map[CIDRRuleKey]ruleIDSet)
	}
	for _, g := range p.Groups {
		if !g.Changed {
			continue
		}
		for id, old := range g.Old {
			if r, ok := h.rules[id]; ok {
				removeRuleID(h.ruleKeyIndex, r.Key, id)
				delete(h.rules, id)
			}
			if r, ok := h.cidrRules[id]; ok {
				removeRuleID(h.cidrRuleKeyIndex, r.Key, id)
				delete(h.cidrRules, id)
				if r.SrcCIDR != "" {
					h.undoCommitBorrows([]commitPrefix{{r.SrcCIDR, true}})
				}
				if r.DstCIDR != "" {
					h.undoCommitBorrows([]commitPrefix{{r.DstCIDR, false}})
				}
			}
			if p.LogicalIDs[old.LogicalID] {
				h.forgetLogicalIDLocked(id, old.LogicalID)
			} else {
				h.retireLogicalIDLocked(id, old.LogicalID)
			}
		}
	}
	for _, g := range p.Groups {
		if !g.Changed {
			continue
		}
		for _, member := range g.Members {
			r := member.Rule
			if member.IsCIDR {
				h.cidrRules[r.ID] = ruleToStoredCIDR(member.CIDR, r.SrcCIDR, r.DstCIDR, r)
				addRuleID(h.cidrRuleKeyIndex, member.CIDR, r.ID)
			} else {
				h.rules[r.ID] = ruleToStored(member.Exact, r)
				addRuleID(h.ruleKeyIndex, member.Exact, r.ID)
			}
			h.rememberLogicalIDLocked(r.ID, r.LogicalID)
		}
	}
	h.comboRefCount, h.cidrComboRefCount = p.Combos, p.CIDRCombos
	var removed []string
	for _, g := range p.Groups {
		if !g.Changed {
			continue
		}
		for id := range g.Old {
			_, exact := h.rules[id]
			_, cidr := h.cidrRules[id]
			if !exact && !cidr {
				removed = append(removed, id)
			}
		}
	}
	return removed
}

func (h *Handlers) reclaimCommitLogicalLocked() {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	if err := h.reclaimPendingLogicalLocked(); err != nil {
		log.Printf("[commit] logical reclamation deferred: %v", err)
	}
}

// DoCommitRules owns S+P for the complete nine-step transaction.
func (h *Handlers) DoCommitRules(groups []CommitGroup) (CommitResult, *commitError) {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()
	h.publishMu.Lock()
	defer h.publishMu.Unlock()
	p, rejection := h.preflightCommit(groups) // 1
	if rejection != nil {
		return CommitResult{}, rejection
	}
	if !p.Changed {
		return p.Result, nil
	}
	logicalUsed, rejection := h.admitCommitLogicalUsageLocked(p)
	if rejection != nil {
		return CommitResult{}, rejection
	}
	defer func() { h.rulesMu.Lock(); h.maybePayLogicalLocked(); h.rulesMu.Unlock() }()
	fail := func(code string, err error) (CommitResult, *commitError) {
		return CommitResult{}, &commitError{Status: 500, Code: code, Message: err.Error()}
	}
	if !h.quiescenceConfirmed {
		h.observeCommit("c-R0")
		if err := h.awaitQuiescence(); err != nil {
			return fail("quiescence_failed", err)
		}
	}
	if err := h.commitFault("c-3"); err != nil {
		h.mirrorReady = false
		h.mirrorFailures++
		return fail("commit_failed", err)
	}
	if err := h.catchUpRuleMirrorLocked(); err != nil {
		return fail("commit_failed", err)
	} // 3
	if err := h.cidrMgr.CatchUp(1 - int(h.activeRuleSlot.Load())); err != nil {
		return fail("commit_failed", err)
	}
	// R0 may be skipped after a pure deletion whose config publish failed.
	// Pending logical IDs therefore wait for this commit's successful Rc.
	h.observeCommit("c-3")
	beforePrefixes := h.cidrMgr.Snapshot([2][]string{})
	var borrowed []commitPrefix
	rows, _, err := h.reserveCommitGroups(p, &borrowed) // 4
	abort := func(err error) (CommitResult, *commitError) {
		h.dirtyCommitRows(rows)
		h.cidrMgr.Invalidate(1 - int(h.activeRuleSlot.Load()))
		h.undoCommitBorrows(borrowed)
		return fail("commit_failed", err)
	}
	if err != nil {
		return abort(err)
	}
	if err := h.commitFault("c-4"); err != nil {
		return abort(err)
	}
	if err := h.applyCommitRows(1-int(h.activeRuleSlot.Load()), rows); err != nil {
		return abort(err)
	}
	h.observeCommit("c-4")
	if err := h.commitFault("c-5"); err != nil {
		return abort(err)
	}
	if err := h.writeCommitConfig(p); err != nil {
		return abort(err)
	} // 5
	h.observeCommit("c-5")
	if err := h.commitFault("c-6"); err != nil {
		return abort(err)
	}
	wantPrefixes := h.cidrMgr.Snapshot(p.retiredPrefixes())
	if err := h.cidrMgr.Apply(1-int(h.activeRuleSlot.Load()), beforePrefixes, wantPrefixes); err != nil {
		return abort(err)
	}
	h.observeCommit("c-6")
	if err := h.commitFault("c-7"); err != nil {
		return abort(err)
	}
	_, _, selector := h.configPublishTables()
	if err := selector.Update(uint32(0), uint64(1-h.activeSlot), ebpf.UpdateExist); err != nil {
		return abort(err)
	} // 7
	h.quiescenceConfirmed = false
	h.activeSlot = 1 - h.activeSlot
	h.activeRuleSlot.Store(1 - h.activeRuleSlot.Load())
	h.ruleRowCounts, h.ruleRowCountsKnown = p.Rows, true
	h.oweCommitRows(rows)
	removed := h.installCommitMemory(p)
	h.rulePPSMu.Lock()
	for _, id := range removed {
		delete(h.lastRuleDropCount, id)
		delete(h.lastRuleStatsTime, id)
	}
	h.rulePPSMu.Unlock()
	h.publishRuleState(len(h.rules), len(h.cidrRules))
	h.publishCommitCapacity(p.Rows, wantPrefixes, logicalUsed)
	h.observeCommit("c-7")
	p.Result.Code, p.Result.Receipt = "committed", "deferred"
	h.observeCommit("c-Rc")
	if err := h.awaitQuiescence(); err != nil { // 8
		h.cidrMgr.Invalidate(1 - int(h.activeRuleSlot.Load()))
		h.commitDeferred++
		log.Printf("[commit] receipt deferred: %v", err)
		return p.Result, nil
	}
	p.Result.Receipt = "confirmed"
	err = h.commitFault("c-9")
	if err == nil {
		err = h.applyCommitRows(1-int(h.activeRuleSlot.Load()), rows)
	} // 9
	if err != nil {
		h.mirrorFailures++
		h.dirtyCommitRows(rows)
		log.Printf("[commit] old-side repair deferred: %v", err)
	} else {
		h.mirrorDebt = [4]map[string]struct{}{}
	}
	if err := h.cidrMgr.Apply(1-int(h.activeRuleSlot.Load()), beforePrefixes, wantPrefixes); err != nil {
		log.Printf("[commit] old trie alignment failed: %v", err)
	}
	h.reclaimCommitLogicalLocked() // Reuses Rc; no second receipt.
	h.observeCommit("c-9")
	return p.Result, nil
}
