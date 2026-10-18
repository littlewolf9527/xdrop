// XDrop Agent - Double-buffer config publish and map selector helpers
package api

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
)

func (h *Handlers) activeMap() *ebpf.Map {
	if h.activeSlot == 0 {
		return h.configA
	}
	return h.configB
}

func (h *Handlers) shadowMap() *ebpf.Map {
	if h.activeSlot == 0 {
		return h.configB
	}
	return h.configA
}

// shadowWhitelist returns the shadow whitelist BPF map (Phase 8 dual-buffer)
func (h *Handlers) shadowWhitelist() *ebpf.Map {
	if h.activeWLSlot == 0 {
		return h.whitelistB
	}
	return h.whitelist
}

// publishConfigUpdateForWLSync performs the config publish step for DoWhitelistAtomicSync.
// Unlike the general publishConfigUpdate, this function:
//   - Writes absolute whitelist count (not a delta)
//   - Rebuilds WL bitmap from the provided newWLComboRefCount (not h.wlComboRefCount)
//   - Preserves all other config slots byte-for-byte (BL, CIDR, anomaly, FF, rate-limit divisor, etc.)
//   - Flips the active_config selector
//
// Caller must hold publishMu and have already set h.activeWLSlot to the new value.
func (h *Handlers) publishConfigUpdateForWLSync(wlAbsoluteCount uint64, newWLComboRefCount [64]int) error {
	shadow, active, selector := h.configPublishTables()

	// Step 1: Copy active → shadow (all entries, preserves BL/CIDR/anomaly/FF slots)
	for i := uint32(0); i < ConfigMapEntries; i++ {
		key := make([]byte, 4)
		binary.LittleEndian.PutUint32(key, i)
		var value [8]byte
		if err := active.Lookup(key, &value); err != nil {
			return fmt.Errorf("failed to read active config index %d: %w", i, err)
		}
		if err := shadow.Update(key, value[:], ebpf.UpdateExist); err != nil {
			return fmt.Errorf("failed to copy config index %d to shadow: %w", i, err)
		}
	}

	// Step 2: Overwrite only the 3 whitelist-owned slots

	// 2a. Absolute whitelist count
	wlCountKey := make([]byte, 4)
	binary.LittleEndian.PutUint32(wlCountKey, ConfigWhitelistCount)
	wlCountValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(wlCountValue, wlAbsoluteCount)
	if err := shadow.Update(wlCountKey, wlCountValue, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("failed to update shadow WL count: %w", err)
	}

	// 2b. WL bitmap rebuilt from newWLComboRefCount
	var wlBitmap uint64
	for i := 0; i < 64; i++ {
		if newWLComboRefCount[i] > 0 {
			wlBitmap |= 1 << uint(i)
		}
	}
	wlBitmapKey := make([]byte, 4)
	binary.LittleEndian.PutUint32(wlBitmapKey, ConfigWLBitmap)
	wlBitmapValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(wlBitmapValue, wlBitmap)
	if err := shadow.Update(wlBitmapKey, wlBitmapValue, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("failed to update shadow WL bitmap: %w", err)
	}

	// 2c. WL map selector (h.activeWLSlot already set by caller)
	wlSelKey := make([]byte, 4)
	binary.LittleEndian.PutUint32(wlSelKey, ConfigWLMapSelector)
	wlSelValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(wlSelValue, uint64(h.activeWLSlot))
	if err := shadow.Update(wlSelKey, wlSelValue, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("failed to update shadow WL map selector: %w", err)
	}

	// Step 3: Atomically flip active_config selector
	newSlot := 1 - h.activeSlot
	selKey := make([]byte, 4)
	selValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(selValue, uint64(newSlot))
	if err := selector.Update(selKey, selValue, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("failed to switch active config: %w", err)
	}
	h.quiescenceConfirmed = false
	h.activeSlot = newSlot
	h.publishWhitelistState(int(wlAbsoluteCount))
	h.publishWhitelistCapacity(int(wlAbsoluteCount))

	log.Printf("[publishConfigUpdateForWLSync] Switched to slot %d, wlBitmap=0x%016x, wlSlot=%d, wlCount=%d",
		newSlot, wlBitmap, h.activeWLSlot, wlAbsoluteCount)

	return nil
}

// shadowBlacklist returns the shadow blacklist BPF map (Phase 4.2 dual rule map)
func (h *Handlers) shadowBlacklist() *ebpf.Map {
	if int(h.activeRuleSlot.Load()) == 0 {
		return h.blacklistB
	}
	return h.blacklist
}

// shadowCidrBlacklist returns the shadow CIDR blacklist BPF map
func (h *Handlers) shadowCidrBlacklist() *ebpf.Map {
	if int(h.activeRuleSlot.Load()) == 0 {
		return h.cidrBlacklistB
	}
	return h.cidrBlacklist
}

// clearMap removes all entries from a BPF hash map using cilium/ebpf's
// iterator. BPF hash maps have no bulk clear; we must iterate + delete.
// Returns a non-nil error containing the count of per-entry delete failures
// (the first failing error is wrapped). All keys are attempted regardless of
// individual failures so the map is left as empty as possible.
func clearMap(m *ebpf.Map) error {
	// Collect all keys first to avoid iterator invalidation on Delete.
	var keys [][]byte
	iter := m.Iterate()
	keySize := int(m.KeySize())
	key := make([]byte, keySize)
	var valueScratch []byte
	if vs := int(m.ValueSize()); vs > 0 {
		valueScratch = make([]byte, vs)
	} else {
		// Per-CPU or otherwise size-zero reporting; fall back to a
		// small scratch buffer. cilium/ebpf handles the actual copy.
		valueScratch = make([]byte, 1)
	}
	for iter.Next(&key, &valueScratch) {
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)
		keys = append(keys, keyCopy)
	}
	if err := iter.Err(); err != nil {
		// Iteration errors are reported but do not prevent deletion of
		// whatever keys we did manage to enumerate.
		log.Printf("[clearMap] iterator error (continuing with %d collected keys): %v", len(keys), err)
	}

	var firstErr error
	failed := 0
	for _, k := range keys {
		if err := m.Delete(k); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("clearMap: %d/%d deletes failed, first error: %w", failed, len(keys), firstErr)
	}
	return nil
}
