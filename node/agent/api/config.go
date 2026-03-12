// XDrop Agent - Double-buffer config publish and map selector helpers
package api

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/dropbox/goebpf"
)

// publishConfigUpdate performs a double-buffer config publish.
// Caller must already hold publishMu.
// Flow: copy active→shadow → modify shadow → switch selector.
//
// countDelta: blacklist count increment
// wlCountDelta: whitelist count increment (most calls pass 0)
// cidrCountDelta: CIDR blacklist count increment (most calls pass 0)
//
// Returns error on failure; caller must rollback memory state and not proceed with BPF map writes.
func (h *Handlers) publishConfigUpdate(countDelta, wlCountDelta, cidrCountDelta int64) error {
	shadow := h.shadowMap()
	active := h.activeMap()

	// Step 1: Copy active → shadow (all entries)
	for i := uint32(0); i < ConfigMapEntries; i++ {
		key := make([]byte, 4)
		binary.LittleEndian.PutUint32(key, i)
		if value, err := active.Lookup(key); err == nil {
			if err := shadow.Update(key, value); err != nil {
				return fmt.Errorf("failed to copy config index %d to shadow: %w", i, err)
			}
		}
	}

	// Step 2: Update dynamic items in shadow

	// 2a. Bitmap: rebuild from comboRefCount (not delta)
	var bitmap uint64
	for i := 0; i < 64; i++ {
		if h.comboRefCount[i] > 0 {
			bitmap |= 1 << uint(i)
		}
	}
	bitmapKey := make([]byte, 4)
	binary.LittleEndian.PutUint32(bitmapKey, ConfigRuleBitmap)
	bitmapValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(bitmapValue, bitmap)
	if err := shadow.Update(bitmapKey, bitmapValue); err != nil {
		return fmt.Errorf("failed to update shadow bitmap: %w", err)
	}

	// 2b. Blacklist count
	if countDelta != 0 {
		countKey := make([]byte, 4)
		binary.LittleEndian.PutUint32(countKey, ConfigBlacklistCount)
		var currentCount uint64
		if v, err := shadow.Lookup(countKey); err == nil && len(v) >= 8 {
			currentCount = binary.LittleEndian.Uint64(v)
		}
		newCount := int64(currentCount) + countDelta
		if newCount < 0 {
			newCount = 0
		}
		countValue := make([]byte, 8)
		binary.LittleEndian.PutUint64(countValue, uint64(newCount))
		if err := shadow.Update(countKey, countValue); err != nil {
			return fmt.Errorf("failed to update shadow blacklist count: %w", err)
		}
	}

	// 2c. Whitelist count
	if wlCountDelta != 0 {
		wlKey := make([]byte, 4)
		binary.LittleEndian.PutUint32(wlKey, ConfigWhitelistCount)
		var currentWlCount uint64
		if v, err := shadow.Lookup(wlKey); err == nil && len(v) >= 8 {
			currentWlCount = binary.LittleEndian.Uint64(v)
		}
		newWlCount := int64(currentWlCount) + wlCountDelta
		if newWlCount < 0 {
			newWlCount = 0
		}
		wlValue := make([]byte, 8)
		binary.LittleEndian.PutUint64(wlValue, uint64(newWlCount))
		if err := shadow.Update(wlKey, wlValue); err != nil {
			return fmt.Errorf("failed to update shadow whitelist count: %w", err)
		}
	}

	// 2d. CIDR bitmap: rebuild from cidrComboRefCount
	var cidrBitmap uint64
	for i := 0; i < 64; i++ {
		if h.cidrComboRefCount[i] > 0 {
			cidrBitmap |= 1 << uint(i)
		}
	}
	cidrBitmapKey := make([]byte, 4)
	binary.LittleEndian.PutUint32(cidrBitmapKey, ConfigCIDRBitmap)
	cidrBitmapValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(cidrBitmapValue, cidrBitmap)
	if err := shadow.Update(cidrBitmapKey, cidrBitmapValue); err != nil {
		return fmt.Errorf("failed to update shadow CIDR bitmap: %w", err)
	}

	// 2e. CIDR blacklist count
	if cidrCountDelta != 0 {
		cidrCountKey := make([]byte, 4)
		binary.LittleEndian.PutUint32(cidrCountKey, ConfigCIDRRuleCount)
		var currentCIDRCount uint64
		if v, err := shadow.Lookup(cidrCountKey); err == nil && len(v) >= 8 {
			currentCIDRCount = binary.LittleEndian.Uint64(v)
		}
		newCIDRCount := int64(currentCIDRCount) + cidrCountDelta
		if newCIDRCount < 0 {
			newCIDRCount = 0
		}
		cidrCountValue := make([]byte, 8)
		binary.LittleEndian.PutUint64(cidrCountValue, uint64(newCIDRCount))
		if err := shadow.Update(cidrCountKey, cidrCountValue); err != nil {
			return fmt.Errorf("failed to update shadow CIDR count: %w", err)
		}
	}

	// Step 3: Atomically switch active selector
	newSlot := 1 - h.activeSlot
	selKey := make([]byte, 4) // key = 0
	selValue := make([]byte, 8)
	binary.LittleEndian.PutUint64(selValue, uint64(newSlot))
	if err := h.activeConfig.Update(selKey, selValue); err != nil {
		return fmt.Errorf("failed to switch active config: %w", err)
	}
	h.activeSlot = newSlot

	log.Printf("[publishConfigUpdate] Switched to slot %d, bitmap=0x%016x, cidrBitmap=0x%016x, blCount delta=%d, wlCount delta=%d, cidrCount delta=%d",
		newSlot, bitmap, cidrBitmap, countDelta, wlCountDelta, cidrCountDelta)

	return nil
}

func (h *Handlers) activeMap() goebpf.Map {
	if h.activeSlot == 0 {
		return h.configA
	}
	return h.configB
}

func (h *Handlers) shadowMap() goebpf.Map {
	if h.activeSlot == 0 {
		return h.configB
	}
	return h.configA
}

// activeBlacklist returns the currently active blacklist BPF map (Phase 4.2 dual rule map)
func (h *Handlers) activeBlacklist() goebpf.Map {
	if h.activeRuleSlot == 0 {
		return h.blacklist
	}
	return h.blacklistB
}

// shadowBlacklist returns the shadow blacklist BPF map (Phase 4.2 dual rule map)
func (h *Handlers) shadowBlacklist() goebpf.Map {
	if h.activeRuleSlot == 0 {
		return h.blacklistB
	}
	return h.blacklist
}

// activeCidrBlacklist returns the currently active CIDR blacklist BPF map
func (h *Handlers) activeCidrBlacklist() goebpf.Map {
	if h.activeRuleSlot == 0 {
		return h.cidrBlacklist
	}
	return h.cidrBlacklistB
}

// shadowCidrBlacklist returns the shadow CIDR blacklist BPF map
func (h *Handlers) shadowCidrBlacklist() goebpf.Map {
	if h.activeRuleSlot == 0 {
		return h.cidrBlacklistB
	}
	return h.cidrBlacklist
}

// clearMap removes all entries from a BPF hash map using GetNextKey iteration.
// BPF hash maps have no bulk clear; we must iterate + delete.
func clearMap(m goebpf.Map) error {
	// Collect all keys first to avoid iterator invalidation
	var keys [][]byte
	var prevKey []byte
	for {
		nextKey, err := m.GetNextKey(prevKey)
		if err != nil {
			break // no more keys
		}
		keyCopy := make([]byte, len(nextKey))
		copy(keyCopy, nextKey)
		keys = append(keys, keyCopy)
		prevKey = nextKey
	}
	for _, key := range keys {
		m.Delete(key) // best-effort; ignore errors on individual deletes
	}
	return nil
}
