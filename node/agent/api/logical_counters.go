package api

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// LogicalRuleCounters mirrors xdrop.h logical_rule_counters. Exact and CIDR
// candidates use the same logical ID. ID 0 is reserved for the knife-four allocator.
type LogicalRuleCounters struct {
	Match      uint64
	Drop       uint64
	MatchBytes uint64
	DropBytes  uint64
	LastHitNS  uint64
}

func (c LogicalRuleCounters) packets() (uint64, uint64) { return c.Match, c.Drop }

// ReadLogicalRuleCounters sums all possible CPU slots in id_counts. A missing
// row is zero; other lookup errors remain visible. ListRules adopts this reader
// with the stored logical IDs in knife four.
func ReadLogicalRuleCounters(m interface{ Lookup(key, valueOut any) error }, ruleID uint32) (LogicalRuleCounters, error) {
	var cpus []LogicalRuleCounters
	if err := m.Lookup(ruleID, &cpus); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return LogicalRuleCounters{}, nil
		}
		return LogicalRuleCounters{}, fmt.Errorf("read logical rule %d counters: %w", ruleID, err)
	}
	var total LogicalRuleCounters
	for _, cpu := range cpus {
		total.add(cpu)
	}
	return total, nil
}

func (total *LogicalRuleCounters) add(cpu LogicalRuleCounters) {
	total.Match += cpu.Match
	total.Drop += cpu.Drop
	total.MatchBytes += cpu.MatchBytes
	total.DropBytes += cpu.DropBytes
	total.LastHitNS = max(total.LastHitNS, cpu.LastHitNS)
}
