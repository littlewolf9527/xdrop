package api

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type startupTable struct {
	name  string
	table StartupMap
}

func clearStartupTables(business, logical []startupTable, receipt quiescer) error {
	for _, table := range business {
		if err := StrictClearAndRecount(table.table); err != nil {
			return fmt.Errorf("business %s: %w", table.name, err)
		}
	}
	if err := receipt.Quiesce(); err != nil {
		return fmt.Errorf("startup receipt: %w", err)
	}
	for _, table := range logical {
		if err := StrictClearAndRecount(table.table); err != nil {
			return fmt.Errorf("logical %s: %w", table.name, err)
		}
	}
	return nil
}

// PreparePinnedStartup drains both rule slots before a receipt, then clears
// the now producer-free logical state. The caller must refuse startup on error.
// NewHandlers keeps its signature and owns a separate runtime receipt.
func PreparePinnedStartup(main, gate *ebpf.Collection) error {
	var business, logical []startupTable
	for _, name := range []string{"blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b", "cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "sv4_cidr_trie_b", "dv4_cidr_trie_b", "sv6_cidr_trie_b", "dv6_cidr_trie_b", "whitelist", "whitelist_b"} {
		collection := main
		if name == "whitelist_b" {
			collection = gate
		}
		if collection == nil || collection.Maps[name] == nil {
			return fmt.Errorf("business %s: map unavailable", name)
		}
		business = append(business, startupTable{name, collection.Maps[name]})
	}
	for _, name := range []string{"id_counts", "id_rl_states"} {
		if main.Maps[name] == nil {
			return fmt.Errorf("logical %s: map unavailable", name)
		}
		logical = append(logical, startupTable{name, main.Maps[name]})
	}
	receipt, err := newQuiescer()
	if err != nil {
		return fmt.Errorf("create startup receipt: %w", err)
	}
	if closer, ok := receipt.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	return clearStartupTables(business, logical, receipt)
}
