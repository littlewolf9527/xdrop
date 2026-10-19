package api

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
)

func TestHCA11CMirror(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(path, err)
		}
		return string(b)
	}
	header, mainC, gateC := read("../../bpf/xdrop.h"), read("../../bpf/xdrop_main.c"), read("../../bpf/xdrop_gate.c")
	mainGo, statsGo := read("../main.go"), read("stats.go")
	number := func(t *testing.T, source, pattern string) int {
		t.Helper()
		m := regexp.MustCompile(pattern).FindAllStringSubmatch(source, -1)
		if len(m) != 1 {
			t.Fatalf("pattern %q: matches=%d want=1", pattern, len(m))
		}
		n, err := strconv.Atoi(m[0][1])
		if err != nil {
			t.Fatal(pattern, err)
		}
		return n
	}
	define := func(name string) string { return `(?m)^#define\s+` + name + `\s+([0-9]+)(?:ULL)?\b` }
	equal := func(t *testing.T, name string, got, want int) {
		t.Helper()
		if got != want {
			t.Errorf("%s: C=%d Go=%d", name, got, want)
		}
	}
	configs := map[string]int{
		"CONFIG_BLACKLIST_COUNT": ConfigBlacklistCount, "CONFIG_WHITELIST_COUNT": ConfigWhitelistCount,
		"CONFIG_RULE_BITMAP": ConfigRuleBitmap, "CONFIG_WL_BITMAP": ConfigWLBitmap,
		"CONFIG_FAST_FORWARD_ENABLED": ConfigFastForwardEnabled, "CONFIG_FILTER_IFINDEX": ConfigFilterIfindex,
		"CONFIG_CIDR_RULE_COUNT": ConfigCIDRRuleCount, "CONFIG_CIDR_BITMAP": ConfigCIDRBitmap,
		"CONFIG_WL_MAP_SELECTOR": ConfigWLMapSelector, "CONFIG_RULE_MAP_SELECTOR": ConfigRuleMapSelector,
		"CONFIG_RL_CPU_DIVISOR": ConfigRLCPUDivisor, "CONFIG_IPV6_DEEP_CHAIN_PASS": ConfigIPv6DeepChainPass,
		"CONFIG_MAP_ENTRIES": ConfigMapEntries,
	}
	for name, want := range configs {
		t.Run(name, func(t *testing.T) { equal(t, name, number(t, header, define(name)), want) })
	}
	t.Run("retired_slot", func(t *testing.T) {
		equal(t, "retired", number(t, header, `Config slot ([0-9]+) is retired`), ConfigAnomalyRuleCount)
	})
	t.Run("config_roster", func(t *testing.T) {
		if n := len(regexp.MustCompile(`(?m)^#define CONFIG_\w+\s`).FindAllString(header, -1)); n != len(configs) {
			t.Fatal("CONFIG roster", n)
		}
	})
	stats := []struct{ macro, field, array string }{
		{"STATS_TOTAL_PACKETS", "TotalPackets", "current"}, {"STATS_DROPPED_PACKETS", "DroppedPackets", "current"},
		{"STATS_PASSED_PACKETS", "PassedPackets", "current"}, {"STATS_WHITELISTED", "WhitelistedPackets", "current"},
		{"STATS_RATE_LIMITED", "RateLimitedPackets", "current"}, {"STATS_MAPPED_V6_DROPPED", "MappedV6Dropped", "current"},
		{"STATS_TOTAL_BYTES", "TotalBytes", "byteCounts"}, {"STATS_DROPPED_BYTES", "DroppedBytes", "byteCounts"},
		{"STATS_PASSED_BYTES", "PassedBytes", "byteCounts"},
	}
	packets := number(t, statsGo, `var current \[([0-9]+)\]uint64`)
	bytes := number(t, statsGo, `var byteCounts \[([0-9]+)\]uint64`)
	byteStart := number(t, statsGo, `h\.stats\.Lookup\(uint32\(([0-9]+)\+i\)`)
	// STATS_IPV6_DEEP_CHAIN_DROPPED is read on its own after the byte counters.
	deep := number(t, statsGo, `h\.stats\.Lookup\(uint32\(([0-9]+)\), &deepPerCPU\)`)
	t.Run("STATS_IPV6_DEEP_CHAIN_DROPPED", func(t *testing.T) {
		if n := len(regexp.MustCompile(`IPv6DeepDropped:\s*deepDropped,`).FindAllString(statsGo, -1)); n != 1 {
			t.Fatal("IPv6DeepDropped field", n)
		}
		equal(t, "STATS_IPV6_DEEP_CHAIN_DROPPED", number(t, header, define("STATS_IPV6_DEEP_CHAIN_DROPPED")), deep)
	})
	for _, s := range stats {
		t.Run(s.macro, func(t *testing.T) {
			index := number(t, statsGo, s.field+`:\s*`+s.array+`\[([0-9]+)\]`)
			if s.array == "byteCounts" {
				index += byteStart
			}
			equal(t, s.macro, number(t, header, define(s.macro)), index)
		})
	}
	t.Run("stats_extent", func(t *testing.T) {
		equal(t, "byte start", byteStart, packets)
		equal(t, "deep index", deep, packets+bytes)
		if n := len(regexp.MustCompile(`(?m)^#define STATS_\w+\s`).FindAllString(header, -1)); n != packets+bytes+1 || n != len(stats)+1 {
			t.Fatal("STATS roster", n)
		}
	})
	mapSize := func(name string) string {
		return `(?s)BPF_MAP_DEF\(` + name + `\)\s*=\s*\{[^}]*?\.max_entries\s*=\s*([0-9]+)`
	}
	for name, source := range map[string]string{"main": mainC, "gate": gateC} {
		t.Run("stats_"+name, func(t *testing.T) {
			equal(t, "stats max_entries", number(t, source, mapSize("stats")), packets+bytes+1)
		})
	}
	t.Run("TAIL_SLOT_FIREWALL_MAIN", func(t *testing.T) {
		equal(t, "tail slot", number(t, header, define("TAIL_SLOT_FIREWALL_MAIN")), number(t, mainGo, `tailSlotFirewallMain := uint32\(([0-9]+)\)`))
	})
	t.Run("RL_MAX_DIVISOR", func(t *testing.T) {
		equal(t, "divisor", number(t, mainC, define("RL_MAX_DIVISOR")), int(ratelimit.MaxDivisor))
	})
	capacity := (&cidr.Manager{}).TrieCapacities()
	for i, name := range []string{"sv4", "dv4", "sv6", "dv6"} {
		for _, suffix := range []string{"", "_b"} {
			t.Run(name+suffix, func(t *testing.T) {
				equal(t, name+suffix, number(t, mainC, mapSize(name+"_cidr_trie"+suffix)), int(capacity[i]))
			})
		}
	}
	t.Run("trie_roster", func(t *testing.T) {
		if n := len(regexp.MustCompile(`(?m)^BPF_MAP_DEF\([sd]v[46]_cidr_trie(?:_b)?\)`).FindAllString(mainC, -1)); n != 8 {
			t.Fatal("trie roster", n)
		}
	})
}
