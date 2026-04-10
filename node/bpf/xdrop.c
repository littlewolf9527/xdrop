// SPDX-License-Identifier: GPL-2.0
// XDrop - XDP Firewall with five-tuple matching
//
// Features:
// - Five-tuple matching (src_ip, dst_ip, src_port, dst_port, protocol)
// - IPv4 and IPv6 dual-stack support
// - Whitelist support (checked first, always pass)
// - Blacklist with wildcard matching
// - Drop/Pass/RateLimit actions
// - Per-rule and global statistics

#include "xdrop.h"

// Blacklist Map - Five-tuple hash map
BPF_MAP_DEF(blacklist) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(struct rule_value),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(blacklist);

// Whitelist Map - Five-tuple hash map (priority over blacklist)
BPF_MAP_DEF(whitelist) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(__u8),
    .max_entries = MAX_WHITELIST,
};
BPF_MAP_ADD(whitelist);

// Global statistics (PERCPU for high-performance counters)
BPF_MAP_DEF(stats) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 5,
};
BPF_MAP_ADD(stats);

// Double-buffer config maps (replaces single config map)
// Config map A
BPF_MAP_DEF(config_a) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = CONFIG_MAP_ENTRIES,
};
BPF_MAP_ADD(config_a);

// Config map B (shadow)
BPF_MAP_DEF(config_b) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = CONFIG_MAP_ENTRIES,
};
BPF_MAP_ADD(config_b);

// Active config selector: value 0 = config_a, value 1 = config_b
BPF_MAP_DEF(active_config) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(active_config);

// Rate limit state map (per-rule token bucket)
BPF_MAP_DEF(rl_states) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(struct rate_limit_state),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(rl_states);

// === CIDR Maps ===

// IPv4 LPM Trie: src IP → CIDR ID
BPF_MAP_DEF(sv4_cidr_trie) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v4_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(sv4_cidr_trie);

// IPv4 LPM Trie: dst IP → CIDR ID
BPF_MAP_DEF(dv4_cidr_trie) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v4_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(dv4_cidr_trie);

// IPv6 LPM Trie: src IP → CIDR ID
BPF_MAP_DEF(sv6_cidr_trie) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v6_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(sv6_cidr_trie);

// IPv6 LPM Trie: dst IP → CIDR ID
BPF_MAP_DEF(dv6_cidr_trie) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v6_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(dv6_cidr_trie);

// CIDR blacklist hash map (key uses integer IDs, not IP addresses)
BPF_MAP_DEF(cidr_blacklist) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct cidr_rule_key),
    .value_size = sizeof(struct rule_value),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(cidr_blacklist);

// CIDR rate limit state map
BPF_MAP_DEF(cidr_rl_states) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct cidr_rule_key),
    .value_size = sizeof(struct rate_limit_state),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(cidr_rl_states);

// === Dual Rule Map (Phase 4.2) — Shadow maps for atomic FullSync ===

// Shadow blacklist (B slot)
BPF_MAP_DEF(blacklist_b) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(struct rule_value),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(blacklist_b);

// Shadow CIDR blacklist (B slot)
BPF_MAP_DEF(cidr_blist_b) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct cidr_rule_key),
    .value_size = sizeof(struct rule_value),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(cidr_blist_b);

// Device map for XDP redirect (fast forward mode)
// Key: ingress interface index, Value: egress interface index
BPF_MAP_DEF(devmap) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 16,
};
BPF_MAP_ADD(devmap);

// Helper: increment stats counter
static INLINE void stats_inc(__u32 idx) {
  __u64 *counter = bpf_map_lookup_elem(&stats, &idx);
  if (counter) {
    (*counter)++;
  }
}

// === Dual Rule Map lookup macros (Phase 4.2) ===
// Select blacklist or blacklist_b based on rule_sel value
#define BLACKLIST_LOOKUP(rule_sel, key_ptr)             \
    ((rule_sel) == 0                                     \
        ? bpf_map_lookup_elem(&blacklist, (key_ptr))     \
        : bpf_map_lookup_elem(&blacklist_b, (key_ptr)))

#define CIDR_BLACKLIST_LOOKUP(rule_sel, key_ptr)                \
    ((rule_sel) == 0                                             \
        ? bpf_map_lookup_elem(&cidr_blacklist, (key_ptr))        \
        : bpf_map_lookup_elem(&cidr_blist_b, (key_ptr)))

// Helper: read active config slot (call once per function entry)
static INLINE __u64 read_active_slot(void) {
  __u32 sel_key = ACTIVE_CONFIG_KEY;
  __u64 *sel = bpf_map_lookup_elem(&active_config, &sel_key);
  return sel ? *sel : 0;
}

// Helper: lookup value from the specified config slot
static INLINE __u64 *config_lookup(__u64 slot, __u32 key_idx) {
  if (slot == 0) {
    return bpf_map_lookup_elem(&config_a, &key_idx);
  } else {
    return bpf_map_lookup_elem(&config_b, &key_idx);
  }
}

// Helper: read rule map selector from the given config slot
// Returns 0 (use blacklist/cidr_blacklist) or 1 (use blacklist_b/cidr_blist_b)
static INLINE int read_rule_map_selector(__u64 slot) {
  __u32 key = CONFIG_RULE_MAP_SELECTOR;
  __u64 *sel = config_lookup(slot, key);
  return sel ? (int)*sel : 0;
}

// Helper: copy IP address
static INLINE void ip_copy(struct ip_addr *dst, const struct ip_addr *src) {
#pragma unroll
  for (int i = 0; i < 16; i++) {
    dst->addr[i] = src->addr[i];
  }
}

// Helper: set IP to zero
static INLINE void ip_zero(struct ip_addr *ip) {
#pragma unroll
  for (int i = 0; i < 16; i++) {
    ip->addr[i] = 0;
  }
}

// Helper: convert IPv4 address to IPv4-mapped IPv6
static INLINE void ipv4_to_mapped(struct ip_addr *dst, __u32 ipv4) {
// Format: ::ffff:x.x.x.x
// First 10 bytes: 0x00
// Bytes 10-11: 0xff 0xff
// Bytes 12-15: IPv4 address
#pragma unroll
  for (int i = 0; i < 10; i++) {
    dst->addr[i] = 0;
  }
  dst->addr[10] = 0xff;
  dst->addr[11] = 0xff;
  // Copy IPv4 address (already in network byte order)
  dst->addr[12] = (ipv4 >> 0) & 0xff;
  dst->addr[13] = (ipv4 >> 8) & 0xff;
  dst->addr[14] = (ipv4 >> 16) & 0xff;
  dst->addr[15] = (ipv4 >> 24) & 0xff;
}

// Helper: copy IPv6 address from packet
static INLINE void ipv6_copy(struct ip_addr *dst, const __u8 *src) {
#pragma unroll
  for (int i = 0; i < 16; i++) {
    dst->addr[i] = src[i];
  }
}

// Helper: check if packet length matches rule constraints
static INLINE int pkt_len_matches(struct rule_value *rule, __u16 pkt_len) {
  if (rule->pkt_len_min > 0 && pkt_len < rule->pkt_len_min)
    return 0;
  if (rule->pkt_len_max > 0 && pkt_len > rule->pkt_len_max)
    return 0;
  return 1;
}

// Helper: check if TCP flags match rule constraints
// Returns 1 if matches (or no flags check), 0 if mismatch
static INLINE int tcp_flags_matches(struct rule_value *rule, __u8 proto, __u8 tcp_flags) {
  if (rule->tcp_flags_mask == 0)
    return 1;  // no flags filter on this rule
  if (proto != PROTO_TCP)
    return 1;  // flags only apply to TCP
  return (tcp_flags & rule->tcp_flags_mask) == rule->tcp_flags_value;
}

// Helper: lookup rule with wildcard fallback (bitmap optimized)
// pkt_len and tcp_flags are checked inline: if a rule matches the 5-tuple
// but fails the length or flags constraint, lookup continues to the next
// (more wildcard) combo instead of returning NULL and silently passing.
static INLINE struct rule_value *lookup_rule(struct rule_key *key,
                                             struct rule_key *matched_key,
                                             __u16 pkt_len,
                                             __u8 tcp_flags,
                                             int rule_sel,
                                             __u64 slot) {

  // Phase 1: Fast-return if no blacklist rules exist
  __u32 bl_count_idx = CONFIG_BLACKLIST_COUNT;
  __u64 *bl_count = config_lookup(slot, bl_count_idx);
  if (!bl_count || *bl_count == 0) {
    return NULL;
  }

  // Phase 2: Get rule bitmap for combo-level skip optimization
  // Bitmap is always valid in double-buffer mode (no BITMAP_VALID needed)
  __u32 bitmap_idx = CONFIG_RULE_BITMAP;
  __u64 *bitmap_ptr = config_lookup(slot, bitmap_idx);
  __u64 bitmap = bitmap_ptr ? *bitmap_ptr : ~0ULL;

  struct rule_value *rule;
  struct rule_key lookup;

  // Combo 0: Exact five-tuple (src_ip + dst_ip + src_port + dst_port +
  // protocol)
  if (bitmap & (1ULL << COMBO_EXACT_5TUPLE)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = key->dst_port;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 1: Wildcard src_ip (dst_ip + src_port + dst_port + protocol)
  if (bitmap & (1ULL << COMBO_WILDCARD_SRC_IP)) {
    ip_zero(&lookup.src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = key->dst_port;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 2: dst_ip + dst_port + protocol (no src_ip, no src_port)
  if (bitmap & (1ULL << COMBO_WILDCARD_SRC_IP_PORT)) {
    ip_zero(&lookup.src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = key->dst_port;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 3: dst_ip + protocol only
  if (bitmap & (1ULL << COMBO_DST_IP_PROTO)) {
    ip_zero(&lookup.src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = 0;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 4: dst_ip only
  if (bitmap & (1ULL << COMBO_DST_IP_ONLY)) {
    ip_zero(&lookup.src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = 0;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 5: protocol only
  if (bitmap & (1ULL << COMBO_PROTO_ONLY)) {
    ip_zero(&lookup.src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = 0;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 6: src_port only
  if (bitmap & (1ULL << COMBO_SRC_PORT_ONLY)) {
    ip_zero(&lookup.src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = 0;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 7: dst_port only
  if (bitmap & (1ULL << COMBO_DST_PORT_ONLY)) {
    ip_zero(&lookup.src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = key->dst_port;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 8: src_ip only
  if (bitmap & (1ULL << COMBO_SRC_IP_ONLY)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = 0;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 9: src_ip + protocol
  if (bitmap & (1ULL << COMBO_SRC_IP_PROTO)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = 0;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 10: src_ip + dst_ip
  if (bitmap & (1ULL << COMBO_SRC_DST_IP)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = 0;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 11: src_ip + dst_port
  if (bitmap & (1ULL << COMBO_SRC_IP_DST_PORT)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = key->dst_port;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 12: dst_ip + dst_port
  if (bitmap & (1ULL << COMBO_DST_IP_DST_PORT)) {
    ip_zero(&lookup.src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = key->dst_port;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 13: src_ip + dst_ip + protocol
  if (bitmap & (1ULL << COMBO_SRC_DST_IP_PROTO)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = 0;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 14: src_ip + dst_port + protocol
  if (bitmap & (1ULL << COMBO_SRC_IP_DST_PORT_PROTO)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = key->dst_port;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 15: src_port + protocol
  if (bitmap & (1ULL << COMBO_SRC_PORT_PROTO)) {
    ip_zero(&lookup.src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = 0;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 16: dst_port + protocol
  if (bitmap & (1ULL << COMBO_DST_PORT_PROTO)) {
    ip_zero(&lookup.src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = key->dst_port;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 17: src_ip + src_port
  if (bitmap & (1ULL << COMBO_SRC_IP_SRC_PORT)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = 0;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 18: src_ip + src_port + protocol
  if (bitmap & (1ULL << COMBO_SRC_IP_SRC_PORT_PROTO)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = 0;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Note: Combo 19 was removed (duplicate of Combo 3: COMBO_DST_IP_PROTO)

  // Combo 20: dst_ip + dst_port + protocol
  if (bitmap & (1ULL << COMBO_DST_IP_DST_PORT_PROTO)) {
    ip_zero(&lookup.src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = key->dst_port;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 21: src_ip + dst_ip + dst_port
  if (bitmap & (1ULL << COMBO_SRC_DST_IP_DST_PORT)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = key->dst_port;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 22: src_ip + dst_ip + dst_port + protocol
  if (bitmap & (1ULL << COMBO_SRC_DST_IP_DST_PORT_PROTO)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = 0;
    lookup.dst_port = key->dst_port;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 23: src_ip + src_port + dst_port
  if (bitmap & (1ULL << COMBO_SRC_IP_PORTS)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = key->dst_port;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 24: src_ip + src_port + dst_port + protocol
  if (bitmap & (1ULL << COMBO_SRC_IP_PORTS_PROTO)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = key->dst_port;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 25: dst_ip + src_port
  if (bitmap & (1ULL << COMBO_DST_IP_SRC_PORT)) {
    ip_zero(&lookup.src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = 0;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 26: dst_ip + src_port + protocol
  if (bitmap & (1ULL << COMBO_DST_IP_SRC_PORT_PROTO)) {
    ip_zero(&lookup.src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = 0;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 27: src_port + dst_port
  if (bitmap & (1ULL << COMBO_PORTS_ONLY)) {
    ip_zero(&lookup.src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = key->dst_port;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 28: src_port + dst_port + protocol
  if (bitmap & (1ULL << COMBO_PORTS_PROTO)) {
    ip_zero(&lookup.src_ip);
    ip_zero(&lookup.dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = key->dst_port;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 29: src_ip + dst_ip + src_port
  if (bitmap & (1ULL << COMBO_SRC_DST_IP_SRC_PORT)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = 0;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 30: src_ip + dst_ip + src_port + protocol
  if (bitmap & (1ULL << COMBO_SRC_DST_IP_SRC_PORT_PROTO)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = 0;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 31: dst_ip + src_port + dst_port
  if (bitmap & (1ULL << COMBO_DST_IP_PORTS)) {
    ip_zero(&lookup.src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = key->dst_port;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 32: dst_ip + src_port + dst_port + protocol
  if (bitmap & (1ULL << COMBO_DST_IP_PORTS_PROTO)) {
    ip_zero(&lookup.src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = key->dst_port;
    lookup.protocol = key->protocol;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  // Combo 33: src_ip + dst_ip + src_port + dst_port (all except protocol)
  if (bitmap & (1ULL << COMBO_ALL_EXCEPT_PROTO)) {
    ip_copy(&lookup.src_ip, &key->src_ip);
    ip_copy(&lookup.dst_ip, &key->dst_ip);
    lookup.src_port = key->src_port;
    lookup.dst_port = key->dst_port;
    lookup.protocol = 0;
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;
    rule = BLACKLIST_LOOKUP(rule_sel, &lookup);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = lookup;
      return rule;
    }
  }

  return NULL;
}

// Helper: CIDR rule lookup with wildcard fallback (bitmap optimized)
// Uses integer IDs (from LPM trie stage) instead of IP addresses.
// Same 34-combo expansion as lookup_rule(), but with much lower instruction cost
// (simple integer assignment vs 16-byte ip_copy/ip_zero loops).
static INLINE struct rule_value *
lookup_cidr_rule(struct cidr_rule_key *key,
                 struct cidr_rule_key *matched_key, __u16 pkt_len,
                 __u8 tcp_flags, int rule_sel, __u64 slot) {

  // Fast-return if no CIDR rules exist
  __u32 cnt_idx = CONFIG_CIDR_RULE_COUNT;
  __u64 *cnt = config_lookup(slot, cnt_idx);
  if (!cnt || *cnt == 0)
    return NULL;

  // Get CIDR bitmap (always valid in double-buffer mode)
  __u32 bm_idx = CONFIG_CIDR_BITMAP;
  __u64 *bm_ptr = config_lookup(slot, bm_idx);
  __u64 bitmap = bm_ptr ? *bm_ptr : ~0ULL;

  struct rule_value *rule;
  struct cidr_rule_key k;

  // Combo 0: exact (src_id + dst_id + src_port + dst_port + protocol)
  if (bitmap & (1ULL << COMBO_EXACT_5TUPLE)) {
    k.src_id = key->src_id;
    k.dst_id = key->dst_id;
    k.src_port = key->src_port;
    k.dst_port = key->dst_port;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 1: * + dst_id + src_port + dst_port + protocol
  if (bitmap & (1ULL << COMBO_WILDCARD_SRC_IP)) {
    k.src_id = 0;
    k.dst_id = key->dst_id;
    k.src_port = key->src_port;
    k.dst_port = key->dst_port;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 2: * + dst_id + * + dst_port + protocol
  if (bitmap & (1ULL << COMBO_WILDCARD_SRC_IP_PORT)) {
    k.src_id = 0;
    k.dst_id = key->dst_id;
    k.src_port = 0;
    k.dst_port = key->dst_port;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 3: * + dst_id + * + * + protocol
  if (bitmap & (1ULL << COMBO_DST_IP_PROTO)) {
    k.src_id = 0;
    k.dst_id = key->dst_id;
    k.src_port = 0;
    k.dst_port = 0;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 4: * + dst_id + * + * + *
  if (bitmap & (1ULL << COMBO_DST_IP_ONLY)) {
    k.src_id = 0;
    k.dst_id = key->dst_id;
    k.src_port = 0;
    k.dst_port = 0;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 5: * + * + * + * + protocol
  if (bitmap & (1ULL << COMBO_PROTO_ONLY)) {
    k.src_id = 0;
    k.dst_id = 0;
    k.src_port = 0;
    k.dst_port = 0;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 6: * + * + src_port + * + *
  if (bitmap & (1ULL << COMBO_SRC_PORT_ONLY)) {
    k.src_id = 0;
    k.dst_id = 0;
    k.src_port = key->src_port;
    k.dst_port = 0;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 7: * + * + * + dst_port + *
  if (bitmap & (1ULL << COMBO_DST_PORT_ONLY)) {
    k.src_id = 0;
    k.dst_id = 0;
    k.src_port = 0;
    k.dst_port = key->dst_port;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 8: src_id + * + * + * + *
  if (bitmap & (1ULL << COMBO_SRC_IP_ONLY)) {
    k.src_id = key->src_id;
    k.dst_id = 0;
    k.src_port = 0;
    k.dst_port = 0;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 9: src_id + * + * + * + protocol
  if (bitmap & (1ULL << COMBO_SRC_IP_PROTO)) {
    k.src_id = key->src_id;
    k.dst_id = 0;
    k.src_port = 0;
    k.dst_port = 0;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 10: src_id + dst_id + * + * + *
  if (bitmap & (1ULL << COMBO_SRC_DST_IP)) {
    k.src_id = key->src_id;
    k.dst_id = key->dst_id;
    k.src_port = 0;
    k.dst_port = 0;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 11: src_id + * + * + dst_port + *
  if (bitmap & (1ULL << COMBO_SRC_IP_DST_PORT)) {
    k.src_id = key->src_id;
    k.dst_id = 0;
    k.src_port = 0;
    k.dst_port = key->dst_port;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 12: * + dst_id + * + dst_port + *
  if (bitmap & (1ULL << COMBO_DST_IP_DST_PORT)) {
    k.src_id = 0;
    k.dst_id = key->dst_id;
    k.src_port = 0;
    k.dst_port = key->dst_port;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 13: src_id + dst_id + * + * + protocol
  if (bitmap & (1ULL << COMBO_SRC_DST_IP_PROTO)) {
    k.src_id = key->src_id;
    k.dst_id = key->dst_id;
    k.src_port = 0;
    k.dst_port = 0;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 14: src_id + * + * + dst_port + protocol
  if (bitmap & (1ULL << COMBO_SRC_IP_DST_PORT_PROTO)) {
    k.src_id = key->src_id;
    k.dst_id = 0;
    k.src_port = 0;
    k.dst_port = key->dst_port;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 15: * + * + src_port + * + protocol
  if (bitmap & (1ULL << COMBO_SRC_PORT_PROTO)) {
    k.src_id = 0;
    k.dst_id = 0;
    k.src_port = key->src_port;
    k.dst_port = 0;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 16: * + * + * + dst_port + protocol
  if (bitmap & (1ULL << COMBO_DST_PORT_PROTO)) {
    k.src_id = 0;
    k.dst_id = 0;
    k.src_port = 0;
    k.dst_port = key->dst_port;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 17: src_id + * + src_port + * + *
  if (bitmap & (1ULL << COMBO_SRC_IP_SRC_PORT)) {
    k.src_id = key->src_id;
    k.dst_id = 0;
    k.src_port = key->src_port;
    k.dst_port = 0;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 18: src_id + * + src_port + * + protocol
  if (bitmap & (1ULL << COMBO_SRC_IP_SRC_PORT_PROTO)) {
    k.src_id = key->src_id;
    k.dst_id = 0;
    k.src_port = key->src_port;
    k.dst_port = 0;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Note: Combo 19 was removed (duplicate of Combo 3)

  // Combo 20: * + dst_id + * + dst_port + protocol
  if (bitmap & (1ULL << COMBO_DST_IP_DST_PORT_PROTO)) {
    k.src_id = 0;
    k.dst_id = key->dst_id;
    k.src_port = 0;
    k.dst_port = key->dst_port;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 21: src_id + dst_id + * + dst_port + *
  if (bitmap & (1ULL << COMBO_SRC_DST_IP_DST_PORT)) {
    k.src_id = key->src_id;
    k.dst_id = key->dst_id;
    k.src_port = 0;
    k.dst_port = key->dst_port;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 22: src_id + dst_id + * + dst_port + protocol
  if (bitmap & (1ULL << COMBO_SRC_DST_IP_DST_PORT_PROTO)) {
    k.src_id = key->src_id;
    k.dst_id = key->dst_id;
    k.src_port = 0;
    k.dst_port = key->dst_port;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 23: src_id + * + src_port + dst_port + *
  if (bitmap & (1ULL << COMBO_SRC_IP_PORTS)) {
    k.src_id = key->src_id;
    k.dst_id = 0;
    k.src_port = key->src_port;
    k.dst_port = key->dst_port;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 24: src_id + * + src_port + dst_port + protocol
  if (bitmap & (1ULL << COMBO_SRC_IP_PORTS_PROTO)) {
    k.src_id = key->src_id;
    k.dst_id = 0;
    k.src_port = key->src_port;
    k.dst_port = key->dst_port;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 25: * + dst_id + src_port + * + *
  if (bitmap & (1ULL << COMBO_DST_IP_SRC_PORT)) {
    k.src_id = 0;
    k.dst_id = key->dst_id;
    k.src_port = key->src_port;
    k.dst_port = 0;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 26: * + dst_id + src_port + * + protocol
  if (bitmap & (1ULL << COMBO_DST_IP_SRC_PORT_PROTO)) {
    k.src_id = 0;
    k.dst_id = key->dst_id;
    k.src_port = key->src_port;
    k.dst_port = 0;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 27: * + * + src_port + dst_port + *
  if (bitmap & (1ULL << COMBO_PORTS_ONLY)) {
    k.src_id = 0;
    k.dst_id = 0;
    k.src_port = key->src_port;
    k.dst_port = key->dst_port;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 28: * + * + src_port + dst_port + protocol
  if (bitmap & (1ULL << COMBO_PORTS_PROTO)) {
    k.src_id = 0;
    k.dst_id = 0;
    k.src_port = key->src_port;
    k.dst_port = key->dst_port;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 29: src_id + dst_id + src_port + * + *
  if (bitmap & (1ULL << COMBO_SRC_DST_IP_SRC_PORT)) {
    k.src_id = key->src_id;
    k.dst_id = key->dst_id;
    k.src_port = key->src_port;
    k.dst_port = 0;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 30: src_id + dst_id + src_port + * + protocol
  if (bitmap & (1ULL << COMBO_SRC_DST_IP_SRC_PORT_PROTO)) {
    k.src_id = key->src_id;
    k.dst_id = key->dst_id;
    k.src_port = key->src_port;
    k.dst_port = 0;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 31: * + dst_id + src_port + dst_port + *
  if (bitmap & (1ULL << COMBO_DST_IP_PORTS)) {
    k.src_id = 0;
    k.dst_id = key->dst_id;
    k.src_port = key->src_port;
    k.dst_port = key->dst_port;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 32: * + dst_id + src_port + dst_port + protocol
  if (bitmap & (1ULL << COMBO_DST_IP_PORTS_PROTO)) {
    k.src_id = 0;
    k.dst_id = key->dst_id;
    k.src_port = key->src_port;
    k.dst_port = key->dst_port;
    k.protocol = key->protocol;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  // Combo 33: src_id + dst_id + src_port + dst_port + * (all except protocol)
  if (bitmap & (1ULL << COMBO_ALL_EXCEPT_PROTO)) {
    k.src_id = key->src_id;
    k.dst_id = key->dst_id;
    k.src_port = key->src_port;
    k.dst_port = key->dst_port;
    k.protocol = 0;
    k.pad[0] = k.pad[1] = k.pad[2] = 0;
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, &k);
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags)) {
      *matched_key = k;
      return rule;
    }
  }

  return NULL;
}

// Helper: check whitelist
// No WHITELIST_COUNT gate: always do lookup to avoid window where entry exists
// but count hasn't been published yet (would cause wrongful DROP).
static INLINE int is_whitelisted(struct rule_key *key) {
  // Exact match
  if (bpf_map_lookup_elem(&whitelist, key))
    return 1;

  // src_ip only whitelist
  struct rule_key lookup = {0};
  ip_copy(&lookup.src_ip, &key->src_ip);
  if (bpf_map_lookup_elem(&whitelist, &lookup))
    return 1;

  // dst_ip only whitelist
  ip_zero(&lookup.src_ip);
  ip_copy(&lookup.dst_ip, &key->dst_ip);
  if (bpf_map_lookup_elem(&whitelist, &lookup))
    return 1;

  return 0;
}

// Helper: check if fast forward mode is enabled
static INLINE int is_fast_forward_enabled(void) {
  __u64 slot = read_active_slot();
  __u32 idx = CONFIG_FAST_FORWARD_ENABLED;
  __u64 *enabled = config_lookup(slot, idx);
  return enabled && *enabled == 1;
}

// Helper: get filter interface index (0 = filter on all interfaces)
static INLINE __u32 get_filter_ifindex(void) {
  __u64 slot = read_active_slot();
  __u32 idx = CONFIG_FILTER_IFINDEX;
  __u64 *ifindex = config_lookup(slot, idx);
  return ifindex ? (__u32)*ifindex : 0;
}

// Helper: check if current interface needs filtering
static INLINE int should_filter(__u32 ingress_ifindex) {
  __u32 filter_ifindex = get_filter_ifindex();
  // 0 means filter on both/all interfaces
  if (filter_ifindex == 0) {
    return 1;
  }
  // Check if current interface matches
  return ingress_ifindex == filter_ifindex;
}

// Helper: Get next header and offset for IPv6 extension headers
// Returns the final protocol number, updates data pointer to L4 header
static INLINE __u8 parse_ipv6_nexthdr(void *data, void *data_end, __u8 nexthdr,
                                      void **l4_data) {
// Walk through extension headers (limited iterations for BPF verifier)
#pragma unroll
  for (int i = 0; i < IPV6_EXT_MAX_DEPTH; i++) {
    // Check for known transport protocols
    if (nexthdr == PROTO_TCP || nexthdr == PROTO_UDP ||
        nexthdr == PROTO_ICMPV6) {
      *l4_data = data;
      return nexthdr;
    }

    // Handle extension headers by type
    switch (nexthdr) {
    case 0:  // Hop-by-Hop Options
    case 43: // Routing
    case 60: // Destination Options
    {
      // Extension header format: next_header(1), length(1), data(variable)
      if (data + 2 > data_end) {
        return 0;
      }
      __u8 *hdr = data;
      __u8 next = hdr[0];
      __u8 len = hdr[1];
      data += (len + 1) * 8; // Length in 8-byte units
      if (data > data_end) {
        return 0;
      }
      nexthdr = next;
      break;
    }
    case 44: // Fragment
    {
      // Fragment header: 8 bytes fixed
      if (data + 8 > data_end) {
        return 0;
      }
      __u8 *hdr = data;
      nexthdr = hdr[0];
      data += 8;
      break;
    }
    case 51: // AH (Authentication Header)
    {
      if (data + 2 > data_end) {
        return 0;
      }
      __u8 *hdr = data;
      __u8 next = hdr[0];
      __u8 len = hdr[1];
      data += (len + 2) * 4; // AH length in 4-byte units
      if (data > data_end) {
        return 0;
      }
      nexthdr = next;
      break;
    }
    case 59: // No Next Header
      *l4_data = data;
      return 0;
    default:
      // Unknown extension header or final protocol
      *l4_data = data;
      return nexthdr;
    }
  }

  *l4_data = data;
  return nexthdr;
}

// XDP program entry point
SEC("xdp")
int xdrop_firewall(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  __u32 ingress_ifindex = ctx->ingress_ifindex;

  // Increment total packets
  stats_inc(STATS_TOTAL_PACKETS);

  // Check if fast forward mode is enabled
  int fast_forward = is_fast_forward_enabled();

  // Parse Ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_ABORTED;
  }

  // Get EtherType and pointer to next header (L3)
  __u16 eth_proto = eth->h_proto;
  void *l3_data = (void *)(eth + 1);

  // Handle VLAN tags (802.1Q and QinQ)
  // Supports up to 2 layers of VLAN (outer QinQ + inner 802.1Q)
  if (eth_proto == ETH_P_8021Q_BE || eth_proto == ETH_P_8021AD_BE) {
    struct vlan_hdr *vlan = l3_data;
    if ((void *)(vlan + 1) > data_end) {
      return XDP_ABORTED;
    }
    eth_proto = vlan->h_vlan_encapsulated_proto;
    l3_data = (void *)(vlan + 1);

    // Check for second VLAN tag (QinQ case)
    if (eth_proto == ETH_P_8021Q_BE) {
      vlan = l3_data;
      if ((void *)(vlan + 1) > data_end) {
        return XDP_ABORTED;
      }
      eth_proto = vlan->h_vlan_encapsulated_proto;
      l3_data = (void *)(vlan + 1);
    }
  }

  // Fast forward mode: Non-IP traffic (ARP, LLDP, etc.) - redirect directly
  if (fast_forward && eth_proto != ETH_P_IP_BE && eth_proto != ETH_P_IPV6_BE) {
    stats_inc(STATS_PASSED_PACKETS);
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }

  // Fast forward mode: IP traffic on non-filter interface - redirect directly
  if (fast_forward && !should_filter(ingress_ifindex)) {
    stats_inc(STATS_PASSED_PACKETS);
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }

  // Initialize rule key, packet length (L3), and TCP flags
  struct rule_key key = {0};
  void *l4_data = NULL;
  __u16 pkt_len = 0;    // L3 (IP layer) packet length
  __u8 tcp_flags = 0;   // TCP flags byte (0 for non-TCP)

  // Process based on EtherType
  if (eth_proto == ETH_P_IP_BE) {
    // ===== IPv4 =====
    struct iphdr *ip = l3_data;
    if ((void *)(ip + 1) > data_end) {
      return XDP_ABORTED;
    }

    // Convert IPv4 to IPv4-mapped IPv6
    ipv4_to_mapped(&key.src_ip, ip->saddr);
    ipv4_to_mapped(&key.dst_ip, ip->daddr);
    key.protocol = ip->protocol;

    // Get L3 packet length (IPv4 total length)
    pkt_len = bpf_ntohs(ip->tot_len);

    // Parse L4 header
    l4_data = l3_data + (ip->ihl * 4);
    if (l4_data > data_end) {
      return XDP_ABORTED;
    }

  } else if (eth_proto == ETH_P_IPV6_BE) {
    // ===== IPv6 =====
    struct ip6hdr *ip6 = l3_data;
    if ((void *)(ip6 + 1) > data_end) {
      return XDP_ABORTED;
    }

    // Copy IPv6 addresses directly
    ipv6_copy(&key.src_ip, ip6->saddr);
    ipv6_copy(&key.dst_ip, ip6->daddr);

    // Get L3 packet length (IPv6 payload + 40-byte header)
    pkt_len = bpf_ntohs(ip6->payload_len) + 40;

    // Parse extension headers to find transport protocol
    void *ext_data = l3_data + sizeof(*ip6);
    key.protocol =
        parse_ipv6_nexthdr(ext_data, data_end, ip6->nexthdr, &l4_data);

    if (l4_data == NULL || l4_data > data_end) {
      // Could not find transport header - pass/redirect
      stats_inc(STATS_PASSED_PACKETS);
      if (fast_forward) {
        return bpf_redirect_map(&devmap, ingress_ifindex, 0);
      }
      return XDP_PASS;
    }

  } else {
    // Not IPv4 or IPv6 - pass/redirect (should not reach here in fast_forward)
    stats_inc(STATS_PASSED_PACKETS);
    if (fast_forward) {
      return bpf_redirect_map(&devmap, ingress_ifindex, 0);
    }
    return XDP_PASS;
  }

  // Parse L4 ports for TCP/UDP
  if (key.protocol == PROTO_TCP) {
    struct tcphdr *tcp = l4_data;
    if ((void *)(tcp + 1) > data_end) {
      return XDP_ABORTED;
    }
    key.src_port = tcp->source;
    key.dst_port = tcp->dest;
    tcp_flags = tcp->flags;
  } else if (key.protocol == PROTO_UDP) {
    struct udphdr *udp = l4_data;
    if ((void *)(udp + 1) > data_end) {
      return XDP_ABORTED;
    }
    key.src_port = udp->source;
    key.dst_port = udp->dest;
  }

  // Check whitelist first (priority)
  if (is_whitelisted(&key)) {
    stats_inc(STATS_WHITELISTED);
    stats_inc(STATS_PASSED_PACKETS);
    if (fast_forward) {
      return bpf_redirect_map(&devmap, ingress_ifindex, 0);
    }
    return XDP_PASS;
  }

  // Read rule map selector once per packet (dual rule map, Phase 4.2)
  __u64 config_slot = read_active_slot();
  int rule_sel = read_rule_map_selector(config_slot);

  // Lookup blacklist with wildcard fallback (pkt_len checked inline per combo)
  struct rule_key matched_key = {0};
  struct rule_value *rule = lookup_rule(&key, &matched_key, pkt_len, tcp_flags, rule_sel, config_slot);

  if (rule) {
    // Update match counter
    rule->match_count++;

    if (rule->action == ACTION_DROP) {
      rule->drop_count++;
      stats_inc(STATS_DROPPED_PACKETS);
      return XDP_DROP;
    }

    if (rule->action == ACTION_RATE_LIMIT && rule->rate_limit > 0) {
      // Token bucket rate limiting
      __u64 now = bpf_ktime_get_ns();
      __u64 rate_pps = rule->rate_limit;
      __u64 max_tokens = rate_pps * RATE_LIMIT_BURST_MULTIPLIER;

      struct rate_limit_state *state =
          bpf_map_lookup_elem(&rl_states, &matched_key);
      if (!state) {
        struct rate_limit_state new_state = {
            .tokens = max_tokens - 1,
            .last_update = now,
        };
        bpf_map_update_elem(&rl_states, &matched_key, &new_state, BPF_ANY);
        stats_inc(STATS_PASSED_PACKETS);
        if (fast_forward) {
          return bpf_redirect_map(&devmap, ingress_ifindex, 0);
        }
        return XDP_PASS;
      }

      __u64 elapsed_ns = now - state->last_update;
      __u64 tokens_to_add = (elapsed_ns * rate_pps) / 1000000000ULL;

      __u64 new_tokens = state->tokens + tokens_to_add;
      if (new_tokens > max_tokens) {
        new_tokens = max_tokens;
      }

      if (new_tokens >= 1) {
        state->tokens = new_tokens - 1;
        state->last_update = now;
        stats_inc(STATS_PASSED_PACKETS);
        if (fast_forward) {
          return bpf_redirect_map(&devmap, ingress_ifindex, 0);
        }
        return XDP_PASS;
      } else {
        if (tokens_to_add > 0) {
          state->last_update = now;
        }
        rule->drop_count++;
        stats_inc(STATS_RATE_LIMITED);
        stats_inc(STATS_DROPPED_PACKETS);
        return XDP_DROP;
      }
    }
  }

  // === CIDR two-stage lookup (after exact blacklist miss) ===
  // Stage 1: LPM trie lookup to convert IP → CIDR ID
  __u32 src_cidr_id = 0, dst_cidr_id = 0;

  if (eth_proto == ETH_P_IP_BE) {
    // Re-parse IPv4 header (bounds check required by BPF verifier)
    struct iphdr *cidr_ip = l3_data;
    if ((void *)(cidr_ip + 1) <= data_end) {
      struct cidr_v4_lpm_key lpm_k;
      // src lookup
      lpm_k.prefixlen = 32;
      __builtin_memcpy(lpm_k.addr, &cidr_ip->saddr, 4);
      __u32 *sid = bpf_map_lookup_elem(&sv4_cidr_trie, &lpm_k);
      if (sid)
        src_cidr_id = *sid;
      // dst lookup
      lpm_k.prefixlen = 32;
      __builtin_memcpy(lpm_k.addr, &cidr_ip->daddr, 4);
      __u32 *did = bpf_map_lookup_elem(&dv4_cidr_trie, &lpm_k);
      if (did)
        dst_cidr_id = *did;
    }
  } else if (eth_proto == ETH_P_IPV6_BE) {
    // Re-parse IPv6 header (bounds check required by BPF verifier)
    struct ip6hdr *cidr_ip6 = l3_data;
    if ((void *)(cidr_ip6 + 1) <= data_end) {
      struct cidr_v6_lpm_key lpm_k6;
      // src lookup
      lpm_k6.prefixlen = 128;
      __builtin_memcpy(lpm_k6.addr, cidr_ip6->saddr, 16);
      __u32 *sid6 = bpf_map_lookup_elem(&sv6_cidr_trie, &lpm_k6);
      if (sid6)
        src_cidr_id = *sid6;
      // dst lookup
      lpm_k6.prefixlen = 128;
      __builtin_memcpy(lpm_k6.addr, cidr_ip6->daddr, 16);
      __u32 *did6 = bpf_map_lookup_elem(&dv6_cidr_trie, &lpm_k6);
      if (did6)
        dst_cidr_id = *did6;
    }
  }

  // Stage 2: If any CIDR ID matched, do hash lookup with 34-combo expansion
  if (src_cidr_id != 0 || dst_cidr_id != 0) {
    struct cidr_rule_key ck = {
        .src_id = src_cidr_id,
        .dst_id = dst_cidr_id,
        .src_port = key.src_port,
        .dst_port = key.dst_port,
        .protocol = key.protocol,
        .pad = {0},
    };

    struct cidr_rule_key cidr_matched_key = {0};
    struct rule_value *cidr_rule =
        lookup_cidr_rule(&ck, &cidr_matched_key, pkt_len, tcp_flags, rule_sel, config_slot);

    if (cidr_rule) {
      cidr_rule->match_count++;

      if (cidr_rule->action == ACTION_DROP) {
        cidr_rule->drop_count++;
        stats_inc(STATS_DROPPED_PACKETS);
        return XDP_DROP;
      }

      if (cidr_rule->action == ACTION_RATE_LIMIT &&
          cidr_rule->rate_limit > 0) {
        __u64 now = bpf_ktime_get_ns();
        __u64 rate_pps = cidr_rule->rate_limit;
        __u64 max_tokens = rate_pps * RATE_LIMIT_BURST_MULTIPLIER;

        struct rate_limit_state *state =
            bpf_map_lookup_elem(&cidr_rl_states, &cidr_matched_key);
        if (!state) {
          struct rate_limit_state new_state = {
              .tokens = max_tokens - 1,
              .last_update = now,
          };
          bpf_map_update_elem(&cidr_rl_states, &cidr_matched_key, &new_state,
                              BPF_ANY);
          stats_inc(STATS_PASSED_PACKETS);
          if (fast_forward) {
            return bpf_redirect_map(&devmap, ingress_ifindex, 0);
          }
          return XDP_PASS;
        }

        __u64 elapsed_ns = now - state->last_update;
        __u64 tokens_to_add = (elapsed_ns * rate_pps) / 1000000000ULL;

        __u64 new_tokens = state->tokens + tokens_to_add;
        if (new_tokens > max_tokens) {
          new_tokens = max_tokens;
        }

        if (new_tokens >= 1) {
          state->tokens = new_tokens - 1;
          state->last_update = now;
          stats_inc(STATS_PASSED_PACKETS);
          if (fast_forward) {
            return bpf_redirect_map(&devmap, ingress_ifindex, 0);
          }
          return XDP_PASS;
        } else {
          if (tokens_to_add > 0) {
            state->last_update = now;
          }
          cidr_rule->drop_count++;
          stats_inc(STATS_RATE_LIMITED);
          stats_inc(STATS_DROPPED_PACKETS);
          return XDP_DROP;
        }
      }
    }
  }

  // Default: pass/redirect
  stats_inc(STATS_PASSED_PACKETS);
  if (fast_forward) {
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
