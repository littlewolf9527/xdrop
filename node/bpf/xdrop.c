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

// === v2.6.1 Phase 4 B5: tail_call infrastructure ===

// prog_tail_map — PROG_ARRAY dispatch table for tail-called XDP programs.
// D6 kernel hard constraint: key_size=4, value_size=4. Both explicitly 4 B
// (not sizeof(X) wrappers). D2 slot allocation: slot 0 = xdp_anomaly_verify,
// slots 1-15 reserved for future matchers (payload / GeoIP / TLS). All
// occupants must be BPF_PROG_TYPE_XDP (D6 constraint).
BPF_MAP_DEF(prog_tail_map) = {
    .map_type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = 4,  // D6: must be exactly 4 bytes, not sizeof()
    .value_size = 4,
    .max_entries = TAIL_SLOT_MAX,
};
BPF_MAP_ADD(prog_tail_map);

// tail_stash — per-CPU single-slot scratch used to transfer state from main
// program to tail-called program across bpf_tail_call. D1 design: one map,
// value is a wide union struct, all tail-called nodes share. Single entry
// per CPU (max_entries=1); same-CPU guarantee validated by §7.8.8 smoke
// test. RT kernels excluded (D1 RT boundary — see proposal §7.8.5).
BPF_MAP_DEF(tail_stash) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct tail_stash),
    .max_entries = 1,
};
BPF_MAP_ADD(tail_stash);

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

// v2.6 Phase 4: parse_v4_anomaly mirrors xsight.c parse_ip (IPv4 branch)
// anomaly detection verbatim. MUST match xsight/node/bpf/xsight.c lines
// 313-362 byte-for-byte so the contract fixtures stay green across repos.
//
// Preconditions:
//   - caller has already verified (ip + 1) <= data_end, so reading all
//     fixed-offset fields (ihl / tot_len / frag_off / protocol) is safe.
// Outputs:
//   - *is_frag_out : true when this packet is any fragment (MF=1 OR offset>0)
//   - return value : ANOMALY_BAD_FRAGMENT | ANOMALY_INVALID bits
//
// Control flow rules (proposal §7.1, locked against xsight.c drift):
//   - ihl<5 → invalid + early return; do NOT trust l4_hdr offset downstream
//     (caller must guard its L4 parse against this — we return anomaly only).
//   - tot_len<hdr_bytes → invalid but CONTINUE; fragment check still runs
//     with guarded payload (avoid unsigned wrap).
//   - frag_end computation is __u32 to avoid u16 overflow on near-65535 ends.
//   - tiny first-frag gate requires BOTH MF=1 AND offset=0 (not either).
static INLINE __u8 parse_v4_anomaly(struct iphdr *ip, bool *is_frag_out) {
  __u8 anom = 0;
  __u8 ihl = ip->ihl;

  // (1) IHL < 5 → invalid; caller must treat L4 offset as untrusted.
  if (ihl < 5) {
    *is_frag_out = false;
    return ANOMALY_INVALID;
  }

  __u16 hdr_bytes = (__u16)ihl * 4;
  __u16 tot_len = bpf_ntohs(ip->tot_len);

  // (2) tot_len < hdr_bytes → invalid, continue.
  if (tot_len < hdr_bytes) {
    anom |= ANOMALY_INVALID;
  }

  __u16 frag_off = bpf_ntohs(ip->frag_off);
  __u16 mf = frag_off & 0x2000;   // More Fragments
  __u16 offset13 = frag_off & 0x1fff;
  bool is_frag = mf || offset13;
  *is_frag_out = is_frag;

  if (is_frag) {
    // Guarded payload — don't let unsigned subtract wrap.
    __u16 payload = (tot_len > hdr_bytes) ? (tot_len - hdr_bytes) : 0;
    // PoD: reassembled end > 65535. 32-bit arithmetic prevents u16 wrap.
    __u32 frag_end = ((__u32)offset13 * 8) + (__u32)payload;
    if (frag_end > 65535) {
      anom |= ANOMALY_BAD_FRAGMENT;
    }
    // Tiny first fragment: first fragment must carry full L4 header.
    if (mf && offset13 == 0) {
      if (ip->protocol == PROTO_TCP && payload < 20) {
        anom |= ANOMALY_BAD_FRAGMENT;
      }
      if (ip->protocol == PROTO_UDP && payload < 8) {
        anom |= ANOMALY_BAD_FRAGMENT;
      }
    }
  }

  return anom;
}

// Helper: lookup rule with wildcard fallback (bitmap optimized)
// pkt_len and tcp_flags are checked inline: if a rule matches the 5-tuple
// but fails the length or flags constraint, lookup continues to the next
// (more wildcard) combo instead of returning NULL and silently passing.
// v2.6 Phase 4: anomaly post-match is handled OUTSIDE this function (single
// check after lookup returns) to keep verifier state space bounded —
// inlining anomaly_matches into all 33 combo checks pushed load time past
// the BPF verifier's practical limit on real kernels.
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
      *matched_key = lookup;
      return rule;
    }
  }

  return NULL;
}

// === v2.6.1 Phase 4 B5: ANOMALY-aware lookup variants ===
// lookup_rule_anomaly mirrors lookup_rule structurally (33 combos, same
// bitmap optimization) but replaces the post-match condition with:
//   `&& rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0`
// — i.e. it only returns ANOMALY rules whose bits intersect pkt_anomaly.
// Called ONLY from xdp_anomaly_verify, which has an independent 1M insn
// budget from xdp_firewall (proposal §7.8.7).
//
// D8 invariant: this function iterates ALL 33 combos and goto next_combo on
// post-match failure — fallback semantics preserved inside the anomaly
// rule subset.

static INLINE struct rule_value *lookup_rule_anomaly(struct rule_key *key,
                                             struct rule_key *matched_key,
                                             __u16 pkt_len,
                                             __u8 tcp_flags,
                                             __u8 pkt_anomaly, int rule_sel,
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly == 0) {
      *matched_key = k;
      return rule;
    }
  }

  return NULL;
}

// lookup_cidr_rule_anomaly — same relation to lookup_cidr_rule that
// lookup_rule_anomaly has to lookup_rule. 33 CIDR combos with anomaly
// post-match. Called only from xdp_anomaly_verify.

static INLINE struct rule_value *
lookup_cidr_rule_anomaly(struct cidr_rule_key *key,
                 struct cidr_rule_key *matched_key, __u16 pkt_len,
                 __u8 tcp_flags, __u8 pkt_anomaly, int rule_sel, __u64 slot) {

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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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
    if (rule && pkt_len_matches(rule, pkt_len) && tcp_flags_matches(rule, key->protocol, tcp_flags) && rule->match_anomaly != 0 && (pkt_anomaly & rule->match_anomaly) != 0) {
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

    // Parse L4 header. v2.5 behavior preserved — IHL<5 packets get garbage
    // ports but typically miss all rules. v2.6 Phase 4 anomaly detection
    // happens LAZILY in the post-lookup gate, never before the 33-combo
    // chain, to stay within the BPF verifier's 1M-insn budget.
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

  // Lookup blacklist with wildcard fallback (pkt_len / tcp_flags / anomaly
  // checked inline per combo). v2.6.1 Phase 4 B5:
  //   - The post-match condition `&& rule->match_anomaly == 0` is now
  //     inlined in every one of the 33 combos in lookup_rule (see xdrop.c
  //     combo checks). lookup_rule therefore only returns NON-anomaly
  //     rules; anomaly-specialized rules are transparently skipped and
  //     lookup continues fallback to more-wildcard combos. This preserves
  //     the D8 fallback invariant (proposal §7.8.7).
  //   - Anomaly rules are processed in a tail-called program
  //     `xdp_anomaly_verify` invoked below, only when lookup misses AND
  //     the system has anomaly rules registered. See the dispatch block
  //     after the rate-limit handling.
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

    // v2.6.1 Phase 4 B5: lookup_cidr_rule inlines `&& rule->match_anomaly == 0`
    // in each combo (same treatment as lookup_rule). Anomaly CIDR rules are
    // processed by xdp_anomaly_verify after the main lookup miss dispatch.
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

  // === v2.6.1 Phase 4 B5: anomaly dispatch on lookup miss ===
  //
  // Both exact and CIDR lookups (above) missed. If the system has at least
  // one anomaly rule registered (CONFIG_ANOMALY_RULE_COUNT > 0), tail_call
  // into xdp_anomaly_verify for an anomaly-aware re-lookup in its own 1M
  // verifier budget. If no anomaly rules exist, skip the tail_call entirely
  // — hot path (§7.8.4 scenario "no anomaly rules") stays zero-cost.
  //
  // Per D1 (proposal §7.8.5): stash main's parsed state into the per-CPU
  // tail_stash map so anomaly_verify can run its lookup without re-parsing
  // the full packet again (though it DOES still re-parse to compute
  // pkt_anomaly bits — that's its specialty).
  //
  // Per D4: static dispatch — only one tail_call site in main program,
  // targeting TAIL_SLOT_ANOMALY_VERIFY. Future payload / GeoIP slots
  // reserved but not wired in B5 (proposal §7.8.5 D4).
  //
  // Per D8: fallback invariant is preserved because lookup_rule already
  // iterated all 33 non-anomaly combos; anomaly_verify will iterate all
  // 33 anomaly combos independently.
  __u64 *anomaly_count_ptr = config_lookup(config_slot, CONFIG_ANOMALY_RULE_COUNT);
  if (anomaly_count_ptr && *anomaly_count_ptr > 0) {
    __u32 stash_zero = 0;
    struct tail_stash stash = {
        .stage = 0,
        .action = 0,
        .match_anomaly = 0,
        .pkt_len = pkt_len,
        .tcp_flags = tcp_flags,
        .eth_proto_is_v6 = (eth_proto == ETH_P_IPV6_BE) ? 1 : 0,
        // v2.6.1 FF regression fix: stash FF state so anomaly_verify can
        // redirect without re-reading config/ctx (verifier insn budget).
        .is_ff = fast_forward ? 1 : 0,
        .ingress_ifindex = ingress_ifindex,
        .key = key,
    };
    bpf_map_update_elem(&tail_stash, &stash_zero, &stash, 0 /* BPF_ANY */);
    bpf_tail_call(ctx, &prog_tail_map, TAIL_SLOT_ANOMALY_VERIFY);
    // Fallthrough: tail_call failed (prog_array slot empty, callee missing,
    // verifier constraint). Safe default: PASS, same as "no anomaly rule"
    // branch. Ops will see anomaly rules as inactive; config counter >0
    // while tail_call consistently fallthrough-s signals loader bug.
  }

  // Default: pass/redirect
  stats_inc(STATS_PASSED_PACKETS);
  if (fast_forward) {
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }
  return XDP_PASS;
}

// ============================================================================
// v2.6.1 Phase 4 B5 — xdp_anomaly_verify: tail-called program
// ============================================================================
//
// Invoked by xdp_firewall via `bpf_tail_call(ctx, &prog_tail_map,
// TAIL_SLOT_ANOMALY_VERIFY)` when:
//   1. Main program lookup_rule / lookup_cidr_rule both missed (no
//      match_anomaly=0 rule matches this packet).
//   2. CONFIG_ANOMALY_RULE_COUNT > 0 (system has at least one anomaly rule).
//
// Responsibilities:
//   1. Read saved state (key, pkt_len, tcp_flags, eth_proto hint) from
//      per-CPU tail_stash.
//   2. Re-parse packet headers to compute pkt_anomaly bits. The main
//      program already parsed the packet but cannot pass parse results
//      across bpf_tail_call except via the stash (D1).
//   3. Run anomaly-aware 33-combo lookup (lookup_rule_anomaly +
//      lookup_cidr_rule_anomaly) filtered by pkt_anomaly intersection.
//   4. If matched: execute action (DROP or rate_limit). On rate_limit,
//      use a fresh reference to the rule (re-lookup by matched_key) —
//      rule pointers from the anomaly-aware lookup already point at the
//      map value, fine to increment counters directly.
//   5. If not matched: XDP_PASS.
//
// D8 fallback invariant: this program's lookup_rule_anomaly iterates ALL
// 33 combos and continues on post-match failure. Fallback is preserved
// within the ANOMALY rule subset.
//
// D7 stack budget: keep ≤ 256 B. All helper calls are __always_inline.
//
// Performance note (§7.8.4): this program runs only on main lookup miss
// with anomaly_rule_count > 0. Typical DDoS mitigation cold path.
SEC("xdp")
int xdp_anomaly_verify(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  // FF state is pulled from the stash (main resolved it once and wrote it
  // before tail_call). Doing config_lookup() again here would re-explode the
  // verifier's insn budget: in the v2.6.1 FF regression fix attempt, adding
  // a second config-map null check at the top pushed xdp_anomaly_verify past
  // 1M insns on 6.12. Keeping FF state on the stash avoids that.
  //
  // B5 v2.6.1 initial release missed the FF branch entirely because D8 ran
  // in traditional mode. Symptom: FF bridge dropped all non-anomaly traffic
  // once any anomaly rule was registered (every miss in main → tail_call →
  // anomaly_verify XDP_PASS → Linux stack on a no-IP interface).
  __u8 fast_forward = 0;
  __u32 ingress_ifindex = 0;

  // Read stashed state (main program wrote this before tail_call).
  __u32 zero = 0;
  struct tail_stash *st = bpf_map_lookup_elem(&tail_stash, &zero);
  if (!st) {
    // Stash unavailable (should never happen). Without FF context we cannot
    // safely redirect — fall back to XDP_PASS. Under a compliant main
    // program this branch is unreachable.
    return XDP_PASS;
  }
  fast_forward = st->is_ff;
  ingress_ifindex = st->ingress_ifindex;

  // Parse ethernet + vlan again (tail_call scrubs stack).
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_ABORTED;
  }
  __u16 eth_proto = eth->h_proto;
  void *l3_data = (void *)(eth + 1);
  if (eth_proto == ETH_P_8021Q_BE || eth_proto == ETH_P_8021AD_BE) {
    struct vlan_hdr *vlan = l3_data;
    if ((void *)(vlan + 1) > data_end) {
      return XDP_ABORTED;
    }
    eth_proto = vlan->h_vlan_encapsulated_proto;
    l3_data = (void *)(vlan + 1);
    if (eth_proto == ETH_P_8021Q_BE) {
      vlan = l3_data;
      if ((void *)(vlan + 1) > data_end) {
        return XDP_ABORTED;
      }
      eth_proto = vlan->h_vlan_encapsulated_proto;
      l3_data = (void *)(vlan + 1);
    }
  }

  // Compute pkt_anomaly.
  __u8 pkt_anomaly = 0;
  if (eth_proto == ETH_P_IP_BE) {
    struct iphdr *ip = l3_data;
    if ((void *)(ip + 1) > data_end) {
      return XDP_ABORTED;
    }
    bool is_frag = false;
    pkt_anomaly = parse_v4_anomaly(ip, &is_frag);
    // TCP doff check — only when L4 header is safely reachable.
    if (ip->ihl >= 5 && !is_frag && ip->protocol == PROTO_TCP) {
      void *l4 = l3_data + (ip->ihl * 4);
      if (l4 + 14 <= data_end) {
        __u8 doff = ((struct tcphdr *)l4)->doff_res >> 4;
        if (doff < 5) {
          pkt_anomaly |= ANOMALY_INVALID;
        }
      }
    }
  } else if (eth_proto == ETH_P_IPV6_BE) {
    // IPv6 scope (proposal §7.4.1 / codex round 9 P1.2 fix):
    //   - bad_fragment: NOT detected on IPv6 (extension header walking for
    //     fragment detection stays deferred; Controller's IPv6 scope guard
    //     in decoder.go rejects bad_fragment+v6 targets up front).
    //   - invalid: fires ONLY on DIRECT TCP doff<5 — i.e. ip6->nexthdr is
    //     literally PROTO_TCP, no extension header in between. This matches
    //     xsight.c parse_ip IPv6 branch contract: `if (nexthdr == TCP)` only,
    //     no walker. Proposal §13.4.1 P4-UT-15b and §14 LT-D-4-11b explicitly
    //     lock this as a contract — an HBH/Routing/Fragment ext header before
    //     TCP must NOT trigger invalid, even with doff<5. If a future revision
    //     wants to walk ext headers for invalid detection, that's an opt-in
    //     contract change and these two locks must move first.
    struct ip6hdr *ip6 = l3_data;
    if ((void *)(ip6 + 1) > data_end) {
      return XDP_ABORTED;
    }
    if (ip6->nexthdr == PROTO_TCP) {
      void *v6_l4 = l3_data + sizeof(*ip6);
      // TCP header is 20 bytes fixed; doff lives in byte 12. Require enough
      // bytes bounded before reading.
      if (v6_l4 + 14 <= data_end) {
        __u8 doff = ((struct tcphdr *)v6_l4)->doff_res >> 4;
        if (doff < 5) {
          pkt_anomaly |= ANOMALY_INVALID;
        }
      }
    }
  }

  if (pkt_anomaly == 0) {
    // Packet carries no anomaly bits — no anomaly rule can match. Fast exit
    // via the unified pass_or_redirect sink (FF mode redirects, traditional
    // mode XDP_PASS).
    goto pass_or_redirect;
  }

  // Read active slot / rule_sel (same as main program).
  __u64 config_slot = read_active_slot();
  int rule_sel = read_rule_map_selector(config_slot);

  // Anomaly-aware lookup 1: exact 33-combo (lookup_rule_anomaly).
  struct rule_key matched_key = {0};
  struct rule_value *rule = lookup_rule_anomaly(
      &st->key, &matched_key, st->pkt_len, st->tcp_flags, pkt_anomaly,
      rule_sel, config_slot);

  if (rule) {
    rule->match_count++;
    if (rule->action == ACTION_DROP) {
      rule->drop_count++;
      stats_inc(STATS_DROPPED_PACKETS);
      return XDP_DROP;
    }
    if (rule->action == ACTION_RATE_LIMIT && rule->rate_limit > 0) {
      // Safety net: Controller (normalizeDecoder P1.1 guard in decoder.go)
      // rejects rate_limit on anomaly rules in v2.6.1, so under a compliant
      // control plane this branch is unreachable. We keep the XDP_DROP
      // fallback so that a downgraded / rogue / stale Controller (or
      // manually edited SQLite DB) cannot leak a silently-enforced rule
      // that bypasses cross-program rate_limit coordination. If you need
      // real anomaly-side rate limiting, land cross-program token-bucket
      // first, then relax both this comment and the Controller guard.
      rule->drop_count++;
      stats_inc(STATS_DROPPED_PACKETS);
      return XDP_DROP;
    }
  }

  // Anomaly-aware lookup 2: CIDR (lookup_cidr_rule_anomaly).
  // Re-derive src/dst CIDR IDs from LPM tries (same as main xdrop_firewall did).
  __u32 src_cidr_id = 0, dst_cidr_id = 0;
  if (eth_proto == ETH_P_IP_BE) {
    struct iphdr *cidr_ip = l3_data;
    if ((void *)(cidr_ip + 1) <= data_end) {
      struct cidr_v4_lpm_key lpm_k;
      lpm_k.prefixlen = 32;
      __builtin_memcpy(lpm_k.addr, &cidr_ip->saddr, 4);
      __u32 *sid = bpf_map_lookup_elem(&sv4_cidr_trie, &lpm_k);
      if (sid) src_cidr_id = *sid;
      lpm_k.prefixlen = 32;
      __builtin_memcpy(lpm_k.addr, &cidr_ip->daddr, 4);
      __u32 *did = bpf_map_lookup_elem(&dv4_cidr_trie, &lpm_k);
      if (did) dst_cidr_id = *did;
    }
  } else if (eth_proto == ETH_P_IPV6_BE) {
    struct ip6hdr *cidr_ip6 = l3_data;
    if ((void *)(cidr_ip6 + 1) <= data_end) {
      struct cidr_v6_lpm_key lpm_k6;
      lpm_k6.prefixlen = 128;
      __builtin_memcpy(lpm_k6.addr, cidr_ip6->saddr, 16);
      __u32 *sid6 = bpf_map_lookup_elem(&sv6_cidr_trie, &lpm_k6);
      if (sid6) src_cidr_id = *sid6;
      lpm_k6.prefixlen = 128;
      __builtin_memcpy(lpm_k6.addr, cidr_ip6->daddr, 16);
      __u32 *did6 = bpf_map_lookup_elem(&dv6_cidr_trie, &lpm_k6);
      if (did6) dst_cidr_id = *did6;
    }
  }

  if (src_cidr_id != 0 || dst_cidr_id != 0) {
    struct cidr_rule_key ck = {
        .src_id = src_cidr_id,
        .dst_id = dst_cidr_id,
        .src_port = st->key.src_port,
        .dst_port = st->key.dst_port,
        .protocol = st->key.protocol,
    };
    struct cidr_rule_key cidr_matched_key = {0};
    struct rule_value *cidr_rule = lookup_cidr_rule_anomaly(
        &ck, &cidr_matched_key, st->pkt_len, st->tcp_flags, pkt_anomaly,
        rule_sel, config_slot);
    if (cidr_rule) {
      cidr_rule->match_count++;
      if (cidr_rule->action == ACTION_DROP) {
        cidr_rule->drop_count++;
        stats_inc(STATS_DROPPED_PACKETS);
        return XDP_DROP;
      }
      if (cidr_rule->action == ACTION_RATE_LIMIT && cidr_rule->rate_limit > 0) {
        // Safety net — see exact-match branch above. Controller rejects
        // rate_limit on anomaly rules (codex round 9 P1.1); reaching here
        // means stale state. Fall through as DROP.
        cidr_rule->drop_count++;
        stats_inc(STATS_DROPPED_PACKETS);
        return XDP_DROP;
      }
    }
  }

  // No anomaly rule matched — funnel through the unified sink.
pass_or_redirect:
  stats_inc(STATS_PASSED_PACKETS);
  if (fast_forward) {
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
