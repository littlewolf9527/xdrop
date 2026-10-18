#define B1_LOOKUP_GENERATION 54
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
#include "combo_masks.h"

// Numeric open-coded iterator kfuncs (Linux >= 6.4).  These declarations
// deliberately stay local to xdrop_main.c: xdrop_gate.c remains outside M1.
struct bpf_iter_num {
  __u64 __opaque[1];
};

extern int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end)
    __attribute__((section(".ksyms")));
extern int *bpf_iter_num_next(struct bpf_iter_num *it)
    __attribute__((section(".ksyms")));
extern void bpf_iter_num_destroy(struct bpf_iter_num *it)
    __attribute__((section(".ksyms")));

_Static_assert(sizeof(combo_field_mask) == COMBO_TABLE_SLOTS,
               "mask table must span the full __u8 index range, not just COMBO_MAX");

// Blacklist Map - Five-tuple hash map
BPF_MAP_DEF(blacklist) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(struct rule_value),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(blacklist);

// B1 condition rows follow the same rule_sel as their referencing rules.
BPF_MAP_DEF(cond_a) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(struct cond_value),
    .max_entries = MAX_RULES,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(cond_a);

BPF_MAP_DEF(cond_b) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(struct cond_value),
    .max_entries = MAX_RULES,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(cond_b);

BPF_MAP_DEF(cidr_cond_a) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct cidr_rule_key),
    .value_size = sizeof(struct cond_value),
    .max_entries = MAX_RULES,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(cidr_cond_a);

BPF_MAP_DEF(cidr_cond_b) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct cidr_rule_key),
    .value_size = sizeof(struct cond_value),
    .max_entries = MAX_RULES,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(cidr_cond_b);

// Shared by exact and CIDR candidates, including physical splits of one rule.
BPF_MAP_DEF(id_counts) = {
    .map_type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct logical_rule_counters),
    .max_entries = 2 * MAX_RULES,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(id_counts);

BPF_MAP_DEF(hot_ids) = {
    .map_type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 16384,
    .map_flags = 0,
};
BPF_MAP_ADD(hot_ids);

BPF_MAP_DEF(id_rl_states) = {
    .map_type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct rate_limit_state),
    .max_entries = 2 * MAX_RULES,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(id_rl_states);

// A flagged rule without its condition row falls back and records a diagnostic.
BPF_MAP_DEF(cond_row_missing) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(cond_row_missing);


static INLINE struct logical_rule_counters *count_logical_match(__u32 *id, __u64 bytes) {
  struct logical_rule_counters *counter = bpf_map_lookup_elem(&id_counts, id);
  if (!counter) {
    struct logical_rule_counters zero = {0};
    bpf_map_update_elem(&id_counts, id, &zero, BPF_NOEXIST);
    counter = bpf_map_lookup_elem(&id_counts, id);
  }
  // Counter allocation failure loses accounting only, never the decision.
  if (counter) {
    counter->match++;
    counter->match_bytes += bytes;
    __u64 now = bpf_ktime_get_coarse_ns();
    if (counter->last_hit_ns != now) {
      counter->last_hit_ns = now;
      __u64 *v = bpf_map_lookup_elem(&hot_ids, id);
      if (v) {
        if (*v != now) *v = now;
      } else {
        bpf_map_update_elem(&hot_ids, id, &counter->last_hit_ns, BPF_NOEXIST);
      }
    }
  }
  return counter;
}

// Whitelist Map - shared map, mainColl creates, gate references via MapReplacements.
// xdp_firewall_main does NOT reference this map in program logic; it exists here
// solely so mainColl.Maps["whitelist"] is available for gate's MapReplacements.
BPF_MAP_DEF(whitelist) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(__u8),
    .max_entries = MAX_WHITELIST,
};
BPF_MAP_ADD(whitelist);

// Verifier prune map - private to xdp_firewall_main, NEVER written by control plane.
// Provides verifier early-return pruning point to keep xdp_firewall_main within
// the 1M instruction budget. max_entries=1 (intentionally tiny, stores no real data).
// PinNone in Go loader — must not appear in handlers/CRUD/sync/clear/reconcile.
// WARNING: prune_hit is a real XDP_PASS branch. Any write to this map would bypass
// blacklist/CIDR/rate/anomaly checks (over-allow). T51 verifies it stays empty.
BPF_MAP_DEF(verifier_prune_map) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(__u8),
    .max_entries = 1,
};
BPF_MAP_ADD(verifier_prune_map);

// Global statistics (PERCPU for high-performance counters)
BPF_MAP_DEF(stats) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 9,
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

BPF_MAP_DEF(sv4_cidr_trie_b) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v4_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(sv4_cidr_trie_b);

// IPv4 LPM Trie: dst IP → CIDR ID
BPF_MAP_DEF(dv4_cidr_trie) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v4_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(dv4_cidr_trie);

BPF_MAP_DEF(dv4_cidr_trie_b) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v4_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(dv4_cidr_trie_b);

// IPv6 LPM Trie: src IP → CIDR ID
BPF_MAP_DEF(sv6_cidr_trie) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v6_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(sv6_cidr_trie);

BPF_MAP_DEF(sv6_cidr_trie_b) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v6_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(sv6_cidr_trie_b);

// IPv6 LPM Trie: dst IP → CIDR ID
BPF_MAP_DEF(dv6_cidr_trie) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v6_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(dv6_cidr_trie);

BPF_MAP_DEF(dv6_cidr_trie_b) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct cidr_v6_lpm_key),
    .value_size = sizeof(__u32),
    .max_entries = 50000,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(dv6_cidr_trie_b);

// CIDR blacklist hash map (key uses integer IDs, not IP addresses)
BPF_MAP_DEF(cidr_blacklist) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct cidr_rule_key),
    .value_size = sizeof(struct rule_value),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(cidr_blacklist);

// CIDR rate limit state map

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
    .map_type = BPF_MAP_TYPE_DEVMAP_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 16,
};
BPF_MAP_ADD(devmap);

// === v2.6.1 Phase 4 B5: tail_call infrastructure ===

// prog_tail_map — PROG_ARRAY dispatch table for tail-called XDP programs.
// D6 kernel hard constraint: key_size=4, value_size=4. Both explicitly 4 B
// (not sizeof(X) wrappers). Slot 0 is retired and cleared by the agent at
// startup; do not reuse. All occupants must be BPF_PROG_TYPE_XDP (D6 constraint).
BPF_MAP_DEF(prog_tail_map) = {
    .map_type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = 4,  // D6: must be exactly 4 bytes, not sizeof()
    .value_size = 4,
    .max_entries = TAIL_SLOT_MAX,
};
BPF_MAP_ADD(prog_tail_map);

// Helper: increment stats counter
static INLINE void stats_inc(__u32 idx) {
  __u64 *counter = bpf_map_lookup_elem(&stats, &idx);
  if (counter) {
    (*counter)++;
  }
}
static INLINE void stats_add(__u32 idx, __u64 bytes) {
  __u64 *counter = bpf_map_lookup_elem(&stats, &idx);
  if (counter)
    *counter += bytes;
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

// Prefix and rule lookups share the packet's single rule selector snapshot.
#define CIDR_TRIE_LOOKUP(rule_sel, trie, key_ptr)             \
    ((rule_sel) == 0                                         \
        ? bpf_map_lookup_elem(&(trie), (key_ptr))             \
        : bpf_map_lookup_elem(&trie##_b, (key_ptr)))

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

// TD-074: constants stay local; bucket layout and timestamp units are unchanged.
#define RL_MAX_DIVISOR 4096ULL
#define RL_NS 1000000000ULL

static INLINE __u64 rate_limit_divisor(__u64 slot) {
  __u32 idx = CONFIG_RL_CPU_DIVISOR;
  __u64 divisor = RL_DIVISOR_FALLBACK;
  __u64 *configured = config_lookup(slot, idx);
  if (configured) {
    __u64 value = *configured;
    if (value > 0) {
      divisor = value;
    }
  }
  return divisor > RL_MAX_DIVISOR ? RL_MAX_DIVISOR : divisor;
}

static INLINE __u64 rate_limit_capacity(__u64 rate, __u64 divisor) {
  return (2ULL * rate + divisor - 1) / divisor;
}

// Pure arithmetic, PLAN ③-2 steps 0–6. The caller owns maps and accounting.
// Overflow bounds: C*d < 2R+d; cap_ns*R < C*d*NS+R;
// add*d*NS <= elapsed*R. R < 2^32 and d <= 4096 imply every product
// is < (3R+d)*NS < 1.3e19 < 2^64. Clamp persistent tokens BEFORE adding.
static INLINE int rate_limit_take(struct rate_limit_state *state, __u64 now,
                                  __u64 rate, __u64 divisor) {
  __u64 capacity = rate_limit_capacity(rate, divisor);
  if (state->last_update == 0) {
    state->tokens = capacity - 1;
    state->last_update = now;
    return 1;
  }
  // 0: future timestamps must not wrap into the new-bucket sentinel.
  if (state->last_update > now) {
    state->last_update = now;
  }
  // 1: normalize an old bucket before tokens + add.
  __u64 tokens = state->tokens;
  if (tokens > capacity) {
    tokens = capacity;
  }
  // 2: fractional low rates may need much more than two seconds.
  __u64 elapsed = now - state->last_update;
  __u64 cap_ns = (capacity * divisor * RL_NS + rate - 1) / rate;
  if (elapsed > cap_ns) {
    elapsed = cap_ns;
  }
  // 3: retain the fractional rate until the final division.
  __u64 add = elapsed * rate / (divisor * RL_NS);
  // 4: cap after replenishment as well as before it.
  __u64 t = tokens + add;
  if (t > capacity) {
    t = capacity;
  }
  // 5: full stops timing; otherwise exchange only rounded-up consumed time.
  if (t == capacity) {
    state->last_update = now;
  } else if (add > 0) {
    state->last_update += (add * divisor * RL_NS + rate - 1) / rate;
  }
  // 6: consume, retaining the time remainder on add-zero passes.
  int allowed = t >= 1;
  state->tokens = allowed ? t - 1 : t;
  return allowed;
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

// Return an all-zero or all-one machine word using arithmetic only.  BPF has
// no conditional-move instruction, so a conditional expression would put a
// branch back into every field selection in every iterator trip.
#define COMBO_WORD_MASK(combo, field_bit)                                     \
  (-(((__u64)combo_field_mask[(combo)] >> (field_bit)) & 1ULL))

// Both builders overwrite the caller-owned matched_key in full.  Keeping the
// candidate out of these subprograms' stack is required by the 512-byte
// combined-call-chain limit.
static INLINE void build_rule_key(struct rule_key *matched_key,
                                  const struct rule_key *key, __u32 combo) {
  __u64 *kw = (__u64 *)matched_key;
  const __u64 *pk = (const __u64 *)key;

  kw[0] = pk[0] & COMBO_WORD_MASK(combo, 0);
  kw[1] = pk[1] & COMBO_WORD_MASK(combo, 0);
  kw[2] = pk[2] & COMBO_WORD_MASK(combo, 1);
  kw[3] = pk[3] & COMBO_WORD_MASK(combo, 1);
  kw[4] = pk[4] &
          ((COMBO_WORD_MASK(combo, 2) & 0x000000000000FFFFULL) |
           (COMBO_WORD_MASK(combo, 3) & 0x00000000FFFF0000ULL) |
           (COMBO_WORD_MASK(combo, 4) & 0x000000FF00000000ULL));
}

static INLINE void build_cidr_rule_key(struct cidr_rule_key *matched_key,
                                       const struct cidr_rule_key *key,
                                       __u32 combo) {
  __u64 *kw = (__u64 *)matched_key;
  const __u64 *pk = (const __u64 *)key;

  kw[0] = pk[0] &
          ((COMBO_WORD_MASK(combo, 0) & 0x00000000FFFFFFFFULL) |
           (COMBO_WORD_MASK(combo, 1) & 0xFFFFFFFF00000000ULL));
  kw[1] = pk[1] &
          ((COMBO_WORD_MASK(combo, 2) & 0x000000000000FFFFULL) |
           (COMBO_WORD_MASK(combo, 3) & 0x00000000FFFF0000ULL) |
           (COMBO_WORD_MASK(combo, 4) & 0x000000FF00000000ULL));
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
// __noinline: shared by all four combo iterators to bound verifier state growth.
static __attribute__((noinline)) int pkt_len_matches(struct rule_value *rule, __u16 pkt_len) {
  if (rule->pkt_len_min > 0 && pkt_len < rule->pkt_len_min)
    return 0;
  if (rule->pkt_len_max > 0 && pkt_len > rule->pkt_len_max)
    return 0;
  return 1;
}

// Helper: check if TCP flags match rule constraints
// Returns 1 if matches (or no flags check), 0 if mismatch
// __noinline: shared by all four combo iterators to bound verifier state growth.
static __attribute__((noinline)) int tcp_flags_matches(struct rule_value *rule, __u8 proto, __u8 tcp_flags, __u8 l4_valid) {
  if (rule->tcp_flags_mask == 0)
    return 1;  // no flags filter on this rule
  if (proto != PROTO_TCP)
    return 1;  // flags only apply to TCP
  if (!l4_valid)
    return 0;
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

// F-125 shape: preserve the runtime value while hiding its range from callers.
__attribute__((noinline)) int xdrop_launder(int x) {
  asm volatile("" : "+r"(x));
  return x;
}

// Parsed packet attributes shared by the four lookup interfaces.
struct pkt_attrs {
  __u16 pkt_len;
  __u8 tcp_flags;
  __u8 pkt_anomaly;
  __u8 ttl;
  __u8 dscp;
  __u8 icmp_type;
  __u8 icmp_code;
  __u8 frag_class;
  __u8 icmp_valid;
  __u8 l4_valid;
  __u8 pad[1];
  struct cond_output out;
};
_Static_assert(sizeof(struct pkt_attrs) == 24, "pkt_attrs ABI");
_Static_assert(__builtin_offsetof(struct pkt_attrs, l4_valid) == 10, "pkt_attrs.l4_valid ABI");
_Static_assert(__builtin_offsetof(struct pkt_attrs, out) == 12, "pkt_attrs.out ABI");
_Static_assert(sizeof(((struct pkt_attrs *)0)->pkt_len) == 2, "pkt_len must stay 16-bit");
_Static_assert(sizeof(((struct pkt_attrs *)0)->tcp_flags) == 1, "tcp_flags must stay 8-bit");
_Static_assert(sizeof(((struct pkt_attrs *)0)->pkt_anomaly) == 1, "pkt_anomaly must stay 8-bit");

// Each byte packs the vectors for two successive attribute values.
#define COND_VEC(tab, x) (((tab)[((__u32)(x) & 255) >> 1] >> (((x) & 1) * 4)) & 15)
#define COND_LOOKUP(sel, k) ((sel) == 0 ? bpf_map_lookup_elem(&cond_a, (k)) : bpf_map_lookup_elem(&cond_b, (k)))
#define CIDR_COND_LOOKUP(sel, k) ((sel) == 0 ? bpf_map_lookup_elem(&cidr_cond_a, (k)) : bpf_map_lookup_elem(&cidr_cond_b, (k)))

// F-125's branchless closed-interval comparison, including empty intervals.
static INLINE __u64 cond_span_matches(__u16 x, __u16 lo, __u16 hi) {
  long long d = (long long)x - lo, w = (long long)hi - lo;
  return (~(__u64)(d | (w - d)) >> 63) & 1;
}

// Global BTF memory arguments are checked here. The caller initializes every
// attrs byte. Outputs are taken from this one row, at constant candidate indices;
// the caller never uses this function's unknown-scalar return to index a row.
__attribute__((noinline)) int cond_match(const struct cond_value *c, struct pkt_attrs *a) {
  if (!c || !a)
    return -1;
  __u32 v = c->active & 15;
  v &= COND_VEC(c->tab[0], a->ttl);
  v &= COND_VEC(c->tab[1], a->dscp);
  v &= COND_VEC(c->tab[2], a->tcp_flags);
  v &= COND_VEC(c->tab[3], a->icmp_type);
  v &= COND_VEC(c->tab[4], a->icmp_code);
  v &= COND_VEC(c->tab[5], a->pkt_anomaly);
  __u32 z = a->frag_class & 7;
  v &= (c->frag[z >> 1] >> ((z & 1) * 4)) & 15;
  if (!a->icmp_valid)
    v &= ~c->icmp_req;
  if (!a->l4_valid) v &= ~c->tcp_req;
  __u16 len = a->pkt_len;
  if ((v & (1U << 0)) &&
      (cond_span_matches(len, c->len[0][0].lo, c->len[0][0].hi) |
       cond_span_matches(len, c->len[0][1].lo, c->len[0][1].hi))) {
    a->out.winner = 0;
    a->out.action = c->action[0];
    a->out.rate = c->rate[0];
    a->out.rule_id = c->rule_id[0];
    return 0;
  }
  if ((v & (1U << 1)) &&
      (cond_span_matches(len, c->len[1][0].lo, c->len[1][0].hi) |
       cond_span_matches(len, c->len[1][1].lo, c->len[1][1].hi))) {
    a->out.winner = 1;
    a->out.action = c->action[1];
    a->out.rate = c->rate[1];
    a->out.rule_id = c->rule_id[1];
    return 1;
  }
  if ((v & (1U << 2)) &&
      (cond_span_matches(len, c->len[2][0].lo, c->len[2][0].hi) |
       cond_span_matches(len, c->len[2][1].lo, c->len[2][1].hi))) {
    a->out.winner = 2;
    a->out.action = c->action[2];
    a->out.rate = c->rate[2];
    a->out.rule_id = c->rule_id[2];
    return 2;
  }
  if ((v & (1U << 3)) &&
      (cond_span_matches(len, c->len[3][0].lo, c->len[3][0].hi) |
       cond_span_matches(len, c->len[3][1].lo, c->len[3][1].hi))) {
    a->out.winner = 3;
    a->out.action = c->action[3];
    a->out.rate = c->rate[3];
    a->out.rule_id = c->rule_id[3];
    return 3;
  }
  return -1;
}

// Helper: lookup rule with wildcard fallback (bitmap optimized)
// pkt_len and tcp_flags are checked inline: if a rule matches the 5-tuple
// but fails the length or flags constraint, lookup continues to the next
// (more wildcard) combo instead of returning NULL and silently passing.
// The non-anomaly post-match predicate stays inside the iterator so a failed
// candidate continues to the next, more-wildcard combo.
static __attribute__((noinline)) struct rule_value *lookup_rule(struct rule_key *key,
                                             struct rule_key *matched_key,
                                             struct pkt_attrs *attrs,
                                             int rule_sel,
                                             __u64 slot) {
  __u16 pkt_len = attrs->pkt_len;
  __u8 tcp_flags = attrs->tcp_flags;

  // Phase 1: Fast-return if no blacklist rules exist
  __u32 bl_count_idx = CONFIG_BLACKLIST_COUNT;
  __u64 *bl_count = config_lookup(slot, bl_count_idx);
  if (!bl_count || *bl_count == 0) {
    return NULL;
  }

  // Phase 2: Get rule bitmap for combo-level skip optimization.
  __u32 bitmap_idx = CONFIG_RULE_BITMAP;
  __u64 *bitmap_ptr = config_lookup(slot, bitmap_idx);
  __u64 bitmap = bitmap_ptr ? *bitmap_ptr : ~0ULL;
  // Filter even the ~0ULL fallback through the generator-owned roster bitmap,
  // so no mask-table hole can construct a five-field wildcard candidate.
  bitmap &= COMBO_VALID_BITMAP;

  struct rule_value *rule = NULL;
  struct bpf_iter_num iter;
  int *pos;

  bpf_iter_num_new(&iter, 0, COMBO_ORDER_LEN);
  while ((pos = bpf_iter_num_next(&iter))) {
    __u32 i = (__u32)*pos;
    if (i >= COMBO_ORDER_LEN)
      break;
    __u32 b = combo_order[i];
    if (b >= COMBO_MAX)
      break;
    if (!(bitmap & (1ULL << b)))
      continue;

    build_rule_key(matched_key, key, b);
    rule = BLACKLIST_LOOKUP(rule_sel, matched_key);
    // B1: a missing condition row is a miss, so D8 keeps looking.
    if (rule && (rule->pad2[0] & RULE_HAS_CONDITIONS)) {
      const struct cond_value *cv = COND_LOOKUP(rule_sel, matched_key);
      if (!cv) {
        __u32 zero = 0;
        __u64 *missing = bpf_map_lookup_elem(&cond_row_missing, &zero);
        if (missing)
          (*missing)++;
      }
      if (cv && cond_match(cv, attrs) >= 0)
        break;
      rule = NULL;
      continue;
    }
    if (rule && pkt_len_matches(rule, pkt_len) &&
        tcp_flags_matches(rule, key->protocol, tcp_flags, attrs->l4_valid) &&
        rule->match_anomaly == 0)
      break;
    rule = NULL;
  }
  bpf_iter_num_destroy(&iter);
  return rule;
}

// Helper: CIDR rule lookup with wildcard fallback (bitmap optimized)
// Uses integer IDs (from LPM trie stage) instead of IP addresses.
// Same 34-slot/33-present ordered mask table as lookup_rule().
static __attribute__((noinline)) struct rule_value *
lookup_cidr_rule(struct cidr_rule_key *key,
                 struct cidr_rule_key *matched_key, struct pkt_attrs *attrs,
                 int rule_sel, __u64 slot) {
  __u16 pkt_len = attrs->pkt_len;
  __u8 tcp_flags = attrs->tcp_flags;

  // Fast-return if no CIDR rules exist
  __u32 cnt_idx = CONFIG_CIDR_RULE_COUNT;
  __u64 *cnt = config_lookup(slot, cnt_idx);
  if (!cnt || *cnt == 0)
    return NULL;

  // Get CIDR bitmap (always valid in double-buffer mode).
  __u32 bm_idx = CONFIG_CIDR_BITMAP;
  __u64 *bm_ptr = config_lookup(slot, bm_idx);
  __u64 bitmap = bm_ptr ? *bm_ptr : ~0ULL;
  bitmap &= COMBO_VALID_BITMAP;

  struct rule_value *rule = NULL;
  struct bpf_iter_num iter;
  int *pos;

  bpf_iter_num_new(&iter, 0, COMBO_ORDER_LEN);
  while ((pos = bpf_iter_num_next(&iter))) {
    __u32 i = (__u32)*pos;
    if (i >= COMBO_ORDER_LEN)
      break;
    __u32 b = combo_order[i];
    if (b >= COMBO_MAX)
      break;
    if (!(bitmap & (1ULL << b)))
      continue;

    if (((combo_field_mask[b] & CM_SRC_IP) && key->src_id == 0) ||
        ((combo_field_mask[b] & CM_DST_IP) && key->dst_id == 0))
      continue;

    build_cidr_rule_key(matched_key, key, b);
    rule = CIDR_BLACKLIST_LOOKUP(rule_sel, matched_key);
    // B1: a missing condition row is a miss, so D8 keeps looking.
    if (rule && (rule->pad2[0] & RULE_HAS_CONDITIONS)) {
      const struct cond_value *cv = CIDR_COND_LOOKUP(rule_sel, matched_key);
      if (!cv) {
        __u32 zero = 0;
        __u64 *missing = bpf_map_lookup_elem(&cond_row_missing, &zero);
        if (missing)
          (*missing)++;
      }
      if (cv && cond_match(cv, attrs) >= 0)
        break;
      rule = NULL;
      continue;
    }
    if (rule && pkt_len_matches(rule, pkt_len) &&
        tcp_flags_matches(rule, key->protocol, tcp_flags, attrs->l4_valid) &&
        rule->match_anomaly == 0)
      break;
    rule = NULL;
  }
  bpf_iter_num_destroy(&iter);
  return rule;
}

// Phase 8: is_whitelisted() REMOVED from xdp_firewall_main.
// Real whitelist lookup is now in xdp_whitelist_gate (xdrop_gate.c).
// Verifier pruning is done via verifier_prune_map lookups below in
// xdp_firewall_main, after L2/L3/L4 parse + rule_key construction.

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
// nonfirst also marks an unreadable extension header: L4 is unavailable.
static INLINE __u8 parse_ipv6_nexthdr(void *data, void *data_end, __u8 nexthdr,
                                      void **l4_data, bool *fragment_seen, bool *nonfirst) {
  *nonfirst = false;
  *fragment_seen = false;
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
        *l4_data = data;
        *nonfirst = true;
        return nexthdr;
      }
      __u8 *hdr = data;
      __u8 next = hdr[0];
      __u8 len = hdr[1];
      data += (len + 1) * 8; // Length in 8-byte units
      if (data > data_end) {
        *l4_data = hdr;
        *nonfirst = true;
        return nexthdr;
      }
      nexthdr = next;
      break;
    }
    case 44: // Fragment
    {
      *fragment_seen = true; // ICMP validity still uses Fragment-header presence.
      // Fragment header: 8 bytes fixed
      if (data + 8 > data_end) {
        *l4_data = data;
        *nonfirst = true;
        return nexthdr;
      }
      __u8 *hdr = data;
      __u16 field = bpf_ntohs(*(__u16 *)(hdr + 2));
      nexthdr = hdr[0];
      data += 8;
      if (field & 0xfff8) {
        *nonfirst = true;
        *l4_data = data;
        return nexthdr;
      }
      break;
    }
    case 51: // AH (Authentication Header)
    {
      if (data + 2 > data_end) {
        *l4_data = data;
        *nonfirst = true;
        return nexthdr;
      }
      __u8 *hdr = data;
      __u8 next = hdr[0];
      __u8 len = hdr[1];
      data += (len + 2) * 4; // AH length in 4-byte units
      if (data > data_end) {
        *l4_data = hdr;
        *nonfirst = true;
        return nexthdr;
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
int xdp_firewall_main(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  __u32 ingress_ifindex = ctx->ingress_ifindex;

  // STATS_TOTAL_PACKETS moved to xdp_whitelist_gate (Phase 8)

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
    stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }

  // Fast forward mode: IP traffic on non-filter interface - redirect directly
  if (fast_forward && !should_filter(ingress_ifindex)) {
    stats_inc(STATS_PASSED_PACKETS);
    stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }

  // Initialize rule key, packet length (L3), and TCP flags
  struct rule_key key __attribute__((aligned(8))) = {0};
  void *l4_data = NULL;
  bool nonfirst = false;
  __u16 pkt_len = 0;    // L3 (IP layer) packet length
  __u8 tcp_flags = 0;   // TCP flags byte (0 for non-TCP)
  __u8 pkt_anomaly = 0;
  __u8 ttl = 0, dscp = 0, icmp_type = 0, icmp_code = 0;
  __u8 frag_class = 0, icmp_valid = 0;
  bool icmp_allowed = false;
  __u32 declared_len = 0; // Unlike pkt_len, the length check must not wrap.

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

    declared_len = pkt_len;
    ttl = ip->ttl;
    dscp = ip->tos >> 2;
    __u16 frag = bpf_ntohs(ip->frag_off);
    nonfirst = (frag & 0x1fff) != 0;
    frag_class = ((frag & 0x4000) >> 12) | ((frag & 0x2000) >> 12) |
                 ((frag & 0x1fff) != 0);
    icmp_allowed = ip->ihl >= 5 && ip->protocol == PROTO_ICMP && !(frag & 0x1fff);
    bool is_frag = false;
    pkt_anomaly = parse_v4_anomaly(ip, &is_frag);
    // A TCP data offset below five is invalid.
    if (ip->ihl >= 5 && !is_frag && ip->protocol == PROTO_TCP) {
      void *l4 = l3_data + (ip->ihl * 4);
      if (l4 + 14 <= data_end) {
        __u8 doff = ((struct tcphdr *)l4)->doff_res >> 4;
        if (doff < 5) {
          pkt_anomaly |= ANOMALY_INVALID;
        }
      }
    }
    if (ip->protocol == PROTO_TCP && (frag & 0x1fff) == 1)
      pkt_anomaly |= ANOMALY_TCP_OFFSET_ONE;

    // Keep the existing L4 parse and early-return decisions, including IHL<5.
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
    declared_len = (__u32)bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
    ttl = ip6->hop_limit;
    dscp = (((__u8 *)ip6)[0] & 0x0f) << 2 | (((__u8 *)ip6)[1] >> 6);
    // Validate the data offset for direct TCP only.
    if (ip6->nexthdr == PROTO_TCP) {
      void *v6_l4 = l3_data + sizeof(*ip6);
      if (v6_l4 + 14 <= data_end) {
        __u8 doff = ((struct tcphdr *)v6_l4)->doff_res >> 4;
        if (doff < 5) {
          pkt_anomaly |= ANOMALY_INVALID;
        }
      }
    }

    // Parse extension headers to find transport protocol
    void *ext_data = l3_data + sizeof(*ip6);
    bool fragment_seen = false;
    key.protocol =
        parse_ipv6_nexthdr(ext_data, data_end, ip6->nexthdr, &l4_data,
                          &fragment_seen, &nonfirst);
    icmp_allowed = key.protocol == PROTO_ICMPV6 && !fragment_seen;

    if (l4_data == NULL || l4_data > data_end) {
      // Could not find transport header - pass/redirect
      stats_inc(STATS_PASSED_PACKETS);
      stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
      if (fast_forward) {
        return bpf_redirect_map(&devmap, ingress_ifindex, 0);
      }
      return XDP_PASS;
    }

  } else {
    // Not IPv4 or IPv6 - pass/redirect (should not reach here in fast_forward)
    stats_inc(STATS_PASSED_PACKETS);
    stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
    if (fast_forward) {
      return bpf_redirect_map(&devmap, ingress_ifindex, 0);
    }
    return XDP_PASS;
  }

  // Measure from L3; VLAN/QinQ consume part of the 60-byte minimum frame
  // (FCS excluded). Excess bytes beyond its possible padding are anomalous.
  __u64 actual_len = data_end - l3_data;
  __u64 l2_len = l3_data - data;
  __u64 padding = l2_len + declared_len < 60 ? 60 - l2_len - declared_len : 0;
  if (actual_len < declared_len || actual_len - declared_len > padding)
    pkt_anomaly |= ANOMALY_LENGTH_MISMATCH;

  if (icmp_allowed && l4_data + 2 <= data_end) {
    icmp_type = ((__u8 *)l4_data)[0];
    icmp_code = ((__u8 *)l4_data)[1];
    icmp_valid = 1;
  }

  __u8 l4_valid = !nonfirst;

  // Parse L4 ports for TCP/UDP
  if (l4_valid) {
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
  }

  // Extraction is complete. Launder before the first rule/config lookup.
  {
    __u32 w0 = (__u32)xdrop_launder((int)((__u32)pkt_len |
        ((__u32)tcp_flags << 16) | ((__u32)pkt_anomaly << 24)));
    __u32 w1 = (__u32)xdrop_launder((int)((__u32)ttl | ((__u32)dscp << 8) |
        ((__u32)icmp_type << 16) | ((__u32)icmp_code << 24)));
    __u32 w2 = (__u32)xdrop_launder((int)((__u32)frag_class | ((__u32)icmp_valid << 8) |
        ((__u32)l4_valid << 16)));
    pkt_len = w0 & 0xffff;
    tcp_flags = (w0 >> 16) & 0xff;
    pkt_anomaly = w0 >> 24;
    ttl = w1 & 0xff;
    dscp = (w1 >> 8) & 0xff;
    icmp_type = (w1 >> 16) & 0xff;
    icmp_code = w1 >> 24;
    frag_class = w2 & 0xff;
    icmp_valid = (w2 >> 8) & 0xff;
    l4_valid = (w2 >> 16) & 0xff;
  }

  // Read rule map selector once per packet (dual rule map, Phase 4.2)
  __u64 config_slot = read_active_slot();
  int rule_sel = read_rule_map_selector(config_slot);

  // Phase 8: verifier_prune_map lookups — provide verifier early-return pruning.
  // These 3 unconditional lookups replace the old is_whitelisted() to give the
  // verifier an early-exit branch before the large blacklist/CIDR/rate/anomaly
  // code block, keeping xdp_firewall_main within 1M processed instructions.
  //
  // verifier_prune_map is NEVER written by control plane (max_entries=1, PinNone).
  // prune_hit is a real XDP_PASS — but it NEVER fires at runtime because the map
  // is always empty. DO NOT add any blacklist/drop logic to prune_hit.
  {
    struct rule_key prune_lookup = {0};

    // Prune lookup 1: exact 5-tuple
    ip_copy(&prune_lookup.src_ip, &key.src_ip);
    ip_copy(&prune_lookup.dst_ip, &key.dst_ip);
    prune_lookup.src_port = key.src_port;
    prune_lookup.dst_port = key.dst_port;
    prune_lookup.protocol = key.protocol;
    if (bpf_map_lookup_elem(&verifier_prune_map, &prune_lookup))
      goto prune_hit;

    // Prune lookup 2: src_ip-only
    ip_zero(&prune_lookup.dst_ip);
    prune_lookup.src_port = 0;
    prune_lookup.dst_port = 0;
    prune_lookup.protocol = 0;
    if (bpf_map_lookup_elem(&verifier_prune_map, &prune_lookup))
      goto prune_hit;

    // Prune lookup 3: dst_ip-only
    ip_zero(&prune_lookup.src_ip);
    ip_copy(&prune_lookup.dst_ip, &key.dst_ip);
    if (bpf_map_lookup_elem(&verifier_prune_map, &prune_lookup))
      goto prune_hit;
  }

  // Lookup blacklist with wildcard fallback (pkt_len / tcp_flags / anomaly
  // checked per iterator candidate). v2.6.1 Phase 4 B5:
  //   - The post-match condition `&& rule->match_anomaly == 0` is now
  //     applied to every enabled candidate in lookup_rule. lookup_rule only returns NON-anomaly
  //     rules; anomaly-specialized rules are transparently skipped and
  //     lookup continues fallback to more-wildcard combos. This preserves
  //     the D8 fallback invariant (proposal §7.8.7).
  struct rule_key matched_key __attribute__((aligned(8))) = {0};
  struct pkt_attrs attrs = {
      .pkt_len = pkt_len,
      .tcp_flags = tcp_flags,
      .pkt_anomaly = pkt_anomaly,
      .ttl = ttl,
      .dscp = dscp,
      .icmp_type = icmp_type,
      .icmp_code = icmp_code,
      .frag_class = frag_class,
      .icmp_valid = icmp_valid,
      .l4_valid = l4_valid, .pad = {0},
      .out = {.winner = COND_NO_WINNER, .action = 0, .pad = {0, 0},
              .rate = 0, .rule_id = 0},
  };
  struct rule_value *rule = lookup_rule(&key, &matched_key,
      &attrs, rule_sel, config_slot);

  if (rule) {
    // Update match counter
    int has_conditions = rule->pad2[0] & RULE_HAS_CONDITIONS;
    __u32 logical_id = has_conditions ? attrs.out.rule_id : rule->logical_id;
    struct logical_rule_counters *counter = has_conditions ?
        count_logical_match(&logical_id, ctx->data_end - ctx->data) : count_logical_match(&rule->logical_id, ctx->data_end - ctx->data);
    __u8 action = (rule->pad2[0] & RULE_HAS_CONDITIONS) ?
        attrs.out.action : rule->action;
    __u32 rate = (rule->pad2[0] & RULE_HAS_CONDITIONS) ?
        attrs.out.rate : rule->rate_limit;

    if (action == ACTION_DROP) {
      if (counter) {
        counter->drop++;
        counter->drop_bytes += ctx->data_end - ctx->data;
      }
      stats_inc(STATS_DROPPED_PACKETS);
      stats_add(STATS_DROPPED_BYTES, ctx->data_end - ctx->data);
      return XDP_DROP;
    }

    if (action == ACTION_RATE_LIMIT && rate > 0) {
      // Token bucket rate limiting
      __u64 now = bpf_ktime_get_ns();
      __u64 divisor = rate_limit_divisor(config_slot);
      __u64 max_tokens = rate_limit_capacity((__u64)rate, divisor);

      struct rate_limit_state *state =
          bpf_map_lookup_elem(&id_rl_states, &logical_id);
      if (!state) {
        struct rate_limit_state new_state = {
            .tokens = max_tokens - 1,
            .last_update = now,
        };
        if (bpf_map_update_elem(&id_rl_states, &logical_id, &new_state, BPF_ANY) != 0) {
          if (counter) {
            counter->drop++;
            counter->drop_bytes += ctx->data_end - ctx->data;
          }
          stats_inc(STATS_RATE_LIMITED);
          stats_inc(STATS_DROPPED_PACKETS);
          stats_add(STATS_DROPPED_BYTES, ctx->data_end - ctx->data);
          return XDP_DROP;
        }
        stats_inc(STATS_PASSED_PACKETS);
        stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
        if (fast_forward) {
          return bpf_redirect_map(&devmap, ingress_ifindex, 0);
        }
        return XDP_PASS;
      }

      if (state->last_update == 0) {
        rate_limit_take(state, now, (__u64)rate, divisor);
        stats_inc(STATS_PASSED_PACKETS);
        stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
        if (fast_forward) {
          return bpf_redirect_map(&devmap, ingress_ifindex, 0);
        }
        return XDP_PASS;
      }

      if (rate_limit_take(state, now, (__u64)rate, divisor)) {
        stats_inc(STATS_PASSED_PACKETS);
        stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
        if (fast_forward) {
          return bpf_redirect_map(&devmap, ingress_ifindex, 0);
        }
        return XDP_PASS;
      } else {
        if (counter) {
          counter->drop++;
          counter->drop_bytes += ctx->data_end - ctx->data;
        }
        stats_inc(STATS_RATE_LIMITED);
        stats_inc(STATS_DROPPED_PACKETS);
        stats_add(STATS_DROPPED_BYTES, ctx->data_end - ctx->data);
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
      __u32 *sid = CIDR_TRIE_LOOKUP(rule_sel, sv4_cidr_trie, &lpm_k);
      if (sid)
        src_cidr_id = *sid;
      // dst lookup
      lpm_k.prefixlen = 32;
      __builtin_memcpy(lpm_k.addr, &cidr_ip->daddr, 4);
      __u32 *did = CIDR_TRIE_LOOKUP(rule_sel, dv4_cidr_trie, &lpm_k);
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
      __u32 *sid6 = CIDR_TRIE_LOOKUP(rule_sel, sv6_cidr_trie, &lpm_k6);
      if (sid6)
        src_cidr_id = *sid6;
      // dst lookup
      lpm_k6.prefixlen = 128;
      __builtin_memcpy(lpm_k6.addr, cidr_ip6->daddr, 16);
      __u32 *did6 = CIDR_TRIE_LOOKUP(rule_sel, dv6_cidr_trie, &lpm_k6);
      if (did6)
        dst_cidr_id = *did6;
    }
  }

  // Stage 2: If any CIDR ID matched, do the ordered mask-table hash lookup
  if (src_cidr_id != 0 || dst_cidr_id != 0) {
    struct cidr_rule_key ck __attribute__((aligned(8))) = {
        .src_id = src_cidr_id,
        .dst_id = dst_cidr_id,
        .src_port = key.src_port,
        .dst_port = key.dst_port,
        .protocol = key.protocol,
        .pad = {0},
    };

    // v2.6.1 Phase 4 B5: lookup_cidr_rule applies `&& rule->match_anomaly == 0`
    // to each enabled candidate (same treatment as lookup_rule).
    struct cidr_rule_key cidr_matched_key __attribute__((aligned(8))) = {0};
    struct pkt_attrs cidr_attrs = {
        .pkt_len = pkt_len,
        .tcp_flags = tcp_flags,
        .pkt_anomaly = pkt_anomaly,
        .ttl = ttl,
        .dscp = dscp,
        .icmp_type = icmp_type,
        .icmp_code = icmp_code,
        .frag_class = frag_class,
        .icmp_valid = icmp_valid,
        .l4_valid = l4_valid, .pad = {0},
        .out = {.winner = COND_NO_WINNER, .action = 0, .pad = {0, 0},
                .rate = 0, .rule_id = 0},
    };
    struct rule_value *cidr_rule =
        lookup_cidr_rule(&ck, &cidr_matched_key,
            &cidr_attrs, rule_sel, config_slot);

    if (cidr_rule) {
      int has_conditions = cidr_rule->pad2[0] & RULE_HAS_CONDITIONS;
      __u32 logical_id = has_conditions ? cidr_attrs.out.rule_id : cidr_rule->logical_id;
      struct logical_rule_counters *counter = has_conditions ?
          count_logical_match(&logical_id, ctx->data_end - ctx->data) : count_logical_match(&cidr_rule->logical_id, ctx->data_end - ctx->data);
      __u8 action = (cidr_rule->pad2[0] & RULE_HAS_CONDITIONS) ?
          cidr_attrs.out.action : cidr_rule->action;
      __u32 rate = (cidr_rule->pad2[0] & RULE_HAS_CONDITIONS) ?
          cidr_attrs.out.rate : cidr_rule->rate_limit;

      if (action == ACTION_DROP) {
        if (counter) {
          counter->drop++;
          counter->drop_bytes += ctx->data_end - ctx->data;
        }
        stats_inc(STATS_DROPPED_PACKETS);
        stats_add(STATS_DROPPED_BYTES, ctx->data_end - ctx->data);
        return XDP_DROP;
      }

      if (action == ACTION_RATE_LIMIT && rate > 0) {
        __u64 now = bpf_ktime_get_ns();
        __u64 divisor = rate_limit_divisor(config_slot);
        __u64 max_tokens = rate_limit_capacity((__u64)rate, divisor);

        struct rate_limit_state *state =
            bpf_map_lookup_elem(&id_rl_states, &logical_id);
        if (!state) {
          struct rate_limit_state new_state = {
              .tokens = max_tokens - 1,
              .last_update = now,
          };
          if (bpf_map_update_elem(&id_rl_states, &logical_id, &new_state, BPF_ANY) != 0) {
            if (counter) {
              counter->drop++;
              counter->drop_bytes += ctx->data_end - ctx->data;
            }
            stats_inc(STATS_RATE_LIMITED);
            stats_inc(STATS_DROPPED_PACKETS);
            stats_add(STATS_DROPPED_BYTES, ctx->data_end - ctx->data);
            return XDP_DROP;
          }
          stats_inc(STATS_PASSED_PACKETS);
          stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
          if (fast_forward) {
            return bpf_redirect_map(&devmap, ingress_ifindex, 0);
          }
          return XDP_PASS;
        }

        if (state->last_update == 0) {
          rate_limit_take(state, now, (__u64)rate, divisor);
          stats_inc(STATS_PASSED_PACKETS);
          stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
          if (fast_forward) {
            return bpf_redirect_map(&devmap, ingress_ifindex, 0);
          }
          return XDP_PASS;
        }

        if (rate_limit_take(state, now, (__u64)rate, divisor)) {
          stats_inc(STATS_PASSED_PACKETS);
          stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
          if (fast_forward) {
            return bpf_redirect_map(&devmap, ingress_ifindex, 0);
          }
          return XDP_PASS;
        } else {
          if (counter) {
            counter->drop++;
            counter->drop_bytes += ctx->data_end - ctx->data;
          }
          stats_inc(STATS_RATE_LIMITED);
          stats_inc(STATS_DROPPED_PACKETS);
          stats_add(STATS_DROPPED_BYTES, ctx->data_end - ctx->data);
          return XDP_DROP;
        }
      }
    }
  }

  // Both exact and CIDR lookups missed; use the default pass/redirect path.

  // Default: pass/redirect
  stats_inc(STATS_PASSED_PACKETS);
  stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
  if (fast_forward) {
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }
  return XDP_PASS;

prune_hit:
  // Phase 8: verifier pruning branch — NEVER fires at runtime.
  // verifier_prune_map is always empty (max_entries=1, never written).
  // This label exists solely to give the BPF verifier an early-return path
  // that terminates exploration before the blacklist/CIDR/rate/anomaly block.
  // DO NOT add any blacklist/drop/stat logic here.
  stats_inc(STATS_PASSED_PACKETS);
  stats_add(STATS_PASSED_BYTES, ctx->data_end - ctx->data);
  if (fast_forward) {
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
