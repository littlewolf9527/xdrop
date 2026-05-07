// SPDX-License-Identifier: GPL-2.0
// XDrop Phase 8 — xdp_whitelist_gate: 31-combo bitmap-gated whitelist lookup
//
// This is the XDP entry point program (attached to NIC). On whitelist miss or
// wl_bitmap==0, tail-calls to xdp_firewall_main (slot 1 in prog_tail_map).
//
// Compiled separately from xdrop_main.c into xdrop_gate.elf to avoid verifier
// budget contamination. Maps declared here are shared with xdrop_main.elf via
// Go agent MapReplacements (except whitelist_b and tailcall_fail_stats which
// are gate-only).

#include "xdrop.h"

// === Shared maps (Go agent uses MapReplacements to point these to mainColl's kernel maps) ===

BPF_MAP_DEF(whitelist) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(__u8),
    .max_entries = MAX_WHITELIST,
};
BPF_MAP_ADD(whitelist);

BPF_MAP_DEF(stats) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 5,
};
BPF_MAP_ADD(stats);

BPF_MAP_DEF(config_a) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = CONFIG_MAP_ENTRIES,
};
BPF_MAP_ADD(config_a);

BPF_MAP_DEF(config_b) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = CONFIG_MAP_ENTRIES,
};
BPF_MAP_ADD(config_b);

BPF_MAP_DEF(active_config) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(active_config);

BPF_MAP_DEF(devmap) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 16,
};
BPF_MAP_ADD(devmap);

BPF_MAP_DEF(prog_tail_map) = {
    .map_type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = 4,
    .value_size = 4,
    .max_entries = TAIL_SLOT_MAX,
};
BPF_MAP_ADD(prog_tail_map);

// === Gate-only maps ===

// Shadow whitelist for Phase 8 dual-buffer atomic sync
BPF_MAP_DEF(whitelist_b) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rule_key),
    .value_size = sizeof(__u8),
    .max_entries = MAX_WHITELIST,
};
BPF_MAP_ADD(whitelist_b);

// Per-CPU counter for gate→main tail-call failure detection
BPF_MAP_DEF(tailcall_fail_stats) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(tailcall_fail_stats);

// === Helpers ===

static INLINE void stats_inc(__u32 idx) {
  __u64 *counter = bpf_map_lookup_elem(&stats, &idx);
  if (counter) { (*counter)++; }
}

static INLINE void tailcall_fail_inc(void) {
  __u32 key = 0;
  __u64 *counter = bpf_map_lookup_elem(&tailcall_fail_stats, &key);
  if (counter) { (*counter)++; }
}

static INLINE __u64 read_active_slot(void) {
  __u32 sel_key = ACTIVE_CONFIG_KEY;
  __u64 *sel = bpf_map_lookup_elem(&active_config, &sel_key);
  return sel ? *sel : 0;
}

static INLINE __u64 *config_lookup(__u64 slot, __u32 key_idx) {
  if (slot == 0) {
    return bpf_map_lookup_elem(&config_a, &key_idx);
  } else {
    return bpf_map_lookup_elem(&config_b, &key_idx);
  }
}

static INLINE int is_fast_forward_enabled(void) {
  __u64 slot = read_active_slot();
  __u32 idx = CONFIG_FAST_FORWARD_ENABLED;
  __u64 *enabled = config_lookup(slot, idx);
  return enabled && *enabled == 1;
}

static INLINE __u32 get_filter_ifindex(void) {
  __u64 slot = read_active_slot();
  __u32 idx = CONFIG_FILTER_IFINDEX;
  __u64 *ifindex = config_lookup(slot, idx);
  return ifindex ? (__u32)*ifindex : 0;
}

static INLINE int should_filter(__u32 ingress_ifindex) {
  __u32 filter_ifindex = get_filter_ifindex();
  if (filter_ifindex == 0) { return 1; }
  return ingress_ifindex == filter_ifindex;
}

static INLINE int read_wl_map_selector(__u64 slot) {
  __u32 key = CONFIG_WL_MAP_SELECTOR;
  __u64 *sel = config_lookup(slot, key);
  return sel ? (int)*sel : 0;
}

// IP address helpers (shared with xdrop_main.c, duplicated here for ELF independence)
static INLINE void ip_copy(struct ip_addr *dst, const struct ip_addr *src) {
  #pragma unroll
  for (int i = 0; i < 16; i++) { dst->addr[i] = src->addr[i]; }
}

static INLINE void ip_zero(struct ip_addr *ip) {
  #pragma unroll
  for (int i = 0; i < 16; i++) { ip->addr[i] = 0; }
}

static INLINE void ipv4_to_mapped(struct ip_addr *dst, __u32 ipv4) {
  #pragma unroll
  for (int i = 0; i < 10; i++) { dst->addr[i] = 0; }
  dst->addr[10] = 0xff; dst->addr[11] = 0xff;
  dst->addr[12] = (ipv4 >> 0) & 0xff; dst->addr[13] = (ipv4 >> 8) & 0xff;
  dst->addr[14] = (ipv4 >> 16) & 0xff; dst->addr[15] = (ipv4 >> 24) & 0xff;
}

static INLINE void ipv6_copy(struct ip_addr *dst, const __u8 *src) {
  #pragma unroll
  for (int i = 0; i < 16; i++) { dst->addr[i] = src[i]; }
}

// IPv6 extension header walker (shared with xdrop_main.c)
static INLINE __u8 parse_ipv6_nexthdr(void *data, void *data_end, __u8 nexthdr, void **l4_data) {
  #pragma unroll
  for (int i = 0; i < IPV6_EXT_MAX_DEPTH; i++) {
    if (nexthdr == PROTO_TCP || nexthdr == PROTO_UDP || nexthdr == PROTO_ICMPV6) {
      *l4_data = data;
      return nexthdr;
    }
    switch (nexthdr) {
    case 0: case 43: case 60: {
      if (data + 2 > data_end) { return 0; }
      __u8 *hdr = data; __u8 next = hdr[0]; __u8 len = hdr[1];
      data += (len + 1) * 8;
      if (data > data_end) { return 0; }
      nexthdr = next; break;
    }
    case 44: {
      if (data + 8 > data_end) { return 0; }
      __u8 *hdr = data; nexthdr = hdr[0]; data += 8; break;
    }
    case 51: {
      if (data + 2 > data_end) { return 0; }
      __u8 *hdr = data; __u8 next = hdr[0]; __u8 len = hdr[1];
      data += (len + 2) * 4;
      if (data > data_end) { return 0; }
      nexthdr = next; break;
    }
    default: *l4_data = data; return nexthdr;
    }
  }
  *l4_data = data;
  return nexthdr;
}

// Whitelist dual-buffer lookup macro
#define WHITELIST_LOOKUP(wl_sel, key_ptr) \
  ((wl_sel) == 0 ? bpf_map_lookup_elem(&whitelist, (key_ptr)) \
                 : bpf_map_lookup_elem(&whitelist_b, (key_ptr)))

// Combo check macro — jumps to wl_hit on match
#define WL_COMBO_CHECK(combo_bit, setup_code)          \
  if (wl_bitmap & (1ULL << (combo_bit))) {             \
    setup_code;                                        \
    lookup.pad[0] = lookup.pad[1] = lookup.pad[2] = 0;\
    if (WHITELIST_LOOKUP(wl_sel, &lookup))             \
      goto wl_hit;                                     \
  }

// === XDP Entry Point ===

SEC("xdp")
int xdp_whitelist_gate(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  __u32 ingress_ifindex = ctx->ingress_ifindex;

  // 1. Unique total packet counter
  stats_inc(STATS_TOTAL_PACKETS);

  // 2. Parse Ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_ABORTED;
  }
  __u16 eth_proto = eth->h_proto;
  void *l3_data = (void *)(eth + 1);

  // Handle VLAN tags (802.1Q and QinQ)
  if (eth_proto == ETH_P_8021Q_BE || eth_proto == ETH_P_8021AD_BE) {
    struct vlan_hdr *vlan = l3_data;
    if ((void *)(vlan + 1) > data_end) { return XDP_ABORTED; }
    eth_proto = vlan->h_vlan_encapsulated_proto;
    l3_data = (void *)(vlan + 1);
    if (eth_proto == ETH_P_8021Q_BE) {
      vlan = l3_data;
      if ((void *)(vlan + 1) > data_end) { return XDP_ABORTED; }
      eth_proto = vlan->h_vlan_encapsulated_proto;
      l3_data = (void *)(vlan + 1);
    }
  }

  // 3. FF early bypass — reuse existing helpers (v2.6.4 behavior)
  int fast_forward = is_fast_forward_enabled();

  if (fast_forward && eth_proto != ETH_P_IP_BE && eth_proto != ETH_P_IPV6_BE) {
    stats_inc(STATS_PASSED_PACKETS);
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }
  if (!fast_forward && eth_proto != ETH_P_IP_BE && eth_proto != ETH_P_IPV6_BE) {
    stats_inc(STATS_PASSED_PACKETS);
    return XDP_PASS;
  }
  if (fast_forward && !should_filter(ingress_ifindex)) {
    stats_inc(STATS_PASSED_PACKETS);
    return bpf_redirect_map(&devmap, ingress_ifindex, 0);
  }

  // 4. Read config slot for WL bitmap + selector
  __u64 config_slot = read_active_slot();

  // 5. Fast path: no whitelist rules → skip L3/L4 parse, tail_call to main
  __u32 wl_bitmap_idx = CONFIG_WL_BITMAP;
  __u64 *wl_bitmap_ptr = config_lookup(config_slot, wl_bitmap_idx);
  __u64 wl_bitmap = wl_bitmap_ptr ? *wl_bitmap_ptr : 0ULL;

  if (wl_bitmap == 0) {
    bpf_tail_call(ctx, &prog_tail_map, TAIL_SLOT_FIREWALL_MAIN);
    tailcall_fail_inc();
    stats_inc(STATS_PASSED_PACKETS);
    if (fast_forward) { return bpf_redirect_map(&devmap, ingress_ifindex, 0); }
    return XDP_PASS;
  }

  // 6. wl_bitmap != 0: parse L3/L4 and build rule_key
  struct rule_key key = {0};
  void *l4_data = NULL;

  if (eth_proto == ETH_P_IP_BE) {
    struct iphdr *ip = l3_data;
    if ((void *)(ip + 1) > data_end) { return XDP_ABORTED; }
    ipv4_to_mapped(&key.src_ip, ip->saddr);
    ipv4_to_mapped(&key.dst_ip, ip->daddr);
    key.protocol = ip->protocol;
    l4_data = l3_data + (ip->ihl * 4);
    if (l4_data > data_end) { return XDP_ABORTED; }
  } else if (eth_proto == ETH_P_IPV6_BE) {
    struct ip6hdr *ip6 = l3_data;
    if ((void *)(ip6 + 1) > data_end) { return XDP_ABORTED; }
    ipv6_copy(&key.src_ip, ip6->saddr);
    ipv6_copy(&key.dst_ip, ip6->daddr);
    void *ext_data = l3_data + sizeof(*ip6);
    key.protocol = parse_ipv6_nexthdr(ext_data, data_end, ip6->nexthdr, &l4_data);
    if (l4_data == NULL || l4_data > data_end) {
      bpf_tail_call(ctx, &prog_tail_map, TAIL_SLOT_FIREWALL_MAIN);
      tailcall_fail_inc();
      stats_inc(STATS_PASSED_PACKETS);
      if (fast_forward) { return bpf_redirect_map(&devmap, ingress_ifindex, 0); }
      return XDP_PASS;
    }
  } else {
    bpf_tail_call(ctx, &prog_tail_map, TAIL_SLOT_FIREWALL_MAIN);
    tailcall_fail_inc();
    stats_inc(STATS_PASSED_PACKETS);
    return XDP_PASS;
  }

  // Parse L4 ports
  if (key.protocol == PROTO_TCP) {
    struct tcphdr *tcp = l4_data;
    if ((void *)(tcp + 1) > data_end) { return XDP_ABORTED; }
    key.src_port = tcp->source;
    key.dst_port = tcp->dest;
  } else if (key.protocol == PROTO_UDP) {
    struct udphdr *udp = l4_data;
    if ((void *)(udp + 1) > data_end) { return XDP_ABORTED; }
    key.src_port = udp->source;
    key.dst_port = udp->dest;
  }

  // 7-8. 31-combo bitmap-gated whitelist lookup
  {
    int wl_sel = read_wl_map_selector(config_slot);
    struct rule_key lookup;

    WL_COMBO_CHECK(COMBO_EXACT_5TUPLE, { ip_copy(&lookup.src_ip, &key.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = key.dst_port; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_WILDCARD_SRC_IP, { ip_zero(&lookup.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = key.dst_port; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_WILDCARD_SRC_IP_PORT, { ip_zero(&lookup.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = 0; lookup.dst_port = key.dst_port; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_DST_IP_PROTO, { ip_zero(&lookup.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = 0; lookup.dst_port = 0; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_DST_IP_ONLY, { ip_zero(&lookup.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = 0; lookup.dst_port = 0; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_PROTO_ONLY, { ip_zero(&lookup.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = 0; lookup.dst_port = 0; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_SRC_PORT_ONLY, { ip_zero(&lookup.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = 0; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_DST_PORT_ONLY, { ip_zero(&lookup.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = 0; lookup.dst_port = key.dst_port; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_SRC_IP_ONLY, { ip_copy(&lookup.src_ip, &key.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = 0; lookup.dst_port = 0; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_SRC_IP_PROTO, { ip_copy(&lookup.src_ip, &key.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = 0; lookup.dst_port = 0; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_SRC_DST_IP, { ip_copy(&lookup.src_ip, &key.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = 0; lookup.dst_port = 0; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_SRC_IP_DST_PORT, { ip_copy(&lookup.src_ip, &key.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = 0; lookup.dst_port = key.dst_port; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_DST_IP_DST_PORT, { ip_zero(&lookup.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = 0; lookup.dst_port = key.dst_port; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_SRC_DST_IP_PROTO, { ip_copy(&lookup.src_ip, &key.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = 0; lookup.dst_port = 0; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_SRC_IP_DST_PORT_PROTO, { ip_copy(&lookup.src_ip, &key.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = 0; lookup.dst_port = key.dst_port; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_SRC_PORT_PROTO, { ip_zero(&lookup.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = 0; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_DST_PORT_PROTO, { ip_zero(&lookup.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = 0; lookup.dst_port = key.dst_port; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_SRC_IP_SRC_PORT, { ip_copy(&lookup.src_ip, &key.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = 0; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_SRC_IP_SRC_PORT_PROTO, { ip_copy(&lookup.src_ip, &key.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = 0; lookup.protocol = key.protocol; })
    // bits 19, 20, 32 are dead aliases — skipped
    WL_COMBO_CHECK(COMBO_SRC_DST_IP_DST_PORT, { ip_copy(&lookup.src_ip, &key.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = 0; lookup.dst_port = key.dst_port; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_SRC_DST_IP_DST_PORT_PROTO, { ip_copy(&lookup.src_ip, &key.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = 0; lookup.dst_port = key.dst_port; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_SRC_IP_PORTS, { ip_copy(&lookup.src_ip, &key.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = key.dst_port; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_SRC_IP_PORTS_PROTO, { ip_copy(&lookup.src_ip, &key.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = key.dst_port; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_DST_IP_SRC_PORT, { ip_zero(&lookup.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = 0; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_DST_IP_SRC_PORT_PROTO, { ip_zero(&lookup.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = 0; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_PORTS_ONLY, { ip_zero(&lookup.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = key.dst_port; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_PORTS_PROTO, { ip_zero(&lookup.src_ip); ip_zero(&lookup.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = key.dst_port; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_SRC_DST_IP_SRC_PORT, { ip_copy(&lookup.src_ip, &key.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = 0; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_SRC_DST_IP_SRC_PORT_PROTO, { ip_copy(&lookup.src_ip, &key.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = 0; lookup.protocol = key.protocol; })
    WL_COMBO_CHECK(COMBO_DST_IP_PORTS, { ip_zero(&lookup.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = key.dst_port; lookup.protocol = 0; })
    WL_COMBO_CHECK(COMBO_ALL_EXCEPT_PROTO, { ip_copy(&lookup.src_ip, &key.src_ip); ip_copy(&lookup.dst_ip, &key.dst_ip); lookup.src_port = key.src_port; lookup.dst_port = key.dst_port; lookup.protocol = 0; })
  }

  // 9. Whitelist miss — tail_call to main
  bpf_tail_call(ctx, &prog_tail_map, TAIL_SLOT_FIREWALL_MAIN);
  // Fallthrough: runtime fail-open
  tailcall_fail_inc();
  stats_inc(STATS_PASSED_PACKETS);
  if (fast_forward) { return bpf_redirect_map(&devmap, ingress_ifindex, 0); }
  return XDP_PASS;

wl_hit:
  stats_inc(STATS_WHITELISTED);
  stats_inc(STATS_PASSED_PACKETS);
  if (fast_forward) { return bpf_redirect_map(&devmap, ingress_ifindex, 0); }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
