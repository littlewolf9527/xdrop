// SPDX-License-Identifier: GPL-2.0
// XDrop - Shared header file for XDP firewall
// Supports both IPv4 and IPv6

#ifndef __XDROP_H
#define __XDROP_H

#include "bpf_helpers.h"

// NULL definition for BPF
#ifndef NULL
#define NULL ((void *)0)
#endif

// BPF map flags (not defined in goebpf bpf_helpers.h)
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

// Network byte order conversion (big-endian to host)
#ifndef bpf_ntohs
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#else
#define bpf_ntohs(x) (x)
#endif
#endif

// Configuration
#define MAX_RULES 500000
#define MAX_WHITELIST 50000

// Protocol definitions
#define PROTO_ALL 0
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMPV6 58

// Action definitions
#define ACTION_PASS 0
#define ACTION_DROP 1
#define ACTION_RATE_LIMIT 2

// EtherType definitions (network byte order)
#define ETH_P_IP_BE 0x0008     // IPv4: 0x0800 in big-endian
#define ETH_P_IPV6_BE 0xDD86   // IPv6: 0x86DD in big-endian
#define ETH_P_8021Q_BE 0x0081  // 802.1Q VLAN: 0x8100 in big-endian
#define ETH_P_8021AD_BE 0xA888 // 802.1ad QinQ: 0x88A8 in big-endian

// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// VLAN header (802.1Q)
struct vlan_hdr {
  __u16 h_vlan_TCI;              // Priority (3) + DEI (1) + VLAN ID (12)
  __u16 h_vlan_encapsulated_proto; // Encapsulated EtherType
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

// IPv6 header
struct ip6hdr {
  __u32 flow;        // version (4), traffic class (8), flow label (20)
  __u16 payload_len; // Length of payload
  __u8 nexthdr;      // Next header type (same as IPv4 protocol field)
  __u8 hop_limit;    // TTL equivalent
  __u8 saddr[16];    // Source address
  __u8 daddr[16];    // Destination address
} __attribute__((packed));

// TCP header (only first 4 bytes for ports)
struct tcphdr {
  __u16 source;
  __u16 dest;
} __attribute__((packed));

// UDP header
struct udphdr {
  __u16 source;
  __u16 dest;
  __u16 len;
  __u16 check;
} __attribute__((packed));

// Unified IP address (supports both IPv4 and IPv6)
// IPv4 addresses are stored as IPv4-mapped IPv6: ::ffff:x.x.x.x
// First 10 bytes: 0x00, next 2 bytes: 0xff ff, last 4 bytes: IPv4 address
struct ip_addr {
  __u8 addr[16];
} __attribute__((packed));

// Helper: Compare two IP addresses
#define IP_EQUAL(a, b)                                                         \
  ((a).addr[0] == (b).addr[0] && (a).addr[1] == (b).addr[1] &&                 \
   (a).addr[2] == (b).addr[2] && (a).addr[3] == (b).addr[3] &&                 \
   (a).addr[4] == (b).addr[4] && (a).addr[5] == (b).addr[5] &&                 \
   (a).addr[6] == (b).addr[6] && (a).addr[7] == (b).addr[7] &&                 \
   (a).addr[8] == (b).addr[8] && (a).addr[9] == (b).addr[9] &&                 \
   (a).addr[10] == (b).addr[10] && (a).addr[11] == (b).addr[11] &&             \
   (a).addr[12] == (b).addr[12] && (a).addr[13] == (b).addr[13] &&             \
   (a).addr[14] == (b).addr[14] && (a).addr[15] == (b).addr[15])

// Five-tuple rule key (unified for IPv4 and IPv6)
struct rule_key {
  struct ip_addr src_ip;   // Source IP (all zeros = any)
  struct ip_addr dst_ip;   // Destination IP (all zeros = any)
  __u16 src_port;          // Source port (0 = any)
  __u16 dst_port;          // Destination port (0 = any)
  __u8 protocol;           // Protocol: 0=any, 1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6
  __u8 pad[3];             // Padding for alignment
} __attribute__((packed)); // Total: 40 bytes

// Rule value (32 bytes, aligned)
struct rule_value {
  __u8 action; // 0=pass, 1=drop, 2=rate_limit
  __u8 pad[3];
  __u32 rate_limit;  // PPS limit (when action=2)
  __u64 match_count; // Match counter
  __u64 drop_count;  // Drop counter
  __u16 pkt_len_min; // Minimum packet length (L3), 0=no limit
  __u16 pkt_len_max; // Maximum packet length (L3), 0=no limit
  __u8 pad2[4];      // Padding for 32-byte alignment
} __attribute__((packed));

// Statistics indices (PERCPU)
#define STATS_TOTAL_PACKETS 0
#define STATS_DROPPED_PACKETS 1
#define STATS_PASSED_PACKETS 2
#define STATS_WHITELISTED 3
#define STATS_RATE_LIMITED 4

// Config map indices (used in config_a / config_b double-buffer maps)
#define CONFIG_BLACKLIST_COUNT 0
#define CONFIG_WHITELIST_COUNT 1      // Agent-side only; BPF no longer gates on this
#define CONFIG_RULE_BITMAP 2          // 64-bit bitmap for 34 combo types
#define CONFIG_BITMAP_VALID 3         // Reserved (unused in double-buffer mode)
#define CONFIG_FAST_FORWARD_ENABLED 4 // 1 = fast forward mode enabled
#define CONFIG_FILTER_IFINDEX 5       // Interface index to filter (0 = all/both)

// Rule combo types (for bitmap optimization)
// Each bit in the bitmap represents whether rules of that combo type exist
#define COMBO_EXACT_5TUPLE 0 // src_ip + dst_ip + src_port + dst_port + protocol
#define COMBO_WILDCARD_SRC_IP 1 // * + dst_ip + src_port + dst_port + protocol
#define COMBO_WILDCARD_SRC_IP_PORT 2   // * + dst_ip + * + dst_port + protocol
#define COMBO_DST_IP_PROTO 3           // * + dst_ip + * + * + protocol
#define COMBO_DST_IP_ONLY 4            // * + dst_ip + * + * + *
#define COMBO_PROTO_ONLY 5             // * + * + * + * + protocol
#define COMBO_SRC_PORT_ONLY 6          // * + * + src_port + * + *
#define COMBO_DST_PORT_ONLY 7          // * + * + * + dst_port + *
#define COMBO_SRC_IP_ONLY 8            // src_ip + * + * + * + *
#define COMBO_SRC_IP_PROTO 9           // src_ip + * + * + * + protocol
#define COMBO_SRC_DST_IP 10            // src_ip + dst_ip + * + * + *
#define COMBO_SRC_IP_DST_PORT 11       // src_ip + * + * + dst_port + *
#define COMBO_DST_IP_DST_PORT 12       // * + dst_ip + * + dst_port + *
#define COMBO_SRC_DST_IP_PROTO 13      // src_ip + dst_ip + * + * + protocol
#define COMBO_SRC_IP_DST_PORT_PROTO 14 // src_ip + * + * + dst_port + protocol
#define COMBO_SRC_PORT_PROTO 15        // * + * + src_port + * + protocol
#define COMBO_DST_PORT_PROTO 16        // * + * + * + dst_port + protocol
#define COMBO_SRC_IP_SRC_PORT 17       // src_ip + * + src_port + * + *
#define COMBO_SRC_IP_SRC_PORT_PROTO 18 // src_ip + * + src_port + * + protocol
// Note: combo 19 was removed (duplicate of COMBO_DST_IP_PROTO)
#define COMBO_DST_IP_DST_PORT_PROTO 20 // * + dst_ip + * + dst_port + protocol
#define COMBO_SRC_DST_IP_DST_PORT 21   // src_ip + dst_ip + * + dst_port + *
#define COMBO_SRC_DST_IP_DST_PORT_PROTO                                        \
  22                          // src_ip + dst_ip + * + dst_port + protocol
#define COMBO_SRC_IP_PORTS 23 // src_ip + * + src_port + dst_port + *
#define COMBO_SRC_IP_PORTS_PROTO                                               \
  24                             // src_ip + * + src_port + dst_port + protocol
#define COMBO_DST_IP_SRC_PORT 25 // * + dst_ip + src_port + * + *
#define COMBO_DST_IP_SRC_PORT_PROTO 26 // * + dst_ip + src_port + * + protocol
#define COMBO_PORTS_ONLY 27            // * + * + src_port + dst_port + *
#define COMBO_PORTS_PROTO 28           // * + * + src_port + dst_port + protocol
#define COMBO_SRC_DST_IP_SRC_PORT 29   // src_ip + dst_ip + src_port + * + *
#define COMBO_SRC_DST_IP_SRC_PORT_PROTO                                        \
  30                          // src_ip + dst_ip + src_port + * + protocol
#define COMBO_DST_IP_PORTS 31 // * + dst_ip + src_port + dst_port + *
#define COMBO_DST_IP_PORTS_PROTO                                               \
  32                              // * + dst_ip + src_port + dst_port + protocol
#define COMBO_ALL_EXCEPT_PROTO 33 // src_ip + dst_ip + src_port + dst_port + *
#define COMBO_MAX 34

// CIDR LPM Trie keys
// IPv4: 8 bytes (4 prefixlen + 4 addr), matches goebpf *net.IPNet serialization
struct cidr_v4_lpm_key {
  __u32 prefixlen;   // 0-32, host byte order (kernel LPM_TRIE requirement)
  __u8  addr[4];     // network byte order (big-endian IPv4)
} __attribute__((packed));

// IPv6: 20 bytes (4 prefixlen + 16 addr), matches goebpf *net.IPNet serialization
struct cidr_v6_lpm_key {
  __u32 prefixlen;   // 0-128, host byte order
  __u8  addr[16];    // IPv6 address
} __attribute__((packed));

// CIDR rule hash key (16 bytes): uses integer IDs instead of IP addresses
struct cidr_rule_key {
  __u32 src_id;    // 0 = wildcard (no src CIDR constraint)
  __u32 dst_id;    // 0 = wildcard (no dst CIDR constraint)
  __u16 src_port;  // 0 = wildcard
  __u16 dst_port;  // 0 = wildcard
  __u8  protocol;  // 0 = wildcard
  __u8  pad[3];
} __attribute__((packed));

// Rate limit state (per-rule token bucket)
struct rate_limit_state {
  __u64 tokens;      // Current tokens available
  __u64 last_update; // Last update timestamp (nanoseconds)
} __attribute__((packed));

// Rate limit configuration
#define RATE_LIMIT_BURST_MULTIPLIER 2 // Allow burst = rate * 2

// CIDR config map indices (continuing from existing 0-5)
#define CONFIG_CIDR_RULE_COUNT   6   // total CIDR rule count
#define CONFIG_CIDR_BITMAP       7   // CIDR combo bitmap (lower 34 bits)
#define CONFIG_CIDR_BITMAP_VALID 8   // 1 = bitmap initialized by agent

// Dual rule map selector (Phase 4.2)
#define CONFIG_RULE_MAP_SELECTOR 9   // 0 = blacklist/cidr_blacklist, 1 = blacklist_b/cidr_blist_b

// Double-buffer config map entries
#define CONFIG_MAP_ENTRIES 10

// Active config selector map key
#define ACTIVE_CONFIG_KEY 0

// IPv6 extension header limit (to prevent infinite loops)
#define IPV6_EXT_MAX_DEPTH 6

#endif // __XDROP_H
