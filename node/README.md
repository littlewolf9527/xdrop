# XDrop Node Agent

The data plane component of XDrop. Runs on each filtering host, loads BPF/XDP programs onto network interfaces, and exposes a REST API for rule management and statistics.

[中文文档](README.zh.md)

---

## How It Works

### XDP Packet Pipeline

```
NIC (hardware)
    │
    ▼  ← XDP hook (before sk_buff allocation)
┌─────────────────────────────────────────────────────────┐
│  xdp_whitelist_gate  [xdrop_gate.elf]                   │
│                                                         │
│  1. Parse Ethernet → (VLAN 802.1Q/802.1ad) → IP        │
│                                                         │
│  2. Whitelist bitmap check (31-combo, v2.7.0+)         │
│     └─ wl_bitmap == 0 → tail-call xdp_firewall_main   │
│                                                         │
│  3. 31-combo whitelist lookup (hash map, bitmap-gated) │
│     └─ HIT  → XDP_PASS  (bypass all blacklist rules)   │
│                                                         │
│  4. tail-call → xdp_firewall_main  [xdrop_main.elf]    │
└─────────────────────────────────────────────────────────┘
    │  (tail-call, slot 1 in prog_tail_map)
    ▼
┌─────────────────────────────────────────────────────────┐
│  xdp_firewall_main  [xdrop_main.elf]                    │
│                                                         │
│  5. BL bitmap check (64-bit, 31 active combos)         │
│     └─ Skip combos with no active rules                │
│                                                         │
│  6. Exact blacklist lookup (hash map)                   │
│     └─ HIT  → check pkt_len + tcp_flags               │
│              → match → apply action (DROP / RATE_LIMIT)│
│              → mismatch → continue to next combo       │
│                                                         │
│  7. CIDR blacklist lookup (LPM trie — src then dst)    │
│     └─ HIT  → anomaly? → tail-call xdp_anomaly_verify │
│              → match → apply action (DROP / RATE_LIMIT)│
│                                                         │
│  8. No match → XDP_PASS                                │
└─────────────────────────────────────────────────────────┘
    │
    ▼  XDP_DROP or XDP_PASS
kernel network stack
```

### BPF Maps

| Map | Type | Max Entries | Purpose |
|-----|------|-------------|---------|
| `whitelist` / `whitelist_b` | Hash | 50,000 each | Bypass entries — active + shadow (double-buffer, v2.7.0+) |
| `blacklist` / `blacklist_b` | Hash | 500,000 each | Exact five-tuple rules (double-buffer) |
| `cidr_blacklist` / `cidr_blist_b` | Hash | 500,000 each | CIDR rule ID → action/rate mapping (double-buffer) |
| `sv4_cidr_trie` / `dv4_cidr_trie` | LPM Trie | 50,000 each | IPv4 src/dst CIDR prefix lookup |
| `sv6_cidr_trie` / `dv6_cidr_trie` | LPM Trie | 50,000 each | IPv6 src/dst CIDR prefix lookup |
| `config_a` / `config_b` | Array | 12 | Double-buffer config (BL/WL bitmaps, counts, FF flags, selectors) |
| `active_config` | Array | 1 | Config map selector (0 = A, 1 = B) |
| `stats` | Per-CPU Array | 5 | Global packet counters (shared between gate and main ELFs) |
| `rl_states` | Hash | 100,000 | Per-rule token bucket state for rate limiting |
| `prog_tail_map` | PROG_ARRAY | 2 | Tail-call dispatch: slot 0 = xdp_anomaly_verify, slot 1 = xdp_firewall_main |
| `tailcall_fail_stats` | Per-CPU Array | 1 | Gate-exclusive fail-open counter (gate→main tail-call failures) |

### Bitmap Optimization

Each rule matches a combination of fields (e.g., "src_ip + dst_port + protocol" = combo type 7). The BPF program maintains a 64-bit bitmap where bit N is set if any active rule uses combo type N. Before probing the hash map, the XDP program checks the bitmap — if the bit for the current packet's matching combination is not set, the entire lookup is skipped. This keeps the hot path at O(1) even with many rule types.

### AtomicSync (Double-Buffer Rule Publishing)

Updating rules involves two operations that must appear atomic to the BPF data path: writing entries to the hash map and updating the lookup bitmap. XDrop uses an RCU-style double-buffer to eliminate the inconsistency window.

**Blacklist AtomicSync:**

```
Active slot = A                    Shadow slot = B
──────────────────────────────────────────────────────
① Write rule to blacklist map  (visible to BPF immediately)
② Update internal ref-counts
③ Copy config_a → config_b
④ Rebuild bitmap in config_b   (BPF still reads config_a)
⑤ atomic: active_config[0] = 1 ← BPF switches to config_b
──────────────────────────────────────────────────────
Active slot = B                    Shadow slot = A (next update)
```

**Whitelist AtomicSync (v2.7.0+, `DoWhitelistAtomicSync`):**

```
Active map = whitelist              Shadow map = whitelist_b
──────────────────────────────────────────────────────
① Clear whitelist_b (shadow)
② Write all entries to whitelist_b
③ Update CONFIG_WL_BITMAP in shadow config
④ atomic: flip CONFIG_WL_MAP_SELECTOR ← BPF switches to whitelist_b
⑤ Clear old active whitelist (now shadow)
──────────────────────────────────────────────────────
Active map = whitelist_b            Shadow map = whitelist
```

Single add/delete writes directly to the active map (single BPF update is atomic). Full sync (Controller FullSync) uses `DoWhitelistAtomicSync`. Three selectors track active sides independently — `active_config` for the config map pair, `rule_map_selector` for the blacklist map pair, `CONFIG_WL_MAP_SELECTOR` for the whitelist map pair.

---

## Deployment Modes

### Traditional Mode

XDP is attached to a single network interface. Traffic arriving on that interface is filtered; outbound traffic is unaffected.

```yaml
server:
  interface: eth0

fast_forward:
  enabled: false
```

### Fast-Forward Mode

XDP is attached to both an inbound (WAN) and an outbound (LAN) interface. The agent acts as a transparent L2 filtering bridge between the two interfaces.

```yaml
fast_forward:
  enabled: true
  pairs:
    - inbound: ens33     # WAN / upstream
      outbound: ens38    # LAN / downstream
      filter_on: both    # "inbound", "outbound", or "both"
```

---

## Configuration

```bash
cp config.example.yaml config.yaml
```

Key settings:

```yaml
server:
  host: 0.0.0.0
  port: 8080
  interface: eth0          # NIC to attach XDP (traditional mode)

auth:
  node_api_key: CHANGE_ME_NODE_KEY              # Required for all API requests; must be a real value (no placeholders)
  controller_url: http://controller-host:8000   # Leave empty for pull-only / standalone mode
  controller_sync_key: CHANGE_ME_SYNC_KEY       # Matches controller auth.external_api_key. Required when controller_url is set.
```

---

## Build

Requires Linux, clang ≥ 11, and Go ≥ 1.21. The BPF program must be compiled **before** the Go agent (the `.elf` is embedded at compile time).

```bash
# From the repository root (run on a Linux host):
./scripts/build-node.sh          # builds BPF program then Go agent

# Or step by step:
./scripts/build-node.sh bpf      # clang → node/bpf/xdrop_main.elf + xdrop_gate.elf
./scripts/build-node.sh agent    # go build → node/xdrop-agent
```

The compiled binary is placed at `node/xdrop-agent`.

---

## Running

```bash
# Start (requires root — XDP needs CAP_NET_ADMIN)
sudo ./scripts/node.sh start

# Stop / restart
sudo ./scripts/node.sh stop
sudo ./scripts/node.sh restart

# Status (process, API health, rule/whitelist counts, XDP mode)
sudo ./scripts/node.sh status

# Tail logs
./scripts/node.sh logs
```

Default log file: `/tmp/xdrop-agent.log`

Environment variable `PORT` overrides the default API port (8080).

---

## API Reference

All routes are under `/api/v1/`. Every request must include `X-API-Key: <node_api_key>`.

### Rules

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/rules` | List rules. Supports `?page=&limit=` |
| `POST` | `/api/v1/rules` | Create a rule (triggers AtomicSync) |
| `GET` | `/api/v1/rules/:id` | Get rule by ID |
| `DELETE` | `/api/v1/rules/:id` | Delete rule (triggers AtomicSync) |
| `POST` | `/api/v1/rules/batch` | Bulk create |
| `DELETE` | `/api/v1/rules/batch` | Bulk delete |

### Whitelist

**Phase 8 (v2.7.0+):** Any non-empty five-tuple field subset is a valid whitelist key (31 canonical combos, bitmap-gated BPF lookup).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/whitelist` | List entries |
| `POST` | `/api/v1/whitelist` | Create entry |
| `DELETE` | `/api/v1/whitelist/:id` | Delete entry |
| `POST` | `/api/v1/whitelist/batch` | Bulk create |
| `DELETE` | `/api/v1/whitelist/batch` | Bulk delete |
| `POST` | `/api/v1/sync/whitelist` | **v2.7.0+.** Atomic full whitelist replacement (used by Controller FullSync) |

### Stats & Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check: `{"status":"healthy"}` |
| `GET` | `/api/v1/stats` | Full stats: PPS, rule counts, XDP info, system metrics, agent state |

**Stats response includes:**

```json
{
  "total_pps": 25000.0,
  "dropped_pps": 1250.5,
  "rules_count": 42,
  "whitelist_count": 3,
  "xdp_info": {
    "mode": "traditional",
    "interfaces": [{ "name": "eth0", "role": "filter" }]
  },
  "system": {
    "cpu_percent": 12.5,
    "mem_used_mb": 128,
    "uptime_seconds": 86400
  },
  "agent_state": {
    "active_slot": 1,
    "rule_map_selector": 0,
    "exact_rules": 40,
    "cidr_rules": 2,
    "whitelist_entries": 3,
    "tailcall_fail": 0
  }
}
```

---

## Directory Structure

```
node/
├── bpf/
│   ├── xdrop_gate.c      # Gate program: whitelist 31-combo + tail-call dispatch (GPL-2.0)
│   ├── xdrop_main.c      # Main program: blacklist lookup + anomaly verify (GPL-2.0)
│   ├── xdrop.h           # Shared BPF type definitions and map declarations
│   └── Makefile          # clang compilation → xdrop_gate.elf + xdrop_main.elf
└── agent/
    ├── main.go           # Entry point (load BPF, start API server)
    ├── api/
    │   ├── handlers.go   # HTTP handlers for health, stats, welcome
    │   ├── rules_list.go # Rule query handlers
    │   ├── rules_mutation.go # Rule create/delete + AtomicSync
    │   ├── whitelist.go  # Whitelist handlers
    │   ├── sync.go       # AtomicSync engine
    │   ├── agent_state.go # In-memory state (rules, whitelist, bitmaps)
    │   ├── bpf_types.go  # BPF map key/value structs
    │   └── types.go      # API request/response types
    ├── cidr/             # CIDR validation, ID allocation, overlap detection
    ├── config/           # Configuration loading (Viper)
    ├── ifmgr/            # Interface and XDP program lifecycle management
    ├── sync/             # Controller sync client (pull on startup)
    ├── go.mod
    └── go.sum
```
