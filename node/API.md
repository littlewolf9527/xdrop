# XDrop Node Agent — API Reference

[中文文档](API.zh.md)

Base URL: `http://<node-host>:8080`

All API endpoints (except `/` and `/api/v1/health`) require the `X-API-Key` header.

---

## Authentication

Every request to the Node Agent API must include:

```
X-API-Key: <node_api_key>
```

The key is set in `config.yaml` under `auth.node_api_key`.

**Unauthenticated endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /` | Welcome / version info |
| `GET /api/v1/health` | Health check |

**Response `401`** is returned for any missing or invalid key on protected endpoints.

---

## Common Response Format

All endpoints return JSON. Errors return an appropriate HTTP status code with:

```json
{ "error": "description" }
```

---

## Info & Health

### `GET /`

```json
{
  "name": "XDrop Agent",
  "version": "2.1.1",
  "status": "running",
  "features": ["ipv4", "ipv6", "rate_limit"]
}
```

### `GET /api/v1/health`

```json
{ "status": "healthy" }
```

---

## Rules

### Rule Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (UUID) | Rule identifier |
| `src_ip` | string | Source IPv4/IPv6 (exact match). Mutually exclusive with `src_cidr` |
| `dst_ip` | string | Destination IPv4/IPv6 (exact match). Mutually exclusive with `dst_cidr` |
| `src_cidr` | string | Source CIDR prefix, e.g. `10.0.0.0/8`. Mutually exclusive with `src_ip` |
| `dst_cidr` | string | Destination CIDR prefix. Mutually exclusive with `dst_ip` |
| `src_port` | integer | Source port. `0` = any |
| `dst_port` | integer | Destination port. `0` = any |
| `protocol` | string | `tcp`, `udp`, `icmp`, `icmpv6`, or `""` (any) |
| `action` | string | `drop` or `rate_limit` |
| `rate_limit` | integer | PPS limit. Required (> 0) when `action` is `rate_limit` |
| `pkt_len_min` | integer | Minimum L3 packet length in bytes. `0` = disabled |
| `pkt_len_max` | integer | Maximum L3 packet length in bytes. `0` = disabled |
| `comment` | string | Free-text note |
| `stats` | RuleStats | Per-rule match/drop counters (included in list responses) |

### RuleStats Object

| Field | Type | Description |
|-------|------|-------------|
| `match_count` | integer | Total packets that matched this rule |
| `drop_count` | integer | Total packets dropped by this rule |
| `drop_pps` | float | Current drop rate (packets per second) |

**Constraints:**
- `src_ip` and `src_cidr` are mutually exclusive.
- `dst_ip` and `dst_cidr` are mutually exclusive.
- `rate_limit` must be > 0 when `action` is `rate_limit`.
- At least one matching field should be set (pure packet-length rules may have restrictions).

---

### `GET /api/v1/rules`

List rules. Includes per-rule statistics.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | — | Page number (≥ 1). If omitted, returns all rules |
| `limit` | integer | `50` | Results per page. Range: 1–1000 |
| `search` | string | — | Search across `src_ip`, `dst_ip`, `src_cidr`, `dst_cidr`, `id` |

> `sort`, `order`, `enabled`, and `action` query parameters are not supported on the node and will return `400`.

**Behavior:**
- If **no pagination parameters**: returns all rules with stats (legacy mode).
- If **any pagination parameter**: returns a paginated slice with stats.

**Response `200` (paginated):**

```json
{
  "rules": [
    {
      "id": "uuid",
      "src_ip": "1.2.3.4",
      "dst_port": 80,
      "protocol": "tcp",
      "action": "drop",
      "rate_limit": 0,
      "pkt_len_min": 0,
      "pkt_len_max": 0,
      "comment": "",
      "stats": {
        "match_count": 10000,
        "drop_count": 9800,
        "drop_pps": 120.5
      }
    }
  ],
  "count": 42,
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 42,
    "pages": 5
  }
}
```

**Response `200` (full list, no pagination):**

```json
{
  "rules": [ { ...Rule + stats } ],
  "count": 42
}
```

**Response `400`:** Invalid parameter or unsupported filter.

---

### `GET /api/v1/rules/:id`

Get a single rule by ID.

**Response `200`:** Rule object (without stats).

**Response `404`:** Rule not found.

---

### `POST /api/v1/rules`

Add a rule. Triggers AtomicSync (double-buffer config publish).

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | **Yes** | `drop` or `rate_limit` |
| `rate_limit` | integer | When action=`rate_limit` | PPS limit (> 0) |
| `id` | string | No | UUID. Auto-generated if omitted |
| `src_ip` | string | No | Source IP (exact) |
| `dst_ip` | string | No | Destination IP (exact) |
| `src_cidr` | string | No | Source CIDR prefix |
| `dst_cidr` | string | No | Destination CIDR prefix |
| `src_port` | integer | No | Source port (0 = any) |
| `dst_port` | integer | No | Destination port (0 = any) |
| `protocol` | string | No | `tcp`, `udp`, `icmp`, `icmpv6`, or `""` |
| `pkt_len_min` | integer | No | Min packet length (0 = disabled) |
| `pkt_len_max` | integer | No | Max packet length (0 = disabled) |
| `comment` | string | No | Notes |

**Response `200`:**

```json
{
  "success": true,
  "rule_id": "uuid",
  "message": "Rule added"
}
```

**Response `400`:** Validation error (mixed IP/CIDR, invalid action, missing rate_limit, etc.).

**Response `409`:** A rule with the same match key already exists under a different ID.

**Response `500`:** BPF map insertion failed.

---

### `DELETE /api/v1/rules/:id`

Delete a rule by ID. Triggers AtomicSync.

**Response `200`:**

```json
{
  "success": true,
  "message": "Rule deleted"
}
```

**Response `404`:** Rule not found.

**Response `500`:** BPF map deletion failed.

---

### `POST /api/v1/rules/batch`

Add multiple rules in one request. A single AtomicSync is performed after all rules are inserted.

**Request body:**

```json
{
  "rules": [
    {
      "id": "optional-uuid",
      "src_ip": "1.2.3.4",
      "dst_port": 80,
      "protocol": "tcp",
      "action": "drop"
    }
  ]
}
```

Each element uses the same fields as `POST /api/v1/rules`.

**Deduplication:** If multiple rules in the batch share the same `id`, the last one wins.

**Response `200`:**

```json
{
  "success": true,
  "added": 8,
  "failed": 2
}
```

Partial success is possible. `failed` counts the number of rejected rules.

**Response `400`:** Invalid request body.

---

### `DELETE /api/v1/rules/batch`

Delete multiple rules. A single AtomicSync is performed after all deletions.

**Request body:**

```json
{ "ids": ["uuid1", "uuid2", "uuid3"] }
```

**Response `200`:**

```json
{
  "success": true,
  "deleted": 3,
  "failed": 0
}
```

---

## Whitelist

Whitelist entries are matched before any blacklist rule. A packet matching a whitelist entry is immediately passed (`XDP_PASS`), bypassing all rules.

### Whitelist Entry Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (UUID) | Entry identifier |
| `src_ip` | string | Source IPv4/IPv6 |
| `dst_ip` | string | Destination IPv4/IPv6 |
| `src_port` | integer | Source port (`0` = any) |
| `dst_port` | integer | Destination port (`0` = any) |
| `protocol` | string | `tcp`, `udp`, `icmp`, `icmpv6`, or `""` |
| `comment` | string | Notes |

**Constraints:**
- At least one IP address (`src_ip` or `dst_ip`) is required.
- Setting `src_port`, `dst_port`, or `protocol` requires both `src_ip` and `dst_ip`.
- The BPF whitelist map supports: src-IP-only, dst-IP-only, or exact five-tuple entries.

---

### `GET /api/v1/whitelist`

List all whitelist entries.

**Response `200`:**

```json
{
  "entries": [ { ...WhitelistEntry } ],
  "count": 3
}
```

---

### `POST /api/v1/whitelist`

Add a whitelist entry.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `src_ip` | string | At least one IP | Source IP |
| `dst_ip` | string | At least one IP | Destination IP |
| `src_port` | integer | No | Source port |
| `dst_port` | integer | No | Destination port |
| `protocol` | string | No | Protocol |
| `id` | string | No | UUID. Auto-generated if omitted |
| `comment` | string | No | Notes |

**Response `200`:**

```json
{
  "success": true,
  "id": "uuid",
  "message": "Whitelist entry added"
}
```

**Response `400`:** No IP specified; port/protocol without IP.

**Response `409`:** Duplicate key already exists under a different ID.

**Response `500`:** BPF map insertion failed.

---

### `DELETE /api/v1/whitelist/:id`

Delete a whitelist entry.

**Response `200`:**

```json
{
  "success": true,
  "message": "Whitelist entry deleted"
}
```

**Response `404`:** Entry not found.

---

### `POST /api/v1/whitelist/batch`

Add multiple whitelist entries. A single BPF update is performed after all entries are inserted.

**Request body:**

```json
{
  "entries": [
    {
      "src_ip": "10.0.0.1",
      "comment": "trusted host"
    }
  ]
}
```

**Response `200`:**

```json
{
  "success": true,
  "added": 5,
  "failed": 0
}
```

---

### `DELETE /api/v1/whitelist/batch`

Delete multiple whitelist entries.

**Request body:**

```json
{ "ids": ["uuid1", "uuid2"] }
```

**Response `200`:**

```json
{
  "success": true,
  "deleted": 5,
  "failed": 0
}
```

---

## Stats

### `GET /api/v1/stats`

Full statistics snapshot. Includes global counters, system metrics, XDP interface info, and internal agent state.

**Response `200`:**

```json
{
  "total_packets": 50000000,
  "dropped_packets": 2500000,
  "passed_packets": 47000000,
  "whitelisted_packets": 500000,
  "rate_limited_packets": 100000,
  "rules_count": 42,
  "whitelist_count": 3,
  "dropped_pps": 1250.5,
  "passed_pps": 23500.0,
  "total_pps": 25000.0,
  "xdp_info": {
    "mode": "traditional",
    "interfaces": [
      { "name": "eth0", "role": "filter" }
    ]
  },
  "system": {
    "cpu_percent": 12.5,
    "mem_total_mb": 8192,
    "mem_used_mb": 1024,
    "mem_percent": 12.5,
    "uptime_seconds": 86400,
    "load_avg_1": 0.8,
    "load_avg_5": 0.9,
    "load_avg_15": 1.0
  },
  "agent_state": {
    "exact_rules": 40,
    "cidr_rules": 2,
    "whitelist_entries": 3,
    "active_slot": 1,
    "rule_map_selector": 0
  }
}
```

**Field descriptions:**

| Field | Description |
|-------|-------------|
| `total_packets` | Total packets seen since agent start |
| `dropped_packets` | Total packets dropped |
| `passed_packets` | Total packets passed |
| `whitelisted_packets` | Total packets bypassed via whitelist |
| `rate_limited_packets` | Total packets rate-limited |
| `*_pps` | Current rate (packets per second), sampled |
| `xdp_info.mode` | `traditional` or `fast_forward` |
| `xdp_info.interfaces` | Attached interfaces with their roles (`filter`, `inbound`, `outbound`) |
| `system.cpu_percent` | Host CPU utilization (%) |
| `system.mem_total_mb` | Total host memory (MB) |
| `system.mem_used_mb` | Used host memory (MB) |
| `system.uptime_seconds` | Host uptime in seconds |
| `system.load_avg_1/5/15` | 1/5/15-minute load averages |
| `agent_state.exact_rules` | Number of exact five-tuple rules in active BPF map |
| `agent_state.cidr_rules` | Number of CIDR rules in active BPF map |
| `agent_state.whitelist_entries` | Number of whitelist entries in BPF map |
| `agent_state.active_slot` | Active config map slot (0 = A, 1 = B) |
| `agent_state.rule_map_selector` | Active rule map selector (0 = primary, 1 = shadow) |

---

## Error Reference

| HTTP Status | Meaning |
|-------------|---------|
| `400` | Bad request — invalid or missing fields |
| `401` | Unauthorized — missing or invalid `X-API-Key` |
| `404` | Not found |
| `409` | Conflict — duplicate entry |
| `500` | Internal error — BPF operation failed |

All error responses include:

```json
{ "error": "description" }
```
