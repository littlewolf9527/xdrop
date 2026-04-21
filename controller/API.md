# XDrop Controller — API Reference

[中文文档](API.zh.md)

Base URL: `http://<controller-host>:8000`

---

## Authentication

The controller supports two authentication mechanisms, both optional and configurable.

### Web UI / JWT

When `auth.enabled: true`, the Web UI login endpoint issues a JWT token stored in a cookie. Subsequent requests from the browser are authenticated automatically.

For programmatic access with JWT:
```
Authorization: Bearer <token>
```

### External API Key

A static API key for scripting and integrations:
```
X-API-Key: <external_api_key>
```

Configured via `auth.external_api_key` in `config.yaml`.

### Unauthenticated Endpoints

The following endpoints always bypass authentication:

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /api/info` | Version info |
| `POST /api/auth/login` | Login |
| `POST /api/auth/logout` | Logout |
| `GET /api/auth/check` | Auth status |

---

## Common Response Format

Successful responses return `200 OK` with a JSON body. Errors return an appropriate HTTP status code and a JSON body:

```json
{ "error": "description of the error" }
```

---

## Info & Health

### `GET /health`

```json
{ "status": "healthy" }
```

### `GET /api/info`

```json
{
  "name": "XDrop Controller",
  "version": "2.6.1",
  "status": "running"
}
```

---

## Authentication

### `POST /api/auth/login`

Log in and receive a session token.

**Request body:**

```json
{
  "password": "string"
}
```

**Response `200`:**

```json
{ "success": true }
```

**Response `401`:** Invalid credentials.

---

### `POST /api/auth/logout`

Invalidate the current session.

**Response `200`:** `{ "success": true }`

---

### `GET /api/auth/check`

Check whether the current request is authenticated.

**Response `200`:**

```json
{
  "authenticated": true,
  "auth_enabled": true
}
```

---

## Rules

All rule endpoints require authentication.

### Rule Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (UUID) | Rule identifier |
| `name` | string | Human-readable label |
| `src_ip` | string | Source IPv4/IPv6 (exact match). Mutually exclusive with `src_cidr` |
| `dst_ip` | string | Destination IPv4/IPv6 (exact match). Mutually exclusive with `dst_cidr` |
| `src_cidr` | string | Source CIDR prefix, e.g. `10.0.0.0/8`. Mutually exclusive with `src_ip` |
| `dst_cidr` | string | Destination CIDR prefix. Mutually exclusive with `dst_ip` |
| `src_port` | integer | Source port. `0` = any |
| `dst_port` | integer | Destination port. `0` = any |
| `protocol` | string | `tcp`, `udp`, `icmp`, `icmpv6`, or `""` (any) |
| `action` | string | **Required.** `drop` or `rate_limit` |
| `rate_limit` | integer | PPS limit. Required (> 0) when `action` is `rate_limit` |
| `pkt_len_min` | integer | Minimum L3 packet length in bytes. `0` = disabled |
| `pkt_len_max` | integer | Maximum L3 packet length in bytes. `0` = disabled |
| `tcp_flags` | string | TCP flags filter (e.g. `SYN`, `SYN,ACK`, `RST`). Requires `protocol=tcp` |
| `source` | string | Origin label (e.g., `api`, `ui`) |
| `comment` | string | Free-text note |
| `enabled` | boolean | Whether the rule is active |
| `expires_at` | string (RFC3339) | Expiry timestamp. `null` = never expires |
| `created_at` | string (RFC3339) | Creation timestamp |
| `updated_at` | string (RFC3339) | Last update timestamp |

**Constraints:**
- `src_ip` and `src_cidr` are mutually exclusive.
- `dst_ip` and `dst_cidr` are mutually exclusive.
- `rate_limit` must be > 0 when `action` is `rate_limit`.

---

### `GET /api/v1/rules`

List rules.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | — | Page number (≥ 1). If omitted, returns all rules |
| `limit` | integer | `50` | Results per page. Range: 1–1000 |
| `search` | string | — | Search across IP/CIDR fields |
| `sort` | string | `created_at` | Sort field: `created_at` or `updated_at` |
| `order` | string | `desc` | Sort order: `asc` or `desc` |
| `enabled` | boolean | — | Filter by `true` or `false` |
| `action` | string | — | Filter by `drop` or `rate_limit` |

**Behavior:**
- If **no pagination parameters** are provided: returns all rules with aggregated `drop_pps` stats per rule (legacy mode, more expensive).
- If **any pagination parameter** is provided: returns a paginated slice without per-rule stats.

**Response `200` (paginated):**

```json
{
  "rules": [ { ...Rule } ],
  "count": 42,
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 42,
    "pages": 5
  }
}
```

**Response `200` (full list, no pagination params):**

```json
{
  "rules": [
    {
      ...Rule,
      "stats": { "drop_pps": 12.5 }
    }
  ],
  "count": 42
}
```

**Response `400`:** Invalid parameter value.

---

### `GET /api/v1/rules/top`

Top rules by current drop rate.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | `10` | Number of results. Max: 50 |

**Response `200`:**

```json
{
  "rules": [
    {
      ...Rule,
      "stats": { "drop_pps": 1200.5 }
    }
  ]
}
```

---

### `GET /api/v1/rules/:id`

Get a single rule by ID.

**Response `200`:** Rule object.

**Response `404`:** Rule not found.

---

### `POST /api/v1/rules`

Create a rule. Triggers an immediate sync to all nodes.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | **Yes** | `drop` or `rate_limit` |
| `rate_limit` | integer | When action=`rate_limit` | PPS limit (> 0) |
| `src_ip` | string | No | Source IP (exact) |
| `dst_ip` | string | No | Destination IP (exact) |
| `src_cidr` | string | No | Source CIDR prefix |
| `dst_cidr` | string | No | Destination CIDR prefix |
| `src_port` | integer | No | Source port (0 = any) |
| `dst_port` | integer | No | Destination port (0 = any) |
| `protocol` | string | No | `tcp`, `udp`, `icmp`, `icmpv6`, or `""` |
| `pkt_len_min` | integer | No | Min packet length (0 = disabled) |
| `pkt_len_max` | integer | No | Max packet length (0 = disabled) |
| `tcp_flags` | string | No | TCP flags filter (e.g. `SYN`, `RST`). Requires `protocol=tcp` |
| `decoder` | string | No | **v2.6+ syntactic sugar.** Expands to underlying `protocol` / `tcp_flags` / `match_anomaly` before storage. Allowed values: `tcp_ack`, `tcp_rst`, `tcp_fin` (Phase 2), `bad_fragment`, `invalid` (Phase 4 anomaly). Mutually exclusive with `protocol`, `tcp_flags`, and `match_anomaly` — setting any of them together → 400. Not returned on `GET /rules` (always replaced by expanded underlying fields). |
| `match_anomaly` | integer | No | **v2.6+ anomaly bitmask** — `bit0=bad_fragment (0x01)`, `bit1=invalid (0x02)`. Typically set via `decoder` sugar; explicit input is rejected when `decoder` is also set. `0` = legacy behavior (don't check anomaly bits). |
| `name` | string | No | Label |
| `comment` | string | No | Notes |
| `source` | string | No | Origin label |
| `expires_in` | string | No | Relative expiry, e.g. `1h`, `30m`, `24h` |

**v2.6+ decoder / anomaly semantics**:

- **Anomaly action restriction**: anomaly rules (any non-zero `match_anomaly`, whether set directly or via `decoder=bad_fragment|invalid`) only support `action=drop`. Sending `action=rate_limit` with an anomaly decoder returns 400 with stable diagnosis substring `does not support action=rate_limit` / `anomaly rules are drop-only`.
- **IPv6 scope guard**: `decoder=bad_fragment` is rejected with 400 when any target field (`src_ip`/`dst_ip`/`src_cidr`/`dst_cidr`) is IPv6 — v1.3 BPF does not detect IPv6 fragment anomalies. Stable diagnosis substring: `not supported for IPv6 target in v1.3` / `deferred to v1.4`. `decoder=invalid` is allowed on IPv6 (direct-TCP doff<5 check works).
- **Anomaly rule merge**: POSTing two anomaly rules with the same 5-tuple + same `action=drop` but different `decoder` (e.g. first `bad_fragment`, then `invalid`) merges the `match_anomaly` bitmask onto the existing rule (`0x01 | 0x02 = 0x03`) and returns the same rule ID — no 409 conflict, no duplicate row. BatchCreate does NOT merge (falls back to legacy UNIQUE conflict semantics). `PUT` replaces `match_anomaly` atomically, does not merge.
- **Anomaly + non-anomaly on same tuple**: creating an anomaly rule on a tuple that already has a non-anomaly rule → 409 conflict (operator must resolve the intent explicitly).

**Response `200`:**

```json
{
  "success": true,
  "rule": { ...Rule },
  "sync": { "failed": 0 }
}
```

The `sync` field is only included when one or more node syncs failed.

**Response `400`:** Validation error (e.g., `src_ip` and `src_cidr` both set; missing `rate_limit`).

---

### `PUT /api/v1/rules/:id`

Update an existing rule. Same request body as `POST`. Triggers sync.

**Response `200`:** Same as `POST`.

**Response `400`:** Validation error.

---

### `DELETE /api/v1/rules/:id`

Delete a rule. Triggers sync.

**Response `200`:**

```json
{
  "success": true,
  "message": "Rule deleted",
  "sync": { "failed": 0 }
}
```

---

### `POST /api/v1/rules/batch`

Create multiple rules in one request. Triggers a single sync after all rules are written.

**Request body:**

```json
{
  "rules": [ { ...RuleRequest }, ... ]
}
```

Each element uses the same fields as `POST /api/v1/rules`.

**Response `200`:**

```json
{
  "success": true,
  "added": 8,
  "failed": 2,
  "rules": [ { ...Rule }, ... ],
  "sync": { "failed": 0 }
}
```

Partial success is possible: `failed` indicates how many rules were rejected.

---

### `DELETE /api/v1/rules/batch`

Delete multiple rules. Triggers a single sync.

**Request body:**

```json
{ "ids": ["uuid1", "uuid2"] }
```

**Response `200`:**

```json
{
  "success": true,
  "deleted": 2,
  "failed": 0,
  "sync": { "failed": 0 }
}
```

---

## Whitelist

Whitelist entries bypass all blacklist rules. A packet matching any whitelist entry is passed immediately.

### Whitelist Entry Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (UUID) | Entry identifier |
| `name` | string | Label |
| `src_ip` | string | Source IPv4/IPv6 |
| `dst_ip` | string | Destination IPv4/IPv6 |
| `src_port` | integer | Source port (`0` = any) |
| `dst_port` | integer | Destination port (`0` = any) |
| `protocol` | string | `tcp`, `udp`, `icmp`, `icmpv6`, or `""` |
| `comment` | string | Notes |
| `created_at` | string (RFC3339) | Creation timestamp |

**Constraints:**
- At least one IP address (`src_ip` or `dst_ip`) is required.
- `src_port`, `dst_port`, and `protocol` require both `src_ip` and `dst_ip` to be set.

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

Create a whitelist entry. Triggers sync.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `src_ip` | string | At least one IP required | Source IP |
| `dst_ip` | string | At least one IP required | Destination IP |
| `src_port` | integer | No | Source port |
| `dst_port` | integer | No | Destination port |
| `protocol` | string | No | Protocol |
| `name` | string | No | Label |
| `comment` | string | No | Notes |

**Response `200`:**

```json
{
  "success": true,
  "entry": { ...WhitelistEntry },
  "sync": { "failed": 0 }
}
```

**Response `400`:** Validation error.

**Response `409`:** Duplicate entry already exists.

---

### `DELETE /api/v1/whitelist/:id`

Delete a whitelist entry. Triggers sync.

**Response `200`:**

```json
{
  "success": true,
  "message": "Whitelist entry deleted",
  "sync": { "failed": 0 }
}
```

---

### `POST /api/v1/whitelist/batch`

Bulk create whitelist entries.

**Request body:**

```json
{
  "entries": [ { ...WhitelistRequest }, ... ]
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

Bulk delete whitelist entries.

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

## Nodes

### Node Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Node identifier (set by config or auto-generated) |
| `name` | string | Node name |
| `endpoint` | string | Node API URL, e.g. `http://192.168.1.10:8080` |
| `status` | string | `online`, `offline`, `syncing`, or `unknown` |
| `last_sync` | string (RFC3339) | Last successful sync timestamp |
| `last_seen` | string (RFC3339) | Last successful health check |
| `created_at` | string (RFC3339) | Registration timestamp |
| `stats` | NodeStats | Latest stats from the node (see below) |

### NodeStats Object

```json
{
  "total_packets": 1000000,
  "dropped_packets": 100000,
  "passed_packets": 890000,
  "whitelisted_packets": 10000,
  "rate_limited_packets": 5000,
  "rules_count": 42,
  "whitelist_count": 3,
  "dropped_pps": 120.5,
  "passed_pps": 980.5,
  "total_pps": 1100.5,
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
  },
  "xdp_info": {
    "mode": "traditional",
    "interfaces": [
      { "name": "eth0", "role": "filter" }
    ]
  }
}
```

---

### `GET /api/v1/nodes`

List all registered nodes with their latest stats.

**Response `200`:**

```json
{
  "nodes": [ { ...Node } ],
  "count": 3
}
```

---

### `GET /api/v1/nodes/:id`

Get a single node.

**Response `200`:** Node object.

**Response `404`:** Node not found.

---

### `POST /api/v1/nodes`

Register a new node.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Node name |
| `endpoint` | string | **Yes** | Node API URL |
| `api_key` | string | No | API key for Controller→Node requests |

**Response `200`:**

```json
{
  "success": true,
  "node": { ...Node }
}
```

**Response `400`:** Missing or invalid fields.

**Response `403`:** Node is read-only.

---

### `PUT /api/v1/nodes/:id`

Update a node's name or API key.

**Request body:**

```json
{
  "name": "new-name",
  "api_key": "new-api-key"
}
```

**Response `200`:** `{ "success": true, "node": { ...Node } }`

**Response `403`:** Node is read-only.

---

### `DELETE /api/v1/nodes/:id`

Delete a node.

**Response `200`:** `{ "success": true, "message": "Node deleted" }`

**Response `403`:** Node is read-only.

---

### `GET /api/v1/nodes/:id/stats`

Fetch the latest stats snapshot for a specific node.

**Response `200`:** NodeStats object.

---

### `POST /api/v1/nodes/:id/sync`

Force an immediate rule push to the specified node, bypassing the normal sync interval.

**Response `200`:** `{ "success": true, "message": "Sync initiated" }`

---

## Stats

### `GET /api/v1/stats`

Aggregated cluster-wide statistics.

**Response `200`:**

```json
{
  "rules_count": 42,
  "whitelist_count": 3,
  "nodes_count": 3,
  "online_nodes": 2,
  "total_dropped_pps": 500.5,
  "total_passed_pps": 5000.5
}
```

---

## Error Reference

| HTTP Status | Meaning |
|-------------|---------|
| `400` | Bad request — invalid or missing fields |
| `401` | Unauthorized — authentication required or invalid |
| `403` | Forbidden — node is read-only |
| `404` | Not found |
| `409` | Conflict — duplicate entry |
| `500` | Internal server error |

All error responses include an `"error"` field:

```json
{ "error": "description" }
```
