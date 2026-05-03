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
  "version": "2.6.3",
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
| `protocol` | string | `tcp`, `udp`, `icmp`, `icmpv6`, `igmp`, `gre`, `esp`, or `""` (any) |
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
- If **any pagination parameter** is provided: returns a paginated slice. v2.6.3+: per-rule `stats` is now included from the in-process stats cache (was previously omitted as the AUD-001 optimization).
- If **no pagination parameters** are provided: returns all rules. v2.6.3+: by default reads from the same in-process stats cache (so the response can be up to `stats_cache.refresh_interval_seconds` stale). When `stats_cache.disabled=true`, falls back to the pre-v2.6.3 behavior (synchronous Node fan-out, no `stats_*` meta fields in the envelope).

**Stats cache meta fields (v2.6.3+):** Every paginated response — and every full-list response when the cache is enabled — now carries six top-level `stats_*` fields describing the cluster-level aggregation state. See [Stats cache contract](#stats-cache-contract-v263) below.

**Response `200` (paginated):**

```json
{
  "rules": [ { ...Rule, "stats": { "match_count": 100, "drop_count": 5, "drop_pps": 0.2 } } ],
  "count": 42,
  "pagination": { "page": 1, "limit": 50, "total": 42, "pages": 1 },
  "stats_status": "ok",
  "stats_freshness_ms": 1234,
  "stats_node_failures": {},
  "stats_offline_nodes": [],
  "stats_unknown_nodes": [],
  "stats_syncing_nodes": []
}
```

**Response `200` (full list, no pagination params, cache enabled):**

```json
{
  "rules": [ { ...Rule, "stats": { "match_count": 100, "drop_count": 5, "drop_pps": 0.2 } } ],
  "count": 42,
  "stats_status": "ok",
  "stats_freshness_ms": 1234,
  "stats_node_failures": {},
  "stats_offline_nodes": [],
  "stats_unknown_nodes": [],
  "stats_syncing_nodes": []
}
```

**Response `200` (full list, `stats_cache.disabled=true`):** Pre-v2.6.3 envelope. No `stats_*` meta fields, stats come from a synchronous fan-out at request time.

```json
{
  "rules": [ { ...Rule, "stats": { ... } } ],
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

**v2.6.3 behavior:** No more on-request fan-out. Reads from the pre-sorted top-N slice computed at refresh time, so request latency is bounded regardless of cluster size or rule count. Responses include the same six `stats_*` meta fields as `/api/v1/rules`.

**Response `200`:**

```json
{
  "rules": [ { ...Rule, "stats": { "drop_pps": 1200.5 } } ],
  "stats_status": "ok",
  "stats_freshness_ms": 567,
  "stats_node_failures": {},
  "stats_offline_nodes": [],
  "stats_unknown_nodes": [],
  "stats_syncing_nodes": []
}
```

When the cache is in a "no usable snapshot" state (`initializing`, `waiting_for_health`, `no_nodes`, `failed_no_snapshot`, `disabled`), `rules` is an empty array and the front-end is expected to dispatch off `stats_status` to render the appropriate message.

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
| `protocol` | string | No | `tcp`, `udp`, `icmp`, `icmpv6`, `igmp`, `gre`, `esp`, or `""` |
| `pkt_len_min` | integer | No | Min packet length (0 = disabled) |
| `pkt_len_max` | integer | No | Max packet length (0 = disabled) |
| `tcp_flags` | string | No | TCP flags filter (e.g. `SYN`, `RST`). Requires `protocol=tcp` |
| `decoder` | string | No | **v2.6+ syntactic sugar.** Expands to underlying `protocol` / `tcp_flags` / `match_anomaly` before storage. Allowed values: `tcp_ack`, `tcp_rst`, `tcp_fin` (Phase 2), `bad_fragment`, `invalid` (Phase 4 anomaly). Mutually exclusive with `protocol`, `tcp_flags`, and `match_anomaly` — setting any of them together → 400. Not returned on `GET /rules` (always replaced by expanded underlying fields). |
| `match_anomaly` | integer | No | **v2.6+ anomaly bitmask** — `bit0=bad_fragment (0x01)`, `bit1=invalid (0x02)`. Typically set via `decoder` sugar; explicit input is rejected when `decoder` is also set. `0` = legacy behavior (don't check anomaly bits). |
| `name` | string | No | Label |
| `comment` | string | No | Notes |
| `source` | string | No | Origin label |
| `expires_in` | string | No | Relative expiry, e.g. `1h`, `30m`, `24h` |
| `enabled` | boolean | No | default `true`; `false` stores the rule in DB without syncing to BPF |

**v2.6+ decoder / anomaly semantics**:

- **Anomaly action restriction**: anomaly rules (any non-zero `match_anomaly`, whether set directly or via `decoder=bad_fragment|invalid`) only support `action=drop`. Sending `action=rate_limit` with an anomaly decoder returns 400 with stable diagnosis substring `does not support action=rate_limit` / `anomaly rules are drop-only`.
- **IPv6 scope guard**: `decoder=bad_fragment` is rejected with 400 when any target field (`src_ip`/`dst_ip`/`src_cidr`/`dst_cidr`) is IPv6 — v1.3 BPF does not detect IPv6 fragment anomalies. Stable diagnosis substring: `not supported for IPv6 target in v1.3` / `deferred to v1.4`. `decoder=invalid` is allowed on IPv6 (direct-TCP doff<5 check works).
- **Anomaly rule merge**: POSTing two anomaly rules with the same 5-tuple + same `action=drop` but different `decoder` (e.g. first `bad_fragment`, then `invalid`) merges the `match_anomaly` bitmask onto the existing rule (`0x01 | 0x02 = 0x03`) and returns the same rule ID — no 409 conflict, no duplicate row. BatchCreate does NOT merge (falls back to legacy UNIQUE conflict semantics). `PUT` replaces `match_anomaly` atomically, does not merge.
- **Anomaly + non-anomaly on same tuple**: creating an anomaly rule on a tuple that already has a non-anomaly rule → 409 conflict (operator must resolve the intent explicitly).
- **Portless protocol + port (B-10)**: ICMP, ICMPv6, IGMP, GRE, ESP do not carry L4 ports. Specifying a non-zero `src_port` or `dst_port` together with one of these protocols returns `400` with diagnosis `protocol=<name> does not carry ports (src_port/dst_port must be 0)`. The BPF data plane only fills `key.src_port/dst_port` for TCP and UDP; storing a portless+port rule would create a permanent lookup miss (a "ghost" rule that never matches). `protocol=all` and empty protocol allow ports — `all` is a wildcard that may match TCP/UDP traffic. The same rule applies to `WhitelistService.Create`.

**Response `201`:**

```json
{
  "success": true,
  "rule": { ...Rule },
  "sync": { "failed": 0 }
}
```

The `sync` field is **always present**. `success: true` only indicates the Controller DB mutation succeeded; check `sync.failed > 0` to determine whether the rule reached the data plane on all nodes.

**Response `400`:** Validation error (e.g., `src_ip` and `src_cidr` both set; missing `rate_limit`).

---

### `PUT /api/v1/rules/:id`

Update an existing rule. Same request body as `POST`. Triggers sync.

**Key fields are immutable**: `src_ip`, `dst_ip`, `src_cidr`, `dst_cidr`, `protocol`, `src_port`, `dst_port`. Sending a different non-empty/non-zero value returns `400` with diagnosis `<field> is a key field and cannot be modified`. Delete and recreate the rule instead. Sending the same value as currently stored is accepted as a no-op (this allows decoder sugar like `decoder=tcp_rst` on an existing tcp rule, which expands to `protocol=tcp` matching the stored value).

**Zero-value PUT limitation**: `protocol`, `src_port`, `dst_port` use scalar (`string` / `int`) request schema, so the server cannot distinguish "field omitted" from "field explicitly set to empty/zero". A request like `PUT {"dst_port": 0}` against an `dst_port=80` rule is treated as **omit/no-op**, not as a clear-to-zero. To change a key field to a different value (including zero), delete and recreate the rule. Pointer-based tri-state schema for these fields is on the v2.7 backlog (see plan §6 R3-002). Same pattern applies to `rate_limit` and `match_anomaly`.

**Explicit-clear for `pkt_len_min/max` (v2.6.4+)**: `pkt_len_min` and `pkt_len_max` use **pointer tri-state** schema — omitting the field keeps the existing value, sending `0` explicitly clears it, sending a positive value sets it. This aligns with `tcp_flags` and `comment`.

**Explicit-clear limitation (remaining int fields)**: `rate_limit` and `match_anomaly` still use `int` schema; sending `0` is treated as "omit/keep existing" rather than "clear". The one exception is `action=drop` in the PUT body — this automatically zeroes `rate_limit`.

`tcp_flags` and `comment` use pointer tri-state: omitting the field keeps the existing value, sending `""` clears it, sending a non-empty string sets it.

**`enabled` field (v2.6.4+)**: pointer tri-state — omitting keeps existing value. Toggling triggers the appropriate data-plane transition: `false→true` adds the rule to BPF (`SyncAddRule`); `true→false` removes it from BPF (`SyncDeleteRule`); `false→false` or `true→true` behaves as before (no-op or update).

**Decoder switching contract (v2.6.2+)**: `tcp_flags` and `match_anomaly` are mutually exclusive at the data plane. When using PUT to switch a rule's decoder type, the client must explicitly clear the conflicting field — the server does NOT auto-clear:

- **tcp_flags rule → anomaly decoder** (e.g. `decoder=bad_fragment` / `invalid`): the request must also send `tcp_flags: ""` to explicitly clear the existing `tcp_flags`. Sending only `decoder=bad_fragment` (without `tcp_flags: ""`) returns `400` with diagnosis substring `cannot have both tcp_flags and match_anomaly`.
- **anomaly rule → tcp_* decoder** (e.g. `decoder=tcp_rst`): `match_anomaly` cannot be explicit-cleared via PUT (its `int` schema has no tri-state). Switching is rejected; delete and recreate the rule instead.

Rationale: v2.6.2 keeps PUT semantics strictly explicit — the server does not implicitly mutate fields the client didn't send. This is symmetric across both directions and consistent with `tcp_flags`'s pointer tri-state contract.

**Response `200`:** Same as `POST`.

**Response `400`:** Validation error.

**Response `404`:** Rule not found.

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
| `protocol` | string | `tcp`, `udp`, `icmp`, `icmpv6`, `igmp`, `gre`, `esp`, or `""` |
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

This endpoint does NOT use the v2.6.3 stats cache. The PPS rollup is computed via a separate, lightweight node-stats path.

---

### `GET /api/v1/stats/cache_health` *(v2.6.3+)*

Operator-facing diagnostic for the in-process aggregated rule-stats cache. Surfaces enough state to tell apart "Node fan-out is failing" vs "the refresh ticker has stalled" without reading logs.

**Response `200`:**

```json
{
  "status": "partial_stale",
  "last_refresh_status": "partial",
  "last_attempt_unix_ms": 1745988123456,
  "last_snapshot_unix_ms": 1745988123100,
  "last_full_success_unix_ms": 1745988123100,
  "freshness_ms": 356,
  "configured_nodes": 3,
  "attempted_nodes": 2,
  "succeeded_nodes": 2,
  "failed_nodes": 0,
  "skipped_offline_nodes": 1,
  "skipped_unknown_nodes": 0,
  "skipped_syncing_nodes": 0,
  "offline_node_names": ["node-c"],
  "unknown_node_names": [],
  "syncing_node_names": [],
  "node_errors": {},
  "rule_count": 142,
  "top_n_cache_size": 50,
  "top_rules_cached": 12,
  "last_refresh_duration_ms": 87,
  "consecutive_all_fail": 0
}
```

`status` and `last_refresh_status` may differ:
- `status` is the **derived** state at read time (includes `stale` / `partial_stale` based on `now - last_snapshot_unix_ms`).
- `last_refresh_status` is the **base outcome** of the most recent refresh (never `stale` / `partial_stale`).

When `status=partial_stale` but `last_refresh_status=partial`, the refresh ticker is stuck — the last successful refresh produced a partial snapshot, but no newer round has landed since.

**Response `503`:** Cache not configured (controller built without wiring the cache).

---

## Stats cache contract (v2.6.3+)

Every stats-aware endpoint (`/rules?page=...`, `/rules/top`, `/rules` listAll when cache is enabled) returns six top-level `stats_*` fields describing the cluster-level cache state.

| Field | Type | Description |
|-------|------|-------------|
| `stats_status` | string | One of 10 states: see table below |
| `stats_freshness_ms` | integer or `null` | Milliseconds since last displayable snapshot. `null` when the cache has no displayable data yet (initializing / disabled / etc.) |
| `stats_node_failures` | object | `{node_name: error_string}` for **attempted Online** nodes that failed. May be empty even in partial / failed states |
| `stats_offline_nodes` | array of strings | Nodes whose health status is `offline` and were not contacted this round |
| `stats_unknown_nodes` | array of strings | Nodes still in `unknown` state (HealthChecker hasn't reached its first verdict) |
| `stats_syncing_nodes` | array of strings | Nodes currently in `syncing` state |

### Status values

| `stats_status` | Per-rule `stats` field | Meaning |
|----------------|------------------------|---------|
| `initializing` | omitted | Cache hasn't completed its first refresh |
| `waiting_for_health` | omitted | All nodes still `unknown`/`syncing`; HealthChecker hasn't promoted any yet |
| `no_nodes` | omitted | `configured_nodes=0`. Cluster has no Node configured |
| `ok` | always present (synth `0/0/0` for no-hits) | All configured nodes contributed successfully and the snapshot is fresh. The only state where `0/0/0` is safe to interpret as "definitely no hits" |
| `partial` | only when the rule had hits on a succeeded node | One or more nodes were excluded (failed / offline / unknown / syncing). Numbers are a lower bound |
| `stale` | last snapshot's stats | `ok` baseline that's now older than `stale_threshold_seconds` (refresh ticker likely stuck) |
| `partial_stale` | last snapshot's stats | `partial` baseline that's now older than threshold (refresh ticker stuck) |
| `failed` | last snapshot's stats | All nodes failed/skipped on the most recent refresh, but a previous snapshot is preserved |
| `failed_no_snapshot` | omitted | All nodes failed/skipped and the cache has no fallback snapshot |
| `disabled` | omitted | `stats_cache.disabled=true` |

### Single-node vs multi-node behavior

Some states are only reachable in multi-node clusters:
- `partial` / `partial_stale` require the cluster to have ≥2 nodes — if one fails on a single-node cluster the result is `failed_no_snapshot` (or `failed` once a snapshot exists).
- `failed` always means *every* node failed, so on a multi-node cluster it requires all nodes to fail simultaneously.

### `listAll` semantics change

In v2.6.2 and earlier, `GET /api/v1/rules` (no pagination params) performed a synchronous Node fan-out on every request — responses were always real-time. v2.6.3 changes the default to reading from the in-process cache, capped at `stats_cache.refresh_interval_seconds` lag.

Diagnostic scripts that need real-time stats can:
1. Hit the Node `/api/v1/rules` endpoint directly (Node API is unchanged).
2. Set `stats_cache.disabled=true` in the controller config and restart — `listAll` falls back to the legacy fan-out behavior.

There is no `?live_stats=true` query parameter; the two options above are the supported escape hatches.

### Node-side load impact

Enabling the cache (the default) adds a periodic background `GET /api/v1/rules` from Controller to every Online Node, regardless of whether anyone is using the UI. At default settings (5s interval, ≤1000 rules/node) this is ~12 calls/min/node. Larger deployments should consider:
- Increasing `stats_cache.refresh_interval_seconds` (max 60).
- Increasing `stats_cache.per_node_timeout_seconds` for slow links.
- Setting `stats_cache.disabled=true` to opt out entirely.

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
