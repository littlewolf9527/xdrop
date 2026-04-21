# XDrop Controller — API 参考

[English](API.md)

Base URL：`http://<controller-host>:8000`

---

## 认证

Controller 支持两种认证方式，均为可选项，通过配置文件控制。

### Web UI / JWT

当 `auth.enabled: true` 时，通过 Web UI 登录后会颁发 JWT，由浏览器自动管理（Cookie）。

编程访问时，将 JWT 放在请求头中：
```
Authorization: Bearer <token>
```

### 外部 API Key

适用于脚本或集成场景的静态密钥：
```
X-API-Key: <external_api_key>
```

在 `config.yaml` 的 `auth.external_api_key` 字段中配置。

### 免认证端点

以下端点始终跳过认证：

| 端点 | 说明 |
|------|------|
| `GET /health` | 健康检查 |
| `GET /api/info` | 版本信息 |
| `POST /api/auth/login` | 登录 |
| `POST /api/auth/logout` | 登出 |
| `GET /api/auth/check` | 认证状态查询 |

---

## 通用响应格式

成功请求返回 `200 OK` 及 JSON 响应体。错误请求返回对应 HTTP 状态码及：

```json
{ "error": "错误描述" }
```

---

## 信息与健康检查

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

## 认证接口

### `POST /api/auth/login`

登录并获取会话令牌。

**请求体：**

```json
{
  "password": "string"
}
```

**响应 `200`：**

```json
{ "success": true }
```

**响应 `401`：** 密码错误。

---

### `POST /api/auth/logout`

注销当前会话。

**响应 `200`：** `{ "success": true }`

---

### `GET /api/auth/check`

查询当前请求是否已认证。

**响应 `200`：**

```json
{
  "authenticated": true,
  "auth_enabled": true
}
```

---

## 规则

所有规则接口需要认证。

### 规则对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string (UUID) | 规则 ID |
| `name` | string | 规则名称 |
| `src_ip` | string | 源 IPv4/IPv6（精确匹配），与 `src_cidr` 互斥 |
| `dst_ip` | string | 目的 IPv4/IPv6（精确匹配），与 `dst_cidr` 互斥 |
| `src_cidr` | string | 源 CIDR 前缀，如 `10.0.0.0/8`，与 `src_ip` 互斥 |
| `dst_cidr` | string | 目的 CIDR 前缀，与 `dst_ip` 互斥 |
| `src_port` | integer | 源端口，`0` = 任意 |
| `dst_port` | integer | 目的端口，`0` = 任意 |
| `protocol` | string | `tcp`、`udp`、`icmp`、`icmpv6` 或 `""`（任意） |
| `action` | string | **必填**，`drop` 或 `rate_limit` |
| `rate_limit` | integer | PPS 限速值，action=`rate_limit` 时必填（> 0） |
| `pkt_len_min` | integer | L3 最小包长（字节），`0` = 不限 |
| `pkt_len_max` | integer | L3 最大包长（字节），`0` = 不限 |
| `tcp_flags` | string | TCP 标志过滤（如 `SYN`、`SYN,ACK`、`RST`），需 `protocol=tcp` |
| `source` | string | 来源标记（如 `api`、`ui`） |
| `comment` | string | 备注 |
| `enabled` | boolean | 规则是否启用 |
| `expires_at` | string (RFC3339) | 过期时间，`null` = 永不过期 |
| `created_at` | string (RFC3339) | 创建时间 |
| `updated_at` | string (RFC3339) | 最后更新时间 |

**约束：**
- `src_ip` 与 `src_cidr` 互斥；`dst_ip` 与 `dst_cidr` 互斥。
- action=`rate_limit` 时，`rate_limit` 必须 > 0。

---

### `GET /api/v1/rules`

查询规则列表。

**查询参数：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `page` | integer | — | 页码（≥ 1）。不传则返回全部规则 |
| `limit` | integer | `50` | 每页条数，范围 1–1000 |
| `search` | string | — | 搜索 IP/CIDR 字段 |
| `sort` | string | `created_at` | 排序字段：`created_at` 或 `updated_at` |
| `order` | string | `desc` | 排序方向：`asc` 或 `desc` |
| `enabled` | boolean | — | 按启用状态过滤：`true` 或 `false` |
| `action` | string | — | 按动作过滤：`drop` 或 `rate_limit` |

**行为说明：**
- **不传任何分页参数**：返回全部规则，并附带每条规则的 `drop_pps` 统计（兼容旧版，查询开销较大）。
- **传入任意分页参数**：返回分页结果，不含每条规则统计。

**响应 `200`（分页）：**

```json
{
  "rules": [ { ...规则对象 } ],
  "count": 42,
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 42,
    "pages": 5
  }
}
```

**响应 `200`（全量，不含分页参数）：**

```json
{
  "rules": [
    {
      ...规则对象,
      "stats": { "drop_pps": 12.5 }
    }
  ],
  "count": 42
}
```

**响应 `400`：** 参数值非法。

---

### `GET /api/v1/rules/top`

按当前丢包速率排序的 Top 规则。

**查询参数：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `limit` | integer | `10` | 返回条数，最大 50 |

**响应 `200`：**

```json
{
  "rules": [
    {
      ...规则对象,
      "stats": { "drop_pps": 1200.5 }
    }
  ]
}
```

---

### `GET /api/v1/rules/:id`

按 ID 查询单条规则。

**响应 `200`：** 规则对象。

**响应 `404`：** 规则不存在。

---

### `POST /api/v1/rules`

创建规则。创建后立即触发向所有节点的同步推送。

**请求体：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `action` | string | **是** | `drop` 或 `rate_limit` |
| `rate_limit` | integer | action=`rate_limit` 时 | PPS 限速值（> 0） |
| `src_ip` | string | 否 | 源 IP（精确） |
| `dst_ip` | string | 否 | 目的 IP（精确） |
| `src_cidr` | string | 否 | 源 CIDR 前缀 |
| `dst_cidr` | string | 否 | 目的 CIDR 前缀 |
| `src_port` | integer | 否 | 源端口（0 = 任意） |
| `dst_port` | integer | 否 | 目的端口（0 = 任意） |
| `protocol` | string | 否 | `tcp`、`udp`、`icmp`、`icmpv6` 或 `""` |
| `pkt_len_min` | integer | 否 | 最小包长（0 = 不限） |
| `pkt_len_max` | integer | 否 | 最大包长（0 = 不限） |
| `tcp_flags` | string | 否 | TCP 标志过滤（如 `SYN`、`SYN,ACK`、`RST`），需 `protocol=tcp` |
| `decoder` | string | 否 | **v2.6+ 语义糖。** 落库前自动展开为 `protocol` / `tcp_flags` / `match_anomaly` 底层字段。可选值：`tcp_ack`、`tcp_rst`、`tcp_fin`（Phase 2）、`bad_fragment`、`invalid`（Phase 4 anomaly）。与 `protocol`、`tcp_flags`、`match_anomaly` 互斥——同时设置任一 → 400。`GET /rules` 响应体**不**返回本字段（展开后的底层字段才返）。 |
| `match_anomaly` | integer | 否 | **v2.6+ anomaly 位图** —— `bit0=bad_fragment (0x01)`、`bit1=invalid (0x02)`。通常通过 `decoder` 糖下发；与 `decoder` 同时设置时显式 `match_anomaly` 输入会被拒。`0` = 不检查 anomaly（老语义）。 |
| `name` | string | 否 | 规则名称 |
| `comment` | string | 否 | 备注 |
| `source` | string | 否 | 来源标记 |
| `expires_in` | string | 否 | 相对过期时间，如 `1h`、`30m`、`24h` |

**v2.6+ decoder / anomaly 语义**：

- **Anomaly action 限制**：anomaly 规则（任何 `match_anomaly` 非零，无论是直接设置还是通过 `decoder=bad_fragment|invalid`）仅支持 `action=drop`。anomaly + `rate_limit` → 400，错误体含稳定子串 `does not support action=rate_limit` / `anomaly rules are drop-only`。
- **IPv6 scope guard**：`decoder=bad_fragment` 配合任何 IPv6 target 字段（`src_ip`/`dst_ip`/`src_cidr`/`dst_cidr`）→ 400 拒绝，v1.3 BPF 不检测 IPv6 fragment anomaly。错误体含稳定子串 `not supported for IPv6 target in v1.3` / `deferred to v1.4`。`decoder=invalid` 在 IPv6 上允许（直连 TCP doff<5 检测生效）。
- **Anomaly 规则合并**：同 5-tuple + 同 `action=drop` 的两次 anomaly 下发（如先 `bad_fragment`、再 `invalid`）自动把 `match_anomaly` bitmap OR 合并到既有规则（`0x01 | 0x02 = 0x03`），返回**同一** rule ID，不 409 冲突、不新增行。BatchCreate **不**做合并（沿用老 UNIQUE 冲突语义）。`PUT` 为**替换**语义，不合并。
- **Anomaly 与非-anomaly 规则共存**：在已有非-anomaly 规则的 tuple 上再下发 anomaly → 409（需显式解决意图）。

**响应 `200`：**

```json
{
  "success": true,
  "rule": { ...规则对象 },
  "sync": { "failed": 0 }
}
```

`sync` 字段仅在有节点同步失败时包含在响应中。

**响应 `400`：** 校验错误（如同时设置了 `src_ip` 和 `src_cidr`；缺少 `rate_limit` 等）。

---

### `PUT /api/v1/rules/:id`

更新已有规则。请求体与 `POST` 相同。触发同步。

**响应 `200`：** 同 `POST`。

**响应 `400`：** 校验错误。

---

### `DELETE /api/v1/rules/:id`

删除规则。触发同步。

**响应 `200`：**

```json
{
  "success": true,
  "message": "Rule deleted",
  "sync": { "failed": 0 }
}
```

---

### `POST /api/v1/rules/batch`

批量创建规则。所有规则写入后触发一次同步。

**请求体：**

```json
{
  "rules": [ { ...规则请求体 }, ... ]
}
```

每个元素与 `POST /api/v1/rules` 的请求体字段相同。

**响应 `200`：**

```json
{
  "success": true,
  "added": 8,
  "failed": 2,
  "rules": [ { ...规则对象 }, ... ],
  "sync": { "failed": 0 }
}
```

支持部分成功，`failed` 表示被拒绝的条数。

---

### `DELETE /api/v1/rules/batch`

批量删除规则。触发一次同步。

**请求体：**

```json
{ "ids": ["uuid1", "uuid2"] }
```

**响应 `200`：**

```json
{
  "success": true,
  "deleted": 2,
  "failed": 0,
  "sync": { "failed": 0 }
}
```

---

## 白名单

白名单条目在所有黑名单规则之前匹配。命中白名单的数据包直接通过（`XDP_PASS`）。

### 白名单条目对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string (UUID) | 条目 ID |
| `name` | string | 名称 |
| `src_ip` | string | 源 IPv4/IPv6 |
| `dst_ip` | string | 目的 IPv4/IPv6 |
| `src_port` | integer | 源端口（`0` = 任意） |
| `dst_port` | integer | 目的端口（`0` = 任意） |
| `protocol` | string | `tcp`、`udp`、`icmp`、`icmpv6` 或 `""` |
| `comment` | string | 备注 |
| `created_at` | string (RFC3339) | 创建时间 |

**约束：**
- 至少需要一个 IP 地址（`src_ip` 或 `dst_ip`）。
- 设置端口或协议时，`src_ip` 和 `dst_ip` 必须同时存在。

---

### `GET /api/v1/whitelist`

查询所有白名单条目。

**响应 `200`：**

```json
{
  "entries": [ { ...白名单条目对象 } ],
  "count": 3
}
```

---

### `POST /api/v1/whitelist`

创建白名单条目。触发同步。

**请求体：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src_ip` | string | 至少一个 IP | 源 IP |
| `dst_ip` | string | 至少一个 IP | 目的 IP |
| `src_port` | integer | 否 | 源端口 |
| `dst_port` | integer | 否 | 目的端口 |
| `protocol` | string | 否 | 协议 |
| `name` | string | 否 | 名称 |
| `comment` | string | 否 | 备注 |

**响应 `200`：**

```json
{
  "success": true,
  "entry": { ...白名单条目对象 },
  "sync": { "failed": 0 }
}
```

**响应 `400`：** 校验错误。

**响应 `409`：** 重复条目已存在。

---

### `DELETE /api/v1/whitelist/:id`

删除白名单条目。触发同步。

**响应 `200`：**

```json
{
  "success": true,
  "message": "Whitelist entry deleted",
  "sync": { "failed": 0 }
}
```

---

### `POST /api/v1/whitelist/batch`

批量创建白名单条目。

**请求体：**

```json
{
  "entries": [ { ...白名单请求体 }, ... ]
}
```

**响应 `200`：**

```json
{
  "success": true,
  "added": 5,
  "failed": 0
}
```

---

### `DELETE /api/v1/whitelist/batch`

批量删除白名单条目。

**请求体：**

```json
{ "ids": ["uuid1", "uuid2"] }
```

**响应 `200`：**

```json
{
  "success": true,
  "deleted": 5,
  "failed": 0
}
```

---

## 节点

### 节点对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 节点 ID（由配置或自动生成） |
| `name` | string | 节点名称 |
| `endpoint` | string | 节点 API 地址，如 `http://192.168.1.10:8080` |
| `status` | string | `online`、`offline`、`syncing` 或 `unknown` |
| `last_sync` | string (RFC3339) | 最后一次成功同步时间 |
| `last_seen` | string (RFC3339) | 最后一次成功健康检查时间 |
| `created_at` | string (RFC3339) | 注册时间 |
| `stats` | NodeStats | 节点最新统计数据（见下方） |

### NodeStats 对象

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

查询所有已注册节点及其最新统计数据。

**响应 `200`：**

```json
{
  "nodes": [ { ...节点对象 } ],
  "count": 3
}
```

---

### `GET /api/v1/nodes/:id`

查询单个节点。

**响应 `200`：** 节点对象。

**响应 `404`：** 节点不存在。

---

### `POST /api/v1/nodes`

注册新节点。

**请求体：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | **是** | 节点名称 |
| `endpoint` | string | **是** | 节点 API 地址 |
| `api_key` | string | 否 | Controller→Node 认证密钥 |

**响应 `200`：**

```json
{
  "success": true,
  "node": { ...节点对象 }
}
```

**响应 `400`：** 缺少必填字段或地址格式非法。

**响应 `403`：** 节点为只读模式。

---

### `PUT /api/v1/nodes/:id`

更新节点名称或 API Key。

**请求体：**

```json
{
  "name": "新名称",
  "api_key": "新密钥"
}
```

**响应 `200`：** `{ "success": true, "node": { ...节点对象 } }`

**响应 `403`：** 节点为只读模式。

---

### `DELETE /api/v1/nodes/:id`

删除节点。

**响应 `200`：** `{ "success": true, "message": "Node deleted" }`

**响应 `403`：** 节点为只读模式。

---

### `GET /api/v1/nodes/:id/stats`

获取指定节点的最新统计快照。

**响应 `200`：** NodeStats 对象。

---

### `POST /api/v1/nodes/:id/sync`

强制立即向指定节点推送规则，跳过正常同步间隔。

**响应 `200`：** `{ "success": true, "message": "Sync initiated" }`

---

## 统计

### `GET /api/v1/stats`

全集群聚合统计数据。

**响应 `200`：**

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

## 错误码参考

| HTTP 状态码 | 含义 |
|------------|------|
| `400` | 请求参数错误或缺失必填字段 |
| `401` | 未认证或认证信息无效 |
| `403` | 禁止操作（节点为只读模式） |
| `404` | 资源不存在 |
| `409` | 冲突（重复条目） |
| `500` | 服务器内部错误 |

所有错误响应均包含 `"error"` 字段：

```json
{ "error": "错误描述" }
```
