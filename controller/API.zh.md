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
  "version": "2.6.3",
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
| `protocol` | string | `tcp`、`udp`、`icmp`、`icmpv6`、`igmp`、`gre`、`esp` 或 `""`（任意） |
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
- **传入任意分页参数**：返回分页结果。v2.6.3+：每条规则的 `stats` 现在通过控制器进程内的 stats cache 返回（早先 AUD-001 优化下被忽略）。
- **不传任何分页参数**：返回全部规则。v2.6.3+：默认从 stats cache 读取，因此响应可能滞后最多 `stats_cache.refresh_interval_seconds`。当 `stats_cache.disabled=true` 时回退到 v2.6.3 之前的行为（请求时同步向 Node 拉取，不附带 `stats_*` meta 字段）。

**Stats cache meta 字段（v2.6.3+）：** 所有分页响应——以及启用 cache 时的全量响应——都附带 6 个顶层 `stats_*` 字段，描述集群级聚合状态。详见下方 [Stats cache 契约](#stats-cache-契约-v263)。

**响应 `200`（分页）：**

```json
{
  "rules": [ { ...规则对象, "stats": { "match_count": 100, "drop_count": 5, "drop_pps": 0.2 } } ],
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

**响应 `200`（全量，cache 启用）：**

```json
{
  "rules": [ { ...规则对象, "stats": { "match_count": 100, "drop_count": 5, "drop_pps": 0.2 } } ],
  "count": 42,
  "stats_status": "ok",
  "stats_freshness_ms": 1234,
  "stats_node_failures": {},
  "stats_offline_nodes": [],
  "stats_unknown_nodes": [],
  "stats_syncing_nodes": []
}
```

**响应 `200`（`stats_cache.disabled=true`）：** 保留 v2.6.3 之前的响应结构，无 `stats_*` 字段，stats 来自请求时同步 fan-out。

```json
{
  "rules": [ { ...规则对象, "stats": { ... } } ],
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

**v2.6.3 行为变化：** 不再请求时 fan-out。从 refresh 时预排好的 top-N 切片读取，请求时延与集群规模/规则数无关。响应附带与 `/api/v1/rules` 相同的 6 个 `stats_*` meta 字段。

**响应 `200`：**

```json
{
  "rules": [ { ...规则对象, "stats": { "drop_pps": 1200.5 } } ],
  "stats_status": "ok",
  "stats_freshness_ms": 567,
  "stats_node_failures": {},
  "stats_offline_nodes": [],
  "stats_unknown_nodes": [],
  "stats_syncing_nodes": []
}
```

当 cache 处于"无可用快照"状态（`initializing` / `waiting_for_health` / `no_nodes` / `failed_no_snapshot` / `disabled`）时，`rules` 返回空数组，前端依据 `stats_status` 渲染对应的状态文案。

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
| `protocol` | string | 否 | `tcp`、`udp`、`icmp`、`icmpv6`、`igmp`、`gre`、`esp` 或 `""` |
| `pkt_len_min` | integer | 否 | 最小包长（0 = 不限） |
| `pkt_len_max` | integer | 否 | 最大包长（0 = 不限） |
| `tcp_flags` | string | 否 | TCP 标志过滤（如 `SYN`、`SYN,ACK`、`RST`），需 `protocol=tcp` |
| `decoder` | string | 否 | **v2.6+ 语义糖。** 落库前自动展开为 `protocol` / `tcp_flags` / `match_anomaly` 底层字段。可选值：`tcp_ack`、`tcp_rst`、`tcp_fin`（Phase 2）、`bad_fragment`、`invalid`（Phase 4 anomaly）。与 `protocol`、`tcp_flags`、`match_anomaly` 互斥——同时设置任一 → 400。`GET /rules` 响应体**不**返回本字段（展开后的底层字段才返）。 |
| `match_anomaly` | integer | 否 | **v2.6+ anomaly 位图** —— `bit0=bad_fragment (0x01)`、`bit1=invalid (0x02)`。通常通过 `decoder` 糖下发；与 `decoder` 同时设置时显式 `match_anomaly` 输入会被拒。`0` = 不检查 anomaly（老语义）。 |
| `name` | string | 否 | 规则名称 |
| `comment` | string | 否 | 备注 |
| `source` | string | 否 | 来源标记 |
| `expires_in` | string | 否 | 相对过期时间，如 `1h`、`30m`、`24h` |
| `enabled` | boolean | 否 | 默认 `true`；`false` 将规则保存到 DB 但不下发 BPF |

**v2.6+ decoder / anomaly 语义**：

- **Anomaly action 限制**：anomaly 规则（任何 `match_anomaly` 非零，无论是直接设置还是通过 `decoder=bad_fragment|invalid`）仅支持 `action=drop`。anomaly + `rate_limit` → 400，错误体含稳定子串 `does not support action=rate_limit` / `anomaly rules are drop-only`。
- **IPv6 scope guard**：`decoder=bad_fragment` 配合任何 IPv6 target 字段（`src_ip`/`dst_ip`/`src_cidr`/`dst_cidr`）→ 400 拒绝，v1.3 BPF 不检测 IPv6 fragment anomaly。错误体含稳定子串 `not supported for IPv6 target in v1.3` / `deferred to v1.4`。`decoder=invalid` 在 IPv6 上允许（直连 TCP doff<5 检测生效）。
- **Anomaly 规则合并**：同 5-tuple + 同 `action=drop` 的两次 anomaly 下发（如先 `bad_fragment`、再 `invalid`）自动把 `match_anomaly` bitmap OR 合并到既有规则（`0x01 | 0x02 = 0x03`），返回**同一** rule ID，不 409 冲突、不新增行。BatchCreate **不**做合并（沿用老 UNIQUE 冲突语义）。`PUT` 为**替换**语义，不合并。
- **Anomaly 与非-anomaly 规则共存**：在已有非-anomaly 规则的 tuple 上再下发 anomaly → 409（需显式解决意图）。
- **Portless 协议 + 端口（B-10）**：ICMP、ICMPv6、IGMP、GRE、ESP 不携带 L4 端口字段。这些协议配合 `src_port` 或 `dst_port` 非零 → 400，错误体含 `protocol=<名> does not carry ports (src_port/dst_port must be 0)`。BPF 数据面只对 TCP/UDP 填 `key.src_port/dst_port`，存储 portless+port 规则会成为永远不命中的 ghost rule。`protocol=all` 和空协议允许带端口（`all` 是通配，可匹配 TCP/UDP 流量）。同款约束也用于 `WhitelistService.Create`。

**响应 `201`：**

```json
{
  "success": true,
  "rule": { ...规则对象 },
  "sync": { "failed": 0 }
}
```

`sync` 字段**始终返回**。`success: true` 仅表示 Controller DB mutation 成功；若要确认规则已到达数据面，需检查 `sync.failed > 0`。

**响应 `400`：** 校验错误（如同时设置了 `src_ip` 和 `src_cidr`；缺少 `rate_limit` 等）。

---

### `PUT /api/v1/rules/:id`

更新已有规则。请求体与 `POST` 相同。触发同步。

**Key 字段不可修改**：`src_ip`、`dst_ip`、`src_cidr`、`dst_cidr`、`protocol`、`src_port`、`dst_port`。发送不同**非空/非零**值会返回 `400`，诊断字符串 `<字段> is a key field and cannot be modified`。请删除后重建。发送与当前存储相同的值视为 no-op 接受（这让 decoder sugar 如 `decoder=tcp_rst` 在已是 tcp 协议的规则上展开成 `protocol=tcp` 与存储值相等可正常工作）。

**零值 PUT 限制**：`protocol`、`src_port`、`dst_port` 使用 scalar（`string` / `int`）请求 schema，服务端无法区分"字段省略"和"字段显式置空/0"。`PUT {"dst_port": 0}` 对一个 `dst_port=80` 的规则被视为 **omit/no-op**，**不**会清空。要把 key 字段改成另一个值（包括 0/空），需要删除规则后重建。这些字段的 pointer 三态 schema 改造在 v2.7 backlog（plan §6 R3-002）。同款限制也适用于 `rate_limit`、`match_anomaly`。

**`pkt_len_min/max` 显式清空（v2.6.4+）**：`pkt_len_min` 和 `pkt_len_max` 使用 **pointer 三态** schema——字段省略保留原值，发 `0` 显式清空，发正整数设置新值。与 `tcp_flags`、`comment` 行为一致。

**剩余 int 字段的显式清空限制**：`rate_limit`、`match_anomaly` 仍使用 `int` schema，发 `0` 视为"省略/保留原值"而非"清空"。唯一例外：PUT body 包含 `action=drop` 时会自动将 `rate_limit` 清零。

`tcp_flags` 和 `comment` 使用 pointer 三态：字段省略表示保留原值，发 `""` 表示清空，发非空字符串表示设置新值。

**`enabled` 字段（v2.6.4+）**：pointer 三态——字段省略保留原值。切换会触发对应数据面操作：`false→true` 将规则写入 BPF（`SyncAddRule`）；`true→false` 从 BPF 删除（`SyncDeleteRule`）；`false→false` / `true→true` 保持原有语义（无操作或 update）。

**Decoder 切换契约（v2.6.2+）**：`tcp_flags` 和 `match_anomaly` 在数据面互斥。用 PUT 切换规则 decoder 类型时，客户端必须**显式**清空冲突字段——服务端**不**做隐式自动清空：

- **tcp_flags 规则 → anomaly decoder**（如 `decoder=bad_fragment` / `invalid`）：请求必须同时带 `tcp_flags: ""` 显式清空旧的 `tcp_flags`。只发 `decoder=bad_fragment` 不带 `tcp_flags: ""` 会返回 `400`，诊断字符串包含 `cannot have both tcp_flags and match_anomaly`。
- **anomaly 规则 → tcp_* decoder**（如 `decoder=tcp_rst`）：`match_anomaly` 是 `int` schema 无 tri-state，PUT 无法显式清空。这种切换会被拒绝；请删除规则后重建。

理由：v2.6.2 保持 PUT 语义严格显式——服务端不会隐式 mutate 客户端没送的字段。两个方向行为对称，与 `tcp_flags` 的 pointer 三态契约保持一致。

**响应 `200`：** 同 `POST`。

**响应 `400`：** 校验错误。

**响应 `404`：** 规则不存在。

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
| `protocol` | string | `tcp`、`udp`、`icmp`、`icmpv6`、`igmp`、`gre`、`esp` 或 `""` |
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

此 endpoint **不**经过 v2.6.3 stats cache，PPS 汇总走独立的轻量 node-stats 路径。

---

### `GET /api/v1/stats/cache_health` *(v2.6.3+)*

运维诊断 endpoint，暴露进程内规则 stats cache 的状态，用于区分"Node fan-out 失败"与"refresh ticker 卡死"。

**响应 `200`：** 见英文文档 `API.md` 中相同 endpoint 的字段说明。关键点：

- `status` 是 **派生**状态（读取时基于 `now - last_snapshot_unix_ms` 推算，可能含 `stale` / `partial_stale`）。
- `last_refresh_status` 是上次 refresh 的 **base outcome**（永不为 stale / partial_stale）。
- 当 `status=partial_stale` 但 `last_refresh_status=partial` 时，refresh ticker 已卡住——上次 refresh 还成功了 partial，但之后没有新一轮 refresh 落地。

**响应 `503`：** Cache 未配置（构建时未注入）。

---

## Stats cache 契约 (v2.6.3+)

所有 stats-aware endpoint（`/rules?page=...`、`/rules/top`、启用 cache 时的 `/rules` listAll）顶层固定附带 6 个 `stats_*` 字段。

| 字段 | 类型 | 说明 |
|------|------|------|
| `stats_status` | string | 10 状态枚举之一，见下表 |
| `stats_freshness_ms` | integer 或 `null` | 距上次可展示快照的毫秒数。无可展示数据时为 `null` |
| `stats_node_failures` | object | `{节点名: 错误描述}`，仅含 **attempted Online** 失败节点；可能为空 |
| `stats_offline_nodes` | string[] | health=`offline` 且本轮未发起请求的节点名 |
| `stats_unknown_nodes` | string[] | 仍在 `unknown` 状态（HealthChecker 还未给出第一轮判断） |
| `stats_syncing_nodes` | string[] | 当前在 `syncing` 状态 |

### Status 状态值

| `stats_status` | 单条 `stats` 字段 | 含义 |
|----------------|-------------------|------|
| `initializing` | 省略 | Cache 还没完成第一轮 refresh |
| `waiting_for_health` | 省略 | 所有节点仍是 `unknown`/`syncing`，HealthChecker 还没给出有效结果 |
| `no_nodes` | 省略 | `configured_nodes=0` |
| `ok` | 总是返回（无命中合成 `0/0/0`） | 全部 configured 节点都成功，且未过期。**唯一**可以把 0 解读为"确定无命中"的状态 |
| `partial` | 仅当该规则在成功节点上有命中时返回 | 有节点未参与成功（fail / offline / unknown / syncing），数值是 lower bound |
| `stale` | 上次快照的 stats | 上次成功是 ok，但已超过 `stale_threshold_seconds` 未刷新（refresh 链路可能异常） |
| `partial_stale` | 上次快照的 stats | partial 基线已过期（refresh 卡住） |
| `failed` | 上次快照的 stats | 最近一轮所有节点都失败/被跳过，但 cache 仍有上次快照 |
| `failed_no_snapshot` | 省略 | 全失败/全跳过，且从未有过快照 |
| `disabled` | 省略 | `stats_cache.disabled=true` |

### 单节点与多节点行为差异

部分状态仅在多节点集群中可达：
- `partial` / `partial_stale` 至少需要 2 个节点；单节点集群中节点失败 = `failed_no_snapshot`（或 `failed`，若有快照）。
- `failed` 表示所有节点都失败，多节点集群中即所有节点同时失败。

### `listAll` 语义变化

v2.6.2 及之前 `GET /api/v1/rules`（无分页参数）每次请求都同步 fan-out Node，返回严格实时数据。v2.6.3 默认从进程内 cache 读取，最多滞后 `stats_cache.refresh_interval_seconds`。

诊断脚本若依赖实时性，有两种选择：
1. 直接调 Node 的 `/api/v1/rules`（Node API 一直是实时）。
2. controller 配置 `stats_cache.disabled=true` 后重启——`listAll` 回退旧 fan-out。

无 `?live_stats=true` query 参数；以上两条是仅有的逃生路径。

### Node 端负载影响

启用 cache（默认）会引入周期性 Controller→Node `GET /api/v1/rules` 调用（即使无人在用 UI）。默认 5s 间隔 + ≤1000 rules/node 时约 12 次/分钟/节点。规模较大时可考虑：
- 调大 `stats_cache.refresh_interval_seconds`（最大 60）。
- 调大 `stats_cache.per_node_timeout_seconds`（链路慢时）。
- 直接 `stats_cache.disabled=true` 关闭。

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
