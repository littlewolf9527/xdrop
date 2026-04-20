# XDrop Node Agent — API 参考

[English](API.md)

Base URL：`http://<node-host>:8080`

除 `/` 和 `/api/v1/health` 外，所有接口均需要 `X-API-Key` 请求头。

---

## 认证

每个请求（免认证端点除外）必须携带：

```
X-API-Key: <node_api_key>
```

密钥在 `config.yaml` 的 `auth.node_api_key` 字段中配置。

**免认证端点：**

| 端点 | 说明 |
|------|------|
| `GET /` | 欢迎信息 / 版本信息 |
| `GET /api/v1/health` | 健康检查 |

受保护端点未提供或提供错误密钥时，返回 **`401`**。

---

## 通用响应格式

所有接口均返回 JSON。错误时返回对应 HTTP 状态码及：

```json
{ "error": "错误描述" }
```

---

## 信息与健康检查

### `GET /`

```json
{
  "name": "XDrop Agent",
  "version": "2.5.0",
  "status": "running",
  "features": ["ipv4", "ipv6", "rate_limit"]
}
```

### `GET /api/v1/health`

```json
{ "status": "healthy" }
```

---

## 规则

### 规则对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string (UUID) | 规则 ID |
| `src_ip` | string | 源 IPv4/IPv6（精确匹配），与 `src_cidr` 互斥 |
| `dst_ip` | string | 目的 IPv4/IPv6（精确匹配），与 `dst_cidr` 互斥 |
| `src_cidr` | string | 源 CIDR 前缀，如 `10.0.0.0/8`，与 `src_ip` 互斥 |
| `dst_cidr` | string | 目的 CIDR 前缀，与 `dst_ip` 互斥 |
| `src_port` | integer | 源端口，`0` = 任意 |
| `dst_port` | integer | 目的端口，`0` = 任意 |
| `protocol` | string | `tcp`、`udp`、`icmp`、`icmpv6` 或 `""`（任意） |
| `action` | string | `drop` 或 `rate_limit` |
| `rate_limit` | integer | PPS 限速值，action=`rate_limit` 时必填（> 0） |
| `pkt_len_min` | integer | L3 最小包长（字节），`0` = 不限 |
| `pkt_len_max` | integer | L3 最大包长（字节），`0` = 不限 |
| `tcp_flags` | string | TCP 标志过滤（如 `SYN`、`SYN,ACK`、`RST`），需 `protocol=tcp` |
| `comment` | string | 备注 |
| `stats` | RuleStats | 每条规则的匹配/丢包计数（列表响应中包含） |

### RuleStats 对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `match_count` | integer | 该规则匹配的总包数 |
| `drop_count` | integer | 该规则丢弃的总包数 |
| `drop_pps` | float | 当前丢包速率（包/秒） |

**约束：**
- `src_ip` 与 `src_cidr` 互斥；`dst_ip` 与 `dst_cidr` 互斥。
- action=`rate_limit` 时，`rate_limit` 必须 > 0。

---

### `GET /api/v1/rules`

查询规则列表，响应中包含每条规则的统计数据。

**查询参数：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `page` | integer | — | 页码（≥ 1），不传则返回全部规则 |
| `limit` | integer | `50` | 每页条数，范围 1–1000 |
| `search` | string | — | 搜索 `src_ip`、`dst_ip`、`src_cidr`、`dst_cidr`、`id` |

> Node 不支持 `sort`、`order`、`enabled`、`action` 参数，传入后将返回 `400`。

**行为说明：**
- **不传任何分页参数**：返回全部规则及统计（兼容旧版）。
- **传入任意分页参数**：返回分页结果及统计。

**响应 `200`（分页）：**

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

**响应 `200`（全量，不含分页参数）：**

```json
{
  "rules": [ { ...规则对象 + stats } ],
  "count": 42
}
```

**响应 `400`：** 参数非法或不支持。

---

### `GET /api/v1/rules/:id`

按 ID 查询单条规则。

**响应 `200`：** 规则对象（不含统计数据）。

**响应 `404`：** 规则不存在。

---

### `POST /api/v1/rules`

添加规则。触发 AtomicSync（双缓冲配置发布）。

**请求体：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `action` | string | **是** | `drop` 或 `rate_limit` |
| `rate_limit` | integer | action=`rate_limit` 时 | PPS 限速值（> 0） |
| `id` | string | 否 | UUID，不传则自动生成 |
| `src_ip` | string | 否 | 源 IP（精确） |
| `dst_ip` | string | 否 | 目的 IP（精确） |
| `src_cidr` | string | 否 | 源 CIDR 前缀 |
| `dst_cidr` | string | 否 | 目的 CIDR 前缀 |
| `src_port` | integer | 否 | 源端口（0 = 任意） |
| `dst_port` | integer | 否 | 目的端口（0 = 任意） |
| `protocol` | string | 否 | `tcp`、`udp`、`icmp`、`icmpv6` 或 `""` |
| `pkt_len_min` | integer | 否 | 最小包长（0 = 不限） |
| `pkt_len_max` | integer | 否 | 最大包长（0 = 不限） |
| `tcp_flags` | string | 否 | TCP 标志过滤（如 `SYN`、`RST`），需 `protocol=tcp` |
| `tcp_flags` | string | TCP 标志过滤（如 `SYN`、`SYN,ACK`、`RST`），需 `protocol=tcp` |
| `comment` | string | 否 | 备注 |

**响应 `200`：**

```json
{
  "success": true,
  "rule_id": "uuid",
  "message": "Rule added"
}
```

**响应 `400`：** 校验错误（如同时设置 IP 和 CIDR；缺少 `rate_limit`；action 非法等）。

**响应 `409`：** 相同匹配键的规则已以不同 ID 存在。

**响应 `500`：** BPF 映射表写入失败。

---

### `DELETE /api/v1/rules/:id`

按 ID 删除规则。触发 AtomicSync。

**响应 `200`：**

```json
{
  "success": true,
  "message": "Rule deleted"
}
```

**响应 `404`：** 规则不存在。

**响应 `500`：** BPF 映射表删除失败。

---

### `POST /api/v1/rules/batch`

批量添加规则。全部规则插入后执行一次 AtomicSync。

**请求体：**

```json
{
  "rules": [
    {
      "id": "可选uuid",
      "src_ip": "1.2.3.4",
      "dst_port": 80,
      "protocol": "tcp",
      "action": "drop"
    }
  ]
}
```

每个元素与 `POST /api/v1/rules` 的请求体字段相同。

**去重规则：** 批次中若有多条规则 `id` 相同，以最后一条为准。

**响应 `200`：**

```json
{
  "success": true,
  "added": 8,
  "failed": 2
}
```

支持部分成功，`failed` 为被拒绝的条数。

**响应 `400`：** 请求体格式错误。

---

### `DELETE /api/v1/rules/batch`

批量删除规则。执行一次 AtomicSync。

**请求体：**

```json
{ "ids": ["uuid1", "uuid2", "uuid3"] }
```

**响应 `200`：**

```json
{
  "success": true,
  "deleted": 3,
  "failed": 0
}
```

---

## 白名单

白名单条目在所有黑名单规则之前匹配。命中白名单的数据包直接通过（`XDP_PASS`）。

### 白名单条目对象

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string (UUID) | 条目 ID |
| `src_ip` | string | 源 IPv4/IPv6 |
| `dst_ip` | string | 目的 IPv4/IPv6 |
| `src_port` | integer | 源端口（`0` = 任意） |
| `dst_port` | integer | 目的端口（`0` = 任意） |
| `protocol` | string | `tcp`、`udp`、`icmp`、`icmpv6` 或 `""` |
| `comment` | string | 备注 |

**约束：**
- 至少需要一个 IP（`src_ip` 或 `dst_ip`）。
- 设置端口或协议时，`src_ip` 和 `dst_ip` 必须同时存在。
- BPF 白名单表支持：仅源 IP、仅目的 IP 或完整五元组三种形式。

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

添加白名单条目。

**请求体：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src_ip` | string | 至少一个 IP | 源 IP |
| `dst_ip` | string | 至少一个 IP | 目的 IP |
| `src_port` | integer | 否 | 源端口 |
| `dst_port` | integer | 否 | 目的端口 |
| `protocol` | string | 否 | 协议 |
| `id` | string | 否 | UUID，不传则自动生成 |
| `comment` | string | 否 | 备注 |

**响应 `200`：**

```json
{
  "success": true,
  "id": "uuid",
  "message": "Whitelist entry added"
}
```

**响应 `400`：** 未指定 IP；端口/协议未附带 IP。

**响应 `409`：** 相同匹配键已以不同 ID 存在。

**响应 `500`：** BPF 映射表写入失败。

---

### `DELETE /api/v1/whitelist/:id`

删除白名单条目。

**响应 `200`：**

```json
{
  "success": true,
  "message": "Whitelist entry deleted"
}
```

**响应 `404`：** 条目不存在。

---

### `POST /api/v1/whitelist/batch`

批量添加白名单条目。全部写入后执行一次 BPF 更新。

**请求体：**

```json
{
  "entries": [
    {
      "src_ip": "10.0.0.1",
      "comment": "受信任主机"
    }
  ]
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

## 统计

### `GET /api/v1/stats`

完整统计快照。包含全局计数器、系统指标、XDP 接口信息和 agent 内部状态。

**响应 `200`：**

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

**字段说明：**

| 字段 | 说明 |
|------|------|
| `total_packets` | agent 启动以来接收的总包数 |
| `dropped_packets` | 总丢包数 |
| `passed_packets` | 总通过包数 |
| `whitelisted_packets` | 通过白名单直接放行的包数 |
| `rate_limited_packets` | 被限速的包数 |
| `*_pps` | 当前速率（包/秒），采样值 |
| `xdp_info.mode` | `traditional` 或 `fast_forward` |
| `xdp_info.interfaces` | 已挂载的接口及其角色（`filter`、`inbound`、`outbound`） |
| `system.cpu_percent` | 主机 CPU 使用率（%） |
| `system.mem_total_mb` | 主机总内存（MB） |
| `system.mem_used_mb` | 主机已用内存（MB） |
| `system.uptime_seconds` | 主机运行时间（秒） |
| `system.load_avg_1/5/15` | 1/5/15 分钟负载均值 |
| `agent_state.exact_rules` | 当前活跃 BPF 表中的精确五元组规则数 |
| `agent_state.cidr_rules` | 当前活跃 BPF 表中的 CIDR 规则数 |
| `agent_state.whitelist_entries` | BPF 白名单表中的条目数 |
| `agent_state.active_slot` | 当前活跃配置表槽位（0=A，1=B） |
| `agent_state.rule_map_selector` | 当前活跃规则表选择器（0=主表，1=影子表） |

---

## 错误码参考

| HTTP 状态码 | 含义 |
|------------|------|
| `400` | 请求参数错误或缺失 |
| `401` | 未认证或 `X-API-Key` 无效 |
| `404` | 资源不存在 |
| `409` | 冲突（重复条目） |
| `500` | 内部错误（BPF 操作失败） |

所有错误响应均包含：

```json
{ "error": "错误描述" }
```
