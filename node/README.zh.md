# XDrop Node Agent

XDrop 的数据平面组件。部署在每台过滤主机上，将 BPF/XDP 程序挂载到网卡，并提供 REST API 用于规则管理和统计查询。

[English](README.md)

---

## 工作原理

### XDP 包处理流程

```
网卡（硬件）
    │
    ▼  ← XDP hook（在 sk_buff 分配之前）
┌─────────────────────────────────────────────────────────┐
│  xdp_whitelist_gate  [xdrop_gate.elf]                   │
│                                                         │
│  1. 解析 Ethernet → (VLAN 802.1Q/802.1ad) → IP          │
│                                                         │
│  2. 白名单位图检查（31-combo，v2.7.0+）                   │
│     └─ wl_bitmap == 0 → tail-call xdp_firewall_main    │
│                                                         │
│  3. 31-combo 白名单查找（哈希表，位图门控）               │
│     └─ 命中 → XDP_PASS（绕过所有黑名单规则）              │
│                                                         │
│  4. tail-call → xdp_firewall_main  [xdrop_main.elf]    │
└─────────────────────────────────────────────────────────┘
    │  （tail-call，prog_tail_map slot 1）
    ▼
┌─────────────────────────────────────────────────────────┐
│  xdp_firewall_main  [xdrop_main.elf]                    │
│                                                         │
│  5. 黑名单位图检查（64 位，31 种活跃组合）                │
│     └─ 跳过无活跃规则的字段组合类型                        │
│                                                         │
│  6. 精确黑名单查找（哈希表）                               │
│     └─ 命中 → 检查 pkt_len + tcp_flags                  │
│              → 匹配 → 执行动作（DROP / RATE_LIMIT）      │
│              → 不匹配 → 继续下一个 combo                 │
│                                                         │
│  7. CIDR 黑名单查找（LPM trie — 先查源地址，再查目的地址） │
│     └─ 命中 → 异常规则？→ tail-call xdp_anomaly_verify  │
│              → 匹配 → 执行动作（DROP / RATE_LIMIT）      │
│                                                         │
│  8. 无匹配 → XDP_PASS                                   │
└─────────────────────────────────────────────────────────┘
    │
    ▼  XDP_DROP 或 XDP_PASS
内核协议栈
```

### BPF 映射表

| 映射表 | 类型 | 最大条目 | 用途 |
|--------|------|---------|------|
| `whitelist` / `whitelist_b` | Hash | 各 50,000 | 白名单条目（活跃+影子双缓冲，v2.7.0+） |
| `blacklist` / `blacklist_b` | Hash | 各 500,000 | 精确五元组规则（双缓冲） |
| `cidr_blacklist` / `cidr_blist_b` | Hash | 各 500,000 | CIDR 规则 ID → 动作/限速映射（双缓冲） |
| `sv4_cidr_trie` / `dv4_cidr_trie` | LPM Trie | 各 50,000 | IPv4 源/目的 CIDR 前缀查找 |
| `sv6_cidr_trie` / `dv6_cidr_trie` | LPM Trie | 各 50,000 | IPv6 源/目的 CIDR 前缀查找 |
| `config_a` / `config_b` | Array | 12 | 双缓冲配置（黑/白名单位图、计数、FF 标志、选择器） |
| `active_config` | Array | 1 | 配置表选择器（0=A，1=B） |
| `stats` | Per-CPU Array | 5 | 全局包计数器（gate 和 main ELF 共享） |
| `rl_states` | Hash | 100,000 | 每条规则的令牌桶限速状态 |
| `prog_tail_map` | PROG_ARRAY | 2 | tail-call 分发：slot 0 = xdp_anomaly_verify，slot 1 = xdp_firewall_main |
| `tailcall_fail_stats` | Per-CPU Array | 1 | gate 独享的 fail-open 计数器（gate→main tail-call 失败次数） |

### 位图优化

每条规则对应一种字段组合（例如 "src_ip + dst_port + protocol" = 组合类型 7）。BPF 程序维护一个 64 位位图，若某组合类型有活跃规则，则对应位置 1。XDP 程序在探测哈希表之前先检查位图——若当前数据包所属的组合类型对应位为 0，则跳过整个查找过程。即使存在多种规则类型，热路径也保持 O(1)。

### AtomicSync（双缓冲原子发布）

规则更新涉及两个操作，必须对 BPF 数据路径表现为原子操作：向哈希表写入条目，以及更新查找位图。XDrop 采用类 RCU 的双缓冲机制，彻底消除不一致窗口。

**黑名单 AtomicSync：**

```
Active slot = A                    Shadow slot = B
──────────────────────────────────────────────────────
① 将规则写入 blacklist map（BPF 立即可见）
② 更新内部引用计数
③ 将 config_a 复制到 config_b
④ 在 config_b 中重建位图（BPF 仍读 config_a）
⑤ 原子写：active_config[0] = 1 ← BPF 切换到 config_b
──────────────────────────────────────────────────────
Active slot = B                    Shadow slot = A（下次更新使用）
```

**白名单 AtomicSync（v2.7.0+，`DoWhitelistAtomicSync`）：**

```
Active map = whitelist              Shadow map = whitelist_b
──────────────────────────────────────────────────────
① 清空 whitelist_b（影子表）
② 将所有条目写入 whitelist_b
③ 在影子 config 中更新 CONFIG_WL_BITMAP
④ 原子写：翻转 CONFIG_WL_MAP_SELECTOR ← BPF 切换到 whitelist_b
⑤ 清空旧活跃 whitelist（现为影子）
──────────────────────────────────────────────────────
Active map = whitelist_b            Shadow map = whitelist
```

单条增删直接写入活跃 map（单次 BPF update 原子）。全量同步（Controller FullSync）使用 `DoWhitelistAtomicSync`。三个选择器分别独立跟踪各自活跃侧——`active_config` 对应配置表对，`rule_map_selector` 对应黑名单映射对，`CONFIG_WL_MAP_SELECTOR` 对应白名单映射对。

---

## 部署模式

### Traditional 模式（单网卡过滤）

XDP 挂载在单个网卡上，对该接口的入向流量进行过滤，出向流量不受影响。

```yaml
server:
  interface: eth0

fast_forward:
  enabled: false
```

### Fast-Forward 模式（双网卡透明过滤）

XDP 同时挂载在入向（WAN）和出向（LAN）两个接口上，agent 作为两个接口之间的透明 L2 过滤桥接器。

```yaml
fast_forward:
  enabled: true
  pairs:
    - inbound: ens33     # WAN / 上游接口
      outbound: ens38    # LAN / 下游接口
      filter_on: both    # "inbound"、"outbound" 或 "both"
```

---

## 配置

```bash
cp config.example.yaml config.yaml
```

关键配置项：

```yaml
server:
  host: 0.0.0.0
  port: 8080
  interface: eth0          # XDP 挂载的网卡（Traditional 模式）

auth:
  node_api_key: 请替换为强密钥                  # 所有 API 请求均需此 Key，必须是真实值（不允许 CHANGE_ME 等占位符）
  controller_url: http://controller-host:8000  # 留空表示 pull-only / 独立模式
  controller_sync_key: 请替换为同步密钥         # 对应 controller 的 auth.external_api_key；当 controller_url 非空时必填
```

---

## 编译

需要 Linux、clang ≥ 11 和 Go ≥ 1.21。BPF 程序必须在 Go agent **之前**编译（`.elf` 文件在编译时嵌入）。

```bash
# 在仓库根目录执行（须在 Linux 主机上）：
./scripts/build-node.sh          # 依次编译 BPF 程序和 Go agent

# 或分步执行：
./scripts/build-node.sh bpf      # clang → node/bpf/xdrop_main.elf + xdrop_gate.elf
./scripts/build-node.sh agent    # go build → node/xdrop-agent
```

编译产物位于 `node/xdrop-agent`。

---

## 运行

```bash
# 启动（需要 root — XDP 需要 CAP_NET_ADMIN）
sudo ./scripts/node.sh start

# 停止 / 重启
sudo ./scripts/node.sh stop
sudo ./scripts/node.sh restart

# 状态（进程、API 健康、规则/白名单计数、XDP 模式）
sudo ./scripts/node.sh status

# 跟踪日志
./scripts/node.sh logs
```

默认日志文件：`/tmp/xdrop-agent.log`

环境变量 `PORT` 可覆盖默认 API 端口（8080）。

---

## API 参考

所有路由位于 `/api/v1/` 下。每个请求均需包含 `X-API-Key: <node_api_key>` 请求头。

### 规则

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/rules` | 规则列表，支持 `?page=&limit=` 分页 |
| `POST` | `/api/v1/rules` | 创建规则（触发 AtomicSync） |
| `GET` | `/api/v1/rules/:id` | 按 ID 查询规则 |
| `DELETE` | `/api/v1/rules/:id` | 删除规则（触发 AtomicSync） |
| `POST` | `/api/v1/rules/batch` | 批量创建 |
| `DELETE` | `/api/v1/rules/batch` | 批量删除 |

### 白名单

**Phase 8（v2.7.0+）：** 五元组字段的任意非空子集均为有效白名单 key（31 种规范 combo，位图门控 BPF 查找）。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/whitelist` | 条目列表 |
| `POST` | `/api/v1/whitelist` | 创建条目 |
| `DELETE` | `/api/v1/whitelist/:id` | 删除条目 |
| `POST` | `/api/v1/whitelist/batch` | 批量创建 |
| `DELETE` | `/api/v1/whitelist/batch` | 批量删除 |
| `POST` | `/api/v1/sync/whitelist` | **v2.7.0+。** 原子全量白名单替换（Controller FullSync 使用） |

### 统计与健康检查

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/health` | 健康检查：`{"status":"healthy"}` |
| `GET` | `/api/v1/stats` | 完整统计：PPS、规则计数、XDP 信息、系统指标、agent 状态 |

**统计响应示例：**

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

## 目录结构

```
node/
├── bpf/
│   ├── xdrop_gate.c      # Gate 程序：白名单 31-combo + tail-call 分发（GPL-2.0）
│   ├── xdrop_main.c      # Main 程序：黑名单查找 + anomaly 验证（GPL-2.0）
│   ├── xdrop.h           # 共享 BPF 类型定义和 map 声明
│   └── Makefile          # clang 编译 → xdrop_gate.elf + xdrop_main.elf
└── agent/
    ├── main.go           # 入口（加载 BPF，启动 API 服务）
    ├── api/
    │   ├── handlers.go   # health、stats、welcome 处理器
    │   ├── rules_list.go # 规则查询处理器
    │   ├── rules_mutation.go # 规则增删 + AtomicSync
    │   ├── whitelist.go  # 白名单处理器
    │   ├── sync.go       # AtomicSync 引擎
    │   ├── agent_state.go # 内存状态（规则、白名单、位图）
    │   ├── bpf_types.go  # BPF 映射表键值结构体
    │   └── types.go      # API 请求/响应类型
    ├── cidr/             # CIDR 校验、ID 分配、重叠检测
    ├── config/           # 配置加载（Viper）
    ├── ifmgr/            # 网卡和 XDP 程序生命周期管理
    ├── sync/             # Controller 同步客户端（启动时拉取规则）
    ├── go.mod
    └── go.sum
```
