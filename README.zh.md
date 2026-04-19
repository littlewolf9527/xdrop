<div align="center">
  <img src=".github/assets/xdrop_logo_v2_transparent.png" alt="XDrop" width="160">

  <h1>XDrop</h1>

  <p>基于 XDP/eBPF 的分布式防火墙，支持线速包过滤与集中管控。</p>

  [![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go)](https://go.dev)
  [![Vue](https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs)](https://vuejs.org)
  [![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-orange?logo=anthropic)](https://claude.com/product/claude-code)

  [English](README.md)
</div>

---

## 项目简介

XDrop 是一套基于 Linux XDP（eXpress Data Path）的分布式高性能包过滤系统。BPF 程序直接挂载在网卡驱动层，完全绕过内核协议栈，在数据包进入系统的最早节点完成 DROP / PASS / rate-limit 动作。

系统由两个组件构成：

- **Node Agent** — 部署在每台过滤主机上，管理 BPF 数据平面，对外暴露 REST API
- **Controller** — 集中管控平面，提供 Web UI，规则存储在 SQLite，并自动推送到所有已注册节点

| Classic 主题 | Amber 主题 |
|:---:|:---:|
| ![Classic](.github/assets/dashboard_classic.png) | ![Amber](.github/assets/dashboard_amber.png) |

```
┌──────────────────────────────────────────────────────────────────────┐
│                            Controller（管控平面）                     │
│                                                                      │
│   ┌──────────────┐   ┌─────────────┐   ┌────────────┐   ┌────────┐  │
│   │  Web UI      │   │  REST API   │   │  同步      │   │SQLite  │  │
│   │  (Vue 3 +    │   │  (Gin)      │   │  调度器    │   │  数据库 │  │
│   │  ECharts)    │   │             │   │            │   │        │  │
│   └──────────────┘   └─────────────┘   └────────────┘   └────────┘  │
└─────────────────────────────────┬────────────────────────────────────┘
                                  │  HTTP（规则推送 / 健康检查）
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
       ┌────────────┐      ┌────────────┐      ┌────────────┐
       │  节点 1    │      │  节点 2    │      │  节点 N    │
       │  Agent     │      │  Agent     │      │  Agent     │
       │ ┌────────┐ │      │ ┌────────┐ │      │ ┌────────┐ │
       │ │XDP/BPF │ │      │ │XDP/BPF │ │      │ │XDP/BPF │ │
       │ └────────┘ │      │ └────────┘ │      │ └────────┘ │
       └────────────┘      └────────────┘      └────────────┘
        线速过滤 ↑           线速过滤 ↑           线速过滤 ↑
```

---

## 核心特性

### BPF 数据平面
- **线速过滤** — XDP 程序在 `sk_buff` 分配之前运行，普通服务器也能接近线速
- **五元组匹配** — 源/目的 IP、源/目的端口、协议
- **IPv4 / IPv6 双栈** — 统一规则格式；IPv4 内部以 IPv4-mapped IPv6 存储
- **CIDR 规则** — 基于 LPM trie 的前缀匹配，支持源/目的方向独立配置，支持 /0–/128
- **白名单** — 优先于黑名单命中，基于哈希表实现
- **动作** — `drop`、`rate_limit`（令牌桶，可配置 PPS）、`pass`
- **包长度过滤** — `pkt_len_min` / `pkt_len_max`（L3 总长度）
- **TCP Flags 匹配** — `tcp_flags` 后匹配过滤（如 `SYN`、`SYN,ACK`、`RST`）；不匹配时继续通配 fallback
- **位图优化** — 64 位位图记录 34 种字段组合中哪些有活跃规则；BPF 跳过无规则的组合，热路径保持 O(1)
- **规则级统计** — 每条规则 per-CPU 累计 `match_count` / `drop_count`，由 agent 聚合

### AtomicSync（双缓冲原子发布）
规则更新采用类 RCU 的双缓冲协议，彻底消除规则写入与位图更新之间的竞态：

1. 将规则写入 BPF 哈希表
2. 在影子 config map 中构建新配置（位图、计数）
3. 单次原子写翻转 `active_config` 选择器——BPF 侧原子切换

BPF 数据路径永远不会看到不一致的位图/规则状态。

### 部署模式
| 模式 | 说明 |
|------|------|
| **Traditional（透传）** | 单网卡，XDP 挂载在单个接口上内联过滤 |
| **Fast-Forward（快转）** | 双网卡网关——XDP 同时挂载在入向和出向接口，实现透明 L2 桥接过滤 |

### 管控平面
- 规则集中存储于 SQLite，支持完整 CRUD 及批量 API
- 可配置同步间隔，支持强制同步（`POST /api/v1/nodes/:id/sync`）
- 节点健康监控，自动更新 online/offline 状态
- Web UI：实时流量仪表盘（ECharts）、节点概览、规则管理、白名单编辑器
- Controller 和 Node 均支持可选 API Key 认证

---

## 项目结构

```
xdrop/
├── node/
│   ├── bpf/          # C 语言 XDP 程序（xdrop.c / xdrop.h）
│   └── agent/        # Go agent — BPF 加载器、API 服务、AtomicSync 引擎
├── controller/
│   ├── cmd/          # 二进制入口
│   ├── internal/     # API、service、repository、scheduler、client
│   └── web/          # Vue 3 + Element Plus + ECharts 前端
└── scripts/          # 编译和服务管理脚本
```

- [Node Agent 文档 →](node/README.zh.md) — XDP 数据平面、BPF 映射表、AtomicSync、API
- [Controller 文档 →](controller/README.zh.md) — 管控平面、Web UI、同步引擎

---

## 环境要求

| 组件 | 要求 |
|------|------|
| Node Agent | Linux 内核 **≥ 5.9**、clang ≥ 11、Go ≥ 1.24、root / CAP_NET_ADMIN |
| Controller | Go ≥ 1.21、Node.js ≥ 18（仅编译前端需要）——可运行于任意系统 |

> Node Agent **必须运行在 Linux 上**（XDP 是 Linux 内核特性）。Controller 可部署在任意系统。

> **内核门槛说明（v2.5+）**：Node Agent 使用 `BPF_LINK_TYPE_XDP` 挂载 XDP 程序，
> 该特性 2020-10 在 Linux 5.9 落地。在 5.8 及以下内核启动会返回明确的错误信息指向
> 此要求。主流发行版已满足：Debian 11+（5.10）、RHEL/Rocky/Alma 9+（5.14）、
> Ubuntu 20.04 HWE / 22.04+（5.15+）。老内核用户请继续使用 xdrop **v2.4.2**
> （最后一版基于 netlink attach 的发布）直到完成升级。

> **BPF pinning（v2.5+）**：Node Agent 默认把 BPF 对象 pin 到
> `/sys/fs/bpf/xdrop/`，让状态跨 `systemctl restart xdrop-agent` 存活：
> - **16 个 map 文件**（Phase 3）—— `blacklist`、`whitelist`、
>   `cidr_blacklist`、4 个 LPM trie、`config_a`/`config_b` 等。
>   map ID 保持稳定，便于 `bpftool map dump pinned
>   /sys/fs/bpf/xdrop/<name>` 跨重启观察，外部 BPF 工具也继续指向
>   同一份对象。
> - **每个接口 1 个 XDP link 文件**（Phase 4）—— `link_<ifname>`
>   （如 `link_ens38`）。Agent 重启通过 `LoadPinnedLink + Link.Update`
>   原子替换 XDP 程序，而不是 detach/reattach —— 内核层面
>   **零空窗** 切换。没有 link pinning 的话，每次重启会有约
>   1.5–3 秒的无过滤窗口。
>
> 前置条件：`/sys/fs/bpf` 必须挂载为 `bpf` 类型文件系统 —— 现代
> 发行版通常由 systemd 自动挂载。若 pinning 失败（未挂载、EPERM 等），
> 默认会静默降级到非 pinned 模式；需要严格行为的话在 `config.yaml` 里
> 设 `bpf.pinning: require`，要完全关闭 pinning 设 `disable`。

详细的环境准备步骤请参见**[准备工作](GETTING_STARTED.zh.md)**。

---

## 快速开始

### 1. 编译

```bash
# 编译 controller（前端 + Go 二进制）
./scripts/build-controller.sh

# 编译 node agent（BPF 程序 + Go 二进制）——需在 Linux 主机上执行
./scripts/build-node.sh
```

### 2. 配置

```bash
# Controller
cp controller/config.example.yaml controller/config.yaml
# 编辑：设置 jwt_secret、external_api_key，并在 nodes: 段添加节点

# Node agent
cp node/config.example.yaml node/config.yaml
# 编辑：设置网卡名称、node_api_key、sync_key
```

### 3. 启动

```bash
# 启动 controller（无需 root）
./scripts/controller.sh start

# 启动 node agent（需要 root — XDP 需要 CAP_NET_ADMIN）
sudo ./scripts/node.sh start

# 查看状态
./scripts/controller.sh status
sudo ./scripts/node.sh status
```

Web UI 默认访问地址：`http://<controller-host>:8000`

---

## API 概览

Controller 和 Node 均在 `/api/v1/` 下提供版本化 REST API。

| 资源 | 端点 | 说明 |
|------|------|------|
| 规则列表 | `GET/POST /api/v1/rules` | 分页：`?page=&limit=` |
| 单条规则 | `GET/PUT/DELETE /api/v1/rules/:id` | |
| 批量规则 | `POST/DELETE /api/v1/rules/batch` | |
| 白名单 | `GET/POST/DELETE /api/v1/whitelist` | |
| 统计 | `GET /api/v1/stats` | PPS、丢包计数、XDP 信息 |
| 节点管理 | `GET/POST /api/v1/nodes` | 仅 Controller |
| 强制同步 | `POST /api/v1/nodes/:id/sync` | 仅 Controller |

Node API 需要 `X-API-Key` 请求头。Controller API Key 为可选项（可配置关闭）。

---

## 许可证

MIT — 详见 [LICENSE](LICENSE)。

BPF/C 内核程序（`node/bpf/`）遵循 GPL-2.0 协议，这是 Linux 内核 BPF 子系统的要求。

---

## 赞助商

本项目由 [Hytron](https://www.hytron.io/) 赞助开发工具支持。

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/sponsor-hytron-dark.png">
  <img src=".github/assets/sponsor-hytron.png" alt="Hytron" height="60">
</picture>

---

<sub>本项目完全通过 <a href="https://claude.com/product/claude-code">Claude Code</a> vibe coding 构建——包括 XDP/BPF 内核程序、Go 并发调度和 Vue 前端。</sub>
