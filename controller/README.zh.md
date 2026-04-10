# XDrop Controller

XDrop 的管控平面。将防火墙规则存储在 SQLite 中，通过 HTTP 推送到节点 agent，并提供 Web UI 用于规则管理和监控。

[English](README.md)

---

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         Controller                              │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Web UI（Vue 3 + Element Plus + ECharts）                 │  │
│  │  通过 go:embed 嵌入 Go 二进制                              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  REST API（Gin）                                          │  │
│  │  /api/v1/rules  /api/v1/whitelist  /api/v1/nodes         │  │
│  │  /api/v1/stats  /api/auth/*                              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────────┐  │
│  │ Rule Service  │  │ Node Service  │  │  Sync Service      │  │
│  │               │  │               │  │（变更时立即推送）   │  │
│  └───────┬───────┘  └───────┬───────┘  └────────┬───────────┘  │
│          └──────────────────┴──────────────────┘              │
│                             │                                   │
│                    ┌────────▼────────┐                          │
│                    │  SQLite（数据库）│                          │
│                    │  rules          │                          │
│                    │  whitelist      │                          │
│                    │  nodes          │                          │
│                    └─────────────────┘                          │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  后台调度器（goroutine）                                    │ │
│  │  • SyncChecker   — 定期向节点推送规则                       │ │
│  │  • HealthChecker — 定期轮询节点 /health                     │ │
│  │  • ExpireCleaner — 清理数据库中已过期的规则                  │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │ HTTP  X-Sync-Key
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         Node Agent 1   Node Agent 2   Node Agent N
```

---

## 工作原理

### 规则生命周期

1. 通过 REST API（或 Web UI）创建规则，持久化到 SQLite。
2. Sync Service 立即触发向所有已注册节点的推送。
3. 各节点收到完整规则集，通过 AtomicSync 加载到 BPF 映射表。
4. SyncChecker goroutine 定期重新同步，补偿任何遗漏的更新。

### 节点注册

节点在 `config.yaml` 的 `nodes:` 段中配置，包含名称、API 地址和同步密钥。Controller 首次联系后将节点信息存入 SQLite，并持续跟踪其健康状态。

### Web UI

Vue 3 前端通过 Vite 编译后，使用 `go:embed` 直接嵌入 Go 二进制。无需单独的 Web 服务器——Controller 二进制同时提供 API 和前端服务。

页面说明：
- **Dashboard** — 实时流量图表（收/发/丢包 PPS）、按命中次数排序的 Top 规则
- **Nodes** — 节点列表（在线/离线状态）、每节点统计数据、XDP 接口信息
- **Rules** — 分页规则列表、创建/删除规则、批量操作
- **Whitelist** — 白名单条目管理

### 认证

Controller 支持两层可选认证：

| 层级 | 配置项 | 请求头 / 字段 |
|------|--------|--------------|
| Web 登录（JWT） | `auth.enabled: true` | Cookie / `Authorization: Bearer` |
| 外部 API Key | `auth.external_api_key` | `X-API-Key` |

内网/受信环境可设置 `auth.enabled: false` 关闭认证。

---

## 配置

首次运行前，复制示例配置并编辑：

```bash
cp config.example.yaml config.yaml
```

关键配置项：

```yaml
server:
  host: 0.0.0.0
  port: 8000

auth:
  enabled: true
  jwt_secret: 请替换为随机32字符
  admin_password: 请替换为强密码
  external_api_key: 请替换为随机64字符

sync:
  interval: 60s   # 定期重新同步间隔

nodes:
  - name: node-01
    endpoint: http://192.168.1.10:8080
    sync_key: 与节点配置的sync_key一致
```

---

## 编译

需要 Go ≥ 1.21 和 Node.js ≥ 18。前端必须在 Go 二进制**之前**编译（编译时嵌入）。

```bash
# 在仓库根目录执行：
./scripts/build-controller.sh        # 依次编译前端和 Go 二进制

# 或分步执行：
./scripts/build-controller.sh web    # npm install + vite build
./scripts/build-controller.sh go     # go build（嵌入 dist/）
```

编译产物位于 `controller/xdrop-controller`。

---

## 运行

```bash
# 启动（无需 root）
./scripts/controller.sh start

# 停止 / 重启
./scripts/controller.sh stop
./scripts/controller.sh restart

# 状态（进程、API 健康、节点状态）
./scripts/controller.sh status

# 跟踪日志
./scripts/controller.sh logs
```

默认日志文件：`/tmp/xdrop-controller.log`

环境变量 `PORT` 可覆盖默认端口（8000）。

---

## API 参考

所有路由位于 `/api/v1/` 下。Controller 还暴露 `/health` 和 `/api/info`。

### 规则

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/rules` | 规则列表，支持 `?page=&limit=` 分页 |
| `POST` | `/api/v1/rules` | 创建规则 |
| `GET` | `/api/v1/rules/:id` | 按 ID 查询规则 |
| `PUT` | `/api/v1/rules/:id` | 更新规则 |
| `DELETE` | `/api/v1/rules/:id` | 删除规则 |
| `POST` | `/api/v1/rules/batch` | 批量创建 |
| `DELETE` | `/api/v1/rules/batch` | 批量删除 |
| `GET` | `/api/v1/rules/top` | 命中次数最多的规则 |

**规则字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `src_ip` | string | 源 IPv4/IPv6（精确匹配） |
| `dst_ip` | string | 目的 IPv4/IPv6（精确匹配） |
| `src_cidr` | string | 源 CIDR 前缀，如 `10.0.0.0/8` |
| `dst_cidr` | string | 目的 CIDR 前缀 |
| `src_port` | int | 源端口（0 = 任意） |
| `dst_port` | int | 目的端口（0 = 任意） |
| `protocol` | string | `tcp`、`udp`、`icmp`、`icmpv6` 或 `""`（任意） |
| `action` | string | `drop` 或 `rate_limit` |
| `rate_limit` | int | PPS 限速值（action 为 rate_limit 时必填） |
| `pkt_len_min` | int | L3 最小包长（0 = 不限） |
| `pkt_len_max` | int | L3 最大包长（0 = 不限） |
| `tcp_flags` | string | TCP 标志过滤，如 `SYN`、`SYN,ACK`、`RST`（需 `protocol=tcp`） |
| `name` | string | 规则名称 |
| `comment` | string | 备注 |
| `expires_at` | string | RFC3339 格式的过期时间（可选） |

> `src_ip` 与 `src_cidr` 互斥，`dst_ip` 与 `dst_cidr` 同理。

### 白名单

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/whitelist` | 条目列表 |
| `POST` | `/api/v1/whitelist` | 创建条目 |
| `DELETE` | `/api/v1/whitelist/:id` | 删除条目 |
| `POST` | `/api/v1/whitelist/batch` | 批量创建 |
| `DELETE` | `/api/v1/whitelist/batch` | 批量删除 |

### 节点

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/nodes` | 节点列表及状态 |
| `GET` | `/api/v1/nodes/:id` | 节点详情及统计 |
| `POST` | `/api/v1/nodes/:id/sync` | 强制向节点推送规则 |

### 统计

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/stats` | 所有节点的聚合统计 |

---

## 目录结构

```
controller/
├── cmd/controller/   # main.go — 二进制入口
├── internal/
│   ├── api/          # Gin 路由及 HTTP handler
│   ├── config/       # 配置加载（Viper）
│   ├── model/        # 数据模型（Rule、Node、Whitelist）
│   ├── repository/   # SQLite 持久层
│   ├── service/      # 业务逻辑（rule、node、sync、whitelist）
│   ├── client/       # 调用节点 API 的 HTTP 客户端
│   └── scheduler/    # 后台 goroutine（sync、health、expire）
├── migrations/       # SQLite Schema 迁移
├── web/              # Vue 3 前端源码
│   └── src/
│       ├── views/    # Dashboard、Nodes、Rules、Whitelist 页面
│       ├── api/      # Axios API 客户端
│       └── locales/  # i18n（英文、中文、日文）
├── embed.go          # go:embed 指令（嵌入 dist/）
├── config.example.yaml
└── go.mod
```
