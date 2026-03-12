# XDrop Controller

The management plane for XDrop. Stores firewall rules in SQLite, syncs them to node agents over HTTP, and serves a Web UI for rule management and monitoring.

[中文文档](README.zh.md)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Controller                              │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Web UI (Vue 3 + Element Plus + ECharts)                 │  │
│  │  Embedded into Go binary via go:embed                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  REST API  (Gin)                                         │  │
│  │  /api/v1/rules  /api/v1/whitelist  /api/v1/nodes         │  │
│  │  /api/v1/stats  /api/auth/*                              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────────┐  │
│  │ Rule Service  │  │ Node Service  │  │  Sync Service      │  │
│  │               │  │               │  │  (push on change)  │  │
│  └───────┬───────┘  └───────┬───────┘  └────────┬───────────┘  │
│          └──────────────────┴──────────────────┘              │
│                             │                                   │
│                    ┌────────▼────────┐                          │
│                    │  SQLite (DB)    │                          │
│                    │  rules          │                          │
│                    │  whitelist      │                          │
│                    │  nodes          │                          │
│                    └─────────────────┘                          │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Schedulers (background goroutines)                       │ │
│  │  • SyncChecker   — periodic rule push to nodes            │ │
│  │  • HealthChecker — poll node /health every N seconds      │ │
│  │  • ExpireCleaner — remove expired rules from DB           │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │ HTTP  X-Sync-Key
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         Node Agent 1   Node Agent 2   Node Agent N
```

---

## How It Works

### Rule Lifecycle

1. A rule is created via the REST API (or Web UI) and persisted to SQLite.
2. The Sync Service immediately triggers a push to all registered nodes.
3. Each node receives the full rule set and loads it into BPF maps via AtomicSync.
4. The SyncChecker goroutine periodically re-syncs any nodes that missed an update.

### Node Registration

Nodes are registered in `config.yaml` under the `nodes:` section with a name, endpoint URL, and sync key. The controller stores them in SQLite on first contact and tracks their health status.

### Web UI

The Vue 3 frontend is compiled with Vite and embedded directly into the Go binary using `go:embed`. No separate web server is needed — the controller binary serves both the API and the frontend.

Pages:
- **Dashboard** — live traffic chart (PPS in/out/drop), top rules by hit count
- **Nodes** — node list with online/offline status, per-node stats, XDP interface info
- **Rules** — paginated rule list, create/delete rules, batch operations
- **Whitelist** — whitelist entry management

### Authentication

The controller supports two optional layers of authentication:

| Layer | Setting | Header / Field |
|-------|---------|---------------|
| Web login (JWT) | `auth.enabled: true` | Cookie / `Authorization: Bearer` |
| External API key | `auth.external_api_key` | `X-API-Key` |

Set `auth.enabled: false` for internal/trusted networks.

---

## Configuration

Copy `config.example.yaml` and edit before first run:

```bash
cp config.example.yaml config.yaml
```

Key settings:

```yaml
server:
  host: 0.0.0.0
  port: 8000

auth:
  enabled: true
  jwt_secret: CHANGE_ME_RANDOM_32_CHARS
  admin_password: CHANGE_ME
  external_api_key: CHANGE_ME_RANDOM_64_CHARS

sync:
  interval: 60s   # periodic re-sync interval

nodes:
  - name: node-01
    endpoint: http://192.168.1.10:8080
    sync_key: CHANGE_ME_NODE_SYNC_KEY
```

---

## Build

Requires Go ≥ 1.21 and Node.js ≥ 18. The frontend must be built **before** the Go binary (it is embedded at compile time).

```bash
# From the repository root:
./scripts/build-controller.sh        # builds frontend then Go binary

# Or step by step:
./scripts/build-controller.sh web    # npm install + vite build
./scripts/build-controller.sh go     # go build (embeds dist/)
```

The compiled binary is placed at `controller/xdrop-controller`.

---

## Running

```bash
# Start (no root required)
./scripts/controller.sh start

# Stop / restart
./scripts/controller.sh stop
./scripts/controller.sh restart

# Status (process, API health, node states)
./scripts/controller.sh status

# Tail logs
./scripts/controller.sh logs
```

Default log file: `/tmp/xdrop-controller.log`

Environment variable `PORT` overrides the default port (8000).

---

## API Reference

All routes are under `/api/v1/`. The controller also exposes `/health` and `/api/info`.

### Rules

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/rules` | List rules. Supports `?page=&limit=` |
| `POST` | `/api/v1/rules` | Create a rule |
| `GET` | `/api/v1/rules/:id` | Get rule by ID |
| `PUT` | `/api/v1/rules/:id` | Update rule |
| `DELETE` | `/api/v1/rules/:id` | Delete rule |
| `POST` | `/api/v1/rules/batch` | Bulk create |
| `DELETE` | `/api/v1/rules/batch` | Bulk delete |
| `GET` | `/api/v1/rules/top` | Top rules by match count |

**Rule fields:**

| Field | Type | Description |
|-------|------|-------------|
| `src_ip` | string | Source IPv4/IPv6 (exact) |
| `dst_ip` | string | Destination IPv4/IPv6 (exact) |
| `src_cidr` | string | Source CIDR prefix, e.g. `10.0.0.0/8` |
| `dst_cidr` | string | Destination CIDR prefix |
| `src_port` | int | Source port (0 = any) |
| `dst_port` | int | Destination port (0 = any) |
| `protocol` | string | `tcp`, `udp`, `icmp`, `icmpv6`, or `""` (any) |
| `action` | string | `drop` or `rate_limit` |
| `rate_limit` | int | PPS limit (required when action is `rate_limit`) |
| `pkt_len_min` | int | Minimum L3 packet length (0 = disabled) |
| `pkt_len_max` | int | Maximum L3 packet length (0 = disabled) |
| `name` | string | Human-readable label |
| `comment` | string | Notes |
| `expires_at` | string | RFC3339 expiry time (optional) |

> `src_ip` and `src_cidr` are mutually exclusive. Same for `dst_ip` / `dst_cidr`.

### Whitelist

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/whitelist` | List entries |
| `POST` | `/api/v1/whitelist` | Create entry |
| `DELETE` | `/api/v1/whitelist/:id` | Delete entry |
| `POST` | `/api/v1/whitelist/batch` | Bulk create |
| `DELETE` | `/api/v1/whitelist/batch` | Bulk delete |

### Nodes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/nodes` | List nodes with status |
| `GET` | `/api/v1/nodes/:id` | Node detail + stats |
| `POST` | `/api/v1/nodes/:id/sync` | Force-push rules to node |

### Stats

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/stats` | Aggregated stats across all nodes |

---

## Directory Structure

```
controller/
├── cmd/controller/   # main.go — binary entry point
├── internal/
│   ├── api/          # Gin router and HTTP handlers
│   ├── config/       # Configuration loading (Viper)
│   ├── model/        # Data models (Rule, Node, Whitelist)
│   ├── repository/   # SQLite persistence layer
│   ├── service/      # Business logic (rule, node, sync, whitelist)
│   ├── client/       # HTTP client for node API calls
│   └── scheduler/    # Background goroutines (sync, health, expire)
├── migrations/       # SQLite schema migrations
├── web/              # Vue 3 frontend source
│   └── src/
│       ├── views/    # Dashboard, Nodes, Rules, Whitelist pages
│       ├── api/      # Axios API client
│       └── locales/  # i18n (English, Chinese, Japanese)
├── embed.go          # go:embed directive for dist/
├── config.example.yaml
└── go.mod
```
