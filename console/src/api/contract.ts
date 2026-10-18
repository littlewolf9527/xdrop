export interface ContractEntry { root: string; endpoint: string; path: string; nullable?: boolean; event?: string; when?: string; status?: number; query?: string }
// BEGIN CONTRACT JSON
export const contracts: ContractEntry[] = [
  {"root": "users", "endpoint": "GET /api/v1/users", "path": "[].username"},
  {"root": "users", "endpoint": "GET /api/v1/users", "path": "[].role"},
  {"root": "users", "endpoint": "GET /api/v1/users", "path": "[].created_at"},
  {"root": "users", "endpoint": "GET /api/v1/users", "path": "[].created_by"},
  {"root": "users", "endpoint": "GET /api/v1/users", "path": "[].password_changed_at"},
  {"root": "credentials", "endpoint": "GET /api/v1/credentials", "path": "[].id"},
  {"root": "credentials", "endpoint": "GET /api/v1/credentials", "path": "[].name"},
  {"root": "credentials", "endpoint": "GET /api/v1/credentials", "path": "[].created_at"},
  {"root": "credentials", "endpoint": "GET /api/v1/credentials", "path": "[].created_by"},
  {"root": "credentials", "endpoint": "GET /api/v1/credentials", "path": "[].retire_at", "nullable": true},
  {"root": "credentials", "endpoint": "GET /api/v1/credentials", "path": "[].revoked_at", "nullable": true},
  {"root": "credentials", "endpoint": "GET /api/v1/credentials", "path": "[].revoked_by", "nullable": true},
  {"root": "credentials", "endpoint": "GET /api/v1/credentials", "path": "[].active"},
  {"root": "issued", "endpoint": "POST /api/v1/credentials", "path": "id"},
  {"root": "issued", "endpoint": "POST /api/v1/credentials", "path": "name"},
  {"root": "issued", "endpoint": "POST /api/v1/credentials", "path": "key"},
  {"root": "issued", "endpoint": "POST /api/v1/credentials", "path": "created_at"},
  {"root": "issued", "endpoint": "POST /api/v1/credentials", "path": "retired[]"},
  {"root": "issued", "endpoint": "POST /api/v1/credentials", "path": "retired[].id"},
  {"root": "issued", "endpoint": "POST /api/v1/credentials", "path": "retired[].retire_at"},
  {"root": "nodeTest", "endpoint": "POST /api/v1/nodes/test", "path": "reachable"},
  {"root": "nodeTest", "endpoint": "POST /api/v1/nodes/test", "path": "compatible"},
  {"root": "nodeTest", "endpoint": "POST /api/v1/nodes/test", "path": "key_accepted"},
  {"root": "nodeTest", "endpoint": "POST /api/v1/nodes/test", "path": "message"},
  {"root": "settings", "endpoint": "GET /api/v1/settings", "path": "session_hours"},
  {"root": "settings", "endpoint": "GET /api/v1/settings", "path": "audit_retention_days"},
  {"root": "settings", "endpoint": "GET /api/v1/settings", "path": "history_retention_days"},
  {"root": "settings", "endpoint": "GET /api/v1/settings", "path": "reconcile_interval_minutes"},
  {"root": "nodes", "endpoint": "GET /api/v1/nodes", "path": "nodes[].base_url"},
  {"root": "nodes", "endpoint": "GET /api/v1/nodes", "path": "nodes[].key_unreadable"},
  {"root": "nodes", "endpoint": "GET /api/v1/events", "path": "nodes[].base_url", "event": "nodes"},
  {"root": "nodes", "endpoint": "GET /api/v1/events", "path": "nodes[].key_unreadable", "event": "nodes"},

  { "root": "error", "endpoint": "GET /api/v1/auth/me", "path": "code", "status": 401 },
  { "root": "error", "endpoint": "GET /api/v1/auth/me", "path": "message", "status": 401 },
  {
    "root": "identity",
    "endpoint": "GET /api/v1/auth/me",
    "path": "name"
  },
  {
    "root": "identity",
    "endpoint": "GET /api/v1/auth/me",
    "path": "role"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].name"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].online"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].incompatible"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].rules.state"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].rules.reason"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].rules.confirmed_gen"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].rules.confirmable"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].rules.rejected",
    "nullable": true
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].whitelist.state"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].whitelist.reason"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].whitelist.confirmed_gen"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].whitelist.confirmable"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].whitelist.rejected",
    "nullable": true
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].health_at"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].health.rules_synced"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].health.whitelist_synced"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].rates.dropped_packets",
    "nullable": true
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].rates.passed_packets",
    "nullable": true
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].rates.dropped_bytes",
    "nullable": true
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].rates.passed_bytes",
    "nullable": true
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].stats.system.cpu_percent",
    "nullable": true
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/nodes",
    "path": "nodes[].stats.system.mem_percent",
    "nullable": true
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].name",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].online",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].incompatible",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].rules.state",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].rules.reason",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].rules.confirmed_gen",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].rules.confirmable",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].rules.rejected",
    "nullable": true,
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].whitelist.state",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].whitelist.reason",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].whitelist.confirmed_gen",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].whitelist.confirmable",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].whitelist.rejected",
    "nullable": true,
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].health_at",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].health.rules_synced",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].health.whitelist_synced",
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].rates.dropped_packets",
    "nullable": true,
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].rates.passed_packets",
    "nullable": true,
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].rates.dropped_bytes",
    "nullable": true,
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].rates.passed_bytes",
    "nullable": true,
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].stats.system.cpu_percent",
    "nullable": true,
    "event": "nodes"
  },
  {
    "root": "nodes",
    "endpoint": "GET /api/v1/events",
    "path": "nodes[].stats.system.mem_percent",
    "nullable": true,
    "event": "nodes"
  },
  {
    "root": "signal",
    "endpoint": "GET /api/v1/events",
    "path": "seq",
    "event": "rules"
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "targets[].target"
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "targets[].dropped_pps"
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "targets[].dropped_bytes_ps"
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "targets[].share",
    "nullable": true
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "rules[].target"
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "rules[].dropped_pps"
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "rules[].dropped_bytes_ps"
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "rules[].share",
    "nullable": true
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "rules[].rule_id"
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "updated_at",
    "nullable": true
  },
  {
    "root": "top",
    "endpoint": "GET /api/v1/traffic/top?n=5",
    "path": "targets_total"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.targets[].target",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.targets[].dropped_pps",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.targets[].dropped_bytes_ps",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.targets[].share",
    "nullable": true,
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.rules[].target",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.rules[].dropped_pps",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.rules[].dropped_bytes_ps",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.rules[].share",
    "nullable": true,
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.rules[].rule_id",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.updated_at",
    "nullable": true,
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "top.targets_total",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "overview.dropped_pps",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "overview.passed_pps",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "overview.dropped_bytes_ps",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "overview.passed_bytes_ps",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "overview.nodes_online",
    "event": "traffic"
  },
  {
    "root": "traffic",
    "endpoint": "GET /api/v1/events",
    "path": "overview.nodes_total",
    "event": "traffic"
  },
  {
    "root": "capacity",
    "endpoint": "GET /api/v1/capacity",
    "path": "tightest.name"
  },
  {
    "root": "capacity",
    "endpoint": "GET /api/v1/capacity",
    "path": "tightest.ratio",
    "nullable": true
  },
  {
    "root": "capacity",
    "endpoint": "GET /api/v1/capacity",
    "path": "tightest.exhausted"
  },
  {
    "root": "capacity",
    "endpoint": "GET /api/v1/capacity",
    "path": "dimensions[].name"
  },
  {
    "root": "capacity",
    "endpoint": "GET /api/v1/capacity",
    "path": "dimensions[].ratio",
    "nullable": true
  },
  {
    "root": "capacity",
    "endpoint": "GET /api/v1/capacity",
    "path": "dimensions[].exhausted"
  },
  {
    "root": "capacity",
    "endpoint": "GET /api/v1/capacity",
    "path": "dimensions[].used"
  },
  {
    "root": "capacity",
    "endpoint": "GET /api/v1/capacity",
    "path": "dimensions[].admission_limit"
  },
  {
    "root": "capacity",
    "endpoint": "GET /api/v1/capacity",
    "path": "dimensions[].limit_source"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=15m",
    "path": "step_s"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=15m",
    "path": "points[].t"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=15m",
    "path": "points[].dropped_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=15m",
    "path": "points[].passed_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=15m",
    "path": "points[].dropped_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=15m",
    "path": "points[].passed_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=1h",
    "path": "step_s"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=1h",
    "path": "points[].t"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=1h",
    "path": "points[].dropped_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=1h",
    "path": "points[].passed_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=1h",
    "path": "points[].dropped_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=1h",
    "path": "points[].passed_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=6h",
    "path": "step_s"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=6h",
    "path": "points[].t"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=6h",
    "path": "points[].dropped_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=6h",
    "path": "points[].passed_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=6h",
    "path": "points[].dropped_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=6h",
    "path": "points[].passed_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=24h",
    "path": "step_s"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=24h",
    "path": "points[].t"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=24h",
    "path": "points[].dropped_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=24h",
    "path": "points[].passed_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=24h",
    "path": "points[].dropped_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=24h",
    "path": "points[].passed_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=7d",
    "path": "step_s"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=7d",
    "path": "points[].t"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=7d",
    "path": "points[].dropped_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=7d",
    "path": "points[].passed_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=7d",
    "path": "points[].dropped_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=7d",
    "path": "points[].passed_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=30d",
    "path": "step_s"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=30d",
    "path": "points[].t"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=30d",
    "path": "points[].dropped_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=30d",
    "path": "points[].passed_pps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=30d",
    "path": "points[].dropped_bytes_ps"
  },
  {
    "root": "history",
    "endpoint": "GET /api/v1/traffic/history?range=30d",
    "path": "points[].passed_bytes_ps"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "logical_id"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "dst_ip"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "dst_cidr"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "src_ip"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "src_cidr"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "protocol"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "src_port"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "dst_port"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "ttl",
    "nullable": true
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "dscp",
    "nullable": true
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "icmp_type",
    "nullable": true
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "icmp_code",
    "nullable": true
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "fragment",
    "nullable": true
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "pkt_len",
    "nullable": true
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "tcp_flags"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "match_anomaly"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "action"
  },
  {
    "root": "rule",
    "endpoint": "GET /api/v1/rules/{rule_id}",
    "path": "rate_limit"
  },
  {
    "root": "settings",
    "endpoint": "GET /api/v1/settings",
    "path": "default_language"
  },
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].logical_id"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].dst_ip"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].dst_cidr"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].src_ip"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].src_cidr"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].protocol"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].src_port"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].dst_port"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].ttl", "nullable": true},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].dscp", "nullable": true},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].icmp_type", "nullable": true},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].icmp_code", "nullable": true},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].fragment", "nullable": true},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].pkt_len", "nullable": true},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].tcp_flags"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].match_anomaly"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].action"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].rate_limit"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].id"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].kind"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].group_key"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].cond_key"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].enabled"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].comment"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].created_at"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].updated_at"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].expires_at", "nullable": true},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].created_by"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "items[].updated_by"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "next_after", "nullable": true},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "counts.all"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "counts.drop"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "counts.rate_limit"},
  {"root": "rulePage", "endpoint": "GET /api/v1/rules?counts=1", "path": "counts.disabled"},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "targets[].target"},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "targets[].dropped_pps"},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "targets[].dropped_bytes_ps"},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "targets[].share", "nullable": true},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "rules[].target"},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "rules[].dropped_pps"},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "rules[].dropped_bytes_ps"},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "rules[].share", "nullable": true},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "rules[].rule_id"},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "updated_at", "nullable": true},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "targets_total"},
  {"root": "topAll", "endpoint": "GET /api/v1/traffic/top?n=all", "path": "incomplete"},
  {"root": "queryError", "endpoint": "GET /api/v1/rules", "path": "code", "status": 400, "query": "q=not-an-address"},
  {"root": "queryError", "endpoint": "GET /api/v1/rules", "path": "field", "status": 400, "query": "q=not-an-address"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch?validate=1", "path": "results[].existing"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch?validate=1", "path": "results[].error.code"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch?validate=1", "path": "results[].error.field"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch?validate=1", "path": "results[].error.rule_id"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch?validate=1", "path": "results[].error.rule_ids[]"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch?validate=1", "path": "results[].error.table"},
  {"root": "write", "endpoint": "POST /api/v1/rules", "path": "id"},
  {"root": "write", "endpoint": "PATCH /api/v1/rules/{rule_id}", "path": "id"},
  {"root": "write", "endpoint": "PUT /api/v1/rules/{rule_id}/enabled", "path": "enabled"},
  {"root": "whitelistPage", "endpoint": "GET /api/v1/whitelist", "path": "items[].id"},
  {"root": "whitelist", "endpoint": "POST /api/v1/whitelist", "path": "id"},
  {"root": "whitelistPage", "endpoint": "GET /api/v1/whitelist", "path": "items[].src_ip"},
  {"root": "whitelist", "endpoint": "POST /api/v1/whitelist", "path": "src_ip"},
  {"root": "whitelistPage", "endpoint": "GET /api/v1/whitelist", "path": "items[].dst_ip"},
  {"root": "whitelist", "endpoint": "POST /api/v1/whitelist", "path": "dst_ip"},
  {"root": "whitelistPage", "endpoint": "GET /api/v1/whitelist", "path": "items[].src_port"},
  {"root": "whitelist", "endpoint": "POST /api/v1/whitelist", "path": "src_port"},
  {"root": "whitelistPage", "endpoint": "GET /api/v1/whitelist", "path": "items[].dst_port"},
  {"root": "whitelist", "endpoint": "POST /api/v1/whitelist", "path": "dst_port"},
  {"root": "whitelistPage", "endpoint": "GET /api/v1/whitelist", "path": "items[].protocol"},
  {"root": "whitelist", "endpoint": "POST /api/v1/whitelist", "path": "protocol"},
  {"root": "whitelistPage", "endpoint": "GET /api/v1/whitelist", "path": "items[].comment"},
  {"root": "whitelist", "endpoint": "POST /api/v1/whitelist", "path": "comment"},
  {"root": "whitelistPage", "endpoint": "GET /api/v1/whitelist", "path": "items[].created_at"},
  {"root": "whitelist", "endpoint": "POST /api/v1/whitelist", "path": "created_at"},
  {"root": "whitelistPage", "endpoint": "GET /api/v1/whitelist", "path": "items[].created_by"},
  {"root": "whitelist", "endpoint": "POST /api/v1/whitelist", "path": "created_by"},
  {"root": "whitelistPage", "endpoint": "GET /api/v1/whitelist", "path": "next_after", "nullable": true},
  {"root": "whitelist", "endpoint": "POST /api/v1/whitelist", "path": "existing"},
  {"root": "templates", "endpoint": "GET /api/v1/templates", "path": "[].id"},
  {"root": "templates", "endpoint": "GET /api/v1/templates", "path": "[].name"},
  {"root": "templates", "endpoint": "GET /api/v1/templates", "path": "[].body"},
  {"root": "templates", "endpoint": "GET /api/v1/templates", "path": "[].created_at"},
  {"root": "templates", "endpoint": "GET /api/v1/templates", "path": "[].updated_at"},
  {"root": "templates", "endpoint": "GET /api/v1/templates", "path": "[].created_by"},
  {"root": "templates", "endpoint": "GET /api/v1/templates", "path": "[].updated_by"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch?validate=1", "path": "epoch"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch?validate=1", "path": "results[].index"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch?validate=1", "path": "results[].rule.id"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch?validate=1", "path": "results[].existing"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch", "path": "epoch"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch", "path": "results[].index"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch", "path": "results[].rule.id"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch", "path": "results[].existing"},
  {"root": "write", "endpoint": "POST /api/v1/rules/batch", "path": "results[].gen"},
  {"root": "auditPage", "endpoint": "GET /api/v1/audit?limit=100", "path": "items[].id"},
  {"root": "auditPage", "endpoint": "GET /api/v1/audit?limit=100", "path": "items[].at"},
  {"root": "auditPage", "endpoint": "GET /api/v1/audit?limit=100", "path": "items[].actor"},
  {"root": "auditPage", "endpoint": "GET /api/v1/audit?limit=100", "path": "items[].source"},
  {"root": "auditPage", "endpoint": "GET /api/v1/audit?limit=100", "path": "items[].action"},
  {"root": "auditPage", "endpoint": "GET /api/v1/audit?limit=100", "path": "items[].target"},
  {"root": "auditPage", "endpoint": "GET /api/v1/audit?limit=100", "path": "items[].before", "nullable": true},
  {"root": "auditPage", "endpoint": "GET /api/v1/audit?limit=100", "path": "items[].after", "nullable": true},
  {"root": "auditPage", "endpoint": "GET /api/v1/audit?limit=100", "path": "next_cursor"}
]
// END CONTRACT JSON
