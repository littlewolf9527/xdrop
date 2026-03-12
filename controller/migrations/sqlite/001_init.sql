-- XDrop Controller initial table schema

-- rules table
CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_port    INTEGER DEFAULT 0,
    dst_port    INTEGER DEFAULT 0,
    protocol    TEXT DEFAULT 'all',
    action      TEXT DEFAULT 'drop',
    rate_limit  INTEGER DEFAULT 0,
    source      TEXT DEFAULT 'manual',
    comment     TEXT,
    enabled     INTEGER DEFAULT 1,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(src_ip, dst_ip, src_port, dst_port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_rules_expires ON rules(expires_at);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

-- whitelist table
CREATE TABLE IF NOT EXISTS whitelist (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_port    INTEGER DEFAULT 0,
    dst_port    INTEGER DEFAULT 0,
    protocol    TEXT,
    comment     TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- nodes table
CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    endpoint    TEXT NOT NULL UNIQUE,
    status      TEXT DEFAULT 'unknown',
    last_sync   DATETIME,
    last_seen   DATETIME,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- sync log table
CREATE TABLE IF NOT EXISTS sync_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id     TEXT NOT NULL,
    action      TEXT NOT NULL,
    rule_id     TEXT,
    status      TEXT NOT NULL,
    error       TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sync_log_node ON sync_log(node_id, created_at);
