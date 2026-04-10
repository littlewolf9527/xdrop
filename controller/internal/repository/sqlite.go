package repository

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

// Initialization SQL (inline)
const initSQL = `
-- Rules table
CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_cidr    TEXT DEFAULT '',
    dst_cidr    TEXT DEFAULT '',
    src_port    INTEGER DEFAULT 0,
    dst_port    INTEGER DEFAULT 0,
    protocol    TEXT DEFAULT 'all',
    action      TEXT DEFAULT 'drop',
    rate_limit  INTEGER DEFAULT 0,
    pkt_len_min INTEGER DEFAULT 0,
    pkt_len_max INTEGER DEFAULT 0,
    tcp_flags TEXT DEFAULT '',
    source      TEXT DEFAULT 'manual',
    comment     TEXT,
    enabled     INTEGER DEFAULT 1,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(src_ip, src_cidr, dst_ip, dst_cidr, src_port, dst_port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_rules_expires ON rules(expires_at);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

-- Whitelist table
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

-- Nodes table
CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    endpoint    TEXT NOT NULL UNIQUE,
    api_key     TEXT,
    status      TEXT DEFAULT 'unknown',
    last_sync   DATETIME,
    last_seen   DATETIME,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Sync log table
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

-- NOTE: rule_node_mapping and whitelist_node_mapping tables removed (unused dead code)
`

// SQLiteDB holds a SQLite database connection
type SQLiteDB struct {
	db *sql.DB
}

// NewSQLiteDB creates a new SQLite connection
func NewSQLiteDB(dsn string) (*SQLiteDB, error) {
	// Ensure the directory exists
	dir := filepath.Dir(dsn)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	// Verify connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Run initialization SQL
	if _, err := db.Exec(initSQL); err != nil {
		return nil, err
	}

	// Run database migrations (ignore "duplicate column" errors)
	runMigrations(db)

	slog.Info("SQLite database connected", "dsn", dsn)
	return &SQLiteDB{db: db}, nil
}

// runMigrations runs database migrations, ignoring already-exists column errors
func runMigrations(db *sql.DB) {
	// Migration 1: add new columns (ignore already-exists errors)
	addColumns := []string{
		"ALTER TABLE rules ADD COLUMN pkt_len_min INTEGER DEFAULT 0",
		"ALTER TABLE rules ADD COLUMN pkt_len_max INTEGER DEFAULT 0",
		"ALTER TABLE rules ADD COLUMN src_cidr TEXT DEFAULT ''",
		"ALTER TABLE rules ADD COLUMN dst_cidr TEXT DEFAULT ''",
		"ALTER TABLE rules ADD COLUMN tcp_flags TEXT DEFAULT ''",
	}

	for _, m := range addColumns {
		_, err := db.Exec(m)
		if err != nil {
			if !strings.Contains(err.Error(), "duplicate column") {
				slog.Warn("Migration failed", "sql", m, "error", err)
			}
		}
	}

	// Migration 2: rebuild UNIQUE constraint (include src_cidr, dst_cidr)
	// Check if rebuild is needed: required if old UNIQUE constraint lacks src_cidr
	rebuildUniqueConstraint(db)
}

// rebuildUniqueConstraint rebuilds the rules table to update the UNIQUE constraint
func rebuildUniqueConstraint(db *sql.DB) {
	// Check whether src_cidr is already included in the UNIQUE constraint.
	// SQLite has no simple way to inspect constraints; checking via schema version
	// flag is simpler than trying a probe insert.
	var version int
	err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		// schema_version table does not exist; create it and start at version 0
		db.Exec("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER)")
		db.Exec("INSERT INTO schema_version (version) VALUES (0)")
		version = 0
	}

	if version >= 1 {
		return // already migrated
	}

	slog.Info("Rebuilding rules table for CIDR UNIQUE constraint...")

	tx, err := db.Begin()
	if err != nil {
		slog.Error("Failed to start migration transaction", "error", err)
		return
	}
	defer tx.Rollback()

	steps := []string{
		`CREATE TABLE rules_new (
			id          TEXT PRIMARY KEY,
			name        TEXT,
			src_ip      TEXT,
			dst_ip      TEXT,
			src_cidr    TEXT DEFAULT '',
			dst_cidr    TEXT DEFAULT '',
			src_port    INTEGER DEFAULT 0,
			dst_port    INTEGER DEFAULT 0,
			protocol    TEXT DEFAULT 'all',
			action      TEXT DEFAULT 'drop',
			rate_limit  INTEGER DEFAULT 0,
			pkt_len_min INTEGER DEFAULT 0,
			pkt_len_max INTEGER DEFAULT 0,
    tcp_flags TEXT DEFAULT '',
			source      TEXT DEFAULT 'manual',
			comment     TEXT,
			enabled     INTEGER DEFAULT 1,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at  DATETIME,
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(src_ip, src_cidr, dst_ip, dst_cidr, src_port, dst_port, protocol)
		)`,
		`INSERT INTO rules_new SELECT id, name, src_ip, dst_ip,
			COALESCE(src_cidr, ''), COALESCE(dst_cidr, ''),
			src_port, dst_port, protocol, action, rate_limit,
			COALESCE(pkt_len_min, 0), COALESCE(pkt_len_max, 0),
			COALESCE(tcp_flags, ''),
			source, comment, enabled, created_at, expires_at, updated_at
		 FROM rules`,
		"DROP TABLE rules",
		"ALTER TABLE rules_new RENAME TO rules",
		"CREATE INDEX IF NOT EXISTS idx_rules_expires ON rules(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled)",
		"UPDATE schema_version SET version = 1",
	}

	for _, s := range steps {
		if _, err := tx.Exec(s); err != nil {
			slog.Error("Migration step failed", "sql", s[:60], "error", err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		slog.Error("Migration commit failed", "error", err)
		return
	}

	slog.Info("Rules table rebuilt successfully with CIDR UNIQUE constraint")
}

// Close closes the database connection
func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

// ==================== RuleRepository ====================

type SQLiteRuleRepo struct {
	db *sql.DB
}

func NewSQLiteRuleRepo(db *SQLiteDB) *SQLiteRuleRepo {
	return &SQLiteRuleRepo{db: db.db}
}

func (r *SQLiteRuleRepo) Create(rule *model.Rule) error {
	_, err := r.db.Exec(`
		INSERT INTO rules (id, name, src_ip, dst_ip, src_cidr, dst_cidr, src_port, dst_port, protocol,
		                   action, rate_limit, pkt_len_min, pkt_len_max, tcp_flags, source, comment, enabled, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, rule.ID, rule.Name, nullString(rule.SrcIP), nullString(rule.DstIP),
		rule.SrcCIDR, rule.DstCIDR,
		rule.SrcPort, rule.DstPort, rule.Protocol, rule.Action, rule.RateLimit,
		rule.PktLenMin, rule.PktLenMax, rule.TcpFlags, rule.Source, rule.Comment, rule.Enabled, nullTime(rule.ExpiresAt))
	return err
}

func (r *SQLiteRuleRepo) BatchCreate(rules []*model.Rule) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO rules (id, name, src_ip, dst_ip, src_cidr, dst_cidr, src_port, dst_port, protocol,
		                   action, rate_limit, pkt_len_min, pkt_len_max, tcp_flags, source, comment, enabled, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, rule := range rules {
		_, err := stmt.Exec(
			rule.ID, rule.Name, nullString(rule.SrcIP), nullString(rule.DstIP),
			rule.SrcCIDR, rule.DstCIDR,
			rule.SrcPort, rule.DstPort, rule.Protocol, rule.Action, rule.RateLimit,
			rule.PktLenMin, rule.PktLenMax, rule.TcpFlags, rule.Source, rule.Comment, rule.Enabled, nullTime(rule.ExpiresAt),
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *SQLiteRuleRepo) Get(id string) (*model.Rule, error) {
	row := r.db.QueryRow(`
		SELECT id, name, src_ip, dst_ip, src_cidr, dst_cidr, src_port, dst_port, protocol,
		       action, rate_limit, pkt_len_min, pkt_len_max, tcp_flags, source, comment, enabled, created_at, expires_at, updated_at
		FROM rules WHERE id = ?
	`, id)
	return scanRule(row)
}

func (r *SQLiteRuleRepo) List() ([]*model.Rule, error) {
	rows, err := r.db.Query(`
		SELECT id, name, src_ip, dst_ip, src_cidr, dst_cidr, src_port, dst_port, protocol,
		       action, rate_limit, pkt_len_min, pkt_len_max, tcp_flags, source, comment, enabled, created_at, expires_at, updated_at
		FROM rules ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRules(rows)
}

// allowedSortColumns is the whitelist of valid sort columns (prevents SQL injection)
var allowedSortColumns = map[string]string{
	"created_at": "created_at",
	"updated_at": "updated_at",
}

func (r *SQLiteRuleRepo) ListPaginated(params PaginationParams) ([]*model.Rule, *PaginationResult, error) {
	// Build WHERE clause
	var conditions []string
	var args []interface{}

	if params.Search != "" {
		searchPattern := "%" + params.Search + "%"
		conditions = append(conditions,
			"(src_ip LIKE ? OR dst_ip LIKE ? OR src_cidr LIKE ? OR dst_cidr LIKE ? OR name LIKE ? OR comment LIKE ?)")
		for i := 0; i < 6; i++ {
			args = append(args, searchPattern)
		}
	}
	if params.Enabled != nil {
		conditions = append(conditions, "enabled = ?")
		if *params.Enabled {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}
	if params.Action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, params.Action)
	}

	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching rows
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM rules"+where, args...).Scan(&total); err != nil {
		return nil, nil, fmt.Errorf("count query failed: %w", err)
	}

	// Paginated query
	col := allowedSortColumns[params.Sort]
	if col == "" {
		col = "created_at"
	}
	order := "DESC"
	if params.Order == "asc" {
		order = "ASC"
	}
	offset := (params.Page - 1) * params.Limit

	query := fmt.Sprintf(`SELECT id, name, src_ip, dst_ip, src_cidr, dst_cidr, src_port, dst_port, protocol,
		action, rate_limit, pkt_len_min, pkt_len_max, tcp_flags, source, comment, enabled, created_at, expires_at, updated_at
		FROM rules%s ORDER BY %s %s, id %s LIMIT ? OFFSET ?`, where, col, order, order)

	pageArgs := append(args, params.Limit, offset)
	rows, err := r.db.Query(query, pageArgs...)
	if err != nil {
		return nil, nil, fmt.Errorf("paginated query failed: %w", err)
	}
	defer rows.Close()

	rules, err := scanRules(rows)
	if err != nil {
		return nil, nil, err
	}

	pages := 0
	if params.Limit > 0 {
		pages = (total + params.Limit - 1) / params.Limit
	}

	return rules, &PaginationResult{
		Page:  params.Page,
		Limit: params.Limit,
		Total: total,
		Pages: pages,
	}, nil
}

func (r *SQLiteRuleRepo) ListEnabled() ([]*model.Rule, error) {
	rows, err := r.db.Query(`
		SELECT id, name, src_ip, dst_ip, src_cidr, dst_cidr, src_port, dst_port, protocol,
		       action, rate_limit, pkt_len_min, pkt_len_max, tcp_flags, source, comment, enabled, created_at, expires_at, updated_at
		FROM rules WHERE enabled = 1 ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRules(rows)
}

func (r *SQLiteRuleRepo) ListExpired() ([]*model.Rule, error) {
	rows, err := r.db.Query(`
		SELECT id, name, src_ip, dst_ip, src_cidr, dst_cidr, src_port, dst_port, protocol,
		       action, rate_limit, pkt_len_min, pkt_len_max, tcp_flags, source, comment, enabled, created_at, expires_at, updated_at
		FROM rules WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRules(rows)
}

func (r *SQLiteRuleRepo) Update(rule *model.Rule) error {
	_, err := r.db.Exec(`
		UPDATE rules SET name=?, src_ip=?, dst_ip=?, src_cidr=?, dst_cidr=?, src_port=?, dst_port=?, protocol=?,
		                 action=?, rate_limit=?, pkt_len_min=?, pkt_len_max=?, tcp_flags=?, source=?, comment=?, enabled=?,
		                 expires_at=?, updated_at=CURRENT_TIMESTAMP
		WHERE id = ?
	`, rule.Name, nullString(rule.SrcIP), nullString(rule.DstIP),
		rule.SrcCIDR, rule.DstCIDR,
		rule.SrcPort, rule.DstPort, rule.Protocol, rule.Action, rule.RateLimit,
		rule.PktLenMin, rule.PktLenMax, rule.TcpFlags, rule.Source, rule.Comment, rule.Enabled, nullTime(rule.ExpiresAt), rule.ID)
	return err
}

func (r *SQLiteRuleRepo) Delete(id string) error {
	_, err := r.db.Exec("DELETE FROM rules WHERE id = ?", id)
	return err
}

func (r *SQLiteRuleRepo) BatchDelete(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("DELETE FROM rules WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, id := range ids {
		_, err := stmt.Exec(id)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *SQLiteRuleRepo) DeleteExpired() (int, error) {
	result, err := r.db.Exec("DELETE FROM rules WHERE expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP")
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

func (r *SQLiteRuleRepo) Exists(srcIP, dstIP string, srcPort, dstPort int, protocol string) (bool, error) {
	var count int
	err := r.db.QueryRow(`
		SELECT COUNT(*) FROM rules
		WHERE COALESCE(src_ip, '') = COALESCE(?, '')
		  AND COALESCE(dst_ip, '') = COALESCE(?, '')
		  AND src_port = ? AND dst_port = ? AND protocol = ?
	`, nullString(srcIP), nullString(dstIP), srcPort, dstPort, protocol).Scan(&count)
	return count > 0, err
}

func (r *SQLiteRuleRepo) CIDRExists(srcCIDR, dstCIDR string, srcPort, dstPort int, protocol string) (bool, error) {
	var count int
	err := r.db.QueryRow(`
		SELECT COUNT(*) FROM rules
		WHERE src_cidr = ? AND dst_cidr = ?
		  AND src_port = ? AND dst_port = ? AND protocol = ?
	`, srcCIDR, dstCIDR, srcPort, dstPort, protocol).Scan(&count)
	return count > 0, err
}

func (r *SQLiteRuleRepo) ListSrcCIDRs() ([]string, error) {
	rows, err := r.db.Query(`SELECT DISTINCT src_cidr FROM rules WHERE src_cidr != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cidrs []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		cidrs = append(cidrs, c)
	}
	return cidrs, nil
}

func (r *SQLiteRuleRepo) ListDstCIDRs() ([]string, error) {
	rows, err := r.db.Query(`SELECT DISTINCT dst_cidr FROM rules WHERE dst_cidr != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cidrs []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		cidrs = append(cidrs, c)
	}
	return cidrs, nil
}

// ==================== WhitelistRepository ====================

type SQLiteWhitelistRepo struct {
	db *sql.DB
}

func NewSQLiteWhitelistRepo(db *SQLiteDB) *SQLiteWhitelistRepo {
	return &SQLiteWhitelistRepo{db: db.db}
}

func (r *SQLiteWhitelistRepo) Create(entry *model.Whitelist) error {
	_, err := r.db.Exec(`
		INSERT INTO whitelist (id, name, src_ip, dst_ip, src_port, dst_port, protocol, comment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, entry.ID, entry.Name, nullString(entry.SrcIP), nullString(entry.DstIP),
		entry.SrcPort, entry.DstPort, entry.Protocol, entry.Comment)
	return err
}

func (r *SQLiteWhitelistRepo) Get(id string) (*model.Whitelist, error) {
	row := r.db.QueryRow(`
		SELECT id, name, src_ip, dst_ip, src_port, dst_port, protocol, comment, created_at
		FROM whitelist WHERE id = ?
	`, id)
	return scanWhitelist(row)
}

func (r *SQLiteWhitelistRepo) List() ([]*model.Whitelist, error) {
	rows, err := r.db.Query(`
		SELECT id, name, src_ip, dst_ip, src_port, dst_port, protocol, comment, created_at
		FROM whitelist ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanWhitelists(rows)
}

func (r *SQLiteWhitelistRepo) Delete(id string) error {
	_, err := r.db.Exec("DELETE FROM whitelist WHERE id = ?", id)
	return err
}

// ==================== NodeRepository ====================

type SQLiteNodeRepo struct {
	db *sql.DB
}

func NewSQLiteNodeRepo(db *SQLiteDB) *SQLiteNodeRepo {
	return &SQLiteNodeRepo{db: db.db}
}

func (r *SQLiteNodeRepo) Create(node *model.Node) error {
	_, err := r.db.Exec(`
		INSERT INTO nodes (id, name, endpoint, api_key, status)
		VALUES (?, ?, ?, ?, ?)
	`, node.ID, node.Name, node.Endpoint, nullString(node.ApiKey), node.Status)
	return err
}

func (r *SQLiteNodeRepo) Get(id string) (*model.Node, error) {
	row := r.db.QueryRow(`
		SELECT id, name, endpoint, api_key, status, last_sync, last_seen, created_at
		FROM nodes WHERE id = ?
	`, id)
	return scanNode(row)
}

func (r *SQLiteNodeRepo) GetByEndpoint(endpoint string) (*model.Node, error) {
	row := r.db.QueryRow(`
		SELECT id, name, endpoint, api_key, status, last_sync, last_seen, created_at
		FROM nodes WHERE endpoint = ?
	`, endpoint)
	return scanNode(row)
}

func (r *SQLiteNodeRepo) List() ([]*model.Node, error) {
	rows, err := r.db.Query(`
		SELECT id, name, endpoint, api_key, status, last_sync, last_seen, created_at
		FROM nodes ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func (r *SQLiteNodeRepo) Update(node *model.Node) error {
	_, err := r.db.Exec(`
		UPDATE nodes SET name=?, endpoint=?, api_key=?, status=?
		WHERE id = ?
	`, node.Name, node.Endpoint, nullString(node.ApiKey), node.Status, node.ID)
	return err
}

func (r *SQLiteNodeRepo) Delete(id string) error {
	_, err := r.db.Exec("DELETE FROM nodes WHERE id = ?", id)
	return err
}

func (r *SQLiteNodeRepo) UpdateStatus(id string, status string) error {
	_, err := r.db.Exec("UPDATE nodes SET status = ? WHERE id = ?", status, id)
	return err
}

func (r *SQLiteNodeRepo) UpdateLastSeen(id string) error {
	_, err := r.db.Exec("UPDATE nodes SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", id)
	return err
}

func (r *SQLiteNodeRepo) UpdateLastSync(id string) error {
	_, err := r.db.Exec("UPDATE nodes SET last_sync = CURRENT_TIMESTAMP WHERE id = ?", id)
	return err
}

// ==================== SyncLogRepository ====================

type SQLiteSyncLogRepo struct {
	db *sql.DB
}

func NewSQLiteSyncLogRepo(db *SQLiteDB) *SQLiteSyncLogRepo {
	return &SQLiteSyncLogRepo{db: db.db}
}

func (r *SQLiteSyncLogRepo) Log(nodeID, action, ruleID, status, errMsg string) error {
	_, err := r.db.Exec(`
		INSERT INTO sync_log (node_id, action, rule_id, status, error)
		VALUES (?, ?, ?, ?, ?)
	`, nodeID, action, ruleID, status, errMsg)
	return err
}

func (r *SQLiteSyncLogRepo) ListByNode(nodeID string, limit int) ([]SyncLogEntry, error) {
	rows, err := r.db.Query(`
		SELECT id, node_id, action, rule_id, status, error, created_at
		FROM sync_log WHERE node_id = ? ORDER BY created_at DESC LIMIT ?
	`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []SyncLogEntry
	for rows.Next() {
		var e SyncLogEntry
		var ruleID, errStr sql.NullString
		if err := rows.Scan(&e.ID, &e.NodeID, &e.Action, &ruleID, &e.Status, &errStr, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.RuleID = ruleID.String
		e.Error = errStr.String
		entries = append(entries, e)
	}
	return entries, nil
}

// ==================== Helper Functions ====================

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func scanRule(row *sql.Row) (*model.Rule, error) {
	var r model.Rule
	var srcIP, dstIP, name, source, comment sql.NullString
	var srcCIDR, dstCIDR sql.NullString
	var expiresAt sql.NullTime

	err := row.Scan(&r.ID, &name, &srcIP, &dstIP, &srcCIDR, &dstCIDR, &r.SrcPort, &r.DstPort, &r.Protocol,
		&r.Action, &r.RateLimit, &r.PktLenMin, &r.PktLenMax, &r.TcpFlags, &source, &comment, &r.Enabled, &r.CreatedAt, &expiresAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}

	r.Name = name.String
	r.SrcIP = srcIP.String
	r.DstIP = dstIP.String
	r.SrcCIDR = srcCIDR.String
	r.DstCIDR = dstCIDR.String
	r.Source = source.String
	r.Comment = comment.String
	if expiresAt.Valid {
		r.ExpiresAt = &expiresAt.Time
	}
	return &r, nil
}

func scanRules(rows *sql.Rows) ([]*model.Rule, error) {
	var rules []*model.Rule
	for rows.Next() {
		var r model.Rule
		var srcIP, dstIP, name, source, comment sql.NullString
		var srcCIDR, dstCIDR sql.NullString
		var expiresAt sql.NullTime

		err := rows.Scan(&r.ID, &name, &srcIP, &dstIP, &srcCIDR, &dstCIDR, &r.SrcPort, &r.DstPort, &r.Protocol,
			&r.Action, &r.RateLimit, &r.PktLenMin, &r.PktLenMax, &r.TcpFlags, &source, &comment, &r.Enabled, &r.CreatedAt, &expiresAt, &r.UpdatedAt)
		if err != nil {
			return nil, err
		}

		r.Name = name.String
		r.SrcIP = srcIP.String
		r.DstIP = dstIP.String
		r.SrcCIDR = srcCIDR.String
		r.DstCIDR = dstCIDR.String
		r.Source = source.String
		r.Comment = comment.String
		if expiresAt.Valid {
			r.ExpiresAt = &expiresAt.Time
		}
		rules = append(rules, &r)
	}
	return rules, nil
}

func scanWhitelist(row *sql.Row) (*model.Whitelist, error) {
	var w model.Whitelist
	var srcIP, dstIP, name, protocol, comment sql.NullString

	err := row.Scan(&w.ID, &name, &srcIP, &dstIP, &w.SrcPort, &w.DstPort, &protocol, &comment, &w.CreatedAt)
	if err != nil {
		return nil, err
	}

	w.Name = name.String
	w.SrcIP = srcIP.String
	w.DstIP = dstIP.String
	w.Protocol = protocol.String
	w.Comment = comment.String
	return &w, nil
}

func scanWhitelists(rows *sql.Rows) ([]*model.Whitelist, error) {
	var entries []*model.Whitelist
	for rows.Next() {
		var w model.Whitelist
		var srcIP, dstIP, name, protocol, comment sql.NullString

		err := rows.Scan(&w.ID, &name, &srcIP, &dstIP, &w.SrcPort, &w.DstPort, &protocol, &comment, &w.CreatedAt)
		if err != nil {
			return nil, err
		}

		w.Name = name.String
		w.SrcIP = srcIP.String
		w.DstIP = dstIP.String
		w.Protocol = protocol.String
		w.Comment = comment.String
		entries = append(entries, &w)
	}
	return entries, nil
}

func scanNode(row *sql.Row) (*model.Node, error) {
	var n model.Node
	var apiKey sql.NullString
	var lastSync, lastSeen sql.NullTime

	err := row.Scan(&n.ID, &n.Name, &n.Endpoint, &apiKey, &n.Status, &lastSync, &lastSeen, &n.CreatedAt)
	if err != nil {
		return nil, err
	}

	n.ApiKey = apiKey.String
	if lastSync.Valid {
		n.LastSync = &lastSync.Time
	}
	if lastSeen.Valid {
		n.LastSeen = &lastSeen.Time
	}
	return &n, nil
}

func scanNodes(rows *sql.Rows) ([]*model.Node, error) {
	var nodes []*model.Node
	for rows.Next() {
		var n model.Node
		var apiKey sql.NullString
		var lastSync, lastSeen sql.NullTime

		err := rows.Scan(&n.ID, &n.Name, &n.Endpoint, &apiKey, &n.Status, &lastSync, &lastSeen, &n.CreatedAt)
		if err != nil {
			return nil, err
		}

		n.ApiKey = apiKey.String
		if lastSync.Valid {
			n.LastSync = &lastSync.Time
		}
		if lastSeen.Valid {
			n.LastSeen = &lastSeen.Time
		}
		nodes = append(nodes, &n)
	}
	return nodes, nil
}
