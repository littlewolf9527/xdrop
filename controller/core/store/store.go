// Package store contains SQLite persistence primitives for the controller.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/mattn/go-sqlite3"
)

type Match struct {
	SrcIP        string  `json:"src_ip"`
	DstIP        string  `json:"dst_ip"`
	SrcCIDR      string  `json:"src_cidr"`
	DstCIDR      string  `json:"dst_cidr"`
	SrcPort      int     `json:"src_port"`
	DstPort      int     `json:"dst_port"`
	Protocol     string  `json:"protocol"`
	TTL          *string `json:"ttl"`
	DSCP         *string `json:"dscp"`
	ICMPType     *string `json:"icmp_type"`
	ICMPCode     *string `json:"icmp_code"`
	Fragment     *string `json:"fragment"`
	PktLen       *string `json:"pkt_len"`
	TCPFlags     string  `json:"tcp_flags"`
	MatchAnomaly int     `json:"match_anomaly"`
	Action       string  `json:"action"`
	RateLimit    int64   `json:"rate_limit"`
}

type Rule struct {
	Match
	ID                            string
	LogicalID                     int64
	Kind, GroupKey, CondKey       string
	Enabled                       bool
	Comment, CreatedAt, UpdatedAt string
	ExpiresAt                     *string
	CreatedBy, UpdatedBy          string
}

type Whitelist struct {
	ID, SrcIP, DstIP, Protocol         string
	SrcPort, DstPort                   int
	Key, Comment, CreatedAt, CreatedBy string
}

type DB struct {
	*sql.DB
	read *sql.DB
}

func (db *DB) Reader() Queryer { return db.read }

// Queryer is implemented by both a connection pool and a transaction.
type Queryer interface {
	Exec(string, ...any) (sql.Result, error)
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

const TimeFormat = "2006-01-02T15:04:05Z"

const schemaV1 = `
CREATE TABLE rules (
 id TEXT PRIMARY KEY,
 logical_id INTEGER NOT NULL UNIQUE CHECK(logical_id > 0),
 kind TEXT NOT NULL,
 src_ip TEXT NOT NULL DEFAULT '', dst_ip TEXT NOT NULL DEFAULT '',
 src_cidr TEXT NOT NULL DEFAULT '', dst_cidr TEXT NOT NULL DEFAULT '',
 src_port INTEGER NOT NULL DEFAULT 0, dst_port INTEGER NOT NULL DEFAULT 0,
 protocol TEXT NOT NULL DEFAULT '',
 ttl TEXT, dscp TEXT, icmp_type TEXT, icmp_code TEXT, fragment TEXT, pkt_len TEXT,
 tcp_flags TEXT NOT NULL DEFAULT '', match_anomaly INTEGER NOT NULL DEFAULT 0,
 group_key TEXT NOT NULL, cond_key TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('drop','rate_limit')),
 rate_limit INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL,
 comment TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 expires_at TEXT, created_by TEXT NOT NULL, updated_by TEXT NOT NULL
);
CREATE UNIQUE INDEX rules_identity ON rules(group_key, cond_key);
CREATE INDEX rules_group ON rules(group_key);
CREATE INDEX rules_expiry ON rules(expires_at);
CREATE TABLE logical_id_hw (id INTEGER PRIMARY KEY CHECK(id = 1), high_water INTEGER NOT NULL);
INSERT INTO logical_id_hw VALUES(1,0);
CREATE TABLE whitelist (
 id TEXT PRIMARY KEY, src_ip TEXT NOT NULL DEFAULT '', dst_ip TEXT NOT NULL DEFAULT '',
 src_port INTEGER NOT NULL DEFAULT 0, dst_port INTEGER NOT NULL DEFAULT 0,
 protocol TEXT NOT NULL DEFAULT '', wl_key TEXT NOT NULL UNIQUE,
 comment TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, created_by TEXT NOT NULL
);
CREATE TABLE claims (
 rule_id TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
 claimant TEXT NOT NULL, claim_ref TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
 PRIMARY KEY(rule_id, claimant, claim_ref)
);`

func Open(path string) (*DB, error) {
	p, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: p, RawQuery: "_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL&_synchronous=FULL"}
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &DB{DB: db}
	if err = s.Migrate(); err != nil {
		db.Close()
		return nil, err
	}
	u.RawQuery = "_foreign_keys=on&_busy_timeout=5000&_query_only=1"
	s.read, err = sql.Open("sqlite3", u.String())
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (db *DB) Close() error {
	err := db.read.Close()
	writeErr := db.DB.Close()
	if err != nil {
		return err
	}
	return writeErr
}

type Snapshot struct {
	Tx   *sql.Tx
	conn *sql.Conn
}

func (db *DB) BeginSnapshot() (*Snapshot, error) {
	ctx := context.Background()
	conn, err := db.read.Conn(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Snapshot{Tx: tx, conn: conn}, nil
}

func (s *Snapshot) Pin() error {
	var highWater int64
	return s.Tx.QueryRow("SELECT high_water FROM logical_id_hw WHERE id=1").Scan(&highWater)
}

func (s *Snapshot) Close() {
	s.Tx.Rollback()
	s.conn.Close()
}

// Migrate appends numbered migrations; an unknown version is never downgraded.
func (db *DB) Migrate() error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS schema_version (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var count, version int
	if err = tx.QueryRow("SELECT COUNT(*), COALESCE(MAX(version),0) FROM schema_version").Scan(&count, &version); err != nil {
		return err
	}
	if count > 1 || version < 0 || version > 6 {
		return fmt.Errorf("unsupported schema version %d (%d rows)", version, count)
	}
	if count == 0 {
		if _, err = tx.Exec("INSERT INTO schema_version VALUES(1,0)"); err != nil {
			return err
		}
	}
	if version == 0 {
		if _, err = tx.Exec(schemaV1); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE schema_version SET version=1"); err != nil {
			return err
		}
		version = 1
	}
	if version == 1 {
		if _, err = tx.Exec(schemaV2); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE schema_version SET version=2"); err != nil {
			return err
		}
		version = 2
	}
	if version == 2 {
		if _, err = tx.Exec(schemaV3); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE schema_version SET version=3"); err != nil {
			return err
		}
		version = 3
	}
	if version == 3 {
		if _, err = tx.Exec(schemaV4); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE schema_version SET version=4"); err != nil {
			return err
		}
		version = 4
	}
	if version == 4 {
		if _, err = tx.Exec(schemaV5); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE schema_version SET version=5"); err != nil {
			return err
		}
		version = 5
	}
	if version == 5 {
		if _, err = tx.Exec(schemaV6); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE schema_version SET version=6"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const ruleColumns = "id,logical_id,kind,src_ip,dst_ip,src_cidr,dst_cidr,src_port,dst_port,protocol,ttl,dscp,icmp_type,icmp_code,fragment,pkt_len,tcp_flags,match_anomaly,group_key,cond_key,action,rate_limit,enabled,comment,created_at,updated_at,expires_at,created_by,updated_by"

func ruleValues(r Rule) []any {
	return []any{r.ID, r.LogicalID, r.Kind, r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR, r.SrcPort, r.DstPort, r.Protocol, r.TTL, r.DSCP, r.ICMPType, r.ICMPCode, r.Fragment, r.PktLen, r.TCPFlags, r.MatchAnomaly, r.GroupKey, r.CondKey, r.Action, r.RateLimit, r.Enabled, r.Comment, r.CreatedAt, r.UpdatedAt, r.ExpiresAt, r.CreatedBy, r.UpdatedBy}
}

func scanRule(s interface{ Scan(...any) error }) (r Rule, err error) {
	err = s.Scan(&r.ID, &r.LogicalID, &r.Kind, &r.SrcIP, &r.DstIP, &r.SrcCIDR, &r.DstCIDR, &r.SrcPort, &r.DstPort, &r.Protocol, &r.TTL, &r.DSCP, &r.ICMPType, &r.ICMPCode, &r.Fragment, &r.PktLen, &r.TCPFlags, &r.MatchAnomaly, &r.GroupKey, &r.CondKey, &r.Action, &r.RateLimit, &r.Enabled, &r.Comment, &r.CreatedAt, &r.UpdatedAt, &r.ExpiresAt, &r.CreatedBy, &r.UpdatedBy)
	return
}

func InsertRule(q Queryer, r Rule) error {
	_, err := q.Exec("INSERT INTO rules ("+ruleColumns+") VALUES ("+strings.TrimSuffix(strings.Repeat("?,", 29), ",")+")", ruleValues(r)...)
	return err
}

func UpdateRule(q Queryer, r Rule) error {
	cols := strings.Split(ruleColumns, ",")
	for i := range cols {
		cols[i] += "=?"
	}
	_, err := q.Exec("UPDATE rules SET "+strings.Join(cols, ",")+" WHERE id=?", append(ruleValues(r), r.ID)...)
	return err
}

func Get(q Queryer, id string) (Rule, error) {
	return scanRule(q.QueryRow("SELECT "+ruleColumns+" FROM rules WHERE id=?", id))
}
func Identity(q Queryer, group, cond string) (Rule, error) {
	return scanRule(q.QueryRow("SELECT "+ruleColumns+" FROM rules WHERE group_key=? AND cond_key=?", group, cond))
}

func List(q Queryer) ([]Rule, error) {
	return listRules(q, " ORDER BY id")
}

// LedgerRows reads occupancy identities, fetching full inputs only for enabled
// conditional members. Callers serialize writes while this snapshot is read.
func LedgerRows(q Queryer, unconditional string) ([]Rule, int, error) {
	var total, whitelist int
	if err := q.QueryRow("SELECT (SELECT COUNT(*) FROM rules),(SELECT COUNT(*) FROM whitelist)").Scan(&total, &whitelist); err != nil {
		return nil, 0, err
	}
	rows, err := q.Query("SELECT id,kind,group_key,cond_key,src_cidr,dst_cidr,enabled FROM rules")
	if err != nil {
		return nil, 0, err
	}
	out := make([]Rule, 0, total)
	for rows.Next() {
		out = append(out, Rule{})
		r := &out[len(out)-1]
		if err = rows.Scan(&r.ID, &r.Kind, &r.GroupKey, &r.CondKey, &r.SrcCIDR, &r.DstCIDR, &r.Enabled); err != nil {
			rows.Close()
			return nil, 0, err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	for i := range out {
		if out[i].Enabled && out[i].CondKey != unconditional {
			out[i], err = Get(q, out[i].ID)
			if err != nil {
				return nil, 0, err
			}
		}
	}
	return out, whitelist, nil
}

func ListPage(q Queryer, afterLogicalID int64, limit int) ([]Rule, error) {
	return listRules(q, " WHERE logical_id>? ORDER BY logical_id LIMIT ?", afterLogicalID, limit)
}

type RuleQuery struct {
	Where  string
	Args   []any
	Prefix netip.Prefix
}

// AfterRuleQueryPage is a test seam; production leaves it nil.
var AfterRuleQueryPage func()

func (f RuleQuery) scan(q Queryer, suffix string, args []any, visit func(Rule) bool) error {
	rows, err := q.Query("SELECT id,logical_id,src_ip,dst_ip,src_cidr,dst_cidr,enabled,action FROM rules WHERE "+f.Where+suffix, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.LogicalID, &r.SrcIP, &r.DstIP, &r.SrcCIDR, &r.DstCIDR, &r.Enabled, &r.Action); err != nil {
			return err
		}
		matched := !f.Prefix.IsValid()
		for _, raw := range []string{r.SrcIP, r.DstIP, r.SrcCIDR, r.DstCIDR} {
			ip, e := netip.ParseAddr(raw)
			if e == nil && f.Prefix.Contains(ip) {
				matched = true
			}
			p, e := netip.ParsePrefix(raw)
			if e == nil && p.Bits() >= f.Prefix.Bits() && f.Prefix.Contains(p.Addr()) {
				matched = true
			}
		}
		if matched && !visit(r) {
			break
		}
	}
	return rows.Err()
}

func (f RuleQuery) Page(q Queryer, state string, after int64, limit int) ([]Rule, error) {
	filter := map[string]string{"": "1", "disabled": "enabled=0", "drop": "enabled=1 AND action='drop'", "rate_limit": "enabled=1 AND action='rate_limit'"}[state]
	suffix := " AND (" + filter + ") AND logical_id>? ORDER BY logical_id"
	args := append(append([]any{}, f.Args...), after)
	if !f.Prefix.IsValid() {
		return listRules(q, " WHERE "+f.Where+suffix+" LIMIT ?", append(args, limit)...)
	}
	ids := []any{}
	err := f.scan(q, suffix, args, func(r Rule) bool { ids = append(ids, r.ID); return len(ids) < limit })
	if err != nil {
		return nil, err
	}
	return listRules(q, " WHERE id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+") ORDER BY logical_id", ids...)
}

func (f RuleQuery) Counts(q Queryer) (map[string]int, error) {
	if AfterRuleQueryPage != nil {
		AfterRuleQueryPage()
	}
	out := map[string]int{"all": 0, "drop": 0, "rate_limit": 0, "disabled": 0}
	if !f.Prefix.IsValid() {
		var all, drop, rate, disabled int
		err := q.QueryRow("SELECT count(*),count(CASE WHEN enabled=1 AND action='drop' THEN 1 END),count(CASE WHEN enabled=1 AND action='rate_limit' THEN 1 END),count(CASE WHEN enabled=0 THEN 1 END) FROM rules WHERE "+f.Where, f.Args...).Scan(&all, &drop, &rate, &disabled)
		out["all"], out["drop"], out["rate_limit"], out["disabled"] = all, drop, rate, disabled
		return out, err
	}
	err := f.scan(q, "", f.Args, func(r Rule) bool {
		state := r.Action
		if !r.Enabled {
			state = "disabled"
		}
		out["all"]++
		out[state]++
		return true
	})
	return out, err
}

func EnabledByGroup(q Queryer, group string) ([]Rule, error) {
	return listRules(q, " WHERE group_key=? AND enabled=1 ORDER BY id", group)
}

func Due(q Queryer, now string) ([]Rule, error) {
	return listRules(q, " INDEXED BY rules_expiry WHERE expires_at<=? ORDER BY id", now)
}

func listRules(q Queryer, suffix string, args ...any) ([]Rule, error) {
	rows, err := q.Query("SELECT "+ruleColumns+" FROM rules"+suffix, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		r, e := scanRule(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var ErrLogicalFull = errors.New("logical ID space exhausted")

func NextLogicalID(q Queryer) (int64, error) {
	r, err := q.Exec("UPDATE logical_id_hw SET high_water=high_water+1 WHERE id=1 AND high_water<4294967295")
	if err != nil {
		return 0, err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, ErrLogicalFull
	}
	var id int64
	err = q.QueryRow("SELECT high_water FROM logical_id_hw WHERE id=1").Scan(&id)
	return id, err
}

func Claim(q Queryer, id, claimant, ref, now string) error {
	_, err := q.Exec("INSERT OR IGNORE INTO claims(rule_id,claimant,claim_ref,created_at) VALUES(?,?,?,?)", id, claimant, ref, now)
	return err
}
func Release(q Queryer, id, claimant, ref string) (bool, error) {
	return changed(q.Exec("DELETE FROM claims WHERE rule_id=? AND claimant=? AND claim_ref=?", id, claimant, ref))
}
func ClaimCount(q Queryer, id string) (int, error) {
	var n int
	err := q.QueryRow("SELECT COUNT(*) FROM claims WHERE rule_id=?", id).Scan(&n)
	return n, err
}
func DeleteRule(q Queryer, id string) error {
	_, err := q.Exec("DELETE FROM rules WHERE id=?", id)
	return err
}

func Unique(err error) bool {
	var e sqlite3.Error
	return errors.As(err, &e) && (e.ExtendedCode == sqlite3.ErrConstraintUnique || e.ExtendedCode == sqlite3.ErrConstraintPrimaryKey)
}

func InsertWhitelist(q Queryer, w Whitelist) error {
	_, err := q.Exec("INSERT INTO whitelist(id,src_ip,dst_ip,src_port,dst_port,protocol,wl_key,comment,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)", w.ID, w.SrcIP, w.DstIP, w.SrcPort, w.DstPort, w.Protocol, w.Key, w.Comment, w.CreatedAt, w.CreatedBy)
	return err
}
func WhitelistIdentity(q Queryer, key string) (w Whitelist, err error) {
	err = q.QueryRow("SELECT id,src_ip,dst_ip,src_port,dst_port,protocol,wl_key,comment,created_at,created_by FROM whitelist WHERE wl_key=?", key).Scan(&w.ID, &w.SrcIP, &w.DstIP, &w.SrcPort, &w.DstPort, &w.Protocol, &w.Key, &w.Comment, &w.CreatedAt, &w.CreatedBy)
	return
}
func ListWhitelist(q Queryer) ([]Whitelist, error) {
	return listWhitelist(q, " ORDER BY id")
}
func ListWhitelistPage(q Queryer, afterID string, limit int) ([]Whitelist, error) {
	return listWhitelist(q, " WHERE id>? ORDER BY id LIMIT ?", afterID, limit)
}
func listWhitelist(q Queryer, suffix string, args ...any) ([]Whitelist, error) {
	rows, err := q.Query("SELECT id,src_ip,dst_ip,src_port,dst_port,protocol,wl_key,comment,created_at,created_by FROM whitelist"+suffix, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Whitelist{}
	for rows.Next() {
		var w Whitelist
		if err = rows.Scan(&w.ID, &w.SrcIP, &w.DstIP, &w.SrcPort, &w.DstPort, &w.Protocol, &w.Key, &w.Comment, &w.CreatedAt, &w.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
func DeleteWhitelist(q Queryer, id string) (bool, error) {
	r, err := q.Exec("DELETE FROM whitelist WHERE id=?", id)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n > 0, err
}
