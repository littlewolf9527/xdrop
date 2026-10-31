package store

import "encoding/json"

const schemaV3 = `
CREATE TABLE audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, source TEXT NOT NULL,
 action TEXT NOT NULL, target TEXT NOT NULL, before TEXT, after TEXT);
CREATE INDEX audit_at ON audit(at);
INSERT INTO settings VALUES('audit_retention_days', 180);`

type AuditEvent struct {
	ID     int64           `json:"id"`
	At     string          `json:"at"`
	Actor  string          `json:"actor"`
	Source string          `json:"source"`
	Action string          `json:"action"`
	Target string          `json:"target"`
	Before json.RawMessage `json:"before"`
	After  json.RawMessage `json:"after"`
}

func InsertAudit(q Queryer, e AuditEvent) error {
	value := func(b json.RawMessage) any {
		if b == nil {
			return nil
		}
		return string(b)
	}
	_, err := q.Exec("INSERT INTO audit(at,actor,source,action,target,before,after) VALUES(?,?,?,?,?,?,?)", e.At, e.Actor, e.Source, e.Action, e.Target, value(e.Before), value(e.After))
	return err
}

func AuditPage(q Queryer, from, to, cursorAt string, cursorID int64, limit int) ([]AuditEvent, error) {
	return AuditPageAction(q, "", from, to, cursorAt, cursorID, limit)
}
func AuditAfter(q Queryer, from, to, afterAt string, afterID int64, limit int) ([]AuditEvent, error) {
	return AuditAfterAction(q, "", from, to, afterAt, afterID, limit)
}

func AuditPageAction(q Queryer, action, from, to, cursorAt string, cursorID int64, limit int) ([]AuditEvent, error) {
	return auditRows(q, action, from, to, cursorAt, cursorID, limit, "<", "DESC")
}
func AuditAfterAction(q Queryer, action, from, to, afterAt string, afterID int64, limit int) ([]AuditEvent, error) {
	return auditRows(q, action, from, to, afterAt, afterID, limit, ">", "ASC")
}

func auditRows(q Queryer, action, from, to, at string, id int64, limit int, cmp, order string) ([]AuditEvent, error) {
	suffix, args := " WHERE 1=1", []any{}
	if action != "" {
		suffix += " AND action=?"
		args = append(args, action)
	}
	for _, bound := range []struct{ value, op string }{{from, ">="}, {to, "<"}} {
		if bound.value != "" {
			suffix += " AND at" + bound.op + "?"
			args = append(args, bound.value)
		}
	}
	if at != "" {
		suffix += " AND (at,id)" + cmp + "(?,?)"
		args = append(args, at, id)
	}
	rows, err := q.Query("SELECT id,at,actor,source,action,target,before,after FROM audit"+suffix+" ORDER BY at "+order+",id "+order+" LIMIT ?", append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		var before, after *string
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Source, &e.Action, &e.Target, &before, &after); err != nil {
			return nil, err
		}
		if before != nil {
			e.Before = json.RawMessage(*before)
		}
		if after != nil {
			e.After = json.RawMessage(*after)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func PurgeAudit(q Queryer, before string, limit int) (int64, error) {
	r, err := q.Exec("DELETE FROM audit WHERE id IN (SELECT id FROM audit WHERE at < ? ORDER BY at,id LIMIT ?)", before, limit)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

type ClaimRow struct {
	Claimant string `json:"claimant"`
	ClaimRef string `json:"claim_ref"`
}

func Claims(q Queryer, ruleID string) ([]ClaimRow, error) {
	rows, err := q.Query("SELECT claimant,claim_ref FROM claims WHERE rule_id=? ORDER BY claimant,claim_ref", ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClaimRow{}
	for rows.Next() {
		var c ClaimRow
		if err := rows.Scan(&c.Claimant, &c.ClaimRef); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func changed(r interface{ RowsAffected() (int64, error) }, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func AddClaim(q Queryer, id, claimant, ref, now string, expiresAt *string) (bool, error) {
	return changed(q.Exec("INSERT OR IGNORE INTO claims(rule_id,claimant,claim_ref,created_at,expires_at) VALUES(?,?,?,?,?)", id, claimant, ref, now, expiresAt))
}
func GetWhitelist(q Queryer, id string) (w Whitelist, err error) {
	err = q.QueryRow("SELECT id,src_ip,dst_ip,src_port,dst_port,protocol,wl_key,comment,created_at,created_by FROM whitelist WHERE id=?", id).Scan(&w.ID, &w.SrcIP, &w.DstIP, &w.SrcPort, &w.DstPort, &w.Protocol, &w.Key, &w.Comment, &w.CreatedAt, &w.CreatedBy)
	return
}

type Settings struct {
	HistoryRetentionDays     int `json:"history_retention_days"`
	SessionHours             int `json:"session_hours"`
	AuditRetentionDays       int `json:"audit_retention_days"`
	ReconcileIntervalMinutes int `json:"reconcile_interval_minutes"`
	DefaultLanguage          int `json:"default_language"`
}

func ReadSettings(q Queryer) (s Settings, err error) {
	err = q.QueryRow("SELECT (SELECT value FROM settings WHERE key='session_hours'),(SELECT value FROM settings WHERE key='audit_retention_days'),(SELECT value FROM settings WHERE key='reconcile_interval_minutes'),(SELECT value FROM settings WHERE key='default_language'),(SELECT value FROM settings WHERE key='history_retention_days')").Scan(&s.SessionHours, &s.AuditRetentionDays, &s.ReconcileIntervalMinutes, &s.DefaultLanguage, &s.HistoryRetentionDays)
	return
}
func SetAuditRetentionDays(q Queryer, days int) error {
	_, err := q.Exec("UPDATE settings SET value=? WHERE key='audit_retention_days'", days)
	return err
}
func SetHistoryRetentionDays(q Queryer, days int) error {
	_, err := q.Exec("UPDATE settings SET value=? WHERE key='history_retention_days'", days)
	return err
}
func SetReconcileIntervalMinutes(q Queryer, minutes int) error {
	_, err := q.Exec("UPDATE settings SET value=? WHERE key='reconcile_interval_minutes'", minutes)
	return err
}
func SetDefaultLanguage(q Queryer, language int) error {
	_, err := q.Exec("UPDATE settings SET value=? WHERE key='default_language'", language)
	return err
}
func Language(n int) string {
	return map[int]string{1: "zh-CN", 2: "ja-JP", 3: "en-US"}[n]
}
func LanguageCode(name string) int {
	for n := 1; n <= 3; n++ {
		if Language(n) == name {
			return n
		}
	}
	return 0
}
