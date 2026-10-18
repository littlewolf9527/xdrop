package store

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
)

func TestC4AStore(t *testing.T) {
	t.Run("C4A-schema", func(t *testing.T) {
		check := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, v1 := range []bool{false, true} {
			path := filepath.Join(t.TempDir(), "accounts.db")
			var before [][]string
			if v1 {
				raw, err := sql.Open("sqlite3", path)
				check(err)
				_, err = raw.Exec(schemaV1 + `CREATE TABLE schema_version(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL); INSERT INTO schema_version VALUES(1,1);`)
				check(err)
				check(InsertRule(raw, Rule{ID: "rule_test", LogicalID: 1, Match: Match{DstIP: "192.0.2.1", Action: "drop"}, Kind: "exact", GroupKey: "test-group", CondKey: "test-condition", CreatedAt: "2026-10-12T00:00:00Z", UpdatedAt: "2026-10-12T00:00:00Z", CreatedBy: "ui", UpdatedBy: "ui"}))
				check(Claim(raw, "rule_test", "ui", "", "2026-10-12T00:00:00Z"))
				check(InsertWhitelist(raw, Whitelist{ID: "wl_test", DstIP: "192.0.2.2", Key: "test-wl", CreatedBy: "ui", CreatedAt: "2026-10-12T00:00:00Z"}))
				before = c4aRows(t, raw, []string{"rules", "claims", "whitelist", "logical_id_hw"})
				check(raw.Close())
			}
			db, err := Open(path)
			check(err)
			if v1 && !reflect.DeepEqual(before, c4aRows(t, db, []string{"rules", "claims", "whitelist", "logical_id_hw"})) {
				t.Fatal("v1 data changed")
			}
			var version, tables, hours int
			check(db.QueryRow("SELECT version FROM schema_version").Scan(&version))
			check(db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('users','sessions','credentials','settings','audit','user_prefs','templates','nodes','traffic_1m','traffic_1h')").Scan(&tables))
			check(db.QueryRow("SELECT value FROM settings WHERE key='session_hours'").Scan(&hours))
			if version != 6 || tables != 10 || hours != 24 {
				t.Fatalf("version=%d tables=%d hours=%d", version, tables, hours)
			}
			var retention int
			check(db.QueryRow("SELECT value FROM settings WHERE key='audit_retention_days'").Scan(&retention))
			if retention != 180 {
				t.Fatal("retention default", retention)
			}
			all := []string{"rules", "claims", "whitelist", "logical_id_hw", "users", "sessions", "credentials", "settings", "schema_version", "audit", "traffic_1m", "traffic_1h"}
			snapshot := c4aRows(t, db, all)
			check(db.Migrate())
			check(db.Migrate())
			if !reflect.DeepEqual(snapshot, c4aRows(t, db, all)) {
				t.Fatal("migration not idempotent")
			}
			_, err = db.Exec("UPDATE schema_version SET version=7")
			check(err)
			check(db.Close())
			future, err := Open(path)
			if future != nil {
				future.Close()
			}
			if err == nil {
				t.Fatal("version 7 accepted")
			}
		}
	})
}
func c4aRows(t *testing.T, q Queryer, tables []string) [][]string {
	t.Helper()
	out := [][]string{}
	for _, table := range tables {
		rows, err := q.Query("SELECT * FROM " + table + " ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]sql.NullString, len(columns))
			ptrs := make([]any, len(columns))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			line := []string{table}
			for _, v := range values {
				if v.Valid {
					line = append(line, "value:"+v.String)
				} else {
					line = append(line, "NULL")
				}
			}
			out = append(out, line)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
	return out
}
