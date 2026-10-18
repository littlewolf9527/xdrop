package store

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
)

func TestC5AStore(t *testing.T) {
	t.Run("C5A-migrate", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "v3.db")
		raw, err := sql.Open("sqlite3", path)
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(err)
		_, err = raw.Exec(schemaV1 + schemaV2 + schemaV3 + `CREATE TABLE schema_version(id INTEGER PRIMARY KEY,version INTEGER);INSERT INTO schema_version VALUES(1,3);
INSERT INTO users VALUES(1,'first','TEST_ONLY_HASH_ONE','2026-10-13T00:00:00Z','cli','2026-10-13T00:00:00Z'),(2,'second','TEST_ONLY_HASH_TWO','2026-10-13T00:00:00Z','cli','2026-10-13T00:00:00Z');
INSERT INTO sessions VALUES('TEST_ONLY_TICKET_HASH',1,'2026-10-13T00:00:00Z');
INSERT INTO audit VALUES(1,'2026-10-13T00:00:00Z','system:cli','','user.create','user:first',NULL,'{}');
UPDATE settings SET value=48 WHERE key='session_hours';UPDATE settings SET value=90 WHERE key='audit_retention_days';`)
		must(err)
		tables := []string{"users", "sessions", "audit", "settings"}
		before := c4aRows(t, raw, tables)
		must(raw.Close())
		db, err := Open(path)
		must(err)
		defer db.Close()
		after := c4aRows(t, db.Reader(), tables)
		filtered := [][]string{}
		users := 0
		for _, row := range after {
			if row[0] == "users" {
				if row[len(row)-1] != "value:admin" {
					t.Fatal("migration did not promote every user")
				}
				users++
				row = row[:len(row)-1]
			}
			if row[0] == "settings" && (row[1] == "value:reconcile_interval_minutes" || row[1] == "value:default_language" || row[1] == "value:history_retention_days") {
				continue
			}
			filtered = append(filtered, row)
		}
		if users != 2 || !reflect.DeepEqual(before, filtered) {
			t.Fatal("v3 old columns changed")
		}
		session, err := FindSession(db.Reader(), "TEST_ONLY_TICKET_HASH")
		must(err)
		if session.Username != "first" || session.Role != "admin" || session.CreatedAt != "2026-10-13T00:00:00Z" || session.Hours != 48 {
			t.Fatal("upgraded session invalid")
		}
		all := append(tables, "schema_version", "user_prefs", "templates", "traffic_1m", "traffic_1h")
		snapshot := c4aRows(t, db.Reader(), all)
		must(db.Migrate())
		if !reflect.DeepEqual(snapshot, c4aRows(t, db.Reader(), all)) {
			t.Fatal("v4 not idempotent")
		}
		var version int
		must(db.QueryRow("SELECT version FROM schema_version").Scan(&version))
		if version != 6 {
			t.Fatal("schema version")
		}
		_, err = db.Exec("UPDATE schema_version SET version=7")
		must(err)
		if db.Migrate() == nil {
			t.Fatal("v7 accepted")
		}
		t.Log("migrated_users=2 preserved_sessions=1 preserved_audit=1 old_settings=2")
	})
}
