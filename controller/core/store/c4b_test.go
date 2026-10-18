package store

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
)

func TestC4BStore(t *testing.T) {
	t.Run("C4B-schema", func(t *testing.T) {
		for _, previous := range []bool{false, true} {
			previous := previous
			t.Run(map[bool]string{false: "fresh", true: "v2"}[previous], func(t *testing.T) {
				must := func(e error) {
					t.Helper()
					if e != nil {
						t.Fatal(e)
					}
				}
				path := filepath.Join(t.TempDir(), "audit.db")
				oldTables := []string{"users", "sessions", "credentials", "settings", "rules", "claims", "whitelist", "logical_id_hw"}
				var before [][]string
				if previous {
					raw, err := sql.Open("sqlite3", path)
					must(err)
					_, err = raw.Exec(schemaV1 + schemaV2 + `CREATE TABLE schema_version(id INTEGER PRIMARY KEY,version INTEGER); INSERT INTO schema_version VALUES(1,2);`)
					must(err)
					_, err = raw.Exec("INSERT INTO users VALUES(1,'seed','TEST_ONLY_HASH_PLACEHOLDER','2026-10-12T00:00:00Z','cli','2026-10-12T00:00:00Z')")
					must(err)
					var u User
					must(raw.QueryRow("SELECT id,username,password_hash,created_at,created_by,password_changed_at FROM users WHERE username='seed'").Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt, &u.CreatedBy, &u.PasswordChangedAt))
					inserted, err := InsertSession(raw, "TEST_ONLY_SESSION_HASH", u, u.CreatedAt)
					must(err)
					if !inserted {
						t.Fatal("session fixture")
					}
					must(InsertCredential(raw, Credential{ID: "test-key-id", Name: "seed", SecretHash: "TEST_ONLY_SECRET_HASH", CreatedAt: u.CreatedAt, CreatedBy: "cli"}))
					must(InsertRule(raw, Rule{ID: "rule_seed", LogicalID: 1, Match: Match{DstIP: "192.0.2.1", Action: "drop"}, Kind: "exact", GroupKey: "seed", CondKey: "seed", CreatedAt: u.CreatedAt, UpdatedAt: u.CreatedAt, CreatedBy: "ui", UpdatedBy: "ui"}))
					must(Claim(raw, "rule_seed", "ui", "", u.CreatedAt))
					must(InsertWhitelist(raw, Whitelist{ID: "wl_seed", DstIP: "192.0.2.2", Key: "seed", CreatedAt: u.CreatedAt, CreatedBy: "ui"}))
					before = c4aRows(t, raw, oldTables)
					must(raw.Close())
				}
				db, err := Open(path)
				must(err)
				defer db.Close()
				if previous {
					after := c4aRows(t, db, oldTables)
					filtered := [][]string{}
					for _, row := range after {
						if row[0] == "users" {
							if row[len(row)-1] != "value:admin" {
								t.Fatal("migrated role")
							}
							row = row[:len(row)-1]
						}
						if !(row[0] == "settings" && (row[1] == "value:audit_retention_days" || row[1] == "value:reconcile_interval_minutes" || row[1] == "value:default_language" || row[1] == "value:history_retention_days")) {
							filtered = append(filtered, row)
						}
					}
					if !reflect.DeepEqual(before, filtered) {
						t.Fatal("v2 data changed", before, filtered)
					}
				}
				var v, tables, indexes, settings, sequence int
				must(db.QueryRow("SELECT version FROM schema_version").Scan(&v))
				must(db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit'").Scan(&tables))
				must(db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='audit_at'").Scan(&indexes))
				must(db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='sqlite_sequence'").Scan(&sequence))
				must(db.QueryRow("SELECT COUNT(*) FROM settings").Scan(&settings))
				s, err := ReadSettings(db)
				must(err)
				if v != 6 || tables != 1 || indexes != 1 || sequence != 0 || settings != 5 || s.SessionHours != 24 || s.AuditRetentionDays != 180 || s.ReconcileIntervalMinutes != 15 || s.DefaultLanguage != 3 || s.HistoryRetentionDays != 30 {
					t.Fatal("schema v4", v, tables, indexes, sequence, settings, s)
				}
				all := append(append([]string{}, oldTables...), "audit", "schema_version", "traffic_1m", "traffic_1h")
				snapshot := c4aRows(t, db, all)
				must(db.Migrate())
				must(db.Migrate())
				if !reflect.DeepEqual(snapshot, c4aRows(t, db, all)) {
					t.Fatal("not idempotent")
				}
				_, err = db.Exec("UPDATE schema_version SET version=7")
				must(err)
				future, err := Open(path)
				if future != nil {
					future.Close()
				}
				if err == nil {
					t.Fatal("version 7 accepted")
				}
			})
		}
	})
}
