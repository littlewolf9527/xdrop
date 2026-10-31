package store

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
)

// TD-164 B9: v6 → v7 backfills each claim's expiry from its rule and leaves rules untouched.
func TestTD164MigrationBackfill(t *testing.T) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "v6.db")
	raw, err := sql.Open("sqlite3", path)
	must(err)
	_, err = raw.Exec(schemaV1 + schemaV2 + schemaV3 + schemaV4 + schemaV5 + schemaV6 + `CREATE TABLE schema_version(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL); INSERT INTO schema_version VALUES(1,6);`)
	must(err)
	finite1, finite2 := "2026-10-10T11:00:00Z", "2026-10-10T12:00:00Z"
	seed := []struct {
		id      string
		expires *string
		claims  [][2]string
	}{
		{"rule_permanent", nil, [][2]string{{"cred:a", "r1"}, {"ui", ""}}},
		{"rule_one", &finite1, [][2]string{{"cred:a", "r1"}}},
		{"rule_two", &finite2, [][2]string{{"cred:a", "r1"}, {"cred:b", ""}, {"ui", ""}}},
	}
	for i, s := range seed {
		r := Rule{ID: s.id, LogicalID: int64(i + 1), Kind: "exact", GroupKey: "g" + s.id, CondKey: "c", Enabled: true,
			CreatedAt: "2026-10-10T10:00:00Z", UpdatedAt: "2026-10-10T10:00:00Z", ExpiresAt: s.expires, CreatedBy: "ui", UpdatedBy: "ui"}
		r.Action = "drop"
		must(InsertRule(raw, r))
		for _, c := range s.claims {
			_, err = raw.Exec("INSERT INTO claims(rule_id,claimant,claim_ref,created_at) VALUES(?,?,?,?)", s.id, c[0], c[1], "2026-10-10T10:00:00Z")
			must(err)
		}
	}
	_, err = raw.Exec("UPDATE logical_id_hw SET high_water=3")
	must(err)
	rulesBefore := c4aRows(t, raw, []string{"rules"})
	var claimsBefore int
	must(raw.QueryRow("SELECT COUNT(*) FROM claims").Scan(&claimsBefore))
	must(raw.Close())

	db, err := Open(path)
	must(err)
	defer db.Close()
	var version int
	must(db.QueryRow("SELECT version FROM schema_version").Scan(&version))
	if version != 7 {
		t.Fatalf("B9 schema version %d, want 7", version)
	}
	if !reflect.DeepEqual(rulesBefore, c4aRows(t, db, []string{"rules"})) {
		t.Fatal("B9 migration changed the rules table")
	}
	var claimsAfter, mismatched int
	must(db.QueryRow("SELECT COUNT(*) FROM claims").Scan(&claimsAfter))
	must(db.QueryRow("SELECT COUNT(*) FROM claims c JOIN rules r ON r.id=c.rule_id WHERE c.expires_at IS NOT r.expires_at").Scan(&mismatched))
	if claimsAfter != claimsBefore || claimsAfter != 6 || mismatched != 0 {
		t.Fatalf("B9 claims before=%d after=%d mismatched=%d", claimsBefore, claimsAfter, mismatched)
	}
	var finite int
	must(db.QueryRow("SELECT COUNT(*) FROM claims WHERE expires_at IS NOT NULL").Scan(&finite))
	if finite != 4 {
		t.Fatalf("B9 backfilled finite claims=%d, want 4", finite)
	}
	snapshot := c4aRows(t, db, []string{"rules", "claims"})
	must(db.Migrate())
	if !reflect.DeepEqual(snapshot, c4aRows(t, db, []string{"rules", "claims"})) {
		t.Fatal("B9 migration not idempotent")
	}
}
