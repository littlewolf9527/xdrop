package repository

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestMigration_IdempotentAcrossRestarts verifies BUG-046: running NewSQLiteDB
// multiple times on the same file (simulating Controller restarts) must not
// fail and must not leave schema_version in an inconsistent state.
func TestMigration_IdempotentAcrossRestarts(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "migrate.db")
	defer os.RemoveAll(tmpDir)

	for i := 0; i < 3; i++ {
		db, err := NewSQLiteDB(dbPath)
		if err != nil {
			t.Fatalf("iter %d: NewSQLiteDB failed: %v", i, err)
		}

		var version int
		if err := db.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version); err != nil {
			t.Fatalf("iter %d: read schema_version: %v", i, err)
		}
		if version != 1 {
			t.Errorf("iter %d: schema_version = %d, want 1", i, version)
		}

		// schema_version must have exactly one row
		var rowCount int
		if err := db.db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&rowCount); err != nil {
			t.Fatalf("iter %d: count schema_version rows: %v", i, err)
		}
		if rowCount != 1 {
			t.Errorf("iter %d: schema_version has %d rows, want 1", i, rowCount)
		}

		db.Close()
	}
}

// TestMigration_RecoversFromEmptySchemaVersionTable simulates the previous
// crash scenario: schema_version table exists but has NO row (because the
// pre-fix code ran CREATE outside tx and got killed before INSERT). The
// migration must still converge to version=1 with exactly one row.
func TestMigration_RecoversFromEmptySchemaVersionTable(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "recovery.db")
	defer os.RemoveAll(tmpDir)

	// Hand-build a DB in the broken intermediate state: rules table exists
	// with old schema, schema_version table exists but empty.
	raw, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open raw DB: %v", err)
	}
	for _, stmt := range []string{
		// Minimal rules schema before the v2.4 CIDR migration, but AFTER the
		// addColumns migration (so all columns referenced in the INSERT SELECT
		// exist). Old UNIQUE constraint without src_cidr/dst_cidr.
		`CREATE TABLE rules (
			id TEXT PRIMARY KEY,
			name TEXT,
			src_ip TEXT, dst_ip TEXT,
			src_cidr TEXT DEFAULT '',
			dst_cidr TEXT DEFAULT '',
			src_port INTEGER DEFAULT 0, dst_port INTEGER DEFAULT 0,
			protocol TEXT DEFAULT 'all',
			action TEXT DEFAULT 'drop',
			rate_limit INTEGER DEFAULT 0,
			pkt_len_min INTEGER DEFAULT 0,
			pkt_len_max INTEGER DEFAULT 0,
			tcp_flags TEXT DEFAULT '',
			source TEXT DEFAULT 'manual',
			comment TEXT,
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(src_ip, dst_ip, src_port, dst_port, protocol)
		)`,
		"CREATE TABLE schema_version (version INTEGER)",
		// Do NOT INSERT a row: this simulates the crash-between-CREATE-and-INSERT
		// scenario the fix is supposed to handle.
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	raw.Close()

	// Run migration — must seed the row and reach version=1
	db, err := NewSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteDB on broken state: %v", err)
	}
	defer db.Close()

	var version, rowCount int
	if err := db.db.QueryRow("SELECT COUNT(*), COALESCE(MAX(version), 0) FROM schema_version").Scan(&rowCount, &version); err != nil {
		t.Fatalf("post-migration check: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("schema_version row count = %d, want 1", rowCount)
	}
	if version != 1 {
		t.Errorf("schema_version.version = %d, want 1", version)
	}
}
