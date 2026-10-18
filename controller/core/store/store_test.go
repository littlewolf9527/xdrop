package store

import (
	"path/filepath"
	"testing"
)

func TestCtlCut1Store(t *testing.T) {
	t.Run("S-open-pragmas", func(t *testing.T) {
		db, e := Open(filepath.Join(t.TempDir(), "store.db"))
		if e != nil {
			t.Fatal(e)
		}
		defer db.Close()
		for name, want := range map[string]int{"foreign_keys": 1, "busy_timeout": 5000} {
			var got int
			if e := db.QueryRow("PRAGMA " + name).Scan(&got); e != nil || got != want {
				t.Fatalf("%s=%d want=%d err=%v", name, got, want, e)
			}
		}
		if e := Claim(db, "missing", "ui", "", "2026-10-10T00:00:00Z"); e == nil {
			t.Fatal("foreign key did not reject orphan claim")
		}
		if _, e := db.Exec("INSERT INTO schema_version VALUES(2,1)"); e == nil {
			t.Fatal("schema version is not singleton")
		}
		if _, e := db.Exec("INSERT INTO logical_id_hw VALUES(2,0)"); e == nil {
			t.Fatal("high water is not singleton")
		}
	})
}
