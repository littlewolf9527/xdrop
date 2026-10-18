package rules

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func TestCtlCut2b(t *testing.T) {
	t.Run("ST-wal", func(t *testing.T) {
		s, _ := setup(t)
		var mode string
		err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode)
		check(t, err == nil && mode == "wal", "journal", mode, err)
		for name, want := range map[string]int{"synchronous": 2, "foreign_keys": 1, "busy_timeout": 5000} {
			var got int
			err := s.db.QueryRow("PRAGMA " + name).Scan(&got)
			check(t, err == nil && got == want, "writer", name, got, want, err)
		}
		snap, err := s.db.BeginSnapshot()
		check(t, err == nil, err)
		defer snap.Close()
		for name, want := range map[string]int{"foreign_keys": 1, "busy_timeout": 5000} {
			var got int
			err := snap.Tx.QueryRow("PRAGMA " + name).Scan(&got)
			check(t, err == nil && got == want, "reader", name, got, want, err)
		}
		_, err = snap.Tx.Exec("UPDATE logical_id_hw SET high_water=high_water WHERE id=1")
		check(t, err != nil && strings.Contains(err.Error(), "readonly"), "reader accepted legal write", err)
	})
	t.Run("ST-close", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rules.db")
		db, err := store.Open(path)
		check(t, err == nil, err)
		defer db.Close()
		r := create(t, New(db, nil), draft(80, ""))
		snap, err := db.BeginSnapshot()
		check(t, err == nil, err)
		check(t, snap.Pin() == nil, "pin")
		rows, err := store.EnabledForNode(snap.Tx)
		check(t, err == nil && len(rows) == 1 && rows[0].ID == r.ID, "snapshot", rows, err)
		snap.Close()
		check(t, db.Close() == nil, "close")
		entries, err := os.ReadDir(filepath.Dir(path))
		check(t, err == nil && len(entries) == 1 && entries[0].Name() == filepath.Base(path), "not a single database file", entries, err)
		reopened, err := store.Open(path)
		check(t, err == nil, err)
		defer reopened.Close()
		got, err := store.Get(reopened, r.ID)
		check(t, err == nil && got.ID == r.ID && got.LogicalID == r.LogicalID, "reopen", got, err)
	})
	t.Run("ST-crashcopy", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "source.db")
		db, err := store.Open(path)
		check(t, err == nil, err)
		defer db.Close()
		s := New(db, nil)
		r := create(t, s, draft(80, ""))
		sqlExec(t, s, "UPDATE rules SET cond_key='wrong' WHERE id=?", r.ID)
		info, err := os.Stat(path + "-wal")
		check(t, err == nil && info.Size() > 0, "WAL must exist before copy", err)
		t.Logf("guard: WAL exists before copy, bytes=%d", info.Size())
		withWAL := filepath.Join(t.TempDir(), "copy.db")
		mainOnly := filepath.Join(t.TempDir(), "copy.db")
		for _, suffix := range []string{"", "-wal"} {
			b, err := os.ReadFile(path + suffix)
			check(t, err == nil, err)
			check(t, os.WriteFile(withWAL+suffix, b, 0600) == nil, "copy", suffix)
			if suffix == "" {
				check(t, os.WriteFile(mainOnly, b, 0600) == nil, "copy main only")
			}
		}
		var out bytes.Buffer
		rc := DryRun(withWAL, &out)
		check(t, rc == 1 && strings.Contains(out.String(), r.ID), "WAL violation missing", rc, out.String())
		out.Reset()
		rc = DryRun(mainOnly, &out)
		check(t, rc != 1, "main-only control unexpectedly retained violation", rc, out.String())
	})
}
