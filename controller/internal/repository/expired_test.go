package repository

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

// NEW-P1-01 regression: ListExpired must correctly identify expired rules
// regardless of timezone offset in stored expires_at.
//
// The pre-fix SQL `expires_at < CURRENT_TIMESTAMP` did lexical comparison
// between a TZ-aware string ("2026-04-17 10:53:37+08:00") and UTC-without-offset
// ("2026-04-17 02:56:57"), which always returned false for eastward offsets.
func TestListExpired_HandlesTimezone(t *testing.T) {
	// Use a temp SQLite DB
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	defer os.RemoveAll(tmpDir)

	db, err := NewSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open DB: %v", err)
	}
	defer db.Close()
	repo := NewSQLiteRuleRepo(db)

	now := time.Now()

	cases := []struct {
		id       string
		expires  time.Time
		wantFind bool
	}{
		{"already-expired-1s-ago", now.Add(-1 * time.Second), true},
		{"expired-1h-ago", now.Add(-1 * time.Hour), true},
		{"expires-in-1h", now.Add(1 * time.Hour), false},
		{"expires-in-24h", now.Add(24 * time.Hour), false},
	}

	// Seed
	for _, c := range cases {
		rule := &model.Rule{
			ID:        c.id,
			Action:    "drop",
			SrcIP:     "10.0.0." + c.id[:1], // cheap uniqueness; not strictly needed
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		}
		exp := c.expires
		rule.ExpiresAt = &exp
		if err := repo.Create(rule); err != nil {
			t.Fatalf("create %s: %v", c.id, err)
		}
	}

	// Also create a rule without expires_at — must NOT be returned
	noExpire := &model.Rule{
		ID:        "never-expires",
		SrcIP:     "10.0.0.99",
		Action:    "drop",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := repo.Create(noExpire); err != nil {
		t.Fatalf("create never-expires: %v", err)
	}

	// Query
	expired, err := repo.ListExpired()
	if err != nil {
		t.Fatalf("ListExpired: %v", err)
	}

	gotIDs := make(map[string]bool)
	for _, r := range expired {
		gotIDs[r.ID] = true
	}

	for _, c := range cases {
		if gotIDs[c.id] != c.wantFind {
			t.Errorf("rule %s expires=%v: got found=%v, want %v",
				c.id, c.expires, gotIDs[c.id], c.wantFind)
		}
	}
	if gotIDs["never-expires"] {
		t.Errorf("rule without expires_at should not be in expired list")
	}
}

// NEW-P1-01 regression: DeleteExpired follows the same Go-side filtering.
func TestDeleteExpired_HandlesTimezone(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	defer os.RemoveAll(tmpDir)

	db, err := NewSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open DB: %v", err)
	}
	defer db.Close()
	repo := NewSQLiteRuleRepo(db)

	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	for _, c := range []struct {
		id      string
		expires *time.Time
	}{
		{"expired-A", &past},
		{"expired-B", &past},
		{"live-C", &future},
		{"no-expire-D", nil},
	} {
		rule := &model.Rule{
			ID:        c.id,
			SrcIP:     "10.0.1." + c.id[len(c.id)-1:], // last char as uniqueness
			Action:    "drop",
			Enabled:   true,
			ExpiresAt: c.expires,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := repo.Create(rule); err != nil {
			t.Fatalf("create %s: %v", c.id, err)
		}
	}

	n, err := repo.DeleteExpired()
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted count: got %d, want 2", n)
	}

	// Verify remaining
	for _, keepID := range []string{"live-C", "no-expire-D"} {
		rule, err := repo.Get(keepID)
		if err != nil || rule == nil {
			t.Errorf("rule %s should still exist; got err=%v rule=%v", keepID, err, rule)
		}
	}
	for _, goneID := range []string{"expired-A", "expired-B"} {
		rule, err := repo.Get(goneID)
		if err == nil && rule != nil {
			t.Errorf("rule %s should have been deleted", goneID)
		}
	}
}
