package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func TestC4BCLI(t *testing.T) {
	t.Run("C4B-actor", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "controller.example.yaml")
		dbpath := filepath.Join(dir, "controller.db")
		keypath := filepath.Join(dir, "test-key")
		c4aAssert(t, os.WriteFile(keypath, []byte(c4aPassword(t)), 0600) == nil, "key fixture")
		text := "listen: 127.0.0.1:18081\ndatabase: " + dbpath + "\nsecret_key_file: " + keypath + "\n"
		c4aAssert(t, os.WriteFile(path, []byte(text), 0600) == nil, "configuration")
		db, e := store.Open(dbpath)
		c4aAssert(t, e == nil, "database")
		defer db.Close()
		c4aAssert(t, store.InsertRule(db, store.Rule{ID: "rule_seed", LogicalID: 1, Match: store.Match{DstIP: "192.0.2.2", Action: "drop"}, GroupKey: "test", CondKey: "test", CreatedAt: "2026-10-12T00:00:00Z", UpdatedAt: "2026-10-12T00:00:00Z", CreatedBy: "ui", UpdatedBy: "ui"}) == nil, "rule fixture")
		c4aAssert(t, store.Claim(db, "rule_seed", "ui", "", "2026-10-12T00:00:00Z", nil) == nil, "claim fixture")
		before, e := store.Claims(db.Reader(), "rule_seed")
		c4aAssert(t, e == nil && len(before) == 1, "claims before")
		for _, operation := range []string{"add", "passwd"} {
			r, w, e := os.Pipe()
			c4aAssert(t, e == nil, "pipe")
			pw := c4aPassword(t)
			_, e = w.WriteString(pw + "\n")
			w.Close()
			c4aAssert(t, e == nil, "password input")
			out := &bytes.Buffer{}
			rc := accountCommand([]string{"user", operation, "alice"}, path, r, out)
			r.Close()
			c4aAssert(t, rc == 0 && !bytes.Contains(out.Bytes(), []byte(pw)), "CLI result")
			after, e := store.Claims(db.Reader(), "rule_seed")
			c4aAssert(t, e == nil && reflect.DeepEqual(before, after), "CLI changed claims")
		}
		u, e := store.FindUser(db.Reader(), "alice")
		c4aAssert(t, e == nil && u.CreatedBy == "system:cli", "CLI created_by")
		rows, e := store.AuditAfter(db.Reader(), "", "", "", 0, 10)
		c4aAssert(t, e == nil && len(rows) == 2, "CLI audit count")
		for i, action := range []string{"user.create", "user.password"} {
			ev := rows[i]
			c4aAssert(t, ev.Actor == "system:cli" && ev.Source == "" && ev.Target == "user:alice" && ev.Action == action, "CLI audit identity")
		}
	})
}
