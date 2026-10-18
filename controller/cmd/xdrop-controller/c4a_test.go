package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func c4aAssert(t *testing.T, ok bool, what string) {
	t.Helper()
	if !ok {
		t.Fatal(what)
	}
}
func c4aPassword(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	_, e := rand.Read(b)
	c4aAssert(t, e == nil, "random input")
	return hex.EncodeToString(b)
}
func TestC4ACLI(t *testing.T) {
	t.Run("C4A-cli", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "controller.example.yaml")
		dbpath := filepath.Join(dir, "controller.db")
		keypath := filepath.Join(dir, "node-key")
		pw, newpw, nodekey := c4aPassword(t), c4aPassword(t), c4aPassword(t)
		c4aAssert(t, os.WriteFile(keypath, []byte(nodekey), 0600) == nil, "node key fixture")
		text := "listen: 192.0.2.1:18081\ndatabase: " + dbpath + "\nsecret_key_file: " + keypath + "\n"
		c4aAssert(t, os.WriteFile(path, []byte(text), 0600) == nil, "configuration fixture")
		output := &bytes.Buffer{}
		command := func(args []string, password string, want int) {
			t.Helper()
			r, w, e := os.Pipe()
			c4aAssert(t, e == nil, "stdin pipe")
			defer r.Close()
			_, e = w.WriteString(password + "\r\n")
			w.Close()
			c4aAssert(t, e == nil, "stdin input")
			code := accountCommand(args, path, r, output)
			c4aAssert(t, code == want, "CLI exit code")
			for _, s := range []string{pw, newpw, nodekey, password} {
				if s != "" {
					c4aAssert(t, !bytes.Contains(output.Bytes(), []byte(s)), "CLI output exposes secret")
				}
			}
		}
		command([]string{"user", "add", "alice"}, pw, 0)
		db, e := store.Open(dbpath)
		c4aAssert(t, e == nil, "open CLI database")
		defer db.Close()
		acc := auth.New(db)
		token, _, ae := acc.Login("alice", pw, "")
		c4aAssert(t, ae == nil, "CLI-created account login")
		other, _, ae := acc.Login("alice", pw, "")
		c4aAssert(t, ae == nil, "second session")
		command([]string{"user", "add", "alice"}, pw, 1)
		command([]string{"user", "add", "bob"}, pw, 0)
		bob, _, ae := acc.Login("bob", pw, "")
		c4aAssert(t, ae == nil, "other user session")
		command([]string{"user", "passwd", "alice"}, newpw, 0)
		for _, old := range []string{token, other, bob} {
			r := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
			r.Header.Set("Cookie", auth.CookieName+"="+old)
			_, err := acc.Authenticate(r)
			c4aAssert(t, (err == nil) == (old == bob), "CLI reset session revocation")
		}
		acc = auth.New(db)
		_, _, ae = acc.Login("alice", pw, "")
		c4aAssert(t, ae != nil && ae.Code == "invalid_credentials", "old CLI password rejected")
		acc = auth.New(db)
		newtoken, _, ae := acc.Login("alice", newpw, "")
		c4aAssert(t, ae == nil, "new CLI password accepted")
		for _, args := range [][]string{{"bogus"}, {"user"}, {"user", "add"}, {"user", "add", "extra-user", "extra"}, {"user", "passwd", "alice", "extra"}} {
			before, e := store.Users(db.Reader())
			c4aAssert(t, e == nil, "users before invalid args")
			command(args, pw, 2)
			after, e := store.Users(db.Reader())
			c4aAssert(t, e == nil && reflect.DeepEqual(before, after), "invalid args changed user rows")
		}
		command([]string{"user", "passwd", "missing"}, pw, 1)
		command([]string{"user", "add", "short"}, pw[:9], 1)
		command([]string{"user", "add", "long"}, pw+pw[:25], 1)
		tx, e := db.Begin()
		c4aAssert(t, e == nil, "busy transaction")
		defer tx.Rollback()
		_, e = tx.Exec("UPDATE settings SET value=value WHERE key='session_hours'")
		c4aAssert(t, e == nil, "hold SQLite writer")
		command([]string{"user", "add", "busy-user"}, pw, 1)
		tx.Rollback()
		_, e = store.FindUser(db.Reader(), "busy-user")
		c4aAssert(t, e != nil, "busy CLI must not commit")
		for _, suffix := range []string{"", "-wal"} {
			b, e := os.ReadFile(dbpath + suffix)
			c4aAssert(t, e == nil, "collect CLI database")
			for _, s := range []string{pw, newpw, nodekey, token, other, bob, newtoken} {
				c4aAssert(t, !bytes.Contains(b, []byte(s)), "CLI database exposes secret")
			}
		}
		t.Log("CLI stdout_bytes=0 stderr_scanned=1 secret_matches=0 invalid_argument_cases=5 busy_exit=1")
	})
}
