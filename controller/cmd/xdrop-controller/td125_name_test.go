package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/secret"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"golang.org/x/crypto/bcrypt"
)

const td125Password = "TEST_ONLY_td125_password"
const td125Key = "TEST_ONLY_td125_node_key"

func td125CLI(t *testing.T) (string, *store.DB, *secret.Key) {
	t.Helper()
	dir := t.TempDir()
	path, dbpath := filepath.Join(dir, "config.example.yaml"), filepath.Join(dir, "names.db")
	master := c5bMasterFile(t)
	text := "listen: 192.0.2.1:18081\ndatabase: " + dbpath + "\nsecret_key_file: " + master + "\n"
	c4aAssert(t, os.WriteFile(path, []byte(text), 0600) == nil, "config fixture")
	db, err := store.Open(dbpath)
	c4aAssert(t, err == nil, "open fixture database")
	t.Cleanup(func() { db.Close() })
	k, err := secret.Load(master)
	c4aAssert(t, err == nil, "load fixture key")
	return path, db, k
}

func td125AccountCommand(t *testing.T, path string, args []string, password string) (int, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "stdin")
	c4aAssert(t, os.WriteFile(p, []byte(password+"\n"), 0600) == nil, "non-terminal input")
	in, err := os.Open(p)
	c4aAssert(t, err == nil, "open non-terminal input")
	defer in.Close()
	var out bytes.Buffer
	rc := accountCommand(args, path, in, &out)
	c4aAssert(t, !strings.Contains(out.String(), password), "password output leak")
	return rc, out.String()
}

func TestTD125G2CLICreateUser(t *testing.T) {
	t.Run("user-add-dotdot", func(t *testing.T) {
		path, db, _ := td125CLI(t)
		rc, out := td125AccountCommand(t, path, []string{"user", "add", ".."}, td125Password)
		c4aAssert(t, rc == 1 && strings.Contains(out, "invalid_field"), "user add .. rejected")
		_, err := store.FindUser(db.Reader(), "..")
		c4aAssert(t, err == sql.ErrNoRows, "rejected user absent")
	})
}

func TestTD125G3CLICreateNode(t *testing.T) {
	t.Run("node-add-dotdot", func(t *testing.T) {
		path, db, _ := td125CLI(t)
		rc, out := c5bCommand(t, path, []string{"node", "add", "..", "--url", "http://192.0.2.2", "--key-stdin"}, td125Key+"\n")
		const message = "invalid_field: name must be 1..64 ASCII letters, digits, '.', '_' or '-', and not '.' or '..'"
		c4aAssert(t, rc == 1 && strings.Contains(string(out), message), "node add .. fixed error")
		c4aAssert(t, !bytes.Contains(out, []byte(td125Key)), "key output leak")
		_, err := store.FindNode(db.Reader(), "..")
		c4aAssert(t, err == sql.ErrNoRows, "rejected node absent")
	})
}

func TestTD125G4CLIOldNames(t *testing.T) {
	t.Run("user-passwd-dotdot", func(t *testing.T) {
		path, db, _ := td125CLI(t)
		hash, err := bcrypt.GenerateFromPassword([]byte(td125Password), bcrypt.DefaultCost)
		c4aAssert(t, err == nil, "old user hash")
		at := time.Now().UTC().Format(store.TimeFormat)
		for _, name := range []string{"keeper", ".."} {
			c4aAssert(t, store.InsertUser(db, store.User{Username: name, PasswordHash: string(hash), Role: "admin", CreatedAt: at, CreatedBy: "system:test", PasswordChangedAt: at}) == nil, "insert old user and keeper directly")
		}
		const next = "TEST_ONLY_td125_new_password"
		rc, _ := td125AccountCommand(t, path, []string{"user", "passwd", ".."}, next)
		c4aAssert(t, rc == 0, "old user passwd")
		u, err := store.FindUser(db.Reader(), "..")
		c4aAssert(t, err == nil && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(next)) == nil, "new password stored")
	})
	for _, operation := range []string{"node-update-dotdot", "node-delete-leading-space"} {
		t.Run(operation, func(t *testing.T) {
			path, db, k := td125CLI(t)
			for _, name := range []string{"..", " lead"} {
				nonce, cipher, err := k.Seal(name, td125Key)
				c4aAssert(t, err == nil, "seal old node key")
				at := time.Now().UTC().Format(store.TimeFormat)
				c4aAssert(t, store.PutNode(db, store.Node{Name: name, BaseURL: "http://192.0.2.2", KeyNonce: nonce, KeyCipher: cipher, CreatedAt: at, UpdatedAt: at, CreatedBy: "system:test", UpdatedBy: "system:test"}, true) == nil, "insert old node directly")
			}
			if operation == "node-update-dotdot" {
				rc, _ := c5bCommand(t, path, []string{"node", "update", "..", "--url", "http://192.0.2.3"}, "")
				c4aAssert(t, rc == 0, "old node update")
				row, err := store.FindNode(db.Reader(), "..")
				c4aAssert(t, err == nil && row.BaseURL == "http://192.0.2.3", "old node URL stored")
				plain, err := k.Open("..", row.KeyNonce, row.KeyCipher)
				c4aAssert(t, err == nil && plain == td125Key, "URL update preserves key")
			} else {
				rc, _ := c5bCommand(t, path, []string{"node", "delete", " lead"}, "")
				c4aAssert(t, rc == 0, "old node delete")
				_, err := store.FindNode(db.Reader(), " lead")
				c4aAssert(t, err == sql.ErrNoRows, "old node gone")
			}
		})
	}
}
