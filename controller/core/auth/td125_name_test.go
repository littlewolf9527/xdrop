package auth

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"golang.org/x/crypto/bcrypt"
)

const td125Password = "TEST_ONLY_td125_password"

var td125Actor = rules.Actor{Kind: rules.System, Name: "test"}

func td125Service(t *testing.T) (*Service, *store.DB) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "names.db"))
	c4aCheck(t, err == nil, "open database")
	t.Cleanup(func() { db.Close() })
	s := New(db)
	c4aCheck(t, s.CreateUser(td125Actor, "keeper", td125Password, "admin") == nil, "keeper administrator")
	return s, db
}

func td125Counts(t *testing.T, db *store.DB) [3]int {
	t.Helper()
	u, err := store.Users(db.Reader())
	c4aCheck(t, err == nil, "read users")
	c, err := store.Credentials(db.Reader())
	c4aCheck(t, err == nil, "read credentials")
	var audit int
	c4aCheck(t, db.Reader().QueryRow("SELECT COUNT(*) FROM audit").Scan(&audit) == nil, "count audit")
	return [3]int{len(u), len(c), audit}
}

func td125OldUser(t *testing.T, db *store.DB, name string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(td125Password), bcrypt.DefaultCost)
	c4aCheck(t, err == nil, "old password hash")
	at := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC).Format(store.TimeFormat)
	c4aCheck(t, store.InsertUser(db, store.User{Username: name, PasswordHash: string(hash), Role: "admin", CreatedAt: at, CreatedBy: "system:test", PasswordChangedAt: at}) == nil, "insert old user directly")
}

func TestTD125G1ValidName(t *testing.T) {
	for _, tc := range []struct {
		label, input string
		want         bool
	}{
		{"letter", "a", true}, {"mixed", "A-1_b.c", true}, {"three-dots", "...", true},
		{"leading-dot", ".a", true}, {"trailing-dot", "a.", true}, {"embedded-dots", "a..b", true},
		{"underscore", "_", true}, {"hyphen", "-", true}, {"length-64", strings.Repeat("a", 64), true},
		{"empty", "", false}, {"dot", ".", false}, {"dotdot", "..", false},
		{"length-65", strings.Repeat("a", 65), false}, {"space", "a b", false},
		{"leading-space", " a", false}, {"trailing-space", "a ", false}, {"tab", "a\t", false},
		{"newline", "a\n", false}, {"slash", "a/b", false}, {"encoded-dots", "%2e%2e", false},
		{"non-ascii", "é", false}, {"nul", "a\x00", false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			if got := ValidName(tc.input); got != tc.want {
				t.Errorf("%s input=%q ValidName=%t want=%t", tc.label, tc.input, got, tc.want)
			}
		})
	}
}

func TestTD125G2ServiceCreate(t *testing.T) {
	for _, tc := range []struct{ label, name string }{{"dot", "."}, {"dotdot", ".."}, {"space", "a b"}} {
		t.Run("user-"+tc.label, func(t *testing.T) {
			s, db := td125Service(t)
			before := td125Counts(t, db)
			e := s.CreateUser(td125Actor, tc.name, td125Password, "admin")
			if e == nil || e.Code != "invalid_field" || e.Field != "username" {
				t.Errorf("input=%q expected invalid_field/username", tc.name)
			}
			if after := td125Counts(t, db); after != before {
				t.Errorf("input=%q counts=%v want=%v", tc.name, after, before)
			}
		})
	}
	for _, tc := range []struct{ label, name string }{{"dot", "."}, {"dotdot", ".."}} {
		t.Run("credential-"+tc.label, func(t *testing.T) {
			s, db := td125Service(t)
			before := td125Counts(t, db)
			_, _, _, e := s.IssueCredential(td125Actor, tc.name)
			if e == nil || e.Code != "invalid_field" || e.Field != "name" {
				t.Errorf("input=%q expected invalid_field/name", tc.name)
			}
			if after := td125Counts(t, db); after != before {
				t.Errorf("input=%q counts=%v want=%v", tc.name, after, before)
			}
		})
	}
	t.Run("user-three-dots", func(t *testing.T) {
		s, db := td125Service(t)
		c4aCheck(t, s.CreateUser(td125Actor, "...", td125Password, "admin") == nil, "create ...")
		_, err := store.FindUser(db.Reader(), "...")
		c4aCheck(t, err == nil, "... persisted")
	})
	t.Run("credential-embedded-dots", func(t *testing.T) {
		s, db := td125Service(t)
		c, _, _, e := s.IssueCredential(td125Actor, "a..b")
		c4aCheck(t, e == nil, "issue a..b")
		row, err := store.FindCredential(db.Reader(), c.ID)
		c4aCheck(t, err == nil && row.Name == "a..b", "a..b persisted")
	})
}

func TestTD125G4ServiceOldUsers(t *testing.T) {
	for _, tc := range []struct{ label, name string }{{"dotdot", ".."}, {"dot", "."}, {"space", "a b"}} {
		for _, operation := range []string{"password", "role", "delete"} {
			t.Run(tc.label+"/"+operation, func(t *testing.T) {
				s, db := td125Service(t)
				td125OldUser(t, db, tc.name)
				switch operation {
				case "password":
					const next = "TEST_ONLY_td125_new_password"
					c4aCheck(t, s.SetPassword(td125Actor, tc.name, next) == nil, "old name password update")
					u, err := store.FindUser(db.Reader(), tc.name)
					c4aCheck(t, err == nil && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(next)) == nil, "new password stored")
				case "role":
					c4aCheck(t, s.SetRole(td125Actor, tc.name, "operator") == nil, "old name role update")
					u, err := store.FindUser(db.Reader(), tc.name)
					c4aCheck(t, err == nil && u.Role == "operator", "new role stored")
				case "delete":
					c4aCheck(t, s.DeleteUser(td125Actor, tc.name) == nil, "old name delete")
					_, err := store.FindUser(db.Reader(), tc.name)
					c4aCheck(t, err == sql.ErrNoRows, "old user gone")
				}
			})
		}
	}
	t.Run("dotdot/login", func(t *testing.T) {
		s, db := td125Service(t)
		td125OldUser(t, db, "..")
		token, expires, e := s.Login("..", td125Password, "")
		c4aCheck(t, e == nil && token != "" && expires.After(s.Now()), "old name login session")
		row, err := store.FindSession(db.Reader(), digest(token))
		c4aCheck(t, err == nil && row.Username == "..", "old user session stored")
	})
}
