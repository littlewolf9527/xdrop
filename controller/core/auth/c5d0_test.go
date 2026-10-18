package auth

import (
	"database/sql"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func TestC5D0ComparisonRace(t *testing.T) {
	for _, mode := range []string{"control", "password", "delete", "recreate"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			s, db, pw := c4aService(t)
			now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
			s.Now = func() time.Time { return now }
			admin := rules.Actor{Kind: rules.UI, Name: "keeper", Admin: true}
			self := rules.Actor{Kind: rules.UI, Name: "alice", Source: "192.0.2.1"}
			c4aCheck(t, s.CreateUser(admin, "keeper", c4aRandom(t), "admin") == nil, "keeper")
			c4aCheck(t, s.DeleteUser(admin, "alice") == nil && s.CreateUser(admin, "alice", pw, "operator") == nil, "highest rowid")
			u, err := store.FindUser(db.Reader(), "alice")
			c4aCheck(t, err == nil, "original row")
			_, _, e := s.Login("alice", pw, "")
			c4aCheck(t, e == nil, "preexisting session")
			_, err = db.Exec("DELETE FROM audit")
			c4aCheck(t, err == nil, "clear setup audit")
			saved := comparePassword
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan *rules.Error, 1)
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			finished := false
			defer func() {
				unblock()
				if !finished {
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("comparison cleanup blocked")
						return
					}
				}
				comparePassword = saved
			}()
			comparePassword = func(hash, password []byte) error {
				if string(hash) == u.PasswordHash {
					close(entered)
					<-release
				}
				return saved(hash, password)
			}
			next, adminPassword := c4aRandom(t), c4aRandom(t)
			go func() { _, e := s.ChangeOwnPassword(self, pw, next, self.Source); done <- e }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("comparison never paused")
			}
			var current store.User
			var token string
			switch mode {
			case "password":
				c4aCheck(t, s.SetPassword(admin, "alice", adminPassword) == nil, "admin reset committed")
			case "delete", "recreate":
				c4aCheck(t, s.DeleteUser(admin, "alice") == nil, "delete committed")
				if mode == "recreate" {
					c4aCheck(t, s.CreateUser(admin, "alice", adminPassword, "operator") == nil, "recreation committed")
					token, _, e = s.Login("alice", adminPassword, "")
					c4aCheck(t, e == nil, "recreated session before release")
				}
			}
			if mode == "password" || mode == "recreate" {
				current, err = store.FindUser(db.Reader(), "alice")
				c4aCheck(t, err == nil && current.ID == u.ID && current.PasswordHash != u.PasswordHash, "same id different committed hash")
			}
			t.Logf("mode=%s comparison_paused=true interleaving_committed=true same_id_new_hash=%t recreated_session=%t", mode, mode == "password" || mode == "recreate", token != "")
			unblock()
			select {
			case e = <-done:
				finished = true
			case <-time.After(5 * time.Second):
				t.Fatal("password change did not finish")
			}
			comparePassword = saved
			rows, err := store.AuditAfter(db.Reader(), "", "", "", 0, 1000)
			c4aCheck(t, err == nil, "audit read")
			failed, own := 0, 0
			for _, ev := range rows {
				if ev.Action == "auth.login_failed" {
					failed++
					c4aCheck(t, string(ev.After) == `{"reason":"stale"}` && ev.Actor == "" && ev.Target == "user:alice" && ev.Source == self.Source, "stale audit")
				}
				if ev.Action == "user.password" && ev.Actor == "user:alice" {
					own++
				}
			}
			if mode == "control" {
				c4aCheck(t, e == nil && failed == 0 && own == 1, "control succeeds")
				return
			}
			c4aCheck(t, e != nil && e.Code == "invalid_credentials" && failed == 1 && own == 0, "stale rejects with exactly one failure audit")
			after, err := store.FindUser(db.Reader(), "alice")
			if mode == "delete" {
				c4aCheck(t, err == sql.ErrNoRows, "deleted user stays absent")
			} else {
				c4aCheck(t, err == nil && after.PasswordHash == current.PasswordHash, "administrator hash preserved")
			}
			if mode == "recreate" {
				r := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
				r.Header.Set("Cookie", CookieName+"="+token)
				a, e := s.Authenticate(r)
				c4aCheck(t, e == nil && a.Name == "alice", "recreated session remains valid")
			}
			s.mu.Lock()
			d := s.delays["alice"]
			noFailures := d == nil || d.failures == 0
			s.mu.Unlock()
			c4aCheck(t, noFailures, "stale did not increase throttle failures")
			_, _, e = s.Login("alice", adminPassword, "")
			if mode == "delete" {
				c4aCheck(t, e != nil && e.Code == "invalid_credentials", "absent user not throttled")
			} else {
				c4aCheck(t, e == nil, "immediate correct login succeeds")
			}
			t.Log("stale_audits=1 own_password_audits=0 throttle_failures=0 immediate_login_not_429=true")
		})
	}
}
