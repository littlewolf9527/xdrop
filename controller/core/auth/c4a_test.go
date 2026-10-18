package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func c4aCheck(t *testing.T, ok bool, message string) {
	t.Helper()
	if !ok {
		t.Fatal(message)
	}
}
func c4aRandom(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	_, err := rand.Read(b)
	c4aCheck(t, err == nil, "random input")
	return hex.EncodeToString(b)
}
func c4aService(t *testing.T) (*Service, *store.DB, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "auth.db"))
	c4aCheck(t, err == nil, "open database")
	t.Cleanup(func() { db.Close() })
	s := New(db)
	pw := c4aRandom(t)
	c4aCheck(t, s.CreateUser(rules.Actor{Kind: rules.UI, Name: "test"}, "alice", pw, "admin") == nil, "create user")
	return s, db, pw
}
func TestC4AAuth(t *testing.T) {
	t.Run("C4A-throttle", func(t *testing.T) {
		s, _, pw := c4aService(t)
		now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
		s.Now = func() time.Time { return now }
		wrong := c4aRandom(t)
		for i, seconds := range []int{1, 2, 4, 8, 16, 32, 60, 60} {
			_, _, e := s.Login("alice", wrong, "")
			c4aCheck(t, e != nil && e.Code == "invalid_credentials", "actual failure")
			_, next, e := s.Login("alice", pw, "")
			c4aCheck(t, e != nil && e.Code == "login_throttled" && next.Sub(now) == time.Duration(seconds)*time.Second, fmt.Sprintf("delay step %d expected %d seconds", i+1, seconds))
			now = now.Add(time.Duration(seconds) * time.Second)
		}
		_, _, e := s.Login("alice", pw, "")
		c4aCheck(t, e == nil, "login at boundary")
		_, _, e = s.Login("alice", wrong, "")
		c4aCheck(t, e != nil && e.Code == "invalid_credentials", "failure after success")
		_, next, e := s.Login("alice", pw, "")
		c4aCheck(t, e != nil && e.Code == "login_throttled" && next.Sub(now) == time.Second, "success resets delay")
		now = next
		saved := comparePassword
		t.Cleanup(func() { comparePassword = saved })
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan *rules.Error, 1)
		var concurrent int32
		comparePassword = func(hash, password []byte) error {
			if atomic.AddInt32(&concurrent, 1) == 1 {
				close(entered)
				<-release
			}
			return saved(hash, password)
		}
		go func() { _, _, e := s.Login("alice", pw, ""); done <- e }()
		<-entered
		_, _, e = s.Login("alice", pw, "")
		close(release)
		first := <-done
		c4aCheck(t, e != nil && e.Code == "login_throttled" && first == nil, "concurrent verification slot")
		comparePassword = func([]byte, []byte) error { panic("test comparison interruption") }
		func() {
			defer func() { c4aCheck(t, recover() != nil, "comparison panic occurred") }()
			_, _, _ = s.Login("alice", pw, "")
		}()
		comparePassword = saved
		_, _, e = s.Login("alice", pw, "")
		c4aCheck(t, e == nil, "panic releases slot")
		calls := 0
		comparePassword = func(hash, password []byte) error {
			calls++
			c4aCheck(t, string(hash) == string(s.dummy), "dummy hash chosen")
			return saved(hash, password)
		}
		for i := 0; i < 20; i++ {
			_, _, e := s.Login(fmt.Sprintf("absent-%d", i), wrong, "")
			c4aCheck(t, e != nil && e.Code == "invalid_credentials", "absent user response")
		}
		c4aCheck(t, calls == 20 && len(s.delays) == 0, "dummy calls and delay table size")
		t.Logf("throttle_delays=1,2,4,8,16,32,60,60 dummy_calls=%d absent_delay_entries=%d", calls, len(s.delays))
	})
	t.Run("C4A-delete-throttle", func(t *testing.T) {
		s, _, _ := c4aService(t)
		c4aCheck(t, s.CreateUser(rules.Actor{Kind: rules.UI, Name: "test"}, "keeper", c4aRandom(t), "admin") == nil, "keeper user")
		_, _, e := s.Login("alice", c4aRandom(t), "")
		c4aCheck(t, e != nil && e.Code == "invalid_credentials" && s.delays["alice"] != nil, "existing user's failure recorded")
		c4aCheck(t, s.DeleteUser(rules.Actor{Kind: rules.UI, Name: "test"}, "alice") == nil, "sequential delete")
		_, remains := s.delays["alice"]
		c4aCheck(t, !remains, "sequential deletion left throttle entry")
	})
	t.Run("C4A-pool", func(t *testing.T) {
		s, db, pw := c4aService(t)
		token, _, e := s.Login("alice", pw, "")
		c4aCheck(t, e == nil, "session setup")
		_, key, _, e := s.IssueCredential(rules.Actor{Kind: rules.UI, Name: "test"}, "machine")
		c4aCheck(t, e == nil, "credential setup")
		tx, err := db.Begin()
		c4aCheck(t, err == nil, "occupy writer")
		defer tx.Rollback()
		_, err = tx.Exec("INSERT INTO settings VALUES('test-pool',1)")
		c4aCheck(t, err == nil, "uncommitted writer")
		done := make(chan struct {
			count   int
			correct bool
		}, 1)
		go func() {
			count, correct := 0, true
			for _, machine := range []bool{false, true} {
				for i := 0; i < 100; i++ {
					r := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
					kind, name := rules.UI, "alice"
					if machine {
						r.Header.Set("Authorization", "Bearer "+key)
						kind, name = rules.Machine, "machine"
					} else {
						r.Header.Set("Cookie", CookieName+"="+token)
					}
					a, e := s.Authenticate(r)
					correct = correct && e == nil && a.Kind == kind && a.Name == name
					count++
				}
			}
			done <- struct {
				count   int
				correct bool
			}{count, correct}
		}()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		timedOut := false
		var result struct {
			count   int
			correct bool
		}
		select {
		case result = <-done:
		case <-timer.C:
			timedOut = true
			tx.Rollback()
			result = <-done
		}
		tx.Rollback()
		t.Logf("pool_completed=%d correct=%t timeout=%t", result.count, result.correct, timedOut)
		c4aCheck(t, !timedOut && result.count == 200 && result.correct, "read-pool authentication blocked or incorrect")
		_, _, e = s.Login("alice", pw, "")
		c4aCheck(t, e == nil, "login after writer released")
	})
	t.Run("PERF-c4a-auth", func(t *testing.T) {
		s, db, pw := c4aService(t)
		u, err := store.FindUser(db.Reader(), "alice")
		c4aCheck(t, err == nil, "perf user")
		tokens, keys := []string{}, []string{}
		tx, err := db.Begin()
		c4aCheck(t, err == nil, "perf transaction")
		defer tx.Rollback()
		at := s.now().Format(store.TimeFormat)
		for i := 0; i < 1000; i++ {
			token := c4aRandom(t)
			ok, err := store.InsertSession(tx, digest(token), u, at)
			c4aCheck(t, err == nil && ok, "perf session seed")
			tokens = append(tokens, token)
		}
		for i := 0; i < 100; i++ {
			secret, err := random(32)
			c4aCheck(t, err == nil, "perf secret")
			id := fmt.Sprintf("%016x", i)
			key := "xdk_" + id + "_" + secret
			c4aCheck(t, store.InsertCredential(tx, store.Credential{ID: id, Name: "perf", SecretHash: digest(secret), CreatedAt: at, CreatedBy: "test"}) == nil, "perf key seed")
			keys = append(keys, key)
		}
		c4aCheck(t, tx.Commit() == nil, "perf commit")
		for _, machine := range []bool{false, true} {
			values := make([]time.Duration, 0, 2000)
			for i := 0; i < 2000; i++ {
				r := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
				if machine {
					r.Header.Set("Authorization", "Bearer "+keys[i%len(keys)])
				} else {
					r.Header.Set("Cookie", CookieName+"="+tokens[i%len(tokens)])
				}
				start := time.Now()
				a, e := s.Authenticate(r)
				values = append(values, time.Since(start))
				c4aCheck(t, e == nil && a.Name != "", "perf authentication")
			}
			sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
			p99 := values[1979]
			t.Logf("PERF-c4a-auth machine=%t samples=%d p99=%s sessions=1000 credentials=100", machine, len(values), p99)
			c4aCheck(t, len(values) == 2000 && p99 < time.Millisecond, "auth p99")
		}
		start := time.Now()
		err = comparePassword([]byte(u.PasswordHash), []byte(pw))
		t.Logf("bcrypt_single=%s", time.Since(start))
		c4aCheck(t, err == nil, "bcrypt sample")
		var count int
		c4aCheck(t, db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count) == nil && count == 1000, "session seed count")
		c4aCheck(t, strings.HasPrefix(u.PasswordHash, "$2"), "password hash encoding")
	})
}

// Complements the HTTP race leaf with a pause inside the permitted comparison seam.
func TestC4AComparisonRace(t *testing.T) {
	t.Run("C4A-login-race", func(t *testing.T) {
		for _, mode := range []string{"control", "password", "delete", "recreate"} {
			mode := mode
			t.Run(mode, func(t *testing.T) {
				s, db, pw := c4aService(t)
				c4aCheck(t, s.CreateUser(rules.Actor{Kind: rules.UI, Name: "test"}, "keeper", c4aRandom(t), "admin") == nil, "keeper")
				c4aCheck(t, s.DeleteUser(rules.Actor{Kind: rules.UI, Name: "test"}, "alice") == nil && s.CreateUser(rules.Actor{Kind: rules.UI, Name: "test"}, "alice", pw, "admin") == nil, "highest rowid")
				u, err := store.FindUser(db.Reader(), "alice")
				c4aCheck(t, err == nil, "original row")
				saved := comparePassword
				entered, release, done := make(chan struct{}), make(chan struct{}), make(chan *rules.Error, 1)
				comparePassword = func(hash, password []byte) error {
					close(entered)
					<-release
					return saved(hash, password)
				}
				go func() { _, _, e := s.Login("alice", pw, ""); done <- e }()
				<-entered
				var change *rules.Error
				switch mode {
				case "password":
					change = s.SetPassword(rules.Actor{Kind: rules.UI, Name: "test"}, "alice", c4aRandom(t))
				case "delete", "recreate":
					change = s.DeleteUser(rules.Actor{Kind: rules.UI, Name: "test"}, "alice")
					if change == nil && mode == "recreate" {
						change = s.CreateUser(rules.Actor{Kind: rules.UI, Name: "test"}, "alice", c4aRandom(t), "admin")
					}
				}
				close(release)
				e := <-done
				comparePassword = saved
				c4aCheck(t, change == nil, "interleaving committed")
				if mode == "recreate" {
					current, err := store.FindUser(db.Reader(), "alice")
					c4aCheck(t, err == nil && current.ID == u.ID && current.PasswordHash != u.PasswordHash, "same rowid different password")
				}
				var count int
				c4aCheck(t, db.Reader().QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id=?", u.ID).Scan(&count) == nil, "session count")
				if mode == "control" {
					c4aCheck(t, e == nil && count == 1, "uncontended comparison")
				} else {
					c4aCheck(t, e != nil && e.Code == "invalid_credentials" && count == 0, "stale comparison cannot create session")
				}
				t.Logf("slow_comparison_interleaving=%s sessions=%d", mode, count)
			})
		}
	})
}
