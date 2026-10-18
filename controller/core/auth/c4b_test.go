package auth

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func TestC4BAuth(t *testing.T) {
	t.Run("C4B-login", func(t *testing.T) {
		s, db, pw := c4aService(t)
		fixed := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
		s.Now = func() time.Time { return fixed }
		_, seedErr := db.Exec("DELETE FROM audit")
		c4aCheck(t, seedErr == nil, "clear audit seeded before clock injection")
		rows := func() []store.AuditEvent {
			t.Helper()
			out, e := store.AuditAfter(db.Reader(), "", "", "", 0, 1000)
			c4aCheck(t, e == nil, "audit read")
			return out
		}
		last := func(reason, target string, n int) {
			t.Helper()
			out := rows()
			c4aCheck(t, len(out) == n, "login audit count")
			ev := out[len(out)-1]
			c4aCheck(t, ev.Action == "auth.login_failed" && ev.Actor == "" && ev.Source == "198.51.100.7" && ev.Target == target && ev.At == fixed.Format(store.TimeFormat) && len(ev.Before) == 0, "login failure columns")
			var got map[string]string
			c4aCheck(t, json.Unmarshal(ev.After, &got) == nil && len(got) == 1 && got["reason"] == reason, "login failure reason")
		}
		n := len(rows())
		_, _, e := s.Login("alice", pw, "198.51.100.7")
		c4aCheck(t, e == nil, "successful login")
		n++
		ev := rows()[n-1]
		c4aCheck(t, ev.Action == "auth.login" && ev.Actor == "user:alice" && ev.Target == "user:alice" && ev.Source == "198.51.100.7", "success event")
		_, _, e = s.Login("alice", c4aRandom(t), "198.51.100.7")
		c4aCheck(t, e != nil && e.Code == "invalid_credentials", "password failure")
		n++
		last("password", "user:alice", n)
		_, _, e = s.Login("alice", pw, "198.51.100.7")
		c4aCheck(t, e != nil && e.Code == "login_throttled", "429 witness")
		c4aCheck(t, len(rows()) == n, "throttled request audited")
		unknown := "absent-" + c4aRandom(t)[:12]
		_, _, e = s.Login(unknown, pw, "198.51.100.7")
		c4aCheck(t, e != nil && e.Code == "invalid_credentials", "unknown user")
		n++
		last("unknown_user", "", n)
		b, _ := json.Marshal(rows()[n-1])
		c4aCheck(t, !strings.Contains(string(b), unknown), "unknown input stored in audit")
		fixed = fixed.Add(time.Second)
		saved := comparePassword
		defer func() { comparePassword = saved }()
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan *rules.Error, 1)
		comparePassword = func(hash, password []byte) error { close(entered); <-release; return saved(hash, password) }
		go func() { _, _, e := s.Login("alice", pw, "198.51.100.7"); done <- e }()
		<-entered
		_, _, e = s.Login("alice", pw, "198.51.100.7")
		c4aCheck(t, e != nil && e.Code == "login_throttled", "occupied 429 witness")
		c4aCheck(t, len(rows()) == n, "occupied request audited")
		close(release)
		c4aCheck(t, <-done == nil, "slot owner success")
		n++
		comparePassword = saved
		_, err := db.Exec("DELETE FROM sessions")
		c4aCheck(t, err == nil, "clear sessions")
		entered, release = make(chan struct{}), make(chan struct{})
		var calls int32
		s.Now = func() time.Time {
			if atomic.AddInt32(&calls, 1) == 2 {
				close(entered)
				<-release
			}
			return fixed
		}
		go func() { _, _, e := s.Login("alice", pw, "198.51.100.7"); done <- e }()
		<-entered
		c4aCheck(t, s.SetPassword(rules.Actor{Kind: rules.System, Name: "cli"}, "alice", c4aRandom(t)) == nil, "concurrent password change")
		n++
		close(release)
		e = <-done
		c4aCheck(t, e != nil && e.Code == "invalid_credentials", "stale witness")
		n++
		last("stale", "user:alice", n)
		var sessions int
		c4aCheck(t, db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&sessions) == nil && sessions == 0, "stale inserted session")
		c4aCheck(t, atomic.LoadInt32(&calls) == 3, "existing Login kept exactly two clock calls plus password change")
		s.Now = func() time.Time { return fixed }
		c4aCheck(t, s.SetPassword(rules.Actor{Kind: rules.System, Name: "cli"}, "alice", pw) == nil, "restore test password")
		n++
		_, err = db.Exec("DROP TABLE sessions")
		c4aCheck(t, err == nil, "database failure fixture")
		_, _, e = s.Login("alice", pw, "198.51.100.7")
		c4aCheck(t, e != nil && e.Code == "internal" && len(rows()) == n, "database error classified as login failure")
		t.Log("login reasons=password,unknown_user,stale throttle_429_no_audit=true slot_429_no_audit=true clock_calls=2")
	})
}
