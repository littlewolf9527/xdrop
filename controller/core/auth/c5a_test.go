package auth

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"github.com/mattn/go-sqlite3"
)

func c5aAwait(t *testing.T, ch <-chan *rules.Error) *rules.Error {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("settings fixture timeout")
		return nil
	}
}
func TestC5AAuth(t *testing.T) {
	t.Run("C5A-settings-order", func(t *testing.T) {
		s, db, _ := c4aService(t)
		m := orch.New(nil, orch.Options{})
		entered, release := make(chan struct{}), make(chan struct{})
		a, b := 2, 3
		s.OnSettings = func(v store.Settings) {
			if v.ReconcileIntervalMinutes == a {
				close(entered)
				select {
				case <-release:
				case <-time.After(3 * time.Second):
					t.Error("callback barrier timeout")
				}
			}
			m.SetReconcileInterval(time.Duration(v.ReconcileIntervalMinutes) * time.Minute)
		}
		first, second := make(chan *rules.Error, 1), make(chan *rules.Error, 1)
		go func() { first <- s.UpdateSettings(rules.Actor{}, SettingsPatch{ReconcileIntervalMinutes: &a}) }()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatal("callback not entered")
		}
		unlocked := s.mu.TryLock()
		if unlocked {
			s.mu.Unlock()
		}
		started := make(chan struct{})
		go func() {
			close(started)
			second <- s.UpdateSettings(rules.Actor{}, SettingsPatch{ReconcileIntervalMinutes: &b})
		}()
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatal("second update not started")
		}
		close(release)
		firstErr, secondErr := c5aAwait(t, first), c5aAwait(t, second)
		c4aCheck(t, !unlocked, "callback must hold auth mutex (TryLock succeeded)")
		c4aCheck(t, firstErr == nil && secondErr == nil, "updates completed")
		stored, err := store.ReadSettings(db.Reader())
		interval := time.Duration(reflect.ValueOf(m).Elem().FieldByName("opts").FieldByName("ReconcileInterval").Int())
		c4aCheck(t, err == nil && stored.ReconcileIntervalMinutes == b && interval == time.Duration(b)*time.Minute, "commit callback ordering")
		t.Log("settings_updates=2 callbacks=2 trylock_held=1 final_database=3 final_orch_minutes=3")
	})
	t.Run("C5A-settings-commit", func(t *testing.T) {
		s, db, _ := c4aService(t)
		before, err := store.ReadSettings(db.Reader())
		c4aCheck(t, err == nil, "initial settings")
		hooks, callbacks := 0, 0
		s.OnSettings = func(store.Settings) { callbacks++ }
		install := func(h func() int) {
			conn, err := db.Conn(context.Background())
			c4aCheck(t, err == nil, "commit hook connection")
			err = conn.Raw(func(v any) error { v.(*sqlite3.SQLiteConn).RegisterCommitHook(h); return nil })
			c4aCheck(t, err == nil && conn.Close() == nil, "commit hook setup")
		}
		install(func() int { hooks++; return 1 })
		defer install(nil)
		minutes := 2
		e := s.UpdateSettings(rules.Actor{}, SettingsPatch{ReconcileIntervalMinutes: &minutes})
		after, err := store.ReadSettings(db.Reader())
		c4aCheck(t, e != nil && e.Code == "internal" && hooks == 1 && callbacks == 0 && err == nil && after == before, "failed COMMIT notified or persisted")
		t.Log("commit_hooks=1 commit_rejections=1 callbacks=0")
	})
	t.Run("C5A-last-admin", func(t *testing.T) {
		s, db, _ := c4aService(t)
		a := rules.Actor{Kind: rules.System, Name: "test"}
		c4aCheck(t, s.CreateUser(a, "operator", c4aRandom(t), "operator") == nil, "operator user witness")
		for _, call := range []func() *rules.Error{func() *rules.Error { return s.SetRole(a, "alice", "operator") }, func() *rules.Error { return s.DeleteUser(a, "alice") }} {
			e := call()
			c4aCheck(t, e != nil && e.Code == "last_admin", "last administrator guard")
		}
		n, err := store.AdminCount(db.Reader())
		c4aCheck(t, err == nil && n == 1, "admin count preserved")
	})
}
