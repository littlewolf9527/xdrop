package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func c5d0Rates(t *testing.T, s *rules.Service) map[string]orch.RuleRate {
	t.Helper()
	rates := map[string]orch.RuleRate{}
	for i := 0; i < 33; i++ {
		target, port := fmt.Sprintf("192.0.2.%d", i%30+1), i+1
		r, e := s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{DstIP: &target, DstPort: &port})
		require(t, e == nil, "seed target rule")
		if i < 22 || i >= 30 {
			rates[r.Rule.ID] = orch.RuleRate{PPS: float64(i + 1), BytesPS: float64(100 * (i + 1)), Nodes: 1}
		}
	}
	require(t, len(rates) == 25, "positive rules witness")
	t.Log("fixture_targets=30 positive_targets=22 positive_rules=25")
	return rates
}

func TestC5D0Top(t *testing.T) {
	t.Run("rankings", func(t *testing.T) {
		f, src, _ := c5cFixture(t)
		src.byNode["a"] = c5d0Rates(t, f.s)
		require(t, c4aCount(t, f.db, "SELECT COUNT(DISTINCT dst_ip) FROM rules") == 30, "stored targets witness")
		all := c5cTop(t, f, "?n=all")
		for _, n := range []string{"5", "20", "all"} {
			n := n
			t.Run(n, func(t *testing.T) {
				v := c5cTop(t, f, "?n="+n)
				rulesN, targetsN := 25, 22
				if n == "5" {
					rulesN, targetsN = 5, 5
				}
				if n == "20" {
					rulesN, targetsN = 20, 20
				}
				require(t, len(v.Rules) == rulesN && len(v.Targets) == targetsN && v.TargetsTotal == 22, "rank counts and untruncated total", n)
				require(t, reflect.DeepEqual(v.Rules, all.Rules[:rulesN]) && reflect.DeepEqual(v.Targets, all.Targets[:targetsN]), "same order and shares")
				require(t, reflect.DeepEqual(v.UpdatedAt, all.UpdatedAt) && v.Incomplete == all.Incomplete && v.TotalPPS == all.TotalPPS && v.TotalBytesPS == all.TotalBytesPS, "same snapshot metadata")
				t.Logf("n=%s rules=%d targets=%d targets_total=%d", n, len(v.Rules), len(v.Targets), v.TargetsTotal)
			})
		}
	})
	t.Run("cache", func(t *testing.T) {
		f, src, q := c5cFixture(t)
		src.byNode["a"] = c5d0Rates(t, f.s)
		key := src.TrafficInput().Key
		c5cTop(t, f, "?n=all")
		c5cTop(t, f, "?n=5")
		batches := q.batches
		for _, n := range []string{"all", "5", "all"} {
			v := c5cTop(t, f, "?n="+n)
			want := 25
			if n == "5" {
				want = 5
			}
			require(t, key == src.TrafficInput().Key && q.batches == batches, "unchanged key and query count")
			require(t, len(v.Rules) == want && v.TargetsTotal == 22, "separate cache slots", n)
		}
		require(t, batches == 2, "two warmed slots")
		t.Logf("key_unchanged=true warm_batches=%d final_batches=%d cache_hits=3", batches, q.batches)
	})
	t.Run("events", func(t *testing.T) {
		f := c5dFresh(t, nil)
		cookie := f.login("alice")
		f.n.rates = c5d0Rates(t, f.s)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := &c5d0Writer{ResponseRecorder: httptest.NewRecorder(), ready: make(chan struct{}), cancel: cancel}
		r := httptest.NewRequest("GET", "/api/v1/events", nil).WithContext(ctx)
		r.Header.Set("Cookie", auth.CookieName+"="+cookie)
		done := make(chan struct{})
		go func() { f.e.ServeHTTP(w, r); close(done) }()
		c5dWait(t, w.ready, "first flush")
		f.step()
		c5dWait(t, done, "traffic flush")
		frames := strings.Split(strings.TrimSpace(w.Body.String()), "\n\n")
		require(t, len(frames) == 4, "prelude and three first snapshots")
		top := c5dDecode(t, frames[3], "traffic")["top"].(map[string]any)
		require(t, top["targets_total"] == float64(22) && len(top["targets"].([]any)) == 5, "first traffic total")
		t.Log("first_traffic targets_total=22 targets=5")
	})
}

type c5d0Writer struct {
	*httptest.ResponseRecorder
	ready   chan struct{}
	cancel  context.CancelFunc
	flushes int
}

func (w *c5d0Writer) Flush() {
	w.ResponseRecorder.Flush()
	w.flushes++
	if w.flushes == 1 {
		close(w.ready)
	}
	if w.flushes == 4 {
		w.cancel()
	}
}

func c5d0Accounts(t *testing.T) *c4aFixture {
	return c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
}
func c5d0Body(current, next string) string {
	return c4aJSON(map[string]string{"current_password": current, "password": next})
}
func c5d0Audit(t *testing.T, f *c4aFixture) []store.AuditEvent {
	t.Helper()
	rows, err := store.AuditAfter(f.db.Reader(), "", "", "", 0, 1000)
	require(t, err == nil, "read audit")
	return rows
}
func c5d0Clear(t *testing.T, f *c4aFixture) {
	t.Helper()
	_, err := f.db.Exec("DELETE FROM audit")
	require(t, err == nil, "clear fixture audit")
}

func c5d0NoClearCookie(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		require(t, c.Name != auth.CookieName, "failure response must not set session cookie")
	}
}

func TestC5D0Password(t *testing.T) {
	for _, role := range []string{"operator", "admin"} {
		role := role
		t.Run("success/"+role, func(t *testing.T) {
			f := c5d0Accounts(t)
			_, err := f.db.Exec("UPDATE users SET role=? WHERE username='alice'", role)
			require(t, err == nil, "fixture role")
			s1, s2, b := f.cookie, f.login(t, "alice", f.pw), f.login(t, "bob", f.pw)
			for _, token := range []string{s1, s2, b} {
				f.call(t, "GET", "/auth/me", token, "", 200)
			}
			c5d0Clear(t, f)
			next := c4aSecret(t)
			w := f.call(t, "PUT", "/auth/me/password", s1, c5d0Body(f.pw, next), 204)
			t.Log("before_change S1=200 S2=200 B=200 change=204")
			t.Run("cookie", func(t *testing.T) {
				cookies := w.Result().Cookies()
				require(t, len(cookies) == 1 && cookies[0].Value == "", "cleared cookie")
				c4aCookieCheck(t, cookies[0], -1)
			})
			for name, token := range map[string]string{"S1": s1, "S2": s2} {
				name, token := name, token
				t.Run(name, func(t *testing.T) { f.call(t, "GET", "/auth/me", token, "", 401) })
			}
			f.call(t, "GET", "/auth/me", b, "", 200)
			rows := c5d0Audit(t, f)
			require(t, len(rows) == 1 && rows[0].Action == "user.password" && rows[0].Actor == "user:alice" && rows[0].Target == "user:alice", "exact self audit")
			f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{"alice", f.pw}), 401)
			f.now = f.now.Add(2 * time.Second)
			f.login(t, "alice", next)
		})
	}
	for _, direction := range []string{"change-login", "login-change"} {
		direction := direction
		t.Run("shared/"+direction, func(t *testing.T) {
			f := c5d0Accounts(t)
			next, wrong := c4aSecret(t), c4aSecret(t)
			u, err := store.FindUser(f.db.Reader(), "alice")
			require(t, err == nil && wrong != f.pw, "wrong password witness")
			f.call(t, "GET", "/auth/me", f.cookie, "", 200)
			c5d0Clear(t, f)
			method, path, input, identity := "PUT", "/auth/me/password", c5d0Body(wrong, next), f.cookie
			if direction == "login-change" {
				method, path, input, identity = "POST", "/auth/login", c4aJSON(LoginInput{"alice", wrong}), ""
			}
			w := f.call(t, method, path, identity, input, 401)
			require(t, decoded[Error](t, w).Code == "invalid_credentials", "failure code")
			c5d0NoClearCookie(t, w)
			rows := c5d0Audit(t, f)
			require(t, len(rows) == 1, "one failure audit")
			ev := rows[0]
			require(t, ev.Action == "auth.login_failed" && ev.Actor == "" && ev.Target == "user:alice" && ev.At == f.now.Format(store.TimeFormat) && ev.Source == "192.0.2.1" && len(ev.Before) == 0 && string(ev.After) == `{"reason":"password"}`, "same login failure fields")
			method, path, input, identity = "POST", "/auth/login", c4aJSON(LoginInput{"alice", f.pw}), ""
			if direction == "login-change" {
				method, path, input, identity = "PUT", "/auth/me/password", c5d0Body(f.pw, next), f.cookie
			}
			limited := f.call(t, method, path, identity, input, 429)
			require(t, decoded[Error](t, limited).Code == "login_throttled" && limited.Header().Get("Retry-After") == "1" && len(c5d0Audit(t, f)) == 1, "shared throttle and no extra audit")
			c5d0NoClearCookie(t, limited)
			encoded, err := json.Marshal(rows)
			require(t, err == nil, "encode audit")
			bytes := string(encoded) + f.logs.String() + w.Body.String() + limited.Body.String()
			for _, secret := range []string{f.pw, next, wrong, u.PasswordHash, f.cookie} {
				require(t, !strings.Contains(bytes, secret), "secret leaked")
			}
			require(t, !strings.Contains(bytes, "$2a$") && !strings.Contains(bytes, "$2b$") && !strings.Contains(bytes, "$2y$"), "password hash leaked")
			t.Log("wrong_password=true failure_audits=1 immediate_correct=429 retry_after=1 secrets=0")
		})
	}
	t.Run("invalid-next", func(t *testing.T) {
		f := c5d0Accounts(t)
		w := f.call(t, "PUT", "/auth/me/password", f.cookie, c5d0Body(f.pw, "123456789"), 400)
		e := decoded[Error](t, w)
		require(t, e.Code == "invalid_field" && e.Field == "password", "new password validation")
		c5d0NoClearCookie(t, w)
		f.login(t, "alice", f.pw)
		w = f.call(t, "PUT", "/auth/me/password", f.cookie, c5d0Body(c4aSecret(t), "123456789"), 400)
		e = decoded[Error](t, w)
		require(t, e.Code == "invalid_field" && e.Field == "password", "invalid next precedes wrong current verification")
		c5d0NoClearCookie(t, w)
		f.login(t, "alice", f.pw)
		t.Log("invalid_next_correct_or_wrong_current=400 immediate_old_password_login=200")
	})
	t.Run("access", func(t *testing.T) {
		f := c5d0Accounts(t)
		key := f.issue(t, "own-password").Key
		for _, tc := range []struct {
			name, identity, body, code string
			status                     int
		}{
			{"machine", key, c5d0Body(f.pw, f.pw), "forbidden", 403},
			{"anonymous", "", c5d0Body(f.pw, f.pw), "unauthenticated", 401},
			{"unknown-field", f.cookie, `{"current_password":"wrong","password":"1234567890","other":true}`, "bad_request", 400},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				w := f.call(t, "PUT", "/auth/me/password", tc.identity, tc.body, tc.status)
				require(t, decoded[Error](t, w).Code == tc.code, "access code")
				c5d0NoClearCookie(t, w)
			})
		}
	})
}

func TestC5D0PasswordRaceHTTP(t *testing.T) {
	for _, mode := range []string{"control", "password", "delete", "recreate"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			f := c5d0Accounts(t)
			admin, next := f.login(t, "bob", f.pw), c4aSecret(t)
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			var calls atomic.Int32
			fixed := f.now
			f.acc.Now = func() time.Time {
				// Authentication reads once, then verification reads twice; pause after comparison.
				if calls.Add(1) == 3 {
					close(entered)
					<-release
				}
				return fixed
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest("PUT", "/api/v1/auth/me/password", strings.NewReader(c5d0Body(f.pw, c4aSecret(t))))
			r.Header.Set("Cookie", auth.CookieName+"="+f.cookie)
			go func() { f.e.ServeHTTP(w, r); close(done) }()
			defer func() {
				unblock()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("HTTP race cleanup blocked")
				}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("HTTP comparison never paused")
			}
			var replacement string
			switch mode {
			case "password":
				f.call(t, "PUT", "/users/alice/password", admin, c4aJSON(PasswordInput{next}), 204)
			case "delete", "recreate":
				f.call(t, "DELETE", "/users/alice", admin, "", 204)
				if mode == "recreate" {
					f.call(t, "POST", "/users", admin, c4aJSON(UserInput{LoginInput{"alice", next}, "operator"}), 201)
					replacement = f.login(t, "alice", next)
					f.call(t, "GET", "/auth/me", replacement, "", 200)
				}
			}
			unblock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("HTTP change did not return")
			}
			if mode == "control" {
				require(t, w.Code == 204, "HTTP race control")
			} else {
				require(t, w.Code == 401 && decoded[Error](t, w).Code == "invalid_credentials", "HTTP stale response")
				c5d0NoClearCookie(t, w)
			}
			if replacement != "" {
				f.call(t, "GET", "/auth/me", replacement, "", 200)
			}
			t.Logf("HTTP mode=%s status=%d recreated_session_before_after_200=%t", mode, w.Code, replacement != "")
		})
	}
}
