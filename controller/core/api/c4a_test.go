package api

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/config"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func testActor(r *http.Request) (rules.Actor, *Error) {
	v := r.Header.Get("X-Xdrop-Actor")
	if v == "ui" {
		return rules.Actor{Kind: rules.UI, Name: "tester", Admin: true}, nil
	}
	if v == "operator" {
		return rules.Actor{Kind: rules.UI, Name: "operator"}, nil
	}
	name := strings.TrimPrefix(v, "machine:")
	if strings.HasPrefix(v, "machine:") && regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`).MatchString(name) {
		return rules.Actor{Kind: rules.Machine, Name: name}, nil
	}
	return rules.Actor{}, &Error{Code: "unauthenticated", Message: "valid actor required"}
}
func c4aRoute(key string) bool {
	return strings.Contains(key, " /auth/") || strings.Contains(key, " /users") || strings.Contains(key, " /credentials") || strings.Contains(key, " /settings") || strings.Contains(key, " /audit") || strings.Contains(key, " /templates")
}
func testLateRoute(t *testing.T, f *fixture) {
	called := false
	f.e.GET("/api/v1/unregistered", func(*gin.Context) { called = true })
	w := request(t, f.e, "GET", "/api/v1/unregistered", "ui", "", 403)
	require(t, decoded[Error](t, w).Code == "forbidden" && !called, "unregistered handler executed")
}

type c4aCorpus struct {
	secrets []string
	samples map[string][][]byte
}

func (c *c4aCorpus) add(kind string, b []byte) {
	c.samples[kind] = append(c.samples[kind], append([]byte(nil), b...))
}

type c4aFixture struct {
	*fixture
	acc              *auth.Service
	path, pw, cookie string
	now              time.Time
	corpus           *c4aCorpus
}

func c4aSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	_, e := rand.Read(b)
	require(t, e == nil, "random input")
	return hex.EncodeToString(b)
}
func c4aJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func c4aFresh(t *testing.T, corpus *c4aCorpus) *c4aFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.db")
	db, e := store.Open(path)
	require(t, e == nil, "database open")
	n := &stubNodes{}
	s := rules.New(db, n, DeliveryStatus(n))
	logs := &bytes.Buffer{}
	f := &c4aFixture{fixture: &fixture{db: db, s: s, n: n, logs: logs}, acc: auth.New(db), path: path, pw: c4aSecret(t), now: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), corpus: corpus}
	f.acc.Now = func() time.Time { return f.now }
	f.e = New(s, n, AccountAuthenticator(f.acc), log.New(logs, "", 0), Options{Accounts: f.acc, Database: path})
	corpus.secrets = append(corpus.secrets, f.pw)
	require(t, f.acc.CreateUser(rules.Actor{Kind: rules.UI, Name: "test"}, "bob", f.pw, "admin") == nil && f.acc.CreateUser(rules.Actor{Kind: rules.UI, Name: "test"}, "alice", f.pw, "admin") == nil, "create fixture users")
	f.cookie = f.login(t, "alice", f.pw)
	t.Cleanup(func() {
		corpus.add("logs", logs.Bytes())
		for _, suffix := range []string{"", "-wal"} {
			b, err := os.ReadFile(path + suffix)
			require(t, err == nil, "collect database before cleanup", suffix)
			kind := "database"
			if suffix != "" {
				kind = "wal"
			}
			corpus.add(kind, b)
		}
		db.Close()
	})
	return f
}
func (f *c4aFixture) call(t *testing.T, method, path, identity, body string, status int) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(body))
	if strings.HasPrefix(identity, "xdk_") {
		r.Header.Set("Authorization", "Bearer "+identity)
	} else if identity != "" {
		r.Header.Set("Cookie", auth.CookieName+"="+identity)
	}
	w := httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	if !(method == "POST" && path == "/credentials") {
		f.corpus.add("responses", w.Body.Bytes())
	}
	require(t, w.Code == status, method, path, "status", w.Code, "expected", status)
	return w
}
func (f *c4aFixture) login(t *testing.T, name, pw string) string {
	t.Helper()
	w := f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{name, pw}), 200)
	cookies := w.Result().Cookies()
	require(t, len(cookies) == 1, "session cookie count")
	f.corpus.secrets = append(f.corpus.secrets, pw, cookies[0].Value)
	return cookies[0].Value
}
func (f *c4aFixture) issue(t *testing.T, name string) IssuedDTO {
	t.Helper()
	w := f.call(t, "POST", "/credentials", f.cookie, c4aJSON(CredentialInput{name}), 201)
	var v IssuedDTO
	require(t, json.Unmarshal(w.Body.Bytes(), &v) == nil, "credential response")
	require(t, len(v.Key) > 21, "credential length")
	f.corpus.secrets = append(f.corpus.secrets, v.Key, v.Key[21:])
	return v
}
func c4aCount(t *testing.T, db *store.DB, query string, args ...any) int {
	t.Helper()
	var n int
	require(t, db.Reader().QueryRow(query, args...).Scan(&n) == nil, "count query")
	return n
}
func c4aCookieCheck(t *testing.T, c *http.Cookie, age int) {
	t.Helper()
	require(t, c.Name == auth.CookieName && c.Path == "/api/v1" && c.Secure && c.HttpOnly && c.SameSite == http.SameSiteStrictMode && c.MaxAge == age, "cookie attributes")
}
func TestC4AAPI(t *testing.T) {
	corpus := &c4aCorpus{samples: map[string][][]byte{}}
	t.Run("C4A-login", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		w := f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{"alice", f.pw}), 200)
		cs := w.Result().Cookies()
		require(t, len(cs) == 1, "cookie count")
		c4aCookieCheck(t, cs[0], 86400)
		corpus.secrets = append(corpus.secrets, cs[0].Value)
		wrong := c4aSecret(t)
		corpus.secrets = append(corpus.secrets, wrong)
		a := f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{"alice", wrong}), 401)
		b := f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{"absent", wrong}), 401)
		require(t, bytes.Equal(a.Body.Bytes(), b.Body.Bytes()) && decoded[Error](t, a).Code == "invalid_credentials", "failure responses differ")
		for _, seconds := range []int{1, 2, 4, 8, 16, 32, 60, 60} {
			w := f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{"alice", wrong}), 429)
			require(t, w.Header().Get("Retry-After") == fmt.Sprint(seconds), "Retry-After sequence", seconds)
			f.now = f.now.Add(time.Duration(seconds) * time.Second)
			f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{"alice", wrong}), 401)
		}
	})
	t.Run("C4A-login-length", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		password := c4aSecret(t) + c4aSecret(t)[:24]
		corpus.secrets = append(corpus.secrets, password)
		require(t, len(password) == 72, "password boundary fixture")
		f.call(t, "POST", "/users", f.cookie, c4aJSON(UserInput{LoginInput{"boundary", password}, "admin"}), 201)
		f.login(t, "boundary", password)
		for _, size := range []int{1, 1024} {
			size := size
			t.Run(fmt.Sprintf("suffix-%d", size), func(t *testing.T) {
				input := password + strings.Repeat(c4aSecret(t), 22)[:size]
				corpus.secrets = append(corpus.secrets, input)
				before := c4aCount(t, f.db, "SELECT COUNT(*) FROM sessions")
				w := f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{"boundary", input}), 401)
				require(t, decoded[Error](t, w).Code == "invalid_credentials" && len(w.Header().Values("Set-Cookie")) == 0, "oversized login response")
				require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM sessions") == before, "oversized login created a session")
				w = f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{"boundary", password}), 429)
				require(t, w.Header().Get("Retry-After") == "1", "oversized login counts one failure")
				f.now = f.now.Add(time.Second)
				f.login(t, "boundary", password)
			})
		}
	})
	t.Run("C4A-cookie-wire", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		key := f.issue(t, "wire")
		valid := "Cookie: " + auth.CookieName + "=" + f.cookie
		bad := "Cookie: " + auth.CookieName + "=\"unterminated"
		for _, test := range []struct {
			name, headers string
			status        int
		}{
			{"valid-malformed", valid + "; " + auth.CookieName + "=\"unterminated", 401},
			{"bearer-malformed", "Authorization: Bearer " + key.Key + "\r\n" + bad, 401},
			{"malformed-only", bad, 401},
			{"duplicate-headers", valid + "\r\n" + valid, 401},
			{"unrelated-same-header", valid + "; other=placeholder", 200},
			{"unrelated-other-header", valid + "\r\nCookie: other=placeholder", 200},
			{"bearer-name-space", "Authorization: Bearer " + key.Key + "\r\nCookie: " + auth.CookieName + " =" + f.cookie, 401},
			{"bearer-name-tab", "Authorization: Bearer " + key.Key + "\r\nCookie: " + auth.CookieName + "\t=" + f.cookie, 401},
			{"valid-malformed-name-space", valid + "; " + auth.CookieName + " =\"unterminated", 401},
			{"second-malformed-name-space", valid + "\r\nCookie: " + auth.CookieName + " =\"unterminated", 401},
			{"bearer-second-session", "Authorization: Bearer " + key.Key + "\r\nCookie: other=placeholder\r\n" + valid, 401},
			{"second-malformed-session", valid + "\r\n" + bad, 401},
		} {
			test := test
			t.Run(test.name, func(t *testing.T) {
				raw := "GET /api/v1/auth/me HTTP/1.1\r\nHost: controller.example\r\n" + test.headers + "\r\n\r\n"
				r, e := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
				require(t, e == nil, "parse wire request")
				defer r.Body.Close()
				w := httptest.NewRecorder()
				f.e.ServeHTTP(w, r)
				corpus.add("responses", w.Body.Bytes())
				require(t, w.Code == test.status, "wire cookie status", w.Code, test.status)
				if test.status == 401 {
					require(t, decoded[Error](t, w).Code == "unauthenticated", "wire cookie rejection code")
				} else {
					require(t, decoded[IdentityDTO](t, w) == (IdentityDTO{"user", "alice", "admin"}), "wire cookie identity")
				}
			})
		}
	})
	t.Run("C4A-session", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		at := f.now
		f.now = at.Add(24*time.Hour - time.Second)
		f.call(t, "GET", "/auth/me", f.cookie, "", 200)
		f.now = at.Add(24 * time.Hour)
		f.call(t, "GET", "/auth/me", f.cookie, "", 401)
		require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM sessions") == 1, "expired row exists before login")
		fresh := f.login(t, "alice", f.pw)
		require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM sessions") == 1, "login cleans exact expiry")
		f.now = f.now.Add(2 * time.Hour)
		admin := f.login(t, "bob", f.pw)
		f.call(t, "PUT", "/settings", admin, `{"session_hours":1}`, 200)
		f.call(t, "GET", "/auth/me", fresh, "", 401)
		f.call(t, "GET", "/auth/me", admin, "", 200)
		w := f.call(t, "POST", "/auth/logout", admin, "", 204)
		cs := w.Result().Cookies()
		require(t, len(cs) == 1, "logout cookie count")
		c4aCookieCheck(t, cs[0], -1)
		f.call(t, "GET", "/auth/me", admin, "", 401)
		require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM sessions") == 1, "logout deleted row")
		f.login(t, "alice", f.pw)
		require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM sessions") == 1, "expired sessions cleaned")
	})
	t.Run("C4A-users", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		bob1 := f.login(t, "bob", f.pw)
		bob2 := f.login(t, "bob", f.pw)
		newpw := c4aSecret(t)
		corpus.secrets = append(corpus.secrets, newpw)
		f.call(t, "POST", "/users", f.cookie, c4aJSON(UserInput{LoginInput{"charlie", newpw}, "admin"}), 201)
		w := f.call(t, "GET", "/users", f.cookie, "", 200)
		users := decoded[[]UserDTO](t, w)
		require(t, len(users) == 3 && users[2].Username == "charlie" && users[2].CreatedBy == "user:alice", "user list")
		f.call(t, "POST", "/users", f.cookie, c4aJSON(UserInput{LoginInput{"charlie", newpw}, "admin"}), 409)
		f.call(t, "PUT", "/users/bob/password", f.cookie, c4aJSON(PasswordInput{newpw}), 204)
		for _, old := range []string{bob1, bob2} {
			f.call(t, "GET", "/auth/me", old, "", 401)
		}
		f.call(t, "GET", "/auth/me", f.cookie, "", 200)
		f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{"bob", f.pw}), 401)
		f.now = f.now.Add(time.Second)
		bob := f.login(t, "bob", newpw)
		f.call(t, "DELETE", "/users/bob", f.cookie, "", 204)
		f.call(t, "GET", "/auth/me", bob, "", 401)
		f.call(t, "DELETE", "/users/charlie", f.cookie, "", 204)
		w = f.call(t, "DELETE", "/users/alice", f.cookie, "", 409)
		require(t, decoded[Error](t, w).Code == "last_user", "last user guard")
		for _, in := range []LoginInput{{"bad name", newpw}, {"short", newpw[:9]}, {"long", newpw + newpw[:25]}} {
			w := f.call(t, "POST", "/users", f.cookie, c4aJSON(UserInput{in, "admin"}), 400)
			e := decoded[Error](t, w)
			require(t, e.Code == "invalid_field" && e.Field != "", "invalid field detail")
		}
		f.call(t, "PUT", "/settings", f.cookie, `{"session_hours":1,"unknown":1}`, 400)
		for _, n := range []int{0, 721} {
			w := f.call(t, "PUT", "/settings", f.cookie, c4aJSON(SettingsDTO{SessionHours: n}), 400)
			require(t, decoded[Error](t, w).Field == "session_hours", "settings bounds")
		}
	})
	t.Run("C4A-cred", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		v := f.issue(t, "x")
		require(t, regexp.MustCompile(`^xdk_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$`).MatchString(v.Key), "key format")
		f.call(t, "GET", "/auth/me", v.Key, "", 200)
		t.Log("legitimate_bearer_status=200 before independent storage assertions")
		secret := v.Key[21:]
		hash := sha256.Sum256([]byte(secret))
		var actual string
		require(t, f.db.Reader().QueryRow("SELECT secret_hash FROM credentials WHERE id=?", v.ID).Scan(&actual) == nil, "stored hash read")
		if actual != hex.EncodeToString(hash[:]) {
			t.Error("secret_hash differs from independent digest")
		}
		w := f.call(t, "GET", "/credentials", f.cookie, "", 200)
		for _, value := range []string{v.Key, secret} {
			if bytes.Contains(w.Body.Bytes(), []byte(value)) {
				t.Error("credential list contains secret")
			}
			for _, suffix := range []string{"", "-wal"} {
				b, e := os.ReadFile(f.path + suffix)
				require(t, e == nil, "database bytes")
				if bytes.Contains(b, []byte(value)) {
					t.Error("database contains credential secret")
				}
			}
		}
		wrong := v.Key[:21] + strings.Repeat("A", 43)
		if wrong == v.Key {
			wrong = v.Key[:21] + strings.Repeat("B", 43)
		}
		for _, test := range []struct {
			values []string
			cookie string
			status int
		}{
			{[]string{"bearer " + v.Key}, "", 200}, {[]string{"Bearer " + wrong}, "", 401}, {[]string{"Bearer y" + v.Key[1:]}, "", 401},
			{[]string{"Basic " + v.Key}, "", 401}, {[]string{"Bearer  " + v.Key}, "", 401}, {[]string{"Bearer " + v.Key + " "}, "", 401},
			{[]string{"Bearer " + v.Key, "Bearer " + v.Key}, "", 401}, {[]string{""}, "", 401}, {nil, auth.CookieName + "=" + f.cookie + "; " + auth.CookieName + "=" + f.cookie, 401},
		} {
			r := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
			for _, value := range test.values {
				r.Header.Add("Authorization", value)
			}
			if test.cookie != "" {
				r.Header.Set("Cookie", test.cookie)
			}
			w := httptest.NewRecorder()
			f.e.ServeHTTP(w, r)
			corpus.add("responses", w.Body.Bytes())
			require(t, w.Code == test.status, "credential parsing status", w.Code, test.status)
		}
	})
	t.Run("C4A-rotate", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		old := f.issue(t, "x")
		created := decoded[CreateResponse](t, f.call(t, "POST", "/rules", old.Key, strings.TrimSuffix(body(91), "}")+`,"claim_ref":"rotation"}`, 201))
		f.now = f.now.Add(time.Hour)
		newer := f.issue(t, "x")
		expected := f.now.Add(24 * time.Hour).Format(store.TimeFormat)
		require(t, len(newer.Retired) == 1 && newer.Retired[0].ID == old.ID && newer.Retired[0].RetireAt == expected, "rotation deadline")
		f.call(t, "GET", "/auth/me", old.Key, "", 200)
		f.call(t, "GET", "/auth/me", newer.Key, "", 200)
		secondAt := f.now
		var firstDeadline string
		require(t, f.db.Reader().QueryRow("SELECT retire_at FROM credentials WHERE id=?", old.ID).Scan(&firstDeadline) == nil && firstDeadline == expected, "second issuance stored deadline")
		f.now = secondAt.Add(time.Hour)
		third := f.issue(t, "x")
		var unchanged, secondDeadline string
		require(t, f.db.Reader().QueryRow("SELECT retire_at FROM credentials WHERE id=?", old.ID).Scan(&unchanged) == nil && unchanged == firstDeadline, "third issuance extended first deadline")
		require(t, f.db.Reader().QueryRow("SELECT retire_at FROM credentials WHERE id=?", newer.ID).Scan(&secondDeadline) == nil && secondDeadline == secondAt.Add(25*time.Hour).Format(store.TimeFormat), "third issuance second deadline")
		f.now = secondAt.Add(24 * time.Hour)
		f.call(t, "GET", "/auth/me", old.Key, "", 401)
		f.call(t, "GET", "/auth/me", newer.Key, "", 200)
		f.call(t, "GET", "/auth/me", third.Key, "", 200)
		f.call(t, "DELETE", "/rules/"+created.ID+"?claim_ref=rotation", newer.Key, "", 204)
		require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM rules WHERE id=?", created.ID) == 0, "new key releases old claim")
	})
	t.Run("C4A-revoke", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		key := f.issue(t, "x")
		f.call(t, "GET", "/auth/me", key.Key, "", 200)
		r := decoded[CreateResponse](t, f.call(t, "POST", "/rules", key.Key, body(92), 201))
		before, e := store.ClaimCount(f.db.Reader(), r.ID)
		require(t, e == nil && before == 1, "claim precondition")
		f.call(t, "DELETE", "/credentials/"+key.ID, f.cookie, "", 204)
		f.call(t, "GET", "/auth/me", key.Key, "", 401)
		after, e := store.ClaimCount(f.db.Reader(), r.ID)
		require(t, e == nil && after == before && c4aCount(t, f.db, "SELECT COUNT(*) FROM rules WHERE id=?", r.ID) == 1, "revocation preserves claims")
		var firstAt, firstBy string
		require(t, f.db.Reader().QueryRow("SELECT revoked_at,revoked_by FROM credentials WHERE id=?", key.ID).Scan(&firstAt, &firstBy) == nil && firstAt == f.now.Format(store.TimeFormat) && firstBy == "user:alice", "first revocation identity")
		f.call(t, "DELETE", "/credentials/"+key.ID, f.cookie, "", 204)
		f.now = f.now.Add(time.Hour)
		bob := f.login(t, "bob", f.pw)
		f.call(t, "DELETE", "/credentials/"+key.ID, bob, "", 204)
		var repeatedAt, repeatedBy string
		require(t, f.db.Reader().QueryRow("SELECT revoked_at,revoked_by FROM credentials WHERE id=?", key.ID).Scan(&repeatedAt, &repeatedBy) == nil && repeatedAt == firstAt && repeatedBy == firstBy, "repeated revocation changed first metadata")
		w := f.call(t, "DELETE", "/credentials/missing", f.cookie, "", 404)
		require(t, decoded[Error](t, w).Code == "credential_not_found", "missing credential code")
	})
	t.Run("C4A-both", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		key := f.issue(t, "x")
		f.call(t, "GET", "/auth/me", f.cookie, "", 200)
		f.call(t, "GET", "/auth/me", key.Key, "", 200)
		for _, value := range []string{"Bearer " + key.Key, ""} {
			r := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
			r.Header.Set("Cookie", auth.CookieName+"="+f.cookie)
			r.Header.Set("Authorization", value)
			w := httptest.NewRecorder()
			f.e.ServeHTTP(w, r)
			corpus.add("responses", w.Body.Bytes())
			require(t, w.Code == 401, "two identities accepted")
		}
	})
	t.Run("C4A-deny", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		key := f.issue(t, "x")
		e := gin.New()
		e.GET("/test", func(*gin.Context) {})
		require(t, checkRoutes(e, map[string]string{}) != nil && checkRoutes(e, map[string]string{"GET /test": "all"}) == nil, "startup route check")
		permissions := map[string]string{}
		for route, p := range permissionOracle {
			pair := strings.SplitN(route, " ", 2)
			permissions[pair[0]+" /api/v1"+pair[1]] = p
		}
		require(t, checkRoutes(f.e, permissions) == nil, "New route registration")
		called := false
		f.e.GET("/api/v1/late", func(*gin.Context) { called = true })
		for _, id := range []string{f.cookie, key.Key} {
			w := f.call(t, "GET", "/late", id, "", 403)
			require(t, !called && decoded[Error](t, w).Code == "forbidden", "late route executed")
			f.call(t, "GET", "/unknown", id, "", 404)
			f.call(t, "PATCH", "/health", id, "", 405)
		}
	})
	t.Run("C4A-actor", func(t *testing.T) {
		f := c4aFresh(t, corpus)
		bob := f.login(t, "bob", f.pw)
		key := f.issue(t, "x")
		r := decoded[CreateResponse](t, f.call(t, "POST", "/rules", f.cookie, `{"dst_cidr":"198.51.100.0/24"}`, 201))
		require(t, r.CreatedBy == "user:alice" && r.UpdatedBy == "user:alice", "user attribution")
		var claimant, ref string
		require(t, f.db.Reader().QueryRow("SELECT claimant,claim_ref FROM claims WHERE rule_id=?", r.ID).Scan(&claimant, &ref) == nil && claimant == "ui" && ref == "", "UI claim")
		updated := decoded[RuleDTO](t, f.call(t, "PATCH", "/rules/"+r.ID, bob, `{"comment":"changed"}`, 200))
		require(t, updated.UpdatedBy == "user:bob", "update attribution")
		m := decoded[CreateResponse](t, f.call(t, "POST", "/rules", key.Key, strings.TrimSuffix(body(93), "}")+`,"claim_ref":"machine-ref"}`, 201))
		require(t, m.CreatedBy == "cred:x" && m.UpdatedBy == "cred:x", "machine attribution")
		require(t, f.db.Reader().QueryRow("SELECT claimant,claim_ref FROM claims WHERE rule_id=?", m.ID).Scan(&claimant, &ref) == nil && claimant == "cred:x" && ref == "machine-ref", "machine claim")
		f.call(t, "DELETE", "/rules/"+m.ID, f.cookie, "", 204)
		require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM rules WHERE id=?", m.ID) == 0, "UI force delete")
	})
	t.Run("C4A-matrix", func(t *testing.T) { c4aMatrix(t, corpus) })
	t.Run("C4A-login-race", func(t *testing.T) { c4aLoginRace(t, corpus) })
	t.Run("C4A-config", func(t *testing.T) {
		dir := t.TempDir()
		key := filepath.Join(dir, "node-key")
		path := filepath.Join(dir, "controller.example.yaml")
		secret := c4aSecret(t)
		require(t, os.WriteFile(key, []byte(secret), 0600) == nil, "test key")
		base := "listen: 192.0.2.1:18081\ndatabase: " + filepath.Join(dir, "controller.db") + "\nsecret_key_file: " + key + "\n"
		for _, old := range []bool{false, true} {
			text := base
			if old {
				text += "insecure_dev_actor_header: true\n"
			}
			require(t, os.WriteFile(path, []byte(text), 0600) == nil, "config write")
			_, e := config.Load(path)
			require(t, (e != nil) == old, "configuration contract")
		}
	})
	t.Run("C4A-secrets", func(t *testing.T) {
		for _, kind := range []string{"logs", "database", "wal", "responses"} {
			require(t, len(corpus.samples[kind]) > 0, "missing secret corpus", kind)
			for _, sample := range corpus.samples[kind] {
				for _, secret := range corpus.secrets {
					if secret != "" && bytes.Contains(sample, []byte(secret)) {
						t.Errorf("secret found in %s", kind)
					}
				}
			}
			t.Logf("secret_scan kind=%s collected=%d matches=0", kind, len(corpus.samples[kind]))
		}
	})
}
func c4aSnapshot(t *testing.T, db *store.DB) [][]string {
	t.Helper()
	out := [][]string{}
	for _, table := range []string{"users", "sessions", "credentials", "settings", "rules", "claims", "whitelist", "logical_id_hw", "audit", "user_prefs", "templates", "nodes", "traffic_1m", "traffic_1h"} {
		rows, e := db.Reader().Query("SELECT * FROM " + table + " ORDER BY rowid")
		require(t, e == nil, "snapshot query")
		columns, e := rows.Columns()
		require(t, e == nil, "snapshot columns")
		for rows.Next() {
			values := make([]sql.NullString, len(columns))
			ptrs := make([]any, len(columns))
			for i := range values {
				ptrs[i] = &values[i]
			}
			require(t, rows.Scan(ptrs...) == nil, "snapshot scan")
			line := []string{table}
			for _, v := range values {
				line = append(line, fmt.Sprint(v.Valid)+":"+v.String)
			}
			out = append(out, line)
		}
		require(t, rows.Err() == nil, "snapshot rows")
		rows.Close()
	}
	return out
}
func c4aMatrix(t *testing.T, corpus *c4aCorpus) {
	seen := map[string]bool{}
	adminDenied := map[string]int{}
	successChecked := 0
	for route, permission := range permissionOracle {
		for _, identity := range []string{"none", "session", "operator", "expired", "key", "revoked", "retired"} {
			func() {
				// Each cell has independent credentials and state, so permitted mutations cannot invalidate later cells.
				f := c4aFresh(t, corpus)
				v := f.issue(t, "matrix")
				id := f.cookie
				tpl, te := f.acc.PutTemplate(rules.Actor{Kind: rules.UI, Name: "alice"}, "", "matrix", "TEST_ONLY_TEMPLATE")
				require(t, te == nil, "matrix template")
				if identity == "operator" {
					_, err := f.db.Exec("UPDATE users SET role='operator' WHERE username='alice'")
					require(t, err == nil, "operator fixture")
				}
				if identity == "none" {
					id = ""
				}
				if identity == "key" || identity == "revoked" || identity == "retired" {
					id = v.Key
				}
				if identity == "expired" {
					_, e := f.db.Exec("UPDATE sessions SET created_at=?", f.now.Add(-25*time.Hour).Format(store.TimeFormat))
					require(t, e == nil, "expire cell session")
				}
				if identity == "revoked" {
					require(t, f.acc.RevokeCredential(rules.Actor{Kind: rules.UI, Name: "test"}, v.ID) == nil, "revoke cell key")
				}
				if identity == "retired" {
					_, e := f.db.Exec("UPDATE credentials SET retire_at=? WHERE id=?", f.now.Format(store.TimeFormat), v.ID)
					require(t, e == nil, "retire cell key")
				}
				r, e := f.s.Create(rules.Actor{Kind: rules.UI, Name: "alice"}, "", rules.RulePatch{DstCIDR: func() *string { s := "198.51.100.0/24"; return &s }()})
				require(t, e == nil, "matrix rule")
				wl, e := f.s.CreateWhitelist(rules.Actor{Kind: rules.UI, Name: "alice"}, rules.WhitelistInput{DstIP: "192.0.2.3"})
				require(t, e == nil, "matrix whitelist")
				parts := strings.SplitN(route, " ", 2)
				method, path := parts[0], parts[1]
				object := r.Rule.ID
				if strings.HasPrefix(path, "/templates/") {
					object = tpl.ID
				}
				if strings.HasPrefix(path, "/whitelist/") {
					object = wl.Whitelist.ID
				}
				if strings.HasPrefix(path, "/credentials/") {
					object = v.ID
				}
				path = strings.ReplaceAll(path, ":id", object)
				name := "bob"
				if strings.HasPrefix(path, "/nodes/") {
					name = "n1"
				}
				path = strings.ReplaceAll(path, ":name", name)
				input := body(94)
				status := 200
				switch route {
				case "PUT /auth/me/password":
					input = c4aJSON(OwnPasswordInput{f.pw, PasswordInput{f.pw}})
					status = 204
				case "PUT /users/:name/role":
					input = `{"role":"operator"}`
					status = 204
				case "PUT /auth/me/prefs":
					input = `{"language":"ja-JP"}`
					status = 204
				case "POST /templates", "PUT /templates/:id":
					input = `{"name":"matrix-next","body":"TEST_ONLY_TEMPLATE_NEXT"}`
					if method == "POST" {
						status = 201
					}

				case "GET /traffic/history":
					path += "?range=15m"
				case "GET /audit":
					input = ""
				case "GET /audit/export":
					path += "?from=2026-10-12T00:00:00Z&to=2026-10-13T00:00:00Z&format=json"
					input = ""
				case "POST /rules", "POST /whitelist":
					status = 201
				case "POST /rules/batch":
					input = `{"items":[` + body(94) + `]}`
				case "PATCH /rules/:id":
					input = `{"comment":"matrix"}`
				case "PUT /rules/:id/enabled":
					input = `{"enabled":false}`
				case "GET /rules/:id/delivery":
					path += "?gen=1&epoch=" + f.s.Epoch()
				case "POST /auth/login":
					input = c4aJSON(LoginInput{"alice", f.pw})
				case "POST /auth/logout":
					status = 204
				case "POST /users":
					input = c4aJSON(UserInput{LoginInput{"charlie", f.pw}, "admin"})
					status = 201
				case "PUT /users/:name/password":
					input = c4aJSON(PasswordInput{f.pw})
				case "POST /credentials":
					input = `{"name":"matrix-new"}`
					status = 201
				case "PUT /settings":
					input = `{"session_hours":12}`
				}
				if method == "DELETE" || route == "PUT /users/:name/password" {
					status = 204
				}
				if strings.HasSuffix(path, "/sync") || strings.HasSuffix(path, "/reconcile") {
					status = 202
				}
				if c5bNodeRoute(route) {
					input, status = c5bMatrixNode(t, f.fixture, f.acc, route)
				}
				valid := identity == "session" || identity == "key" || identity == "operator"
				blocked := permission != "public" && (!valid || (permission == "ui" && identity == "key" || permission == "admin" && identity != "session"))
				if permission != "public" && !valid {
					status = 401
				} else if permission == "ui" && identity == "key" || permission == "admin" && identity != "session" {
					status = 403
				}
				before := c4aSnapshot(t, f.db)
				changes, syncs, reconciles := len(f.n.changes), f.n.syncs, f.n.reconciles
				send := f.call
				if path == "/events" {
					input, send = "", f.c5dCall
				}
				if identity == "session" {
					allowed := false
					for _, code := range strings.Split(successOracle[route], " / ") {
						allowed = allowed || fmt.Sprint(status) == code
					}
					require(t, allowed, "success oracle mismatch", route, status)
					successChecked++
				}
				response := send(t, method, path, id, input, status)
				if valid && permission == "admin" && identity != "session" {
					require(t, decoded[Error](t, response).Code == "admin_required", "admin route code", route, identity)
					adminDenied[identity]++
				}
				if blocked {
					require(t, reflect.DeepEqual(before, c4aSnapshot(t, f.db)) && len(f.n.changes) == changes && f.n.syncs == syncs && f.n.reconciles == reconciles, "denied matrix cell changed service or account rows", route, identity)
				}
				seen[route+"|"+identity] = true
			}()
		}
	}
	want := map[string]bool{}
	for route := range permissionOracle {
		for _, id := range []string{"none", "session", "operator", "expired", "key", "revoked", "retired"} {
			want[route+"|"+id] = true
		}
	}
	require(t, len(permissionOracle) == 47 && len(seen) == len(permissionOracle)*7 && reflect.DeepEqual(seen, want), "matrix execution set")
	require(t, adminDenied["operator"] == 17 && adminDenied["key"] == 17, "admin deny execution count")
	t.Logf("admin_denied operator=%d key=%d expected=17_each", adminDenied["operator"], adminDenied["key"])
	t.Logf("matrix_routes=%d identities=7 executed=%d expected=%d", len(permissionOracle), len(seen), len(permissionOracle)*7)
	require(t, successChecked == len(permissionOracle), "success oracle execution count", successChecked)
	t.Logf("success_oracle_checked=%d", successChecked)
}
func c4aLoginRace(t *testing.T, corpus *c4aCorpus) {
	for _, mode := range []string{"control", "password", "delete", "recreate"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			f := c4aFresh(t, corpus)
			admin := f.login(t, "bob", f.pw)
			_, e := f.db.Exec("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username='alice')")
			require(t, e == nil, "clear prior sessions")
			var id int64
			require(t, f.db.Reader().QueryRow("SELECT id FROM users WHERE username='alice'").Scan(&id) == nil, "race user id")
			// The second clock read in Login settles comparison after bcrypt, before the write transaction.
			// Blocking there keeps the verified row stale while real HTTP account mutations commit.
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan *httptest.ResponseRecorder, 1)
			var calls int32
			fixed := f.now
			f.acc.Now = func() time.Time {
				if atomic.AddInt32(&calls, 1) == 2 {
					close(entered)
					<-release
				}
				return fixed
			}
			go func() {
				r := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(c4aJSON(LoginInput{"alice", f.pw})))
				w := httptest.NewRecorder()
				f.e.ServeHTTP(w, r)
				done <- w
			}()
			<-entered
			newpw := c4aSecret(t)
			corpus.secrets = append(corpus.secrets, newpw)
			switch mode {
			case "password":
				f.call(t, "PUT", "/users/alice/password", admin, c4aJSON(PasswordInput{newpw}), 204)
			case "delete", "recreate":
				f.call(t, "DELETE", "/users/alice", admin, "", 204)
				if mode == "recreate" {
					f.call(t, "POST", "/users", admin, c4aJSON(UserInput{LoginInput{"alice", newpw}, "admin"}), 201)
					var reused int64
					require(t, f.db.Reader().QueryRow("SELECT id FROM users WHERE username='alice'").Scan(&reused) == nil && reused == id, "rowid reuse witness")
				}
			}
			close(release)
			w := <-done
			corpus.add("responses", w.Body.Bytes())
			if mode == "control" {
				require(t, w.Code == 200, "race control succeeds")
				require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM sessions WHERE user_id=?", id) == 1, "control session inserted")
				for _, c := range w.Result().Cookies() {
					corpus.secrets = append(corpus.secrets, c.Value)
				}
			} else {
				require(t, w.Code == 401 && decoded[Error](t, w).Code == "invalid_credentials", "stale password accepted", mode)
				require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM sessions WHERE user_id=?", id) == 0, "stale session inserted")
				wrong := f.call(t, "POST", "/auth/login", "", c4aJSON(LoginInput{"absent", newpw}), 401)
				require(t, bytes.Equal(w.Body.Bytes(), wrong.Body.Bytes()), "race failure response differs")
			}
		})
	}
}
