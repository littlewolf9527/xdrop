package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestRouter(secure bool) (*gin.Engine, *AuthHandler) {
	h := NewAuthHandler("admin", "correctpass", "unit-test-secret", true, secure)
	r := gin.New()
	r.POST("/login", h.Login)
	r.POST("/logout", h.Logout)
	r.GET("/check", h.Check)
	return r, h
}

func post(r *gin.Engine, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// OPEN-P2-04 regression: valid credentials return 200 + session cookie.
func TestLogin_ValidCredentials(t *testing.T) {
	r, _ := newTestRouter(false)
	w := post(r, map[string]string{"username": "admin", "password": "correctpass"})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !hasCookie(w, "xdrop_session") {
		t.Fatalf("expected xdrop_session cookie, got headers: %v", w.Header())
	}
}

// OPEN-P2-04 regression: invalid credentials return 401.
func TestLogin_InvalidCredentials(t *testing.T) {
	r, _ := newTestRouter(false)
	cases := []map[string]string{
		{"username": "wrong", "password": "correctpass"},
		{"username": "admin", "password": "wrong"},
		{"username": "", "password": ""},
	}
	for _, c := range cases {
		w := post(r, c)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("creds %v: want 401, got %d", c, w.Code)
		}
	}
}

// OPEN-P2-04 regression: Secure=true when configured.
func TestLogin_SecureCookieFlag(t *testing.T) {
	tests := []struct {
		name       string
		secure     bool
		wantSecure bool
	}{
		{"dev mode", false, false},
		{"prod mode", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestRouter(tt.secure)
			w := post(r, map[string]string{"username": "admin", "password": "correctpass"})
			setCookie := w.Header().Get("Set-Cookie")
			hasSecure := strings.Contains(setCookie, "Secure")
			if hasSecure != tt.wantSecure {
				t.Errorf("secure=%v: Set-Cookie %q hasSecure=%v want %v", tt.secure, setCookie, hasSecure, tt.wantSecure)
			}
			if !strings.Contains(setCookie, "HttpOnly") {
				t.Errorf("HttpOnly must always be set: got %q", setCookie)
			}
		})
	}
}

// SmokeLogin_TimingRatio is a non-blocking timing smoke test.
// It does NOT fail on ratio violations because wall-clock noise dominates at
// this granularity in CI/shared runners. Use it as a diagnostic: a dramatic
// ratio change after refactoring credential comparison would indicate
// regression to non-constant-time code. For the real invariant, rely on
// static inspection that crypto/subtle.ConstantTimeCompare is used (see
// auth_handler.go Login()).
//
// Skipped in -short mode.
func TestLogin_TimingSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing smoke test in -short mode")
	}
	r, _ := newTestRouter(false)

	const iterations = 200
	var dUserMismatch, dPassMismatch time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		_ = post(r, map[string]string{"username": "zzzzzzzzzzzzzz", "password": "correctpass"})
		dUserMismatch += time.Since(start)

		start = time.Now()
		_ = post(r, map[string]string{"username": "admin", "password": "zzzzzzzzzzzzzz"})
		dPassMismatch += time.Since(start)
	}

	avgUser := dUserMismatch / iterations
	avgPass := dPassMismatch / iterations
	ratio := float64(avgUser) / float64(avgPass)
	t.Logf("timing smoke: user-mismatch avg=%v, pass-mismatch avg=%v, ratio=%.2f", avgUser, avgPass, ratio)
	// Intentionally no assertion — see doc comment above.
}

// OPEN-P2-04 regression: token round-trip works.
func TestSessionToken_RoundTrip(t *testing.T) {
	secret := "test-secret"
	token := generateSessionToken(secret)
	if !validateSessionToken(token, secret) {
		t.Fatal("valid token rejected")
	}
	if validateSessionToken(token, "wrong-secret") {
		t.Fatal("token accepted with wrong secret")
	}
	if validateSessionToken("bogus.token", secret) {
		t.Fatal("malformed token accepted")
	}
}

func hasCookie(w *httptest.ResponseRecorder, name string) bool {
	for _, h := range w.Result().Cookies() {
		if h.Name == name {
			return true
		}
	}
	return false
}
