package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const sessionCookieName = "xdrop_session"
const sessionMaxAge = 86400 // 24h

// AuthHandler handles Web UI authentication
type AuthHandler struct {
	username      string
	password      string
	sessionSecret string
	authEnabled   bool
	secureCookie  bool // set Secure flag on session cookie (HTTPS-only)
}

// NewAuthHandler creates a new AuthHandler.
// secureCookie controls the `Secure` attribute on the session cookie.
// Production deployments behind HTTPS should set this to true; HTTP dev mode
// keeps it false.
func NewAuthHandler(username, password, sessionSecret string, authEnabled, secureCookie bool) *AuthHandler {
	return &AuthHandler{
		username:      username,
		password:      password,
		sessionSecret: sessionSecret,
		authEnabled:   authEnabled,
		secureCookie:  secureCookie,
	}
}

// Login handles POST /api/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Reject login when web credentials are not configured
	if h.username == "" || h.password == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "web login disabled"})
		return
	}

	// Constant-time comparison to prevent timing side-channels on credential checks.
	// Evaluate both comparisons unconditionally so total time is independent of
	// which field mismatches first.
	userOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(h.username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(req.Password), []byte(h.password)) == 1
	if !userOK || !passOK {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token := generateSessionToken(h.sessionSecret)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookieName, token, sessionMaxAge, "/", "", h.secureCookie, true)
	c.JSON(http.StatusOK, gin.H{"message": "ok", "username": req.Username})
}

// Logout handles POST /api/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookieName, "", -1, "/", "", h.secureCookie, true)
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

// Check handles GET /api/auth/check
func (h *AuthHandler) Check(c *gin.Context) {
	// When auth is disabled, always pass
	if !h.authEnabled {
		c.JSON(http.StatusOK, gin.H{"message": "ok", "auth_enabled": false})
		return
	}

	token, err := c.Cookie(sessionCookieName)
	if err != nil || !validateSessionToken(token, h.sessionSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok", "username": h.username})
}

// generateSessionToken creates a stateless signed token: base64(expiry).base64(hmac)
func generateSessionToken(secret string) string {
	expiry := time.Now().Add(sessionMaxAge * time.Second).Unix()
	expiryStr := strconv.FormatInt(expiry, 10)
	expiryB64 := base64.RawURLEncoding.EncodeToString([]byte(expiryStr))

	sig := computeHMAC(expiryStr, secret)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s", expiryB64, sigB64)
}

// validateSessionToken verifies token signature and expiry
func validateSessionToken(token, secret string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}

	expiryBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expiryStr := string(expiryBytes)

	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return false
	}

	if time.Now().Unix() > expiry {
		return false
	}

	expectedSig := computeHMAC(expiryStr, secret)
	actualSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	return hmac.Equal(expectedSig, actualSig)
}

// computeHMAC computes HMAC-SHA256
func computeHMAC(message, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return mac.Sum(nil)
}
