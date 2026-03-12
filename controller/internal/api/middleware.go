package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware creates a dual-channel authentication middleware.
// Two independent allow-paths — either one passing is sufficient:
//   - Path 1: valid X-API-Key header (external_api_key — for API clients, scripts, and Node→Controller sync)
//   - Path 2: valid xdrop_session cookie (for Web UI)
func AuthMiddleware(externalKey, sessionSecret string, enabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !enabled {
			c.Next()
			return
		}

		// Path 1: API Key (external only)
		providedKey := c.GetHeader("X-API-Key")
		if providedKey != "" && externalKey != "" && providedKey == externalKey {
			c.Next()
			return
		}

		// Path 2: Session cookie
		if token, err := c.Cookie(sessionCookieName); err == nil {
			if validateSessionToken(token, sessionSecret) {
				c.Next()
				return
			}
		}

		// Both paths failed
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "Valid API key or session required",
		})
	}
}
