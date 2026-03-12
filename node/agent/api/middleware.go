package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware creates an API Key authentication middleware for Node
func AuthMiddleware(apiKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth if no API key configured
		if apiKey == "" {
			c.Next()
			return
		}

		// Get API key from header
		providedKey := c.GetHeader("X-API-Key")

		// Check if API key matches
		if providedKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Missing API key",
				"message": "Please provide X-API-Key header",
			})
			return
		}

		if providedKey != apiKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid API key",
				"message": "The provided API key is incorrect",
			})
			return
		}

		c.Next()
	}
}
