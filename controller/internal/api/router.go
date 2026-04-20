package api

import (
	"github.com/gin-gonic/gin"
)

// Router holds all API handlers and middleware.
type Router struct {
	rules          *RulesHandler
	whitelist      *WhitelistHandler
	nodes          *NodesHandler
	stats          *StatsHandler
	auth           *AuthHandler
	authMiddleware gin.HandlerFunc
}

// NewRouter creates a new Router.
func NewRouter(rules *RulesHandler, whitelist *WhitelistHandler, nodes *NodesHandler, stats *StatsHandler, auth *AuthHandler, authMiddleware gin.HandlerFunc) *Router {
	return &Router{
		rules:          rules,
		whitelist:      whitelist,
		nodes:          nodes,
		stats:          stats,
		auth:           auth,
		authMiddleware: authMiddleware,
	}
}

// Setup registers all routes on the provided engine.
func (r *Router) Setup(engine *gin.Engine) {
	// Public endpoints (no authentication required)
	// Note: root path "/" is handled by embed.go's SetupStatic which serves the Web UI

	engine.GET("/api/info", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"name":    "XDrop Controller",
			"version": "2.5.0",
			"status":  "running",
		})
	})

	engine.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// Auth endpoints (public — no middleware)
	authGroup := engine.Group("/api/auth")
	{
		authGroup.POST("/login", r.auth.Login)
		authGroup.POST("/logout", r.auth.Logout)
		authGroup.GET("/check", r.auth.Check)
	}

	// API v1 (authentication required)
	v1 := engine.Group("/api/v1")
	v1.Use(r.authMiddleware)
	{
		// Rules
		rules := v1.Group("/rules")
		{
			rules.GET("", r.rules.List)
			rules.GET("/top", r.rules.TopRules)
			rules.GET("/:id", r.rules.Get)
			rules.POST("", r.rules.Create)
			rules.PUT("/:id", r.rules.Update)
			rules.DELETE("/:id", r.rules.Delete)
			rules.POST("/batch", r.rules.BatchCreate)
			rules.DELETE("/batch", r.rules.BatchDelete)
		}

		// Whitelist
		whitelist := v1.Group("/whitelist")
		{
			whitelist.GET("", r.whitelist.List)
			whitelist.POST("", r.whitelist.Create)
			whitelist.DELETE("/:id", r.whitelist.Delete)
		}

		// Nodes
		nodes := v1.Group("/nodes")
		{
			nodes.GET("", r.nodes.List)
			nodes.GET("/:id", r.nodes.Get)
			nodes.POST("", r.nodes.Register)
			nodes.PUT("/:id", r.nodes.Update)
			nodes.DELETE("/:id", r.nodes.Delete)
			nodes.GET("/:id/stats", r.nodes.GetStats)
			nodes.POST("/:id/sync", r.nodes.ForceSync)
		}

		// Stats
		v1.GET("/stats", r.stats.GetStats)
	}
}
