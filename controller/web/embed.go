package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed dist/*
var staticFS embed.FS

// SetupStatic registers static file serving routes
func SetupStatic(engine *gin.Engine) {
	// Get dist sub-directory
	distFS, _ := fs.Sub(staticFS, "dist")
	httpFS := http.FS(distFS)

	// Root path - serve index.html (Web UI entry point)
	engine.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		data, _ := fs.ReadFile(distFS, "index.html")
		c.Data(200, "text/html; charset=utf-8", data)
	})

	// Static assets - use Static instead of StaticFS to avoid redirects
	engine.GET("/assets/*filepath", func(c *gin.Context) {
		filepath := c.Param("filepath")
		c.FileFromFS("assets"+filepath, httpFS)
	})

	// favicon
	engine.GET("/favicon.ico", func(c *gin.Context) {
		c.FileFromFS("favicon.svg", httpFS)
	})
	engine.GET("/favicon.svg", func(c *gin.Context) {
		c.FileFromFS("favicon.svg", httpFS)
	})

	// SPA fallback - return index.html for all non-API paths
	engine.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		// Return 404 for API requests
		if strings.HasPrefix(path, "/api") {
			c.JSON(404, gin.H{"error": "Not Found"})
			return
		}
		// All other requests return index.html (SPA routing)
		c.Header("Content-Type", "text/html; charset=utf-8")
		data, _ := fs.ReadFile(distFS, "index.html")
		c.Data(200, "text/html; charset=utf-8", data)
	})
}
