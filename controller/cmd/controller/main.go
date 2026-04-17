package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/internal/api"
	"github.com/littlewolf9527/xdrop/controller/internal/client"
	"github.com/littlewolf9527/xdrop/controller/internal/config"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
	"github.com/littlewolf9527/xdrop/controller/internal/scheduler"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
	"github.com/littlewolf9527/xdrop/controller/web"
)

func main() {
	// Command-line flags
	configPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// Configure logging
	config.SetupLogging(cfg.Logging.Level)
	slog.Info("XDrop Controller starting...")

	// Set Gin mode
	if cfg.Logging.Level != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Connect to database
	db, err := repository.NewSQLiteDB(cfg.Database.DSN)
	if err != nil {
		slog.Error("Failed to connect database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Create repositories (note: nodes no longer use the database)
	ruleRepo := repository.NewSQLiteRuleRepo(db)
	wlRepo := repository.NewSQLiteWhitelistRepo(db)
	syncLogRepo := repository.NewSQLiteSyncLogRepo(db)

	// Create node client
	nodeClient := client.NewNodeClient(cfg.Sync.Timeout)

	// Create NodeService (in-memory mode)
	nodeService := service.NewNodeService(ruleRepo, wlRepo, nil, nodeClient)

	// Initialize nodes from config
	nodeService.InitFromConfig(cfg.Nodes)

	// Create SyncService
	syncService := service.NewSyncService(
		nodeService, syncLogRepo, ruleRepo, wlRepo, nodeClient,
		cfg.Sync.Concurrent, cfg.Sync.RetryCount, cfg.Sync.RetryInterval,
	)

	// Wire SyncService back into NodeService (breaks the circular dependency)
	nodeService.SetSyncService(syncService)

	// Create remaining services
	ruleService := service.NewRuleService(ruleRepo, syncService)
	wlService := service.NewWhitelistService(wlRepo, syncService)

	// Create API handlers
	rulesHandler := api.NewRulesHandler(ruleService, nodeService)
	wlHandler := api.NewWhitelistHandler(wlService)
	nodesHandler := api.NewNodesHandler(nodeService)
	statsHandler := api.NewStatsHandler(ruleService, wlService, nodeService)

	// Validate auth configuration
	if cfg.Auth.Enabled {
		if cfg.Auth.SessionSecret == "" {
			slog.Error("auth.session_secret must not be empty when auth is enabled")
			os.Exit(1)
		}
		if cfg.Auth.WebUsername == "" || cfg.Auth.WebPassword == "" {
			slog.Warn("auth.web_username or web_password is empty — Web UI login is disabled")
		}
		// Reject well-known placeholder secrets (AUD-007)
		placeholders := map[string]string{
			"external_api_key": cfg.Auth.ExternalAPIKey,
			"session_secret":   cfg.Auth.SessionSecret,
			"web_password":     cfg.Auth.WebPassword,
		}
		for field, val := range placeholders {
			lower := strings.ToLower(val)
			if strings.Contains(lower, "change-me") || strings.Contains(lower, "changeme") {
				slog.Error("auth config contains placeholder value — please change it before running in production",
					"field", field)
				os.Exit(1)
			}
		}
	}

	// Create Web UI auth handler
	authHandler := api.NewAuthHandler(cfg.Auth.WebUsername, cfg.Auth.WebPassword, cfg.Auth.SessionSecret, cfg.Auth.Enabled, cfg.Auth.SecureCookie)

	// Create auth middleware (dual-channel: external API key OR session cookie)
	authMiddleware := api.AuthMiddleware(cfg.Auth.ExternalAPIKey, cfg.Auth.SessionSecret, cfg.Auth.Enabled)

	// Create router
	router := api.NewRouter(rulesHandler, wlHandler, nodesHandler, statsHandler, authHandler, authMiddleware)

	// Set up Gin engine
	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(gin.Logger())

	router.Setup(engine)

	// Set up embedded Web UI static files
	web.SetupStatic(engine)

	// Start scheduled tasks
	expireCleaner := scheduler.NewExpireCleaner(ruleRepo, syncService, cfg.Rules.CleanupInterval)
	expireCleaner.Start()
	defer expireCleaner.Stop()

	healthChecker := scheduler.NewHealthChecker(nodeService, nodeClient, cfg.HealthCheck.Interval)
	healthChecker.Start()
	defer healthChecker.Stop()

	// Start sync checker (if enabled)
	if cfg.SyncCheck.Enabled {
		syncChecker := scheduler.NewSyncChecker(
			nodeService, ruleRepo, wlRepo, nodeClient, syncService, cfg.SyncCheck.Interval,
		)
		syncChecker.Start()
		defer syncChecker.Stop()
	}

	// Start HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	slog.Info("Starting HTTP server", "addr", addr)

	go func() {
		if err := engine.Run(addr); err != nil {
			slog.Error("HTTP server failed", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down...")
}
