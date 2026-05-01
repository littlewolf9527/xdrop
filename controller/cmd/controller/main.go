package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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

	// Stats cache (v2.6.3) — periodically aggregates per-rule stats from
	// nodes in the background. Wired here (not in the config package) so
	// the seconds→time.Duration conversion stays out of config and the
	// service package doesn't import config back.
	statsCache := service.NewStatsCache(
		nodeService,
		service.RealClock{},
		buildStatsCacheConfig(cfg.StatsCache),
	)

	// Create API handlers
	rulesHandler := api.NewRulesHandler(ruleService, nodeService, statsCache)
	wlHandler := api.NewWhitelistHandler(wlService)
	nodesHandler := api.NewNodesHandler(nodeService)
	statsHandler := api.NewStatsHandler(ruleService, wlService, nodeService)
	cacheHealthHandler := api.NewCacheHealthHandler(statsCache)

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
	router := api.NewRouter(rulesHandler, wlHandler, nodesHandler, statsHandler, cacheHealthHandler, authHandler, authMiddleware)

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

	// Stats cache (v2.6.3) lifecycle. The cache uses its own context so
	// shutdown can interrupt an in-flight refresh; without it Stop() would
	// have to wait for the longest per-node timeout to elapse.
	statsCacheCtx, statsCacheCancel := context.WithCancel(context.Background())
	statsCache.Start(statsCacheCtx)
	defer func() {
		statsCacheCancel()
		statsCache.Stop()
	}()

	// Start sync checker (if enabled)
	if cfg.SyncCheck.Enabled {
		syncChecker := scheduler.NewSyncChecker(
			nodeService, ruleRepo, wlRepo, nodeClient, syncService, cfg.SyncCheck.Interval,
		)
		syncChecker.Start()
		defer syncChecker.Stop()
	}

	// Start HTTP server using an explicit http.Server so ListenAndServe failures
	// can fall through to the normal shutdown path (defer'd cleanups run), rather
	// than bypassing defers via os.Exit(1).
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	slog.Info("Starting HTTP server", "addr", addr)

	srv := &http.Server{
		Addr:    addr,
		Handler: engine,
	}

	srvErrCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErrCh <- err
			return
		}
		srvErrCh <- nil
	}()

	// Wait for shutdown signal OR server failure; either path falls through so
	// every `defer` above (db.Close, scheduler.Stop, etc.) actually runs.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		slog.Info("Shutdown signal received")
	case err := <-srvErrCh:
		if err != nil {
			slog.Error("HTTP server failed — triggering cleanup", "error", err)
		}
	}

	slog.Info("Shutting down...")

	// Give in-flight requests up to 10s to finish, then force-close.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("HTTP server shutdown returned error", "error", err)
	}
}

// buildStatsCacheConfig converts the user-facing int-seconds raw config into
// the runtime time.Duration form consumed by the service package.
//
// Why this lives in main.go (not config or service):
//   - service already imports config; if config returned service types we'd
//     have an import cycle.
//   - Keeping the conversion in the wiring layer is the smallest move that
//     breaks the cycle without restructuring either package.
//
// All inputs are assumed to have been Validate()d already by config.Load().
func buildStatsCacheConfig(raw config.StatsCacheRawConfig) service.StatsCacheConfig {
	return service.StatsCacheConfig{
		RefreshInterval:  time.Duration(raw.RefreshIntervalSeconds) * time.Second,
		StaleThreshold:   time.Duration(raw.StaleThresholdSeconds) * time.Second,
		PerNodeTimeout:   time.Duration(raw.PerNodeTimeoutSeconds) * time.Second,
		MaxConcurrency:   raw.MaxConcurrency,
		BackoffOnAllFail: time.Duration(raw.BackoffOnAllFailSeconds) * time.Second,
		TopNCacheSize:    raw.TopNCacheSize,
		Disabled:         raw.Disabled,
	}
}
