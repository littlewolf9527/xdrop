// XDrop Agent - Main entry point
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/dropbox/goebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"github.com/littlewolf9527/xdrop/node/agent/config"
	"github.com/littlewolf9527/xdrop/node/agent/ifmgr"
	"github.com/littlewolf9527/xdrop/node/agent/sync"
)

// Config map indices (must match xdrop.h)
const (
	ConfigFastForwardEnabled = 4
	ConfigFilterIfindex      = 5
)

func main() {
	// Command-line flags (optionally override config file values)
	configPath := flag.String("config", "config.yaml", "Path to config file")
	ifaceOverride := flag.String("iface", "", "Network interface (overrides config, traditional mode only)")
	flag.Parse()

	// Load configuration
	cfg := config.MustLoad(*configPath)

	// Detect operating mode
	fastForwardMode := cfg.FastForward.Enabled

	// Apply command-line override (traditional mode only)
	if *ifaceOverride != "" && !fastForwardMode {
		cfg.Server.Interface = *ifaceOverride
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Config validation failed: %v", err)
	}

	// Load BPF program
	log.Printf("Loading BPF program from %s...", cfg.BPF.Path)
	bpf := goebpf.NewDefaultEbpfSystem()
	if err := bpf.LoadElf(cfg.BPF.Path); err != nil {
		log.Fatalf("Failed to load BPF ELF: %v", err)
	}

	// Get required maps
	blacklist := bpf.GetMapByName("blacklist")
	if blacklist == nil {
		log.Fatal("BPF map 'blacklist' not found")
	}

	whitelist := bpf.GetMapByName("whitelist")
	if whitelist == nil {
		log.Fatal("BPF map 'whitelist' not found")
	}

	stats := bpf.GetMapByName("stats")
	if stats == nil {
		log.Fatal("BPF map 'stats' not found")
	}

	rlStates := bpf.GetMapByName("rl_states")
	if rlStates == nil {
		log.Fatal("BPF map 'rl_states' not found")
	}

	configA := bpf.GetMapByName("config_a")
	if configA == nil {
		log.Fatal("BPF map 'config_a' not found")
	}

	configB := bpf.GetMapByName("config_b")
	if configB == nil {
		log.Fatal("BPF map 'config_b' not found")
	}

	activeConfig := bpf.GetMapByName("active_config")
	if activeConfig == nil {
		log.Fatal("BPF map 'active_config' not found")
	}

	// Get CIDR maps
	cidrBlacklist := bpf.GetMapByName("cidr_blacklist")
	if cidrBlacklist == nil {
		log.Fatal("BPF map 'cidr_blacklist' not found")
	}

	cidrRlStates := bpf.GetMapByName("cidr_rl_states")
	if cidrRlStates == nil {
		log.Fatal("BPF map 'cidr_rl_states' not found")
	}

	srcV4Trie := bpf.GetMapByName("sv4_cidr_trie")
	if srcV4Trie == nil {
		log.Fatal("BPF map 'sv4_cidr_trie' not found")
	}

	dstV4Trie := bpf.GetMapByName("dv4_cidr_trie")
	if dstV4Trie == nil {
		log.Fatal("BPF map 'dv4_cidr_trie' not found")
	}

	srcV6Trie := bpf.GetMapByName("sv6_cidr_trie")
	if srcV6Trie == nil {
		log.Fatal("BPF map 'sv6_cidr_trie' not found")
	}

	dstV6Trie := bpf.GetMapByName("dv6_cidr_trie")
	if dstV6Trie == nil {
		log.Fatal("BPF map 'dv6_cidr_trie' not found")
	}

	cidrMgr := cidr.NewManager(srcV4Trie, dstV4Trie, srcV6Trie, dstV6Trie)
	log.Println("CIDR manager initialized")

	// Get shadow maps for dual rule map (Phase 4.2)
	blacklistB := bpf.GetMapByName("blacklist_b")
	if blacklistB == nil {
		log.Fatal("BPF map 'blacklist_b' not found")
	}

	cidrBlacklistB := bpf.GetMapByName("cidr_blist_b")
	if cidrBlacklistB == nil {
		log.Fatal("BPF map 'cidr_blist_b' not found")
	}

	// Get devmap for fast forward mode
	var devmap goebpf.Map
	if fastForwardMode {
		devmap = bpf.GetMapByName("devmap")
		if devmap == nil {
			log.Fatal("BPF map 'devmap' not found (required for fast forward mode)")
		}
	}

	// Get XDP program
	xdp := bpf.GetProgramByName("xdrop_firewall")
	if xdp == nil {
		log.Fatal("XDP program 'xdrop_firewall' not found")
	}

	// Load XDP program
	if err := xdp.Load(); err != nil {
		log.Fatalf("Failed to load XDP program: %v", err)
	}

	// Interface manager for fast forward mode
	var ifMgr *ifmgr.InterfaceManager
	// Track all XDP-attached interfaces for reliable cleanup
	// (goebpf's Detach() is unreliable for dual-NIC: GetProgramByName returns
	// the same object, so the second Attach overwrites p.ifname and Detach
	// only removes XDP from the last-attached interface)
	var xdpAttachedIfaces []string

	if fastForwardMode {
		// === FAST FORWARD MODE ===
		log.Println("Fast Forward mode enabled")
		ifMgr = ifmgr.NewInterfaceManager()
		pair := cfg.FastForward.Pairs[0]

		// Get interface indices
		inboundIdx, err := ifmgr.GetInterfaceIndex(pair.Inbound)
		if err != nil {
			log.Fatalf("Failed to find inbound interface: %v", err)
		}
		outboundIdx, err := ifmgr.GetInterfaceIndex(pair.Outbound)
		if err != nil {
			log.Fatalf("Failed to find outbound interface: %v", err)
		}
		log.Printf("Interface indices: %s=%d, %s=%d", pair.Inbound, inboundIdx, pair.Outbound, outboundIdx)

		// Configure interfaces (UP, promiscuous, disable offloads)
		if err := ifMgr.ConfigureInterface(pair.Inbound); err != nil {
			log.Fatalf("Failed to configure inbound interface: %v", err)
		}
		if err := ifMgr.ConfigureInterface(pair.Outbound); err != nil {
			ifMgr.RestoreAll()
			log.Fatalf("Failed to configure outbound interface: %v", err)
		}

		// Setup devmap: bidirectional mapping
		if err := setupDevmap(devmap, inboundIdx, outboundIdx); err != nil {
			ifMgr.RestoreAll()
			log.Fatalf("Failed to setup devmap: %v", err)
		}
		log.Printf("Devmap configured: %d <-> %d", inboundIdx, outboundIdx)

		// Configure fast forward settings in BPF config map
		if err := configureFastForward(configA, configB, pair, inboundIdx, outboundIdx); err != nil {
			ifMgr.RestoreAll()
			log.Fatalf("Failed to configure fast forward: %v", err)
		}

		// Pre-detach: clear any stale XDP programs left by a previous crash/kill -9
		detachXDP(pair.Inbound)
		detachXDP(pair.Outbound)

		// Attach XDP to inbound interface
		if err := xdp.Attach(pair.Inbound); err != nil {
			ifMgr.RestoreAll()
			log.Fatalf("Failed to attach XDP to %s: %v", pair.Inbound, err)
		}
		xdpAttachedIfaces = append(xdpAttachedIfaces, pair.Inbound)
		log.Printf("XDP program attached to %s (inbound)", pair.Inbound)

		// Attach XDP to outbound interface
		// Note: goebpf.GetProgramByName returns the same object pointer, so
		// xdp.Attach(outbound) overwrites the internal p.ifname state.
		// We do NOT rely on goebpf Detach(); instead we track interfaces in
		// xdpAttachedIfaces and use detachXDP() for reliable cleanup.
		if err := xdp.Attach(pair.Outbound); err != nil {
			detachXDP(pair.Inbound) // clean up inbound manually
			ifMgr.RestoreAll()
			log.Fatalf("Failed to attach XDP to %s: %v", pair.Outbound, err)
		}
		xdpAttachedIfaces = append(xdpAttachedIfaces, pair.Outbound)
		log.Printf("XDP program attached to %s (outbound)", pair.Outbound)

	} else {
		// === TRADITIONAL MODE ===
		log.Println("Traditional mode (single interface)")
		// Pre-detach: clear any stale XDP program left by a previous crash/kill -9
		detachXDP(cfg.Server.Interface)
		if err := xdp.Attach(cfg.Server.Interface); err != nil {
			log.Fatalf("Failed to attach XDP to %s: %v", cfg.Server.Interface, err)
		}
		xdpAttachedIfaces = append(xdpAttachedIfaces, cfg.Server.Interface)
		log.Printf("XDP program attached to %s", cfg.Server.Interface)
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")

		// Detach XDP from all attached interfaces
		for _, iface := range xdpAttachedIfaces {
			if err := detachXDP(iface); err != nil {
				log.Printf("Warning: failed to detach XDP from %s: %v", iface, err)
			} else {
				log.Printf("XDP detached from %s", iface)
			}
		}

		// Restore interfaces in fast forward mode
		if fastForwardMode && ifMgr != nil {
			ifMgr.RestoreAll()
		}

		os.Exit(0)
	}()

	// Initialize API handlers
	handlers := api.NewHandlers(blacklist, whitelist, stats, configA, configB, activeConfig, rlStates,
		cidrBlacklist, cidrRlStates, cidrMgr,
		blacklistB, cidrBlacklistB)

	// Set XDP interface info for stats reporting
	if fastForwardMode {
		pair := cfg.FastForward.Pairs[0]
		handlers.SetXDPInfo(&api.XDPInfo{
			Mode: "fast_forward",
			Interfaces: []api.XDPInterface{
				{Name: pair.Inbound, Role: "inbound"},
				{Name: pair.Outbound, Role: "outbound"},
			},
		})
	} else {
		handlers.SetXDPInfo(&api.XDPInfo{
			Mode: "traditional",
			Interfaces: []api.XDPInterface{
				{Name: cfg.Server.Interface, Role: "filter"},
			},
		})
	}

	// Sync from Controller if configured
	if cfg.Auth.ControllerURL != "" {
		log.Printf("Controller configured: %s", cfg.Auth.ControllerURL)
		syncConfig := sync.SyncConfig{
			ControllerURL: cfg.Auth.ControllerURL,
			APIKey:        cfg.Auth.ControllerSyncKey,
			RetryCount:    3,
			RetryInterval: 5 * time.Second,
			Timeout:       10 * time.Second,
		}
		controllerSync := sync.NewControllerSync(syncConfig)
		if err := controllerSync.SyncOnStartup(handlers); err != nil {
			log.Printf("[Sync] Warning: failed to sync from Controller: %v", err)
			log.Printf("[Sync] Continuing without initial rules...")
		}
	}

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Public endpoints (no authentication required)
	router.GET("/", handlers.Welcome)
	router.GET("/api/v1/health", handlers.Health)

	// Authenticated API routes
	authMiddleware := api.AuthMiddleware(cfg.Auth.NodeAPIKey)
	protected := router.Group("/api/v1")
	protected.Use(authMiddleware)
	{
		// Rules API
		rules := protected.Group("/rules")
		{
			rules.GET("", handlers.ListRules)
			rules.POST("", handlers.AddRule)
			rules.DELETE("/:id", handlers.DeleteRule)
			rules.POST("/batch", handlers.AddRulesBatch)
			rules.DELETE("/batch", handlers.DeleteRulesBatch)
		}

		// Whitelist API
		wl := protected.Group("/whitelist")
		{
			wl.GET("", handlers.ListWhitelist)
			wl.POST("", handlers.AddWhitelist)
			wl.DELETE("/:id", handlers.DeleteWhitelist)
			wl.POST("/batch", handlers.AddWhitelistBatch)
			wl.DELETE("/batch", handlers.DeleteWhitelistBatch)
		}

		// Sync API (Phase 4.2 atomic sync)
		syncGroup := protected.Group("/sync")
		{
			syncGroup.POST("/atomic", handlers.AtomicSync)
		}

		// Stats API
		protected.GET("/stats", handlers.GetStats)
	}

	// Start server
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	log.Printf("XDrop Agent listening on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// setupDevmap configures bidirectional interface mapping
func setupDevmap(devmap goebpf.Map, inboundIdx, outboundIdx int) error {
	// inbound -> outbound (use Update for BPF_ANY, allows overwrite)
	if err := devmap.Update(uint32ToBytes(uint32(inboundIdx)), uint32ToBytes(uint32(outboundIdx))); err != nil {
		return fmt.Errorf("failed to set devmap[%d]=%d: %w", inboundIdx, outboundIdx, err)
	}

	// outbound -> inbound
	if err := devmap.Update(uint32ToBytes(uint32(outboundIdx)), uint32ToBytes(uint32(inboundIdx))); err != nil {
		return fmt.Errorf("failed to set devmap[%d]=%d: %w", outboundIdx, inboundIdx, err)
	}

	return nil
}

// configureFastForward sets up fast forward mode in both config maps (double-buffer)
func configureFastForward(configA, configB goebpf.Map, pair config.InterfacePair, inboundIdx, outboundIdx int) error {
	key := make([]byte, 4)
	value := make([]byte, 8)

	// Determine filter interface index
	var filterIdx uint32 = 0 // 0 = filter on both
	filterOn := pair.GetFilterOn()
	switch filterOn {
	case "inbound":
		filterIdx = uint32(inboundIdx)
	case "outbound":
		filterIdx = uint32(outboundIdx)
	case "both":
		filterIdx = 0
	}

	// Write to both config maps so whichever is active sees the values
	for _, m := range []goebpf.Map{configA, configB} {
		binary.LittleEndian.PutUint32(key, ConfigFastForwardEnabled)
		binary.LittleEndian.PutUint64(value, 1)
		if err := m.Update(key, value); err != nil {
			return fmt.Errorf("failed to enable fast forward: %w", err)
		}

		binary.LittleEndian.PutUint32(key, ConfigFilterIfindex)
		binary.LittleEndian.PutUint64(value, uint64(filterIdx))
		if err := m.Update(key, value); err != nil {
			return fmt.Errorf("failed to set filter ifindex: %w", err)
		}
	}

	log.Printf("Fast forward configured: filter_on=%s, filter_ifindex=%d", filterOn, filterIdx)
	return nil
}

// detachXDP removes XDP program from interface using ip command directly.
// This bypasses goebpf's Detach() which is unreliable for dual-NIC mode
// (GetProgramByName returns the same object, so p.ifname gets overwritten).
func detachXDP(ifname string) error {
	return exec.Command("ip", "link", "set", ifname, "xdp", "off").Run()
}

// uint32ToBytes converts uint32 to little-endian byte slice
func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
