// XDrop Agent - Main entry point
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	xdropbpf "github.com/littlewolf9527/xdrop/node/agent/bpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"github.com/littlewolf9527/xdrop/node/agent/config"
	"github.com/littlewolf9527/xdrop/node/agent/ifmgr"
	"github.com/littlewolf9527/xdrop/node/agent/sync"
)

// Config map indices now live in the api package alongside the other
// dynamic config slots so initDynamicConfig can zero them on every
// startup (AUD-PH3-001). main.go uses api.ConfigFastForwardEnabled /
// api.ConfigFilterIfindex at its own write sites in configureFastForward.

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

	// ==========================================================================
	// Phase 8: Dual-ELF loading — mainColl (xdrop_main.elf) + gateColl (xdrop_gate.elf)
	// ==========================================================================
	//
	// Main ELF: creates all shared kernel maps + verifier_prune_map.
	// Gate ELF: references shared maps via MapReplacements, creates whitelist_b + tailcall_fail_stats.
	//
	// Pinning policy is threaded through the Phase 3 loader for both.
	// verifier_prune_map + tailcall_fail_stats use PinNone (security + restart-clear).

	mainPath := cfg.BPF.MainPath
	gatePath := cfg.BPF.GatePath

	// Migration hint: if old bpf.path is set but new paths are defaults, warn
	if cfg.BPF.Path != "" && cfg.BPF.Path != "../bpf/xdrop.elf" {
		log.Printf("[Phase8] WARN: bpf.path=%q is set but ignored — migrate to bpf.main_path + bpf.gate_path", cfg.BPF.Path)
	}

	// Phase 8 P1-3: clean stale verifier_prune_map pin BEFORE loading (over-allow risk)
	if err := xdropbpf.CleanStalePins(xdropbpf.DefaultPinRoot, []string{"verifier_prune_map", "tailcall_fail_stats"}); err != nil {
		log.Fatalf("[Phase8] FATAL: %v — refusing to start", err)
	}

	// 1. Load xdrop_main.elf — creates all shared kernel maps
	log.Printf("Loading main BPF from %s...", mainPath)
	mainColl, mainPinResult, err := xdropbpf.Load(xdropbpf.Options{
		SpecPath:         mainPath,
		Mode:             xdropbpf.Mode(cfg.BPF.Pinning),
		PinNoneOverrides: []string{"verifier_prune_map"}, // P1-3: NEVER pin
	})
	if err != nil {
		log.Fatalf("Failed to load main BPF collection: %v", err)
	}
	logPinResult("main", mainPinResult)

	// Helper to fetch a required map by name from a collection.
	requireMapFrom := func(coll *ebpf.Collection, collName, name string) *ebpf.Map {
		m, ok := coll.Maps[name]
		if !ok || m == nil {
			log.Fatalf("BPF map %q not found in %s ELF", name, collName)
		}
		return m
	}

	// Extract shared maps from mainColl (these will be passed to gateColl via MapReplacements)
	whitelist := requireMapFrom(mainColl, "main", "whitelist")
	blacklist := requireMapFrom(mainColl, "main", "blacklist")
	stats := requireMapFrom(mainColl, "main", "stats")
	configA := requireMapFrom(mainColl, "main", "config_a")
	configB := requireMapFrom(mainColl, "main", "config_b")
	activeConfig := requireMapFrom(mainColl, "main", "active_config")
	devmapMain := mainColl.Maps["devmap"] // may be nil if not in main ELF; FF check below
	progTailMap := requireMapFrom(mainColl, "main", "prog_tail_map")
	rlStates := requireMapFrom(mainColl, "main", "rl_states")
	cidrBlacklist := requireMapFrom(mainColl, "main", "cidr_blacklist")
	cidrRlStates := requireMapFrom(mainColl, "main", "cidr_rl_states")
	srcV4Trie := requireMapFrom(mainColl, "main", "sv4_cidr_trie")
	dstV4Trie := requireMapFrom(mainColl, "main", "dv4_cidr_trie")
	srcV6Trie := requireMapFrom(mainColl, "main", "sv6_cidr_trie")
	dstV6Trie := requireMapFrom(mainColl, "main", "dv6_cidr_trie")
	blacklistB := requireMapFrom(mainColl, "main", "blacklist_b")
	cidrBlacklistB := requireMapFrom(mainColl, "main", "cidr_blist_b")

	// 2. Load xdrop_gate.elf — gate ELF references shared maps from mainColl
	log.Printf("Loading gate BPF from %s...", gatePath)
	if _, err := os.Stat(gatePath); err != nil {
		log.Fatalf("FATAL: Phase 8 requires xdp_whitelist_gate ELF at %s — whitelist disabled: %v", gatePath, err)
	}

	// Build MapReplacements: gate's shared map declarations → mainColl's kernel fds
	gateMapReplacements := map[string]*ebpf.Map{
		"whitelist":     whitelist,
		"stats":         stats,
		"config_a":      configA,
		"config_b":      configB,
		"active_config": activeConfig,
		"prog_tail_map": progTailMap,
	}
	if devmapMain != nil {
		gateMapReplacements["devmap"] = devmapMain
	}

	gateColl, gatePinResult, err := xdropbpf.Load(xdropbpf.Options{
		SpecPath:         gatePath,
		Mode:             xdropbpf.Mode(cfg.BPF.Pinning),
		PinNoneOverrides: []string{"tailcall_fail_stats"}, // restart-clear semantics
		MapReplacements:  gateMapReplacements,
	})
	if err != nil {
		log.Fatalf("Failed to load gate BPF collection: %v", err)
	}
	logPinResult("gate", gatePinResult)

	// Gate-only maps
	whitelistB := requireMapFrom(gateColl, "gate", "whitelist_b")

	// Clear data maps — dual-collection aware (rev11 P2-1)
	if mainPinResult.PinPath != "" {
		// Main-owned business maps
		if err := xdropbpf.ClearDataMaps(mainColl, []string{
			"blacklist", "blacklist_b",
			"whitelist", // main-owned shared map
			"cidr_blacklist", "cidr_blist_b",
			"rl_states", "cidr_rl_states",
			"sv4_cidr_trie", "dv4_cidr_trie",
			"sv6_cidr_trie", "dv6_cidr_trie",
			// verifier_prune_map NOT in clear list (main-private, always empty)
		}); err != nil {
			log.Printf("WARN: main data-map clear reported error (continuing): %v", err)
		}
		// Gate-owned business maps
		if err := xdropbpf.ClearDataMaps(gateColl, []string{
			"whitelist_b", // gate-owned shadow map
			// tailcall_fail_stats: PinNone, restart auto-clears PERCPU_ARRAY
		}); err != nil {
			log.Printf("WARN: gate data-map clear reported error (continuing): %v", err)
		}
	}

	cidrMgr := cidr.NewManager(srcV4Trie, dstV4Trie, srcV6Trie, dstV6Trie)
	log.Println("CIDR manager initialized")

	// Fast forward devmap (only required when enabled)
	var devmap *ebpf.Map
	if fastForwardMode {
		if devmapMain == nil {
			log.Fatal("BPF map 'devmap' not found in main ELF but fast_forward is enabled")
		}
		devmap = devmapMain
	}

	// Phase 8: XDP entry point is xdp_whitelist_gate from gate ELF.
	xdpProg, ok := gateColl.Programs["xdp_whitelist_gate"]
	if !ok || xdpProg == nil {
		log.Fatal("XDP program 'xdp_whitelist_gate' not found in gate ELF")
	}

	// Phase 8: xdp_firewall_main from main ELF — tail-call target in slot 1.
	firewallMain, ok := mainColl.Programs["xdp_firewall_main"]
	if !ok || firewallMain == nil {
		log.Fatal("XDP program 'xdp_firewall_main' not found in main ELF")
	}
	if firewallMain.Type() != ebpf.XDP {
		log.Fatalf("xdp_firewall_main has unexpected type %v (want XDP) — D6 violation", firewallMain.Type())
	}

	// xdp_anomaly_verify from main ELF — tail-call target in slot 0.
	anomalyProg, ok := mainColl.Programs["xdp_anomaly_verify"]
	if !ok || anomalyProg == nil {
		log.Fatal("XDP program 'xdp_anomaly_verify' not found in main ELF")
	}
	if anomalyProg.Type() != ebpf.XDP {
		log.Fatalf("xdp_anomaly_verify has unexpected type %v (want XDP) — D6 violation", anomalyProg.Type())
	}
	tailStashMap := requireMapFrom(mainColl, "main", "tail_stash")
	_ = tailStashMap // used only by BPF programs; hold ref to keep pinned
	// D6 verification: PROG_ARRAY key/value must be exactly 4 bytes.
	if info, err := progTailMap.Info(); err == nil {
		if info.KeySize != 4 || info.ValueSize != 4 {
			log.Fatalf("prog_tail_map key/value sizes = %d/%d, want 4/4 (D6)",
				info.KeySize, info.ValueSize)
		}
	}
	// D1 RT-kernel boundary (proposal §7.8.5). On PREEMPT_RT kernels the
	// single-entry per-CPU tail_stash is not safe against intra-CPU BPF
	// program preemption. Detection via /sys/kernel/realtime (presence of
	// the file + content "1") or /proc/version containing "PREEMPT_RT".
	// On detection, we SKIP populating prog_tail_map[0] — the main
	// program's bpf_tail_call then fallthroughs to XDP_PASS, which is the
	// documented "anomaly disabled but agent continues normally" behavior.
	if isRTKernel() {
		log.Printf("[bpf] WARN: PREEMPT_RT kernel detected — anomaly data plane disabled " +
			"(tail_call skipped, per-CPU single-slot stash unsafe under RT interleaving). " +
			"Controller will still accept/store anomaly rules but BPF won't drop anomaly " +
			"packets. See proposal §7.8.5 D1 RT boundary.")
		// Do not populate prog_tail_map[0]. bpf_tail_call in main will fallthrough.
	} else {
		// Populate slot 0. D5 implementation checklist: after agent restart this
		// same block re-runs — since cilium/ebpf re-creates programs on every
		// NewCollection (or loads pinned program with a fresh FD), we always
		// write the current FD into the map. This is what smoke test's
		// TestPinning phase-2 lesson says: on reopen, always re-populate.
		tailSlotAnomalyVerify := uint32(0) // matches xdrop.h TAIL_SLOT_ANOMALY_VERIFY
		anomalyFD := uint32(anomalyProg.FD())
		if err := progTailMap.Update(tailSlotAnomalyVerify, anomalyFD, ebpf.UpdateAny); err != nil {
			log.Fatalf("populate prog_tail_map[0] with xdp_anomaly_verify FD: %v", err)
		}
		log.Printf("[bpf] prog_tail_map[%d] = xdp_anomaly_verify FD=%d (B5 anomaly dispatch wired)",
			tailSlotAnomalyVerify, anomalyFD)
	}

	// Phase 8: Register xdp_firewall_main in slot 1 — MUST succeed before attach.
	// Unlike anomaly slot 0 (which is RT-skippable because it uses per-CPU tail_stash),
	// slot 1 is the main firewall chain and must ALWAYS be registered regardless of RT kernel.
	{
		tailSlotFirewallMain := uint32(1)
		firewallMainFD := uint32(firewallMain.FD())
		if err := progTailMap.Update(tailSlotFirewallMain, firewallMainFD, ebpf.UpdateAny); err != nil {
			log.Fatalf("populate prog_tail_map[1] with xdp_firewall_main FD: %v — cannot attach gate without main firewall", err)
		}
		log.Printf("[bpf] prog_tail_map[%d] = xdp_firewall_main FD=%d (Phase 8 main firewall wired)",
			tailSlotFirewallMain, firewallMainFD)
	}

	// Phase 8: tailcall_fail_stats (gate-owned, PinNone → restart-clear)
	// Passed to NewHandlers → exposed in /stats API as "tailcall_fail"
	tailcallFailStats := requireMapFrom(gateColl, "gate", "tailcall_fail_stats")

	// Interface manager for fast forward mode.
	var ifMgr *ifmgr.InterfaceManager

	// Track both the attached interface names (for logging) and the
	// resolved XDP links. Each ResolvedXDPLink wraps a cilium/ebpf
	// link.Link plus pin metadata — Phase 4 may reuse an existing
	// pinned link via LoadPinned + Update (zero gap), pin a fresh
	// attach (Phase-3-equivalent state, zero gap on next restart), or
	// fall back to fresh-unpinned (Phase-2-equivalent ~1.5s gap on
	// next restart). Shutdown calls Link.Close() on each; pinned links
	// stay alive in the kernel across process exit, unpinned links
	// detach. See bpf/xdp_link.go.
	var xdpAttachedIfaces []string
	var xdpLinks []*xdropbpf.ResolvedXDPLink

	// Initialize API handlers before XDP attach so the signal handler can call
	// handlers.Shutdown(). NewHandlers only needs BPF map handles; it does not
	// depend on XDP being attached. SetXDPInfo is called later, after attach.
	handlers := api.NewHandlers(blacklist, whitelist, whitelistB, stats, configA, configB, activeConfig, rlStates,
		cidrBlacklist, cidrRlStates, cidrMgr,
		blacklistB, cidrBlacklistB,
		tailcallFailStats)

	// Setup graceful shutdown BEFORE XDP attach and ifmgr config, so Ctrl-C
	// during startup still runs cleanup. The goroutine captures ifMgr,
	// xdpAttachedIfaces, xdpLinks, mainColl, gateColl by reference — all are still
	// zero-value here but will be populated synchronously below, so they're
	// valid by the time a signal can actually be delivered after startup.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")

		// Stop background samplers started by Handlers
		handlers.Shutdown()

		// Close each XDP link. For pinned links (Phase 4), Close only drops
		// the userspace fd — kernel-side attachment persists via the pin
		// file, which is exactly what enables zero-gap restart on the next
		// boot (LoadPinnedLink picks up the same link and Update()s the
		// program pointer). For unpinned links, Close tears down the XDP
		// attach. The iface list is only used for log messages.
		for i, res := range xdpLinks {
			ifaceLabel := ""
			if i < len(xdpAttachedIfaces) {
				ifaceLabel = xdpAttachedIfaces[i]
			}
			pinned := res.PinPath != ""
			if err := res.Link.Close(); err != nil {
				log.Printf("Warning: failed to close XDP link for %s: %v", ifaceLabel, err)
				continue
			}
			if ifaceLabel == "" {
				continue
			}
			if pinned {
				log.Printf("XDP link fd released for %s (pin persists, next restart is zero-gap)", ifaceLabel)
			} else {
				log.Printf("XDP detached from %s", ifaceLabel)
			}
		}

		// Release both collections: closes every map + program fd. Pinned maps
		// (Phase 3+) survive Close(); unpinned maps are freed.
		mainColl.Close()
		gateColl.Close()

		// Restore interfaces in fast forward mode (nil if signal fired pre-init)
		if fastForwardMode && ifMgr != nil {
			if err := ifMgr.RestoreAll(); err != nil {
				log.Printf("[main] Warning: ifMgr.RestoreAll() reported errors: %v", err)
			}
		}

		os.Exit(0)
	}()

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
			if rErr := ifMgr.RestoreAll(); rErr != nil {
				log.Printf("[main] Warning: interface restore reported errors during fatal cleanup: %v", rErr)
			}
			log.Fatalf("Failed to configure outbound interface: %v", err)
		}

		// Setup devmap: bidirectional mapping
		if err := setupDevmap(devmap, inboundIdx, outboundIdx); err != nil {
			if rErr := ifMgr.RestoreAll(); rErr != nil {
				log.Printf("[main] Warning: interface restore reported errors during fatal cleanup: %v", rErr)
			}
			log.Fatalf("Failed to setup devmap: %v", err)
		}
		log.Printf("Devmap configured: %d <-> %d", inboundIdx, outboundIdx)

		// Configure fast forward settings in BPF config map
		if err := configureFastForward(configA, configB, pair, inboundIdx, outboundIdx); err != nil {
			if rErr := ifMgr.RestoreAll(); rErr != nil {
				log.Printf("[main] Warning: interface restore reported errors during fatal cleanup: %v", rErr)
			}
			log.Fatalf("Failed to configure fast forward: %v", err)
		}

		// Attach XDP to inbound interface via the Phase 4 resolver. The
		// resolver handles pre-detach internally when taking the fresh-
		// attach branch, and skips pre-detach when reusing a pinned link
		// (pre-detach in the reuse path would break zero-gap continuity).
		inRes, err := resolveLink(xdpProg, pair.Inbound, cfg.BPF.Pinning)
		if err != nil {
			if rErr := ifMgr.RestoreAll(); rErr != nil {
				log.Printf("[main] Warning: interface restore reported errors during fatal cleanup: %v", rErr)
			}
			logXDPAttachFailure(pair.Inbound, err)
		}
		xdpLinks = append(xdpLinks, inRes)
		xdpAttachedIfaces = append(xdpAttachedIfaces, pair.Inbound)
		logXDPAttachOutcome(pair.Inbound, "inbound", inRes)

		// Attach XDP to outbound interface. With cilium/ebpf each attach
		// returns an independent Link, so the dual-NIC detach correctness
		// quirk we had with goebpf's shared program pointer no longer
		// applies.
		outRes, err := resolveLink(xdpProg, pair.Outbound, cfg.BPF.Pinning)
		if err != nil {
			// Roll back the inbound attach before failing startup. Must
			// use ForceDetach, not Link.Close: if the inbound link is
			// pinned (Phase 4), a plain Close only drops the userspace
			// fd and the pin keeps the kernel-side XDP attached — we'd
			// exit fatally with inbound XDP still live and no agent
			// tracking it. ForceDetach unpins first so the refcount
			// actually hits zero.
			if dErr := inRes.ForceDetach(); dErr != nil {
				log.Printf("[main] Warning: failed to tear down inbound XDP link during rollback: %v", dErr)
			}
			// Drop the inbound link from the shutdown tracking list so the
			// EXIT handler doesn't try to Close() it twice.
			xdpLinks = xdpLinks[:len(xdpLinks)-1]
			xdpAttachedIfaces = xdpAttachedIfaces[:len(xdpAttachedIfaces)-1]
			if rErr := ifMgr.RestoreAll(); rErr != nil {
				log.Printf("[main] Warning: interface restore reported errors during fatal cleanup: %v", rErr)
			}
			logXDPAttachFailure(pair.Outbound, err)
		}
		xdpLinks = append(xdpLinks, outRes)
		xdpAttachedIfaces = append(xdpAttachedIfaces, pair.Outbound)
		logXDPAttachOutcome(pair.Outbound, "outbound", outRes)

	} else {
		// === TRADITIONAL MODE ===
		log.Println("Traditional mode (single interface)")
		res, err := resolveLink(xdpProg, cfg.Server.Interface, cfg.BPF.Pinning)
		if err != nil {
			logXDPAttachFailure(cfg.Server.Interface, err)
		}
		xdpLinks = append(xdpLinks, res)
		xdpAttachedIfaces = append(xdpAttachedIfaces, cfg.Server.Interface)
		logXDPAttachOutcome(cfg.Server.Interface, "filter", res)
	}

	// Set XDP interface info for stats reporting (after XDP attach completed)
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

		// Sync API (Phase 4.2 atomic sync + Phase 8 whitelist atomic sync)
		syncGroup := protected.Group("/sync")
		{
			syncGroup.POST("/atomic", handlers.AtomicSync)
			syncGroup.POST("/whitelist", handlers.SyncWhitelistHandler) // Phase 8
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

// logPinResult logs the pinning outcome for a BPF collection (main or gate).
func logPinResult(label string, r xdropbpf.Result) {
	switch r.EffectiveMode {
	case xdropbpf.ModeAuto:
		if len(r.Wiped) > 0 {
			log.Printf("[%s] BPF pinning enabled at %s (wiped schema-mismatched: %v)", label, r.PinPath, r.Wiped)
		} else {
			log.Printf("[%s] BPF pinning enabled at %s", label, r.PinPath)
		}
	case xdropbpf.ModeDisable:
		if r.FallbackReason != "" {
			log.Printf("[%s] BPF pinning disabled (fallback): %s", label, r.FallbackReason)
		} else {
			log.Printf("[%s] BPF pinning disabled (configured)", label)
		}
	}
}

// resolveLink is the Phase 4 XDP attach entrypoint called from main().
// It hands off to the bpf package's ResolveXDPLink, which runs the
// LoadPinned+Update / fresh-attach+Pin / fresh-unpinned decision tree
// gated on the bpf.pinning policy. The returned ResolvedXDPLink is
// tracked in xdpLinks so the shutdown goroutine can Close() every fd.
//
// KERNEL FLOOR: cilium/ebpf v0.21.0's link.AttachXDP issues
// BPF_LINK_CREATE with type BPF_LINK_TYPE_XDP, which landed in Linux
// 5.9. The pre-5.9 netlink-attach fallback described in §Phase 4.a is
// intentionally NOT implemented (AUD-PH2-001 closure) — every current
// stable distro ships a recent-enough kernel. On older kernels the
// resolver wraps the returned error with ErrLinkPinningUnsupported so
// operators see the right diagnostic rather than a raw ENOTSUP.
func resolveLink(xdpProg *ebpf.Program, ifname, pinningMode string) (*xdropbpf.ResolvedXDPLink, error) {
	return xdropbpf.ResolveXDPLink(xdpProg, ifname, xdropbpf.Mode(pinningMode), xdropbpf.DefaultPinRoot)
}

// logXDPAttachOutcome emits a structured startup log line describing
// what Phase 4 actually did for this interface. "reused" is the
// zero-gap path (program swapped in-place on an existing pinned link);
// "pinned" means fresh attach + newly pinned (zero-gap available on
// next restart); "unpinned" means the Phase-2-equivalent fallback.
func logXDPAttachOutcome(ifname, role string, res *xdropbpf.ResolvedXDPLink) {
	switch {
	case res.Reused:
		log.Printf("XDP program updated in place on %s (%s, zero-gap link reuse via %s)", ifname, role, res.PinPath)
	case res.PinPath != "":
		log.Printf("XDP program attached and pinned on %s (%s, pin=%s)", ifname, role, res.PinPath)
	default:
		reason := res.DowngradeReason
		if reason == "" {
			reason = "link pinning disabled"
		}
		log.Printf("XDP program attached on %s (%s, unpinned — next restart will have a brief gap; reason: %s)",
			ifname, role, reason)
	}
}

// logXDPAttachFailure logs+exits for a resolver error. Splits into
// three categories so the operator-facing hint points at the actual
// cause rather than a hardcoded "upgrade your kernel":
//
//  1. pre-5.9 kernel (AttachXDP returned ErrNotSupported / ENOTSUP /
//     EOPNOTSUPP): emit the Linux 5.9+ / BPF_LINK_TYPE_XDP hint.
//  2. other ErrLinkPinningUnsupported (bpffs not mounted, MkdirAll
//     EPERM, Pin() EPERM in require mode, etc.): emit a pin-layer
//     diagnostic pointing at bpffs / permissions, NOT a kernel hint —
//     those failures happen on fully-supported modern kernels and the
//     kernel hint would actively mislead.
//  3. anything else: generic "attach failed" message.
func logXDPAttachFailure(ifname string, err error) {
	if xdropbpf.IsXDPLinkUnsupported(err) {
		log.Fatalf(
			"Failed to attach XDP to %s: %v\n\n"+
				"  xdrop requires Linux 5.9+ for XDP attach (BPF_LINK_TYPE_XDP).\n"+
				"  The pre-5.9 netlink fallback described in proposal §Phase 4.a is\n"+
				"  intentionally NOT implemented (AUD-PH2-001 closure). Upgrade the\n"+
				"  host kernel or hold xdrop on the prior v2.4.2 goebpf-based release.",
			ifname, err)
	}
	if errors.Is(err, xdropbpf.ErrLinkPinningUnsupported) {
		log.Fatalf(
			"Failed to attach XDP to %s: %v\n\n"+
				"  bpf.pinning=require but link pinning could not be enabled. This\n"+
				"  is NOT a kernel-version problem — AttachXDP itself succeeded.\n"+
				"  Likely causes: /sys/fs/bpf is not mounted as bpffs, EPERM on\n"+
				"  /sys/fs/bpf/xdrop/, or Pin() rejected for another reason.\n"+
				"  Check `stat -f -c '%%T' /sys/fs/bpf` (expect bpf_fs), verify the\n"+
				"  agent runs as root, or set bpf.pinning=auto to downgrade silently.",
			ifname, err)
	}
	log.Fatalf("Failed to attach XDP to %s: %v", ifname, err)
}

// setupDevmap configures bidirectional interface mapping. DEVMAP is an
// array-backed type — all max_entries slots are pre-allocated with empty
// references, so Update(UpdateExist) succeeds and strictly matches the
// pre-migration goebpf.Update (BPF_EXIST) semantics per §5.2.
func setupDevmap(devmap *ebpf.Map, inboundIdx, outboundIdx int) error {
	// inbound -> outbound
	if err := devmap.Update(uint32ToBytes(uint32(inboundIdx)), uint32ToBytes(uint32(outboundIdx)), ebpf.UpdateExist); err != nil {
		return fmt.Errorf("failed to set devmap[%d]=%d: %w", inboundIdx, outboundIdx, err)
	}

	// outbound -> inbound
	if err := devmap.Update(uint32ToBytes(uint32(outboundIdx)), uint32ToBytes(uint32(inboundIdx)), ebpf.UpdateExist); err != nil {
		return fmt.Errorf("failed to set devmap[%d]=%d: %w", outboundIdx, inboundIdx, err)
	}

	return nil
}

// configureFastForward sets up fast forward mode in both config maps
// (double-buffer). config_a / config_b are ARRAY maps — Update(UpdateExist)
// is the direct translation of pre-migration goebpf.Update (BPF_EXIST)
// per §5.2, and since all array slots are pre-populated it is equivalent
// to Put here while remaining semantically precise.
func configureFastForward(configA, configB *ebpf.Map, pair config.InterfacePair, inboundIdx, outboundIdx int) error {
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

	// Write to both config maps so whichever is active sees the values.
	// Runs AFTER NewHandlers → initDynamicConfig has zeroed both slots
	// (AUD-PH3-001); these writes overwrite with the real FF values.
	for _, m := range []*ebpf.Map{configA, configB} {
		binary.LittleEndian.PutUint32(key, api.ConfigFastForwardEnabled)
		binary.LittleEndian.PutUint64(value, 1)
		if err := m.Update(key, value, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("failed to enable fast forward: %w", err)
		}

		binary.LittleEndian.PutUint32(key, api.ConfigFilterIfindex)
		binary.LittleEndian.PutUint64(value, uint64(filterIdx))
		if err := m.Update(key, value, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("failed to set filter ifindex: %w", err)
		}
	}

	log.Printf("Fast forward configured: filter_on=%s, filter_ifindex=%d", filterOn, filterIdx)
	return nil
}

// uint32ToBytes converts uint32 to little-endian byte slice
func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
