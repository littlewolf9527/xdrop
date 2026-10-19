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

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	xdropbpf "github.com/littlewolf9527/xdrop/node/agent/bpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"github.com/littlewolf9527/xdrop/node/agent/config"
	"github.com/littlewolf9527/xdrop/node/agent/ifmgr"
	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
)

// Config map indices now live in the api package alongside the other
// dynamic config slots. FF slots are written before publishing new programs
// and preserved by initDynamicConfig. main.go uses api.ConfigFastForwardEnabled /
// api.ConfigFilterIfindex / api.ConfigRLCPUDivisor at its own write sites.

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
	if err := xdropbpf.CleanStalePins(xdropbpf.DefaultPinRoot, []string{"verifier_prune_map", "tailcall_fail_stats", "tail_stash", "rl_states", "cidr_rl_states"}); err != nil {
		log.Fatalf("[Phase8] FATAL: %v — refusing to start", err)
	}

	// 1. Load xdrop_main.elf — creates all shared kernel maps
	log.Printf("Loading main BPF from %s...", mainPath)
	mainColl, mainPinResult, err := xdropbpf.Load(xdropbpf.Options{
		SpecPath:         mainPath,
		Mode:             xdropbpf.Mode(cfg.BPF.Pinning),
		PinNoneOverrides: []string{"verifier_prune_map", "hot_ids"}, // fresh candidate table; NEVER pin
	})
	if err != nil {
		logBPFLoadFailure("main", mainPath, err)
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
	condRowMissing := requireMapFrom(mainColl, "main", "cond_row_missing")
	// B1 logical state is loaded now; control-plane consumers follow in knife four.
	requireMapFrom(mainColl, "main", "id_counts")
	requireMapFrom(mainColl, "main", "id_rl_states")
	cidrBlacklist := requireMapFrom(mainColl, "main", "cidr_blacklist")
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
		Mode:             mainPinResult.EffectiveMode,
		PinNoneOverrides: []string{"tailcall_fail_stats"}, // restart-clear semantics
		MapReplacements:  gateMapReplacements,
	})
	if err != nil {
		logBPFLoadFailure("gate", gatePath, err)
	}
	logPinResult("gate", gatePinResult)

	// Gate-only maps
	whitelistB := requireMapFrom(gateColl, "gate", "whitelist_b")

	// Pinned XDP may still run: business clear/recount, receipt, logical clear/recount.
	// Failure leaves startup closed, before NewHandlers can reset selectors.
	if mainPinResult.PinPath != "" {
		if err := api.PreparePinnedStartup(mainColl, gateColl); err != nil {
			log.Fatalf("[startup] pinned state reset failed: %v", err)
		}
	}

	cidrMgr := cidr.NewManager(srcV4Trie, dstV4Trie, srcV6Trie, dstV6Trie,
		requireMapFrom(mainColl, "main", "sv4_cidr_trie_b"), requireMapFrom(mainColl, "main", "dv4_cidr_trie_b"),
		requireMapFrom(mainColl, "main", "sv6_cidr_trie_b"), requireMapFrom(mainColl, "main", "dv6_cidr_trie_b"))
	log.Println("CIDR manager initialized")

	// FF state must be ready before any new program can receive traffic.
	if fastForwardMode {
		if devmapMain == nil {
			log.Fatal("BPF map 'devmap' not found in main ELF but fast_forward is enabled")
		}
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

		// Setup devmap: bidirectional mapping
		if err := setupDevmap(devmapMain, inboundIdx, outboundIdx); err != nil {
			log.Fatalf("Failed to setup devmap: %v", err)
		}
		log.Printf("Devmap configured: %d <-> %d", inboundIdx, outboundIdx)

		// Configure fast forward settings in BPF config map
		if err := configureFastForward(configA, configB, pair, inboundIdx, outboundIdx); err != nil {
			log.Fatalf("Failed to configure fast forward: %v", err)
		}

	} else if err := clearFastForwardSlots(configA, configB); err != nil {
		log.Fatalf("Failed to clear fast forward: %v", err)
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

	// D6 verification: PROG_ARRAY key/value must be exactly 4 bytes.
	if info, err := progTailMap.Info(); err == nil {
		if info.KeySize != 4 || info.ValueSize != 4 {
			log.Fatalf("prog_tail_map key/value sizes = %d/%d, want 4/4 (D6)",
				info.KeySize, info.ValueSize)
		}
	}
	if err := xdropbpf.ClearRetiredTailSlot(progTailMap); err != nil {
		log.Fatalf("[startup] %v", err)
	}

	// Phase 8: Register xdp_firewall_main in slot 1 — MUST succeed before attach.
	// Slot 1 is the main firewall chain on every kernel.
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
	handlers := api.NewHandlers(blacklist, whitelist, whitelistB, stats, configA, configB, activeConfig,
		cidrBlacklist, cidrMgr,
		blacklistB, cidrBlacklistB,
		tailcallFailStats, mainColl.Maps["id_counts"],
		mainColl.Maps["cond_a"], mainColl.Maps["cond_b"], mainColl.Maps["cidr_cond_a"], mainColl.Maps["cidr_cond_b"], mainColl.Maps["id_rl_states"], condRowMissing)
	handlers.SetHits(mainColl.Maps["hot_ids"], cfg.Server.HitsRateLimit)
	rateLimit, err := configureRateLimitDivisor(configA, configB, cfg.BPF.RateLimitDivisor)
	if err != nil {
		log.Fatalf("Failed to configure rate-limit divisor: %v", err)
	}
	handlers.SetRateLimitSnapshot(rateLimit)
	if err := configureIPv6DeepChain(configA, configB, ipv6DeepChainPass(cfg.BPF)); err != nil {
		log.Fatalf("Failed to configure IPv6 deep chain: %v", err)
	}

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
			if err := restoreFFInterfaces(cfg.FastForward.Pairs[0], xdropbpf.ReadXDPAttachment, ifMgr.RestoreInterface); err != nil {
				log.Printf("[main] Warning: interface restore reported errors: %v", err)
			}
		}

		os.Exit(0)
	}()

	if fastForwardMode {
		// === FAST FORWARD MODE ===
		log.Println("Fast Forward mode enabled")
		ifMgr = ifmgr.NewInterfaceManager()
		pair := cfg.FastForward.Pairs[0]

		// Configure interfaces (UP, promiscuous, disable offloads)
		if err := ifMgr.ConfigureInterface(pair.Inbound); err != nil {
			log.Fatalf("Failed to configure inbound interface: %v", err)
		}
		if err := ifMgr.ConfigureInterface(pair.Outbound); err != nil {
			if rErr := restoreFFInterfaces(cfg.FastForward.Pairs[0], xdropbpf.ReadXDPAttachment, ifMgr.RestoreInterface); rErr != nil {
				log.Printf("[main] Warning: interface restore reported errors during fatal cleanup: %v", rErr)
			}
			log.Fatalf("Failed to configure outbound interface: %v", err)
		}

		// Attach XDP to inbound interface via the Phase 4 resolver. The
		// resolver handles pre-detach internally when taking the fresh-
		// attach branch, and skips pre-detach when reusing a pinned link
		// (pre-detach in the reuse path would break zero-gap continuity).
		inRes, err := resolveLink(xdpProg, pair.Inbound, string(mainPinResult.EffectiveMode), cfg.BPF.XDPMode)
		if err != nil {
			if rErr := restoreFFInterfaces(cfg.FastForward.Pairs[0], xdropbpf.ReadXDPAttachment, ifMgr.RestoreInterface); rErr != nil {
				log.Printf("[main] Warning: interface restore reported errors during fatal cleanup: %v", rErr)
			}
			logXDPAttachFailure(pair.Inbound, cfg.BPF.XDPMode, err)
		}
		xdpLinks = append(xdpLinks, inRes)
		xdpAttachedIfaces = append(xdpAttachedIfaces, pair.Inbound)
		logXDPAttachOutcome(pair.Inbound, "inbound", cfg.BPF.XDPMode, inRes)

		// Attach XDP to outbound interface. With cilium/ebpf each attach
		// returns an independent Link, so the dual-NIC detach correctness
		// quirk we had with goebpf's shared program pointer no longer
		// applies.
		outRes, err := resolveLink(xdpProg, pair.Outbound, string(mainPinResult.EffectiveMode), cfg.BPF.XDPMode)
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
			if rErr := restoreFFInterfaces(cfg.FastForward.Pairs[0], xdropbpf.ReadXDPAttachment, ifMgr.RestoreInterface); rErr != nil {
				log.Printf("[main] Warning: interface restore reported errors during fatal cleanup: %v", rErr)
			}
			logXDPAttachFailure(pair.Outbound, cfg.BPF.XDPMode, err)
		}
		xdpLinks = append(xdpLinks, outRes)
		xdpAttachedIfaces = append(xdpAttachedIfaces, pair.Outbound)
		logXDPAttachOutcome(pair.Outbound, "outbound", cfg.BPF.XDPMode, outRes)
		warnXDPFFModes(pair.Inbound, pair.Outbound, inRes, outRes)

	} else {
		// === TRADITIONAL MODE ===
		log.Println("Traditional mode (single interface)")
		res, err := resolveLink(xdpProg, cfg.Server.Interface, string(mainPinResult.EffectiveMode), cfg.BPF.XDPMode)
		if err != nil {
			logXDPAttachFailure(cfg.Server.Interface, cfg.BPF.XDPMode, err)
		}
		xdpLinks = append(xdpLinks, res)
		xdpAttachedIfaces = append(xdpAttachedIfaces, cfg.Server.Interface)
		logXDPAttachOutcome(cfg.Server.Interface, "filter", cfg.BPF.XDPMode, res)
	}

	// Set XDP interface info for stats reporting (after XDP attach completed)
	if fastForwardMode {
		pair := cfg.FastForward.Pairs[0]
		handlers.SetXDPInfo(&api.XDPInfo{
			Mode: "fast_forward",
			Interfaces: []api.XDPInterface{
				{Name: pair.Inbound, Role: "inbound", AttachMode: xdpLinks[0].AttachMode},
				{Name: pair.Outbound, Role: "outbound", AttachMode: xdpLinks[1].AttachMode},
			},
		})
	} else {
		handlers.SetXDPInfo(&api.XDPInfo{
			Mode: "traditional",
			Interfaces: []api.XDPInterface{
				{Name: cfg.Server.Interface, Role: "filter", AttachMode: xdpLinks[0].AttachMode},
			},
		})
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
			rules.GET("/hits", handlers.Hits)
			rules.POST("/commit", handlers.CommitRules)
		}

		// Whitelist API
		wl := protected.Group("/whitelist")
		{
			wl.GET("", handlers.ListWhitelist)
		}

		// Sync API (Phase 4.2 atomic sync + Phase 8 whitelist atomic sync)
		syncGroup := protected.Group("/sync")
		{
			syncGroup.POST("/atomic", handlers.AtomicSync)
			syncGroup.POST("/whitelist", handlers.SyncWhitelistHandler) // Phase 8
		}

		// Stats API
		protected.GET("/stats", handlers.GetStats)
		protected.GET("/stats/cpu", handlers.GetCPUStats)
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
func resolveLink(xdpProg *ebpf.Program, ifname, pinningMode, xdpMode string) (*xdropbpf.ResolvedXDPLink, error) {
	return xdropbpf.ResolveXDPLink(xdpProg, ifname, xdropbpf.Mode(pinningMode), xdropbpf.XDPMode(xdpMode), xdropbpf.DefaultPinRoot)
}

// logXDPAttachOutcome emits a structured startup log line describing
// what Phase 4 actually did for this interface. "reused" is the
// zero-gap path (program swapped in-place on an existing pinned link);
// "pinned" means fresh attach + newly pinned (zero-gap available on
// next restart); "unpinned" means the Phase-2-equivalent fallback.
func warnXDPFFModes(inbound, outbound string, inRes, outRes *xdropbpf.ResolvedXDPLink) {
	if inRes.AttachMode != outRes.AttachMode {
		log.Printf("WARN: FF interfaces have different XDP modes: %s=%s %s=%s", inbound, inRes.AttachMode, outbound, outRes.AttachMode)
	}
}

func logXDPAttachOutcome(ifname, role, requested string, res *xdropbpf.ResolvedXDPLink) {
	switch {
	case res.Reused:
		log.Printf("XDP program updated in place on %s (%s, zero-gap link reuse via %s) requested=%s attached=%s", ifname, role, res.PinPath, requested, res.AttachMode)
	case res.PinPath != "":
		log.Printf("XDP program attached and pinned on %s (%s, pin=%s) requested=%s attached=%s", ifname, role, res.PinPath, requested, res.AttachMode)
	default:
		reason := res.DowngradeReason
		if reason == "" {
			reason = "link pinning disabled"
		}
		log.Printf("XDP program attached on %s (%s, unpinned — next restart will have a brief gap; reason: %s) requested=%s attached=%s",
			ifname, role, reason, requested, res.AttachMode)
	}
}

// logBPFLoadFailure logs+exits when a BPF collection fails to load.
//
// KERNEL FLOOR — this is the step with the *higher* floor, and it runs
// before attach. xdp_firewall_main walks its combination loops with the
// open-coded iterator kfuncs (bpf_iter_num_new / _next / _destroy), which
// landed in Linux 6.4; earlier verifiers refuse the program. kfunc calls
// additionally need the BPF JIT — with the JIT disabled, load fails on
// 6.4+ too. (Until B1 cut 5-4 the documented reason was "subprogram calls
// mixed with bpf_tail_call" with a 5.10 floor; 5-4 removed main's tail
// call, and the iterator requirement already applied since M1.)
//
// Do not infer the cause from the verifier message alone; this diagnostic
// names both causes and asks for the version and the sysctl separately.
//
// 5.9 IS mentioned below, deliberately, and only as a contrast: an
// operator who followed the pre-2026-08-20 docs believes 5.9 is the
// requirement, and deleting the number leaves them unable to place their
// own situation. What this diagnostic must never do is state 5.9 as the
// requirement — that was the defect it replaced ("requires Linux 5.9+"
// printed to someone already running 5.9, pointing them the wrong way).
func logBPFLoadFailure(which, path string, err error) {
	log.Fatalf(
		"Failed to load %s BPF collection from %s: %v\n\n"+
			"  If this is a verifier rejection, check the kernel floor for\n"+
			"  *loading* xdrop (higher than the 5.9 floor for XDP attach):\n"+
			"    >= 6.4 (x86-64 / arm64)\n"+
			"  xdrop supports little-endian x86-64 and arm64 only.\n"+
			"  xdp_firewall_main uses open-coded iterator kfuncs (bpf_iter_num_*),\n"+
			"  added in Linux 6.4; earlier verifiers refuse the program.\n\n"+
			"  Calling kfuncs also requires the BPF JIT to be enabled. Verify:\n"+
			"    uname -rm\n"+
			"    sysctl net.core.bpf_jit_enable   # expect non-zero\n"+
			"      0 = JIT off | 1 = on | 2 = on with JIT debug output\n"+
			"  With the JIT off, load fails on 6.4+ as well.\n"+
			"  NOTE: do not rely on the verifier message alone — check the\n"+
			"  kernel version and the sysctl separately.",
		which, path, err)
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
func logXDPAttachFailure(ifname, requested string, err error) {
	if requested == "native" && xdropbpf.XDPFailureReason(err) == "xdp_attach_failed" {
		log.Fatalf("Failed to attach XDP to %s: requested=native: 驱动不支持 native 或驱动故障: %v", ifname, err)
	}
	if xdropbpf.IsXDPLinkUnsupported(err) {
		log.Fatalf(
			"Failed to attach XDP to %s: %v\n\n"+
				"  XDP attach via BPF_LINK_TYPE_XDP requires Linux 5.9+. (Note: the\n"+
				"  BPF program already loaded, and loading needs a HIGHER kernel —\n"+
				"  >= 6.4 — so a version problem is unlikely here.)\n"+
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

// setupDevmap writes both DEVMAP_HASH directions before removing obsolete keys.
func setupDevmap(devmap *ebpf.Map, inboundIdx, outboundIdx int) error {
	// inbound -> outbound
	if err := devmap.Update(uint32ToBytes(uint32(inboundIdx)), uint32ToBytes(uint32(outboundIdx)), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to set devmap[%d]=%d: %w", inboundIdx, outboundIdx, err)
	}

	// outbound -> inbound
	if err := devmap.Update(uint32ToBytes(uint32(outboundIdx)), uint32ToBytes(uint32(inboundIdx)), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to set devmap[%d]=%d: %w", outboundIdx, inboundIdx, err)
	}

	var key, value uint32
	var stale []uint32
	iter := devmap.Iterate()
	for iter.Next(&key, &value) {
		if key != uint32(inboundIdx) && key != uint32(outboundIdx) {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate devmap: %w", err)
	}
	for _, key := range stale {
		if err := devmap.Delete(key); err != nil {
			return fmt.Errorf("delete devmap[%d]: %w", key, err)
		}
	}
	return nil
}

// ipv6DeepChainPass: bpf.ipv6_deep_chain_drop missing or true drops; only an explicit false passes.
func ipv6DeepChainPass(b config.BPFConfig) bool {
	return b.IPv6DeepChainDrop != nil && !*b.IPv6DeepChainDrop
}

func configureIPv6DeepChain(configA, configB interface {
	Update(interface{}, interface{}, ebpf.MapUpdateFlags) error
}, pass bool) error {
	value := uint64(0)
	if pass {
		value = 1
	}
	for _, m := range []interface {
		Update(interface{}, interface{}, ebpf.MapUpdateFlags) error
	}{configA, configB} {
		if err := m.Update(uint32(api.ConfigIPv6DeepChainPass), value, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("failed to set IPv6 deep chain pass: %w", err)
		}
	}
	log.Printf("bpf.ipv6_deep_chain_drop=%t (slot 12=%d)", !pass, value)
	return nil
}

func configureRateLimitDivisor(configA, configB *ebpf.Map, override int) (ratelimit.Snapshot, error) {
	snapshot, err := ratelimit.Resolve("/sys/devices/system/cpu/online", ebpf.PossibleCPU, override)
	if err != nil {
		return snapshot, err
	}
	if snapshot.Source == "possible" {
		log.Print("[rate_limit] WARN: online CPU source unavailable or invalid; using possible CPU count")
	}
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, api.ConfigRLCPUDivisor)
	value := make([]byte, 8)
	binary.LittleEndian.PutUint64(value, uint64(snapshot.Divisor))
	for _, m := range []*ebpf.Map{configA, configB} {
		if err := m.Update(key, value, ebpf.UpdateExist); err != nil {
			return snapshot, fmt.Errorf("failed to set rate-limit CPU divisor: %w", err)
		}
	}
	log.Print(snapshot.LogLine())
	return snapshot, nil
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
	// Runs before tail/link publication; initDynamicConfig preserves both slots.
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

// clearFastForwardSlots owns the traditional-mode reset (AUD-PH3-001).
func clearFastForwardSlots(configA, configB *ebpf.Map) error {
	for _, m := range []*ebpf.Map{configA, configB} {
		for _, slot := range []uint32{api.ConfigFastForwardEnabled, api.ConfigFilterIfindex} {
			if err := m.Update(slot, uint64(0), ebpf.UpdateExist); err != nil {
				return fmt.Errorf("clear FF slot %d: %w", slot, err)
			}
		}
	}
	return nil
}

// Read the kernel, including attachments inherited from an earlier process.
func restoreFFInterfaces(pair config.InterfacePair, read func(string) (xdropbpf.XDPAttachment, error), restore func(string) error) error {
	var errs []error
	for _, name := range []string{pair.Inbound, pair.Outbound} {
		state, err := read(name)
		if err != nil {
			log.Printf("[main] WARN: XDP readback for %s failed; restoring: %v", name, err)
		} else if state.Attached != 0 {
			log.Printf("[main] XDP still attached to %s; skipping interface restore", name)
			continue
		}
		errs = append(errs, restore(name))
	}
	return errors.Join(errs...)
}
