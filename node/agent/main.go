// XDrop Agent - Main entry point
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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

	// Load BPF ELF into a cilium/ebpf Collection via the Phase 3 loader
	// helper, which threads the bpffs probe, pinned-map schema reconcile,
	// and the `bpf.pinning: auto|require|disable` policy knob into a
	// single call. Pinning is silently disabled under `auto` when bpffs
	// is not mounted or otherwise unusable — rules still load, the agent
	// just loses restart survival for this boot.
	log.Printf("Loading BPF program from %s...", cfg.BPF.Path)
	coll, pinResult, err := xdropbpf.Load(xdropbpf.Options{
		SpecPath: cfg.BPF.Path,
		Mode:     xdropbpf.Mode(cfg.BPF.Pinning),
	})
	if err != nil {
		log.Fatalf("Failed to load BPF collection: %v", err)
	}
	switch pinResult.EffectiveMode {
	case xdropbpf.ModeAuto:
		if len(pinResult.Wiped) > 0 {
			log.Printf("BPF pinning enabled at %s (wiped schema-mismatched: %v)",
				pinResult.PinPath, pinResult.Wiped)
		} else {
			log.Printf("BPF pinning enabled at %s", pinResult.PinPath)
		}
		// Phase 3 only promises MAP-INFRASTRUCTURE continuity across
		// restart (stable fds for bpftool observers, config-map /
		// stats-counter preservation). Data-map CONTENTS are wiped
		// here so the in-memory rule index the agent is about to build
		// reconverges with the kernel on controller sync — otherwise
		// Update(UpdateNoExist) would trip ErrKeyExist on every rule
		// the previous agent's life left behind. True zero-gap data
		// plane comes in Phase 4 via link pinning + idempotent sync.
		if err := xdropbpf.ClearDataMaps(coll, []string{
			"blacklist", "blacklist_b",
			"whitelist",
			"cidr_blacklist", "cidr_blist_b",
			"rl_states", "cidr_rl_states",
			"sv4_cidr_trie", "dv4_cidr_trie",
			"sv6_cidr_trie", "dv6_cidr_trie",
		}); err != nil {
			log.Printf("WARN: data-map clear reported error (continuing): %v", err)
		}
	case xdropbpf.ModeDisable:
		if pinResult.FallbackReason != "" {
			log.Printf("BPF pinning disabled (fallback): %s", pinResult.FallbackReason)
		} else {
			log.Printf("BPF pinning disabled (configured)")
		}
	}

	// Helper to fetch a required map by name.
	requireMap := func(name string) *ebpf.Map {
		m, ok := coll.Maps[name]
		if !ok || m == nil {
			log.Fatalf("BPF map %q not found in ELF", name)
		}
		return m
	}

	blacklist := requireMap("blacklist")
	whitelist := requireMap("whitelist")
	stats := requireMap("stats")
	rlStates := requireMap("rl_states")
	configA := requireMap("config_a")
	configB := requireMap("config_b")
	activeConfig := requireMap("active_config")
	cidrBlacklist := requireMap("cidr_blacklist")
	cidrRlStates := requireMap("cidr_rl_states")
	srcV4Trie := requireMap("sv4_cidr_trie")
	dstV4Trie := requireMap("dv4_cidr_trie")
	srcV6Trie := requireMap("sv6_cidr_trie")
	dstV6Trie := requireMap("dv6_cidr_trie")
	blacklistB := requireMap("blacklist_b")
	cidrBlacklistB := requireMap("cidr_blist_b")

	cidrMgr := cidr.NewManager(srcV4Trie, dstV4Trie, srcV6Trie, dstV6Trie)
	log.Println("CIDR manager initialized")

	// Fast forward devmap (only required when enabled)
	var devmap *ebpf.Map
	if fastForwardMode {
		devmap = requireMap("devmap")
	}

	// XDP program. cilium/ebpf does not require an explicit Load() step —
	// NewCollection already JITed + verified it. Attach happens via the
	// link package further down.
	xdpProg, ok := coll.Programs["xdrop_firewall"]
	if !ok || xdpProg == nil {
		log.Fatal("XDP program 'xdrop_firewall' not found in ELF")
	}

	// Interface manager for fast forward mode.
	var ifMgr *ifmgr.InterfaceManager

	// Track both the attached interface names (for logging + pre-detach on
	// crash recovery) and the cilium Link objects that actually own the
	// kernel-side attachment. Link.Close() on shutdown replaces the old
	// shell-out to `ip link set ... xdp off` as the primary detach path
	// (§5.5). detachXDP() is kept as a pre-attach stale-cleanup helper.
	var xdpAttachedIfaces []string
	var xdpLinks []link.Link

	// Initialize API handlers before XDP attach so the signal handler can call
	// handlers.Shutdown(). NewHandlers only needs BPF map handles; it does not
	// depend on XDP being attached. SetXDPInfo is called later, after attach.
	handlers := api.NewHandlers(blacklist, whitelist, stats, configA, configB, activeConfig, rlStates,
		cidrBlacklist, cidrRlStates, cidrMgr,
		blacklistB, cidrBlacklistB)

	// Setup graceful shutdown BEFORE XDP attach and ifmgr config, so Ctrl-C
	// during startup still runs cleanup. The goroutine captures ifMgr,
	// xdpAttachedIfaces, xdpLinks, and coll by reference — all are still
	// zero-value here but will be populated synchronously below, so they're
	// valid by the time a signal can actually be delivered after startup.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")

		// Stop background samplers started by Handlers
		handlers.Shutdown()

		// Close each XDP link — this is what actually detaches the program
		// from the kernel with cilium/ebpf. Iterate over both slices: the
		// link list is the authoritative owner of the attachment, the iface
		// list is only used for log messages.
		for i, lnk := range xdpLinks {
			ifaceLabel := ""
			if i < len(xdpAttachedIfaces) {
				ifaceLabel = xdpAttachedIfaces[i]
			}
			if err := lnk.Close(); err != nil {
				log.Printf("Warning: failed to close XDP link for %s: %v", ifaceLabel, err)
			} else if ifaceLabel != "" {
				log.Printf("XDP detached from %s", ifaceLabel)
			}
		}

		// Release collection: closes every map + program fd. Pinned maps
		// (Phase 3+) would survive this; in Phase 2 all maps are unpinned
		// so they're freed here. Collection.Close returns no error.
		coll.Close()

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

		// Pre-detach: clear any stale XDP programs left by a previous crash/kill -9.
		// Error is expected when nothing is attached — we log at DEBUG level only.
		if err := detachXDP(pair.Inbound); err != nil {
			log.Printf("[main] pre-detach XDP from %s returned error (likely no program attached): %v", pair.Inbound, err)
		}
		if err := detachXDP(pair.Outbound); err != nil {
			log.Printf("[main] pre-detach XDP from %s returned error (likely no program attached): %v", pair.Outbound, err)
		}

		// Attach XDP to inbound interface via cilium/ebpf link. Flags:0 gives
		// kernel best-effort (auto-select driver vs generic) — matches the
		// pre-migration goebpf XdpAttachModeNone default (§5.1 / AUD-MIG-001).
		inLink, err := attachXDPLink(xdpProg, pair.Inbound)
		if err != nil {
			if rErr := ifMgr.RestoreAll(); rErr != nil {
				log.Printf("[main] Warning: interface restore reported errors during fatal cleanup: %v", rErr)
			}
			log.Fatalf("Failed to attach XDP to %s: %v", pair.Inbound, err)
		}
		xdpLinks = append(xdpLinks, inLink)
		xdpAttachedIfaces = append(xdpAttachedIfaces, pair.Inbound)
		log.Printf("XDP program attached to %s (inbound)", pair.Inbound)

		// Attach XDP to outbound interface. With cilium/ebpf each
		// link.AttachXDP returns an independent Link object, so the dual-NIC
		// detach correctness quirk we had with goebpf's shared program
		// pointer no longer applies — we simply Close() each Link on exit.
		outLink, err := attachXDPLink(xdpProg, pair.Outbound)
		if err != nil {
			// Roll back the inbound attach before failing startup.
			if cErr := inLink.Close(); cErr != nil {
				log.Printf("[main] Warning: failed to close inbound XDP link while rolling back: %v", cErr)
			}
			// Drop the inbound link from the shutdown tracking list so the
			// EXIT handler doesn't try to Close() it twice.
			xdpLinks = xdpLinks[:len(xdpLinks)-1]
			xdpAttachedIfaces = xdpAttachedIfaces[:len(xdpAttachedIfaces)-1]
			if rErr := ifMgr.RestoreAll(); rErr != nil {
				log.Printf("[main] Warning: interface restore reported errors during fatal cleanup: %v", rErr)
			}
			log.Fatalf("Failed to attach XDP to %s: %v", pair.Outbound, err)
		}
		xdpLinks = append(xdpLinks, outLink)
		xdpAttachedIfaces = append(xdpAttachedIfaces, pair.Outbound)
		log.Printf("XDP program attached to %s (outbound)", pair.Outbound)

	} else {
		// === TRADITIONAL MODE ===
		log.Println("Traditional mode (single interface)")
		// Pre-detach: clear any stale XDP program left by a previous crash/kill -9.
		// Error is expected when nothing is attached — we only log.
		if err := detachXDP(cfg.Server.Interface); err != nil {
			log.Printf("[main] pre-detach XDP from %s returned error (likely no program attached): %v", cfg.Server.Interface, err)
		}
		lnk, err := attachXDPLink(xdpProg, cfg.Server.Interface)
		if err != nil {
			log.Fatalf("Failed to attach XDP to %s: %v", cfg.Server.Interface, err)
		}
		xdpLinks = append(xdpLinks, lnk)
		xdpAttachedIfaces = append(xdpAttachedIfaces, cfg.Server.Interface)
		log.Printf("XDP program attached to %s", cfg.Server.Interface)
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

// attachXDPLink wires the XDP program onto the named interface via
// cilium/ebpf's link package. Flags: 0 requests kernel best-effort
// (native if the driver supports it, generic otherwise) — this matches
// the pre-migration goebpf XdpAttachModeNone default behaviour
// (proposal §5.1 / AUD-MIG-001). Do NOT hardcode link.XDPGenericMode;
// a future config knob cfg.XDP.Mode can override if operators need it.
//
// KERNEL FLOOR: cilium/ebpf v0.21.0's link.AttachXDP issues BPF_LINK_CREATE
// with type BPF_LINK_TYPE_XDP, which landed in Linux 5.9. Phase 2 of the
// goebpf→cilium/ebpf migration intentionally does NOT implement the pre-5.9
// netlink-attach fallback described in §Phase 4.a of the proposal — the
// audit closure for AUD-PH2-001 narrows the supported floor to 5.9+ on the
// grounds that every current stable distro ships a recent-enough kernel
// (Debian 11+, RHEL 9+, Ubuntu 20.04 HWE+). On older kernels the returned
// error is wrapped with an explicit pointer at this comment so operators
// don't have to guess.
func attachXDPLink(xdpProg *ebpf.Program, ifname string) (link.Link, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %s: %w", ifname, err)
	}
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
		// Flags: 0 (default) — best-effort / auto-select.
	})
	if err != nil {
		if isXDPLinkUnsupported(err) {
			return nil, fmt.Errorf(
				"link.AttachXDP(%s) failed: %w\n\n"+
					"  xdrop requires Linux 5.9+ for XDP attach (BPF_LINK_TYPE_XDP).\n"+
					"  The pre-5.9 netlink fallback described in the migration\n"+
					"  proposal §Phase 4.a is intentionally NOT implemented — closure\n"+
					"  for AUD-PH2-001. Upgrade the host kernel or hold xdrop on the\n"+
					"  prior v2.4.2 goebpf-based release.",
				ifname, err)
		}
		return nil, fmt.Errorf("link.AttachXDP(%s): %w", ifname, err)
	}
	return lnk, nil
}

// isXDPLinkUnsupported heuristically classifies an AttachXDP error as
// "kernel lacks BPF_LINK_TYPE_XDP support". cilium/ebpf surfaces this via
// ebpf.ErrNotSupported; older kernels can also return ENOTSUP / EOPNOTSUPP
// directly. We deliberately do NOT match EINVAL (too ambiguous — many real
// misuse cases also return EINVAL and we don't want false positives leading
// operators to suspect the kernel when the fault is in xdrop config).
func isXDPLinkUnsupported(err error) bool {
	if errors.Is(err, ebpf.ErrNotSupported) {
		return true
	}
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		return true
	}
	return false
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

// detachXDP removes any stale XDP program from an interface using the `ip`
// command. Kept post-migration as a pre-attach cleanup helper for recovery
// from crashes / kill -9 — see proposal §5.5. Normal-path detach is now
// link.Close() on the shutdown-tracked Link objects.
func detachXDP(ifname string) error {
	return exec.Command("ip", "link", "set", ifname, "xdp", "off").Run()
}

// uint32ToBytes converts uint32 to little-endian byte slice
func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
