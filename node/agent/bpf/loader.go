// Package bpf implements Phase 3 of the goebpf→cilium/ebpf migration:
// BPF map pinning with an operator-configurable policy.
//
// The loader wraps cilium/ebpf's `LoadCollectionSpec` + `NewCollection`
// path and threads three concerns the library does not handle on its own:
//
//  1. bpffs precondition (§Phase 3.a). We statfs the pin root and only
//     proceed with pinning if the filesystem reports BPF_FS_MAGIC. When
//     it doesn't, the `auto` policy downgrades to non-pinned mode with
//     a WARN log; the `require` policy fails startup loudly.
//
//  2. Pinned-map schema drift (§Phase 3.b). If an existing pinned map
//     on disk has a different type/key size/value size/max_entries/flags
//     than the ELF spec, we unlink it before creating a fresh map.
//     cilium/ebpf's own NewCollection would otherwise refuse to load
//     with a typed error; we prefer an explicit wipe-and-recreate so
//     operators don't have to run a manual `rm /sys/fs/bpf/xdrop/*`
//     every time the BPF ELF's map layout is intentionally updated.
//
//  3. Recoverable pinning failures (§Phase 3.c). EPERM, ENOSPC, or any
//     other NewCollectionWithOptions error that is not an outright
//     "can't load the program" is classified as pinning-unavailable
//     under the `auto` policy and retried in non-pinned mode.
//
// The pinning policy itself comes from cfg.BPF.Pinning — see the §Phase
// 3.d knob documented in node/agent/config/config.go.
package bpf

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// bpfFSMagic is the Linux kernel's BPF_FS_MAGIC constant (see
// include/uapi/linux/magic.h). `statfs(2)` on a correctly-mounted bpffs
// returns this in f_type.
const bpfFSMagic int64 = 0xCAFE4A11

// DefaultPinRoot is where Phase 3 pins all xdrop maps. Fixed rather than
// config-driven because /sys/fs/bpf is the canonical bpffs mountpoint on
// every supported distro, and xdrop must coexist with other BPF tooling
// (xnat, xsight, third-party) pinning under the same root. The `xdrop/`
// subdirectory isolates xdrop-owned state.
const DefaultPinRoot = "/sys/fs/bpf/xdrop"

// Mode selects the pinning policy.
type Mode string

const (
	// ModeAuto: try pinning, silently fall back if unavailable.
	ModeAuto Mode = "auto"
	// ModeRequire: fail startup if pinning cannot be enabled.
	ModeRequire Mode = "require"
	// ModeDisable: never pin.
	ModeDisable Mode = "disable"
)

// Options governs a single LoadCollection call.
type Options struct {
	// SpecPath is the path to the BPF ELF file.
	SpecPath string
	// PinRoot is the bpffs directory that will hold the pin files.
	// Defaults to DefaultPinRoot when empty.
	PinRoot string
	// Mode selects the pinning policy. Empty string ≡ ModeAuto.
	Mode Mode
}

// Result reports what the loader actually did, for logging + LT
// assertions. PinPath is non-empty iff the collection's maps are pinned.
type Result struct {
	// EffectiveMode is the mode the loader actually used. Differs from
	// Options.Mode only when Auto falls back to non-pinned (EffectiveMode
	// becomes "disabled" with FallbackReason populated).
	EffectiveMode Mode
	// PinPath is the directory maps are pinned under, or "" if unpinned.
	PinPath string
	// FallbackReason is non-empty when EffectiveMode != Options.Mode.
	FallbackReason string
	// Wiped lists maps that had an incompatible pinned version unlinked
	// before loading. Empty on a clean first boot.
	Wiped []string
}

// Load parses a BPF ELF into a Collection, honouring the pinning mode.
// Returns the Collection and a Result describing the pin outcome.
//
// The caller must Close() the returned Collection on shutdown. Pinned
// maps survive Close(); unpinned maps are freed.
func Load(opts Options) (*ebpf.Collection, Result, error) {
	spec, err := ebpf.LoadCollectionSpec(opts.SpecPath)
	if err != nil {
		return nil, Result{}, fmt.Errorf("parse ELF %q: %w", opts.SpecPath, err)
	}
	return loadFromSpec(spec, opts)
}

// loadFromSpec is the core logic — split out so tests can inject a
// hand-built CollectionSpec without writing an ELF to disk.
func loadFromSpec(spec *ebpf.CollectionSpec, opts Options) (*ebpf.Collection, Result, error) {
	mode := opts.Mode
	if mode == "" {
		mode = ModeAuto
	}
	pinRoot := opts.PinRoot
	if pinRoot == "" {
		pinRoot = DefaultPinRoot
	}

	if mode == ModeDisable {
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			return nil, Result{}, fmt.Errorf("load BPF collection (pinning disabled): %w", err)
		}
		return coll, Result{EffectiveMode: ModeDisable, FallbackReason: "config bpf.pinning=disable"}, nil
	}

	// Probe bpffs. Failure here is "pinning unavailable" — under Auto we
	// fall through to non-pinned load, under Require we fail.
	if err := probeBPFFS(pinRoot); err != nil {
		if mode == ModeRequire {
			return nil, Result{}, fmt.Errorf("bpf.pinning=require but bpffs probe failed: %w", err)
		}
		log.Printf("[bpf] WARN: pinning disabled: %v", err)
		coll, cerr := ebpf.NewCollection(spec)
		if cerr != nil {
			return nil, Result{}, fmt.Errorf("load BPF collection (pinning fallback): %w", cerr)
		}
		return coll, Result{EffectiveMode: ModeDisable, FallbackReason: err.Error()}, nil
	}

	// Ensure the per-agent pin directory exists. 0700 because bpffs
	// contents expose raw kernel state; anyone who can read the fds
	// effectively gets CAP_BPF-equivalent read power over the maps.
	if err := os.MkdirAll(pinRoot, 0o700); err != nil {
		if mode == ModeRequire {
			return nil, Result{}, fmt.Errorf("bpf.pinning=require: MkdirAll(%s): %w", pinRoot, err)
		}
		log.Printf("[bpf] WARN: pinning disabled: MkdirAll(%s): %v", pinRoot, err)
		coll, cerr := ebpf.NewCollection(spec)
		if cerr != nil {
			return nil, Result{}, fmt.Errorf("load BPF collection (MkdirAll fallback): %w", cerr)
		}
		return coll, Result{EffectiveMode: ModeDisable, FallbackReason: err.Error()}, nil
	}

	// Walk pinned maps that already exist on disk; if any has a schema
	// that doesn't match what the new ELF expects, unlink it so the load
	// below creates a fresh one. Strict equality per proposal §3.b — we
	// do not attempt any semver-like migration.
	wiped, err := reconcilePinnedMaps(spec, pinRoot)
	if err != nil {
		if mode == ModeRequire {
			return nil, Result{}, fmt.Errorf("bpf.pinning=require: reconcile pinned maps: %w", err)
		}
		log.Printf("[bpf] WARN: pinning disabled: reconcile pinned maps: %v", err)
		coll, cerr := ebpf.NewCollection(spec)
		if cerr != nil {
			return nil, Result{}, fmt.Errorf("load BPF collection (reconcile fallback): %w", cerr)
		}
		return coll, Result{EffectiveMode: ModeDisable, FallbackReason: err.Error()}, nil
	}

	// Tag every map for pinning. cilium/ebpf then either creates +
	// pins, or loads an existing pin, depending on presence on disk.
	// The ORDER matters: we flipped Pinning BEFORE NewCollection sees
	// the spec.
	for _, ms := range spec.Maps {
		ms.Pinning = ebpf.PinByName
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinRoot},
	})
	if err != nil {
		if mode == ModeRequire {
			return nil, Result{}, fmt.Errorf("bpf.pinning=require: NewCollectionWithOptions: %w", err)
		}
		log.Printf("[bpf] WARN: pinning failed, retrying without pin: %v", err)
		// Reset Pinning flag so the retry doesn't keep the per-map PinByName.
		for _, ms := range spec.Maps {
			ms.Pinning = ebpf.PinNone
		}
		coll2, cerr := ebpf.NewCollection(spec)
		if cerr != nil {
			return nil, Result{}, fmt.Errorf("load BPF collection (NewCollectionWithOptions fallback): %w", cerr)
		}
		return coll2, Result{EffectiveMode: ModeDisable, FallbackReason: err.Error(), Wiped: wiped}, nil
	}
	return coll, Result{EffectiveMode: ModeAuto, PinPath: pinRoot, Wiped: wiped}, nil
}

// probeBPFFS verifies the given directory lives on a bpf-typed filesystem.
// It is valid for the directory itself to not yet exist — statfs on the
// parent covers that case because mount type is a filesystem-wide
// attribute.
func probeBPFFS(dir string) error {
	// Walk up until a path that exists — bpffs root (/sys/fs/bpf) must
	// exist; any deeper path might not yet be created, but statfs on
	// /sys/fs/bpf still answers.
	probe := dir
	for {
		if _, err := os.Stat(probe); err == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return fmt.Errorf("no existing ancestor of %q to probe", dir)
		}
		probe = parent
	}
	var st unix.Statfs_t
	if err := unix.Statfs(probe, &st); err != nil {
		return fmt.Errorf("statfs(%q): %w", probe, err)
	}
	if int64(st.Type) != bpfFSMagic {
		return fmt.Errorf("filesystem at %q is not bpffs (f_type=0x%x, want 0x%x); mount with `mount -t bpf bpf /sys/fs/bpf`", probe, uint64(st.Type), uint64(bpfFSMagic))
	}
	return nil
}

// reconcilePinnedMaps walks spec.Maps and, for each map that already has
// a pin file under pinRoot, compares the on-disk schema against the
// spec. Mismatches are unlinked (not loaded), so the subsequent
// NewCollectionWithOptions call creates a fresh one. Returns the list of
// wiped map names for caller logging.
func reconcilePinnedMaps(spec *ebpf.CollectionSpec, pinRoot string) ([]string, error) {
	var wiped []string
	for name, ms := range spec.Maps {
		path := filepath.Join(pinRoot, name)
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return wiped, fmt.Errorf("stat pin file %q: %w", path, err)
		}

		pinned, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			// Pin exists but cilium refuses to open it → wipe and let
			// the load path recreate. This handles corrupted state from
			// a previous crash during map create.
			log.Printf("[bpf] WARN: pinned map %q unreadable (%v), unlinking", path, err)
			if rerr := os.Remove(path); rerr != nil {
				return wiped, fmt.Errorf("unlink %q: %w", path, rerr)
			}
			wiped = append(wiped, name)
			continue
		}

		info, err := pinned.Info()
		if err != nil {
			pinned.Close()
			log.Printf("[bpf] WARN: pinned map %q info unavailable (%v), unlinking", path, err)
			if rerr := os.Remove(path); rerr != nil {
				return wiped, fmt.Errorf("unlink %q: %w", path, rerr)
			}
			wiped = append(wiped, name)
			continue
		}

		if mismatch := compareMapSchema(info, ms); mismatch != "" {
			pinned.Close()
			log.Printf("[bpf] WARN: pinned map %q schema drift (%s), unlinking", path, mismatch)
			if rerr := os.Remove(path); rerr != nil {
				return wiped, fmt.Errorf("unlink %q: %w", path, rerr)
			}
			wiped = append(wiped, name)
			continue
		}
		// Close our probe fd — cilium/ebpf will re-open via PinByName.
		pinned.Close()
	}
	return wiped, nil
}

// ClearDataMaps empties every hash / LPM-trie map named in dataMapNames.
// Must be called after Load() returns a pin-enabled Result but BEFORE the
// API handlers expose the agent to the controller, so controller
// AtomicSync / per-rule Update(UpdateNoExist) call sites don't trip
// ErrKeyExist on leftover entries from a previous agent's life.
//
// Phase 3 explicitly does NOT promise data-plane continuity across
// restart — that's Phase 4's link-pinning scope. What Phase 3 gives is
// map-infrastructure continuity (stable map IDs, same fds for bpftool
// observers, config-map continuity). Data-map contents are wiped by
// design so the agent's in-memory rule index and the pinned state
// reconverge on controller resync.
//
// Config / stats / devmap / active_config must NOT be in dataMapNames —
// they're either re-initialised by NewHandlers or carry cumulative
// counters worth preserving.
func ClearDataMaps(coll *ebpf.Collection, dataMapNames []string) error {
	var firstErr error
	wiped := 0
	for _, name := range dataMapNames {
		m, ok := coll.Maps[name]
		if !ok || m == nil {
			continue
		}
		if err := clearHashOrTrie(m); err != nil {
			log.Printf("[bpf] WARN: ClearDataMaps(%s): %v", name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		wiped++
	}
	if wiped > 0 {
		log.Printf("[bpf] cleared %d data map(s) for pin-reuse reconciliation", wiped)
	}
	return firstErr
}

// clearHashOrTrie deletes every entry from a hash or LPM_TRIE map via
// iterator. Kernel array types (ARRAY / PERCPU_ARRAY / DEVMAP) do not
// support Delete and would error out; they must not be in the clear
// list. We let the Delete failure bubble up, not try to be clever.
func clearHashOrTrie(m *ebpf.Map) error {
	var keys [][]byte
	iter := m.Iterate()
	ksz := int(m.KeySize())
	if ksz <= 0 {
		return nil
	}
	key := make([]byte, ksz)
	// Scratch value for Iterate — cilium requires a destination even if
	// we only care about keys. Value size may be 0 on percpu, but this
	// helper is only for hash/LPMTrie so it's always nonzero.
	valScratch := make([]byte, max(int(m.ValueSize()), 1))
	for iter.Next(&key, &valScratch) {
		kc := make([]byte, len(key))
		copy(kc, key)
		keys = append(keys, kc)
	}
	if err := iter.Err(); err != nil {
		// Continue to delete whatever we did collect; iteration errors
		// are not fatal for clearing.
		log.Printf("[bpf] iterator over %s returned %v (continuing with %d collected keys)",
			m.String(), err, len(keys))
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil {
			return fmt.Errorf("delete key from %s: %w", m.String(), err)
		}
	}
	return nil
}

// compareMapSchema returns a human-readable description of the first
// mismatched field, or "" if every tracked field matches (§3.b). Strict
// equality on Type / KeySize / ValueSize / MaxEntries. Flags use
// "spec bits subset of info bits" semantics, NOT pure equality, because
// some map types (notably BPF_MAP_TYPE_DEVMAP) have kernel-internal
// flag bits auto-added at create time — DEVMAP gets BPF_F_RDONLY_PROG
// (0x80) set by the kernel regardless of user spec. Pure equality would
// false-positive these as schema drift on every single restart after
// the first. What we really want to catch is user-visible flag drift
// (e.g. operator added BPF_F_NO_PREALLOC in the ELF but the pinned map
// was created without it), which the subset check still catches
// correctly because spec.Flags becoming a non-subset means a bit
// required by the new spec is missing from the pinned map.
func compareMapSchema(info *ebpf.MapInfo, spec *ebpf.MapSpec) string {
	if info.Type != spec.Type {
		return fmt.Sprintf("type %v != spec %v", info.Type, spec.Type)
	}
	if info.KeySize != spec.KeySize {
		return fmt.Sprintf("key_size %d != spec %d", info.KeySize, spec.KeySize)
	}
	if info.ValueSize != spec.ValueSize {
		return fmt.Sprintf("value_size %d != spec %d", info.ValueSize, spec.ValueSize)
	}
	if info.MaxEntries != spec.MaxEntries {
		return fmt.Sprintf("max_entries %d != spec %d", info.MaxEntries, spec.MaxEntries)
	}
	// Require every bit the current ELF spec asks for to be present in
	// the pinned map. Extra kernel-injected bits (DEVMAP's 0x80, etc.)
	// are ignored.
	if info.Flags&spec.Flags != spec.Flags {
		return fmt.Sprintf("flags 0x%x missing bits from spec 0x%x", info.Flags, spec.Flags)
	}
	return ""
}
