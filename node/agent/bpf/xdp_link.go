// Phase 4 of the goebpf→cilium/ebpf migration: pin the XDP link itself,
// enabling zero-gap program updates across agent restart.
//
// The current Phase 3 shape is:
//   - Maps are pinned; they survive restart.
//   - The XDP program is (re-)loaded from the ELF each boot and attached
//     via link.AttachXDP → link.Link. Close() on shutdown detaches XDP.
//     Result: a ~1.5–3 s gap where no filter is in the data path.
//
// Phase 4 closes that gap. Instead of always-fresh attach:
//  1. Check whether a pinned link exists for this interface under
//     <pinRoot>/link_<ifname>.
//  2. If it does, LoadPinnedLink + Update(newProg) atomically swaps
//     the program bytecode in-place. No detach, no reattach.
//  3. Otherwise fresh AttachXDP + Pin(linkPath).
//
// The whole dance is gated on the same bpf.pinning knob as Phase 3:
//   - auto    → try link pin; silently downgrade to Phase-2-equivalent
//     fresh attach when the kernel or bpffs rejects it.
//   - require → hard-fail startup if link pinning isn't available.
//   - disable → always fresh attach; actively clean up any stale pin so
//     operators who toggle auto→disable aren't left with a
//     zombie kernel link they can't detach via `ip link`.
//
// §Phase 4 of the migration proposal. Kernel floor: Linux 5.9 (same as
// the Phase 2 kernel floor — BPF_LINK_TYPE_XDP landed in 5.9).
package bpf

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// linkPinPrefix is the filename prefix for XDP link pins. The pin root
// (/sys/fs/bpf/xdrop by default) holds both map pins (named by BPF map
// name, e.g. `blacklist`) and link pins (named `link_<ifname>`). The
// prefix disambiguates and makes the pin easy to spot in bpftool.
const linkPinPrefix = "link_"

// LinkPinPathFor returns the canonical pin path for the XDP link on
// `ifname` under `pinRoot`. Callers that need to poke at the pin file
// directly (e.g. rollback / cleanup tooling) should use this helper so
// the path convention stays in one place.
func LinkPinPathFor(pinRoot, ifname string) string {
	return filepath.Join(pinRoot, linkPinPrefix+ifname)
}

// XDPLink is the narrow surface of a cilium/ebpf link.Link that Phase 4
// cares about: atomic program swap, pin, unpin, close. Declared here
// rather than reusing link.Link directly because link.Link has an
// unexported marker method (isLink) that prevents external packages
// (including tests) from synthesising fakes. The real link.Link
// satisfies this interface naturally by method-set match.
type XDPLink interface {
	// Update atomically swaps the attached program bytecode for prog.
	// This is the zero-gap path — no XDP detach/reattach on the iface.
	Update(prog *ebpf.Program) error
	// Pin persists the link under path on bpffs. The kernel then holds
	// a reference to the link independent of this process's fd, so the
	// link survives across agent restart.
	Pin(path string) error
	// Unpin drops the bpffs reference previously added by Pin. After
	// Unpin + Close the link's refcount hits zero and the kernel-side
	// XDP attachment is torn down. Used by ForceDetach on abnormal exit
	// paths (startup rollback) where we explicitly do NOT want the
	// attachment to survive.
	Unpin() error
	// Close releases this process's fd on the link. If the link has
	// been Pin()ed the kernel-side attachment survives; otherwise
	// Close() tears down the XDP attach as well.
	Close() error
}

// ResolvedXDPLink describes the outcome of ResolveXDPLink. Callers keep
// the Link in their shutdown-tracking slice and invoke Close() during
// graceful shutdown regardless of Pinned — Close on a pinned link only
// drops the userspace fd, the kernel-side attachment stays alive thanks
// to the pin file (that's the whole point of Phase 4). Abnormal exit
// paths (startup rollback, forced detach) should call ForceDetach()
// instead — it unlinks the pin BEFORE closing so the kernel-side
// attachment goes with us.
type ResolvedXDPLink struct {
	// Link is the live XDP link. Never nil when error is nil.
	Link XDPLink
	// PinPath is the absolute pin path, or "" when the link is not pinned.
	PinPath string
	// Reused is true when we loaded an existing pinned link and Update()d
	// its program pointer rather than creating a fresh attach.
	// Reused=true ⇒ zero-gap outcome for this interface.
	Reused bool
	// EffectiveMode captures the policy the resolver actually ran with.
	// auto may downgrade to disable at runtime; this field records that.
	EffectiveMode Mode
	// DowngradeReason is non-empty when EffectiveMode != requested Mode.
	DowngradeReason string
}

// ForceDetach tears down the XDP attachment unconditionally — if the
// link is pinned it Unpins first so the bpffs reference is released,
// then Close drops the fd and the kernel-side refcount hits zero.
// Intended for startup rollback and other error paths where leaving a
// pinned XDP program attached without an owning agent would be worse
// than briefly losing the filter. The graceful-shutdown path uses a
// plain Link.Close() instead so the pin survives into the next boot.
//
// Returns the first error encountered, but still best-effort calls
// every tear-down step so a failure in one doesn't prevent the rest.
func (r *ResolvedXDPLink) ForceDetach() error {
	if r == nil || r.Link == nil {
		return nil
	}
	var firstErr error
	if r.PinPath != "" {
		if err := r.Link.Unpin(); err != nil {
			firstErr = fmt.Errorf("unpin %s: %w", r.PinPath, err)
		}
	}
	if err := r.Link.Close(); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("close link: %w", err)
	}
	return firstErr
}

// ErrLinkPinningUnsupported is returned by ResolveXDPLink when
// Mode=require and the kernel or bpffs rejects link pinning. Wrapped;
// callers can errors.Is it to distinguish "upgrade kernel / fix bpffs"
// from "misconfigured agent".
var ErrLinkPinningUnsupported = errors.New("XDP link pinning unsupported")

// linkOps is the kernel-facing surface ResolveXDPLink invokes. Exposed
// as an interface so tests can drive the decision tree without actually
// touching BPF / netlink / bpffs.
type linkOps interface {
	// LoadPinned reopens a pinned link by path. Must surface
	// os.ErrNotExist when the pin file isn't there.
	LoadPinned(path string) (XDPLink, error)
	// AttachXDP calls link.AttachXDP on ifname with Flags=0.
	AttachXDP(prog *ebpf.Program, ifname string) (XDPLink, error)
	// PreDetach best-effort clears any non-link XDP program left on the
	// interface by a crashed previous-version agent. Errors are ignored
	// by ResolveXDPLink — nothing attached is the common case.
	PreDetach(ifname string)
	// StatPin returns nil when a pin file exists at path, or an error
	// (including os.ErrNotExist) otherwise.
	StatPin(path string) error
	// RemovePin removes the pin file at path. A nonexistent file is not
	// an error — callers use this both to unlink stale pins and after
	// Update() failures.
	RemovePin(path string) error
}

// realLinkOps is the production implementation of linkOps.
type realLinkOps struct{}

func (realLinkOps) LoadPinned(path string) (XDPLink, error) {
	l, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (realLinkOps) AttachXDP(prog *ebpf.Program, ifname string) (XDPLink, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %s: %w", ifname, err)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		// Flags: 0 — kernel best-effort (native where driver supports,
		// generic otherwise). Matches pre-migration XdpAttachModeNone.
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (realLinkOps) PreDetach(ifname string) {
	// Ignore the error: nothing attached is common and expected.
	_ = exec.Command("ip", "link", "set", ifname, "xdp", "off").Run()
}

func (realLinkOps) StatPin(path string) error {
	_, err := os.Stat(path)
	return err
}

func (realLinkOps) RemovePin(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// IsXDPLinkUnsupported reports whether err from AttachXDP / Pin / etc.
// indicates the running kernel doesn't support BPF_LINK_TYPE_XDP (pre-
// 5.9). Call sites use this to emit the "upgrade kernel or pin xdrop on
// v2.4.2 goebpf build" hint rather than a generic syscall error.
//
// Heuristic matches §Phase 2 closure for AUD-PH2-001: we treat
// ebpf.ErrNotSupported, ENOTSUP, and EOPNOTSUPP as "library / kernel
// says this kind of link isn't supported". EINVAL is deliberately
// excluded — it's too ambiguous (many real misuse cases also return
// EINVAL, and misclassifying would send operators chasing the wrong
// root cause).
func IsXDPLinkUnsupported(err error) bool {
	if errors.Is(err, ebpf.ErrNotSupported) {
		return true
	}
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		return true
	}
	return false
}

// ResolveXDPLink is the Phase 4 attach entrypoint. Given a program to
// attach and an interface name, it returns a ResolvedXDPLink describing
// what happened — caller decides how verbose to log and whether to
// tolerate a downgrade to the unpinned (Phase-2-equivalent) mode.
//
// mode=disable: always fresh attach, no pin. Any stale pin file is
//
//	actively unlinked so operators who flip auto→disable aren't left
//	with a kernel link they cannot detach via `ip link xdp off`.
//
// mode=auto / mode=require:
//
//  1. If a pin file exists, try LoadPinned + Update(newProg). Success →
//     zero-gap reuse.
//  2. If step 1 fails at any point, close any partial link, unlink the
//     pin file (releases the kernel-side bpf_link ref so AttachXDP
//     doesn't hit EBUSY on the interface), and fall through.
//  3. Best-effort pre-detach of any legacy non-link XDP program left
//     from a crashed pre-Phase-4 agent.
//  4. Fresh AttachXDP. If this fails on what looks like a pre-5.9
//     kernel, wrap the error with ErrLinkPinningUnsupported so require
//     mode can hard-fail with the right diagnostic.
//  5. Pin the newly attached link. If Pin fails:
//     - mode=require: close link, return ErrLinkPinningUnsupported.
//     - mode=auto: log a WARN, return the unpinned link. Next restart
//     goes through the full fresh-attach path with the usual Phase-2
//     gap; no worse than if Phase 4 weren't enabled at all.
func ResolveXDPLink(prog *ebpf.Program, ifname string, mode Mode, pinRoot string) (*ResolvedXDPLink, error) {
	return resolveXDPLink(prog, ifname, mode, pinRoot, realLinkOps{})
}

// resolveXDPLink is the pure decision-tree, parameterized over linkOps
// so tests can drive every branch without touching the kernel.
func resolveXDPLink(prog *ebpf.Program, ifname string, mode Mode, pinRoot string, ops linkOps) (*ResolvedXDPLink, error) {
	if mode == "" {
		mode = ModeAuto
	}

	// Disable path: always fresh. Actively sweep any stale link pin so
	// operators can switch auto→disable without zombie kernel links.
	if mode == ModeDisable {
		pinPath := LinkPinPathFor(pinRoot, ifname)
		if err := ops.StatPin(pinPath); err == nil {
			// Pin exists → release it. LoadPinned lets us Close() the
			// kernel ref cleanly; if that fails, RemovePin alone also
			// suffices once the agent process exits.
			if l, lerr := ops.LoadPinned(pinPath); lerr == nil {
				_ = l.Close()
			}
			if rerr := ops.RemovePin(pinPath); rerr != nil {
				log.Printf("[bpf] WARN: pinning=disable: could not remove stale link pin %q: %v", pinPath, rerr)
			}
		}
		ops.PreDetach(ifname)
		l, err := ops.AttachXDP(prog, ifname)
		if err != nil {
			return nil, fmt.Errorf("AttachXDP(%s): %w", ifname, wrapIfUnsupported(err))
		}
		return &ResolvedXDPLink{
			Link:            l,
			EffectiveMode:   ModeDisable,
			DowngradeReason: "config bpf.pinning=disable",
		}, nil
	}

	// Probe bpffs first. Without bpffs, pin/LoadPinned is a non-starter
	// — under auto we downgrade cleanly to Phase-2-equivalent fresh
	// attach; under require we fail loudly so operators notice.
	if err := probeBPFFS(pinRoot); err != nil {
		if mode == ModeRequire {
			return nil, fmt.Errorf("bpf.pinning=require: %w: %w", ErrLinkPinningUnsupported, err)
		}
		log.Printf("[bpf] WARN: link pinning downgraded: bpffs probe failed: %v", err)
		ops.PreDetach(ifname)
		l, aerr := ops.AttachXDP(prog, ifname)
		if aerr != nil {
			return nil, fmt.Errorf("AttachXDP(%s) (pin-downgrade): %w", ifname, wrapIfUnsupported(aerr))
		}
		return &ResolvedXDPLink{
			Link:            l,
			EffectiveMode:   ModeDisable,
			DowngradeReason: fmt.Sprintf("bpffs probe failed: %v", err),
		}, nil
	}

	// Ensure the pin-root directory exists. MkdirAll is a no-op when it
	// already does; bpffs doesn't support chmod so mode is advisory.
	if err := os.MkdirAll(pinRoot, 0o700); err != nil {
		if mode == ModeRequire {
			return nil, fmt.Errorf("bpf.pinning=require: MkdirAll(%s): %w: %w", pinRoot, ErrLinkPinningUnsupported, err)
		}
		log.Printf("[bpf] WARN: link pinning downgraded: MkdirAll(%s): %v", pinRoot, err)
		ops.PreDetach(ifname)
		l, aerr := ops.AttachXDP(prog, ifname)
		if aerr != nil {
			return nil, fmt.Errorf("AttachXDP(%s) (pin-downgrade): %w", ifname, wrapIfUnsupported(aerr))
		}
		return &ResolvedXDPLink{
			Link:            l,
			EffectiveMode:   ModeDisable,
			DowngradeReason: fmt.Sprintf("MkdirAll(%s): %v", pinRoot, err),
		}, nil
	}

	pinPath := LinkPinPathFor(pinRoot, ifname)

	// Step 1: try to reuse a pinned link.
	if serr := ops.StatPin(pinPath); serr == nil {
		l, lerr := ops.LoadPinned(pinPath)
		switch {
		case lerr == nil:
			// Got a live handle to the kernel-side link. Atomically
			// swap the program pointer. This is the zero-gap path.
			if uerr := l.Update(prog); uerr == nil {
				return &ResolvedXDPLink{
					Link:          l,
					PinPath:       pinPath,
					Reused:        true,
					EffectiveMode: ModeAuto,
				}, nil
			} else {
				// Update failed. Close our handle and unlink the pin so
				// the refcount drops to zero and we can AttachXDP fresh
				// without EBUSY on the interface.
				log.Printf("[bpf] WARN: Update() on pinned XDP link %q failed (%v), falling back to fresh attach", pinPath, uerr)
				_ = l.Close()
				if rerr := ops.RemovePin(pinPath); rerr != nil {
					log.Printf("[bpf] WARN: could not remove pin %q after Update failure: %v", pinPath, rerr)
				}
			}
		default:
			// Stat said yes, LoadPinned said no. Corrupt pin, stale
			// file, or kernel feature missing. Unlink and fall through.
			log.Printf("[bpf] WARN: LoadPinnedLink(%q) failed (%v), unlinking and falling back to fresh attach", pinPath, lerr)
			if rerr := ops.RemovePin(pinPath); rerr != nil {
				log.Printf("[bpf] WARN: could not remove unreadable pin %q: %v", pinPath, rerr)
			}
		}
	}

	// Step 3: fresh attach. Pre-detach legacy non-link XDP first.
	ops.PreDetach(ifname)
	freshLink, attachErr := ops.AttachXDP(prog, ifname)
	if attachErr != nil {
		wrapped := wrapIfUnsupported(attachErr)
		if mode == ModeRequire {
			return nil, fmt.Errorf("bpf.pinning=require: AttachXDP(%s): %w", ifname, wrapped)
		}
		return nil, fmt.Errorf("AttachXDP(%s): %w", ifname, wrapped)
	}

	// Step 5: pin the fresh link.
	if perr := freshLink.Pin(pinPath); perr != nil {
		if mode == ModeRequire {
			_ = freshLink.Close()
			return nil, fmt.Errorf("bpf.pinning=require: Pin(%s): %w: %w", pinPath, ErrLinkPinningUnsupported, perr)
		}
		log.Printf("[bpf] WARN: Pin(%q) failed (%v); XDP attached unpinned — next restart will have Phase-2 gap", pinPath, perr)
		return &ResolvedXDPLink{
			Link:            freshLink,
			EffectiveMode:   ModeDisable,
			DowngradeReason: fmt.Sprintf("Pin(%s): %v", pinPath, perr),
		}, nil
	}

	return &ResolvedXDPLink{
		Link:          freshLink,
		PinPath:       pinPath,
		EffectiveMode: ModeAuto,
	}, nil
}

// wrapIfUnsupported tags err with ErrLinkPinningUnsupported when the
// error looks like pre-5.9-kernel "BPF_LINK_TYPE_XDP not supported",
// leaving other errors untouched. Used on AttachXDP failures so require
// mode can emit a targeted diagnostic rather than a generic syscall
// error.
func wrapIfUnsupported(err error) error {
	if IsXDPLinkUnsupported(err) {
		return fmt.Errorf("%w: %w", ErrLinkPinningUnsupported, err)
	}
	return err
}
