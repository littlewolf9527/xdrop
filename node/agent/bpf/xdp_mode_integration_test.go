//go:build linux && integration

package bpf

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Run only via the delivered private-netns runner. Missing envelope inputs fail;
// they are never converted to SKIP or an implicit default pin root.
// The runner must mount a private bpffs in netns exec's private mount namespace first (ip netns exec does not bring bpffs); never use the host bpffs.
type td073Envelope struct {
	t          *testing.T
	root       string
	hostNS     uint64
	interfaces map[string]bool
}

func (e *td073Envelope) namespace() {
	e.t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &st); err != nil {
		e.t.Fatal(err)
	}
	if st.Ino == e.hostNS {
		e.t.Fatal("envelope: test is in host netns")
	}
}
func (e *td073Envelope) path(path string) {
	e.t.Helper()
	e.namespace()
	if path == "" || filepath.Clean(path) != path || !strings.HasPrefix(path, e.root+"/") {
		e.t.Fatalf("envelope: pin path outside private root: %q", path)
	}
	for p := path; p != filepath.Dir(e.root); p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil && !os.IsNotExist(err) {
			e.t.Fatal(err)
		}
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			e.t.Fatalf("envelope: symlink in pin path %s", p)
		}
	}
}
func (e *td073Envelope) iface(name string) {
	e.t.Helper()
	e.namespace()
	if !e.interfaces[name] {
		e.t.Fatalf("envelope: interface not created by this test: %q", name)
	}
}
func (e *td073Envelope) ip(args ...string) {
	e.t.Helper()
	e.namespace()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		e.t.Fatalf("ip %v: %s: %v", args, out, err)
	}
}
func (e *td073Envelope) load(path, name string) *ebpf.Collection {
	e.t.Helper()
	opts := Options{SpecPath: path, Mode: ModeRequire, PinRoot: filepath.Join(e.root, name), PinNoneOverrides: []string{"tailcall_fail_stats"}}
	// These checks precede Load, which may create/reconcile/pin maps.
	e.path(opts.PinRoot)
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		e.t.Fatal(err)
	}
	for key, m := range spec.Maps {
		e.path(filepath.Join(opts.PinRoot, key))
		e.path(filepath.Join(opts.PinRoot, m.Name))
	}
	coll, result, err := Load(opts)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(coll.Close)
	if result.PinPath != opts.PinRoot {
		e.t.Fatalf("unexpected actual PinRoot: %+v", result)
	}
	if coll.Programs["xdp_whitelist_gate"] == nil {
		e.t.Fatal("ELF lacks xdp_whitelist_gate")
	}
	return coll
}

type td073GuardOps struct {
	realLinkOps
	envelope *td073Envelope
}
type td073GuardLink struct {
	XDPLink
	envelope       *td073Envelope
	ifaceName, pin string
}

func (l *td073GuardLink) Update(p *ebpf.Program) error {
	l.envelope.iface(l.ifaceName)
	return l.XDPLink.Update(p)
}
func (l *td073GuardLink) Pin(path string) error {
	l.envelope.iface(l.ifaceName)
	l.envelope.path(path)
	err := l.XDPLink.Pin(path)
	if err == nil {
		l.pin = path
	}
	return err
}
func (l *td073GuardLink) Unpin() error {
	l.envelope.iface(l.ifaceName)
	l.envelope.path(l.pin)
	return l.XDPLink.Unpin()
}
func (l *td073GuardLink) Close() error { l.envelope.iface(l.ifaceName); return l.XDPLink.Close() }
func (o td073GuardOps) ProbeBPFFS(path string) error {
	o.envelope.path(path)
	return o.realLinkOps.ProbeBPFFS(path)
}
func (o td073GuardOps) MkdirAll(path string, mode os.FileMode) error {
	o.envelope.path(path)
	return o.realLinkOps.MkdirAll(path, mode)
}
func (o td073GuardOps) StatPin(path string) error {
	o.envelope.path(path)
	return o.realLinkOps.StatPin(path)
}
func (o td073GuardOps) RemovePin(path string) error {
	o.envelope.path(path)
	o.envelope.iface(strings.TrimPrefix(filepath.Base(path), linkPinPrefix))
	return o.realLinkOps.RemovePin(path)
}
func (o td073GuardOps) LoadPinned(path string) (XDPLink, error) {
	o.envelope.path(path)
	name := strings.TrimPrefix(filepath.Base(path), linkPinPrefix)
	o.envelope.iface(name)
	l, err := o.realLinkOps.LoadPinned(path)
	if err != nil {
		return nil, err
	}
	return &td073GuardLink{l, o.envelope, name, path}, nil
}
func (o td073GuardOps) PreDetach(name string) { o.envelope.iface(name); o.realLinkOps.PreDetach(name) }
func (o td073GuardOps) ReadXDP(name string) (XDPAttachment, error) {
	o.envelope.iface(name)
	return o.realLinkOps.ReadXDP(name)
}
func (o td073GuardOps) AttachXDP(p *ebpf.Program, name string, mode XDPMode) (XDPLink, error) {
	o.envelope.iface(name)
	l, err := o.realLinkOps.AttachXDP(p, name, mode)
	if err != nil {
		return nil, err
	}
	return &td073GuardLink{l, o.envelope, name, ""}, nil
}

func TestTD073Kernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	run := os.Getenv("TD073_RUN_ID")
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`).MatchString(run) {
		t.Fatal("TD073_RUN_ID required: 1-32 lowercase letters/digits/hyphens")
	}
	host, err := strconv.ParseUint(os.Getenv("TD073_HOST_NETNS_INODE"), 10, 64)
	if err != nil || host == 0 {
		t.Fatal("TD073_HOST_NETNS_INODE required")
	}
	root := "/sys/fs/bpf/xdrop-td073-" + run
	if os.Getenv("TD073_PIN_ROOT") != root {
		t.Fatal("TD073_PIN_ROOT must equal the private run root")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("private pin root must not exist before test")
	}
	e := &td073Envelope{t: t, root: root, hostNS: host, interfaces: map[string]bool{}}
	e.namespace()
	// Create only known interfaces in the already-private namespace. No addresses.
	e.ip("link", "add", "td073v0", "type", "veth", "peer", "name", "td073v1")
	e.interfaces["td073v0"], e.interfaces["td073v1"] = true, true
	t.Cleanup(func() { e.iface("td073v0"); e.ip("link", "del", "td073v0") })
	e.ip("link", "add", "td073d0", "type", "dummy")
	e.interfaces["td073d0"] = true
	t.Cleanup(func() { e.iface("td073d0"); e.ip("link", "del", "td073d0") })
	for name := range e.interfaces {
		e.iface(name)
		e.ip("link", "set", name, "up")
	}
	// Cleanup is registered before Load, so partial map pinning is covered.
	t.Cleanup(func() {
		e.namespace()
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if path != root {
				e.path(path)
			}
			if !d.IsDir() {
				e.path(path)
				return os.Remove(path)
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
		// Every file unlink was checked above; RemoveAll now removes directories.
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
		if _, err := os.Lstat(root); !os.IsNotExist(err) {
			t.Error("private pin root survived cleanup")
		}
	})
	gate := os.Getenv("TD073_GATE_ELF")
	if gate == "" || !filepath.IsAbs(gate) {
		t.Fatal("TD073_GATE_ELF must be an absolute path to the real gate ELF")
	}
	current := e.load(gate, "maps-current")
	other := e.load(gate, "maps-other")
	p, q := current.Programs["xdp_whitelist_gate"], other.Programs["xdp_whitelist_gate"]
	id, err := (realLinkOps{}).ProgramID(p)
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := (realLinkOps{}).ProgramID(q)
	if err != nil || otherID == id {
		t.Fatalf("independent program identity: %d %d %v", id, otherID, err)
	}
	links := filepath.Join(root, "links")
	e.path(links)
	count := 0
	t.Run("attach-layer-native-dummy", func(t *testing.T) {
		count++
		sub := *e
		sub.t = t
		ops := td073GuardOps{envelope: &sub}
		// Direct real AttachXDP boundary, independent of resolver rejection/cleanup.
		sub.iface("td073d0")
		l, err := (realLinkOps{}).AttachXDP(p, "td073d0", XDPNative)
		if l != nil {
			t.Cleanup(func() {
				sub.iface("td073d0")
				if err := l.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		if err == nil {
			t.Error("attach-layer native dummy MUST return kernel error")
		}
		td073AssertNone(t, ops, "td073d0")
	})
	if t.Failed() {
		t.Fatal("STOP: attach-layer prerequisite failed")
	}
	for _, c := range []struct {
		name, iface string
		request     XDPMode
		mode        string
		fail        bool
	}{
		{"veth-native", "td073v0", XDPNative, "native", false},
		{"veth-generic", "td073v0", XDPGeneric, "generic", false},
		{"veth-auto", "td073v0", XDPAuto, "native", false},
		{"dummy-native", "td073d0", XDPNative, "", true},
		{"dummy-auto", "td073d0", XDPAuto, "generic", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			count++
			sub := *e
			sub.t = t
			ops := td073GuardOps{envelope: &sub}
			var output bytes.Buffer
			writer := log.Writer()
			log.SetOutput(&output)
			defer log.SetOutput(writer)
			res, err := resolveXDPLink(p, c.iface, ModeRequire, c.request, links, ops)
			if res != nil {
				t.Cleanup(func() {
					if err := res.ForceDetach(); err != nil {
						t.Error(err)
					}
					td073AssertNone(t, ops, c.iface)
				})
			}
			if c.fail {
				if err == nil || XDPFailureReason(err) != "xdp_attach_failed" {
					t.Fatalf("dummy native prerequisite: kernel attach must reject: %v", err)
				}
				td073AssertNone(t, ops, c.iface)
				return
			}
			if err != nil {
				t.Fatalf("kernel prerequisite/attach: %v", err)
			}
			if res.AttachMode != c.mode || res.Reused {
				t.Fatalf("AttachMode=%q Reused=%v want %q false", res.AttachMode, res.Reused, c.mode)
			}
			got, err := readVerifiedXDP(p, c.iface, ops)
			if err != nil || got != c.mode {
				t.Fatalf("identity/mode: %q %v", got, err)
			}
			if c.name == "dummy-auto" && !strings.Contains(output.String(), "性能约低一个量级") {
				t.Fatal("dummy-auto WARN missing")
			}
		})
		if t.Failed() {
			t.Fatal("STOP: kernel prerequisite/case failed")
		}
	}
	t.Run("reuse-generic-to-native", func(t *testing.T) {
		count++
		sub := *e
		sub.t = t
		ops := td073GuardOps{envelope: &sub}
		old, err := resolveXDPLink(q, "td073v0", ModeRequire, XDPGeneric, links, ops)
		if err != nil {
			t.Fatal(err)
		}
		oldInfo, err := old.Link.(*td073GuardLink).XDPLink.(link.Link).Info()
		if err != nil {
			t.Fatal(err)
		}
		if err := old.Link.Close(); err != nil {
			t.Fatal(err)
		}
		res, err := resolveXDPLink(p, "td073v0", ModeRequire, XDPNative, links, ops)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := res.ForceDetach(); err != nil {
				t.Error(err)
			}
			td073AssertNone(t, ops, "td073v0")
		})
		if res.Reused || res.AttachMode != "native" {
			t.Fatalf("mode change did not reattach: %+v", res)
		}
		sub.path(res.PinPath)
		pinned, err := link.LoadPinnedLink(res.PinPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer pinned.Close()
		info, err := pinned.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.ID == oldInfo.ID || uint32(info.Program) != id {
			t.Fatalf("pin not replaced with current program: old=%+v new=%+v", oldInfo, info)
		}
		mode, err := readVerifiedXDP(p, "td073v0", ops)
		if err != nil || mode != "native" {
			t.Fatalf("remount identity: %q %v", mode, err)
		}
	})
	if t.Failed() {
		t.Fatal("STOP: remount case failed")
	}
	t.Run("foreign-program", func(t *testing.T) {
		count++
		sub := *e
		sub.t = t
		ops := td073GuardOps{envelope: &sub}
		l, err := ops.AttachXDP(q, "td073v0", XDPGeneric)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := l.Close(); err != nil {
				t.Error(err)
			}
			td073AssertNone(t, ops, "td073v0")
		})
		// No resolver/PreDetach: keep the other program attached as the control.
		_, err = readVerifiedXDP(p, "td073v0", ops)
		if XDPFailureReason(err) != "xdp_prog_mismatch" {
			t.Fatalf("foreign identity reason=%q want xdp_prog_mismatch: %v", XDPFailureReason(err), err)
		}
	})
	if count != 8 {
		t.Fatalf("kernel cases=%d want 8", count)
	}
	fmt.Printf("TD073_KERNEL_CASES ran=%d skip=0\n", count)
}

func td073AssertNone(t *testing.T, ops td073GuardOps, name string) {
	t.Helper()
	snapshot, err := ops.ReadXDP(name)
	if err != nil || snapshot.Attached != 0 {
		t.Errorf("interface must have no residual XDP: %+v %v", snapshot, err)
	}
}
