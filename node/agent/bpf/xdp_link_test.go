//go:build linux

// Phase 4 unit coverage for the ResolveXDPLink decision tree. The
// interesting logic — "do we LoadPinned+Update, or fresh attach, or
// downgrade to unpinned?" — lives entirely in resolveXDPLink, which
// takes a linkOps dependency we can fake. We deliberately do NOT
// exercise the actual kernel attach path here; that's LT-X6's job
// and needs a real XDP program + interface.
//
// Default build tag (no `integration`) because these tests don't need
// CAP_BPF or a live kernel.
package bpf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

// fakeLink implements the narrow XDPLink interface this package uses.
// It does NOT implement cilium/ebpf's full link.Link (that interface
// has an unexported marker method preventing external fakes). The
// resolver never sees a real link.Link in tests — it only sees XDPLink.
type fakeLink struct {
	name       string
	updateErr  error
	pinErr     error
	closeErr   error
	closed     bool
	updateArgs []*ebpf.Program
	pinArgs    []string
}

func (f *fakeLink) Update(p *ebpf.Program) error {
	f.updateArgs = append(f.updateArgs, p)
	return f.updateErr
}
func (f *fakeLink) Pin(path string) error { f.pinArgs = append(f.pinArgs, path); return f.pinErr }
func (f *fakeLink) Close() error          { f.closed = true; return f.closeErr }

// fakeOps is a scripted linkOps implementation. Each call records its
// arguments, and returns values are pulled from the configured fields.
type fakeOps struct {
	statErr      error
	loadPinLink  XDPLink
	loadPinErr   error
	attachLink   XDPLink
	attachErr    error
	preDetachCnt int
	removePinCnt int
	removePinErr error
	statCalls    []string
	loadCalls    []string
	attachCalls  []string
	preDetachIfs []string
	removedPaths []string
}

func (o *fakeOps) LoadPinned(path string) (XDPLink, error) {
	o.loadCalls = append(o.loadCalls, path)
	return o.loadPinLink, o.loadPinErr
}

func (o *fakeOps) AttachXDP(prog *ebpf.Program, ifname string) (XDPLink, error) {
	o.attachCalls = append(o.attachCalls, ifname)
	return o.attachLink, o.attachErr
}

func (o *fakeOps) PreDetach(ifname string) {
	o.preDetachCnt++
	o.preDetachIfs = append(o.preDetachIfs, ifname)
}

func (o *fakeOps) StatPin(path string) error {
	o.statCalls = append(o.statCalls, path)
	return o.statErr
}

func (o *fakeOps) RemovePin(path string) error {
	o.removePinCnt++
	o.removedPaths = append(o.removedPaths, path)
	return o.removePinErr
}

// newBpffsPinRoot creates a tmpdir and — just for the bpffs probe —
// arranges for probeBPFFS to succeed. Since probeBPFFS uses statfs, we
// can't trivially fake it in a tmpdir. The workaround is to set pinRoot
// to an already-existing bpffs path when available, else skip the tests
// that need the real probe. For the disable-mode tests we don't need
// bpffs at all (disable path never calls probeBPFFS).
func newBpffsPinRoot(t *testing.T) string {
	t.Helper()
	// Phase 3 tests already run on a host with /sys/fs/bpf mounted.
	// Reuse that mount; create a per-test subdir so parallel runs don't
	// collide. If /sys/fs/bpf is not bpffs (dev workstation), skip.
	root := "/sys/fs/bpf"
	if err := probeBPFFS(root); err != nil {
		t.Skipf("no bpffs available (%v) — run on a host with /sys/fs/bpf mounted", err)
	}
	sub := filepath.Join(root, fmt.Sprintf("xdrop-xdplink-ut-%d", os.Getpid()))
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Skipf("MkdirAll %s: %v", sub, err)
	}
	t.Cleanup(func() {
		// Best-effort cleanup — pin files may or may not exist
		// depending on which branch the test exercised.
		_ = os.RemoveAll(sub)
	})
	return sub
}

// -- Disable-mode tests (do not require bpffs) ---------------------------

func TestResolveXDPLink_Disable_FreshAttachNoPin(t *testing.T) {
	l := &fakeLink{name: "fresh"}
	ops := &fakeOps{
		statErr:    os.ErrNotExist, // no stale pin to clean
		attachLink: l,
	}
	// Use a tmpdir — we're in disable mode so bpffs probe is never called.
	pinRoot := t.TempDir()

	res, err := resolveXDPLink(nil, "ens38", ModeDisable, pinRoot, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Link != l {
		t.Errorf("res.Link = %v, want %v", res.Link, l)
	}
	if res.PinPath != "" {
		t.Errorf("PinPath = %q, want empty (disable mode)", res.PinPath)
	}
	if res.EffectiveMode != ModeDisable {
		t.Errorf("EffectiveMode = %q, want disable", res.EffectiveMode)
	}
	if ops.preDetachCnt != 1 {
		t.Errorf("preDetach calls = %d, want 1", ops.preDetachCnt)
	}
	if len(ops.attachCalls) != 1 || ops.attachCalls[0] != "ens38" {
		t.Errorf("attach calls = %v, want [ens38]", ops.attachCalls)
	}
	if len(l.pinArgs) != 0 {
		t.Errorf("disable mode must NOT Pin; got Pin(%v)", l.pinArgs)
	}
}

func TestResolveXDPLink_Disable_SweepsStalePin(t *testing.T) {
	stale := &fakeLink{name: "stale-pin"}
	fresh := &fakeLink{name: "fresh"}
	ops := &fakeOps{
		statErr:     nil, // pin file exists
		loadPinLink: stale,
		attachLink:  fresh,
	}
	pinRoot := t.TempDir()

	res, err := resolveXDPLink(nil, "ens38", ModeDisable, pinRoot, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !stale.closed {
		t.Error("disable mode found a stale pin but did not Close() its loaded handle")
	}
	if ops.removePinCnt != 1 {
		t.Errorf("RemovePin calls = %d, want 1 (sweep stale)", ops.removePinCnt)
	}
	if ops.removedPaths[0] != LinkPinPathFor(pinRoot, "ens38") {
		t.Errorf("removed pin path = %q, want %q", ops.removedPaths[0], LinkPinPathFor(pinRoot, "ens38"))
	}
	if res.Link != fresh {
		t.Errorf("res.Link = %v, want fresh", res.Link)
	}
}

func TestResolveXDPLink_Disable_AttachErrorSurfaced(t *testing.T) {
	ops := &fakeOps{
		statErr:   os.ErrNotExist,
		attachErr: fmt.Errorf("simulated attach error"),
	}
	pinRoot := t.TempDir()
	_, err := resolveXDPLink(nil, "ens38", ModeDisable, pinRoot, ops)
	if err == nil {
		t.Fatal("expected attach error, got nil")
	}
	if !strings.Contains(err.Error(), "simulated attach error") {
		t.Errorf("error does not mention simulated cause: %v", err)
	}
}

// -- Auto / require-mode tests (need bpffs so probeBPFFS succeeds) -------

func TestResolveXDPLink_Auto_ReuseViaLoadPinnedAndUpdate(t *testing.T) {
	pinRoot := newBpffsPinRoot(t)
	reused := &fakeLink{name: "reused"}
	ops := &fakeOps{
		statErr:     nil, // pin exists
		loadPinLink: reused,
	}
	res, err := resolveXDPLink(nil, "ens38", ModeAuto, pinRoot, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Reused {
		t.Error("Reused should be true for LoadPinned+Update success path")
	}
	if res.Link != reused {
		t.Errorf("res.Link = %v, want reused", res.Link)
	}
	if res.EffectiveMode != ModeAuto {
		t.Errorf("EffectiveMode = %q, want auto", res.EffectiveMode)
	}
	if res.PinPath != LinkPinPathFor(pinRoot, "ens38") {
		t.Errorf("PinPath = %q, want %q", res.PinPath, LinkPinPathFor(pinRoot, "ens38"))
	}
	if len(reused.updateArgs) != 1 {
		t.Errorf("Update should be called exactly once on reused link, got %d", len(reused.updateArgs))
	}
	// Reuse path MUST NOT call PreDetach or AttachXDP — that's the
	// whole point of zero-gap.
	if ops.preDetachCnt != 0 {
		t.Errorf("preDetach was called %d times on reuse path; want 0", ops.preDetachCnt)
	}
	if len(ops.attachCalls) != 0 {
		t.Errorf("AttachXDP was called %d times on reuse path; want 0", len(ops.attachCalls))
	}
}

func TestResolveXDPLink_Auto_ReuseUpdateFails_FallsThroughToFreshAttach(t *testing.T) {
	pinRoot := newBpffsPinRoot(t)
	bad := &fakeLink{name: "bad", updateErr: fmt.Errorf("program signature mismatch")}
	fresh := &fakeLink{name: "fresh"}
	ops := &fakeOps{
		statErr:     nil, // pin exists
		loadPinLink: bad,
		attachLink:  fresh,
	}
	res, err := resolveXDPLink(nil, "ens38", ModeAuto, pinRoot, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bad.closed {
		t.Error("bad reused link must be Close()d when Update fails")
	}
	if ops.removePinCnt != 1 {
		t.Error("must RemovePin after Update failure to clear kernel ref")
	}
	if ops.preDetachCnt != 1 {
		t.Error("must call PreDetach before fresh attach")
	}
	if res.Reused {
		t.Error("Reused should be false after fallthrough")
	}
	if res.Link != fresh {
		t.Errorf("res.Link = %v, want fresh", res.Link)
	}
	if len(fresh.pinArgs) != 1 {
		t.Errorf("fresh link must be Pinned, got Pin args %v", fresh.pinArgs)
	}
}

func TestResolveXDPLink_Auto_LoadPinnedFails_FallsThrough(t *testing.T) {
	pinRoot := newBpffsPinRoot(t)
	fresh := &fakeLink{name: "fresh"}
	ops := &fakeOps{
		statErr:    nil, // pin file exists on disk
		loadPinErr: fmt.Errorf("corrupt pin"),
		attachLink: fresh,
	}
	res, err := resolveXDPLink(nil, "ens38", ModeAuto, pinRoot, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ops.removePinCnt != 1 {
		t.Errorf("RemovePin calls = %d, want 1 after LoadPinned failure", ops.removePinCnt)
	}
	if res.Link != fresh {
		t.Errorf("res.Link = %v, want fresh", res.Link)
	}
}

func TestResolveXDPLink_Auto_NoPinExists_FreshAttachAndPin(t *testing.T) {
	pinRoot := newBpffsPinRoot(t)
	fresh := &fakeLink{name: "fresh"}
	ops := &fakeOps{
		statErr:    os.ErrNotExist, // no prior pin
		attachLink: fresh,
	}
	res, err := resolveXDPLink(nil, "ens38", ModeAuto, pinRoot, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ops.loadCalls) != 0 {
		t.Error("LoadPinned should NOT be called when stat returns ENOENT")
	}
	if ops.preDetachCnt != 1 {
		t.Error("PreDetach must be called before fresh attach")
	}
	if len(fresh.pinArgs) != 1 || fresh.pinArgs[0] != LinkPinPathFor(pinRoot, "ens38") {
		t.Errorf("fresh link Pin args = %v, want [%q]", fresh.pinArgs, LinkPinPathFor(pinRoot, "ens38"))
	}
	if res.Reused {
		t.Error("Reused must be false for no-pin path")
	}
	if res.EffectiveMode != ModeAuto {
		t.Errorf("EffectiveMode = %q, want auto", res.EffectiveMode)
	}
}

func TestResolveXDPLink_Auto_PinFails_DowngradesToUnpinned(t *testing.T) {
	pinRoot := newBpffsPinRoot(t)
	fresh := &fakeLink{name: "fresh", pinErr: fmt.Errorf("simulated pin failure")}
	ops := &fakeOps{
		statErr:    os.ErrNotExist,
		attachLink: fresh,
	}
	res, err := resolveXDPLink(nil, "ens38", ModeAuto, pinRoot, ops)
	if err != nil {
		t.Fatalf("auto mode should not error on Pin failure: %v", err)
	}
	if res.EffectiveMode != ModeDisable {
		t.Errorf("EffectiveMode = %q, want disable (Pin failure downgrade)", res.EffectiveMode)
	}
	if res.PinPath != "" {
		t.Errorf("PinPath = %q, want empty (Pin failed)", res.PinPath)
	}
	if !strings.Contains(res.DowngradeReason, "Pin") {
		t.Errorf("DowngradeReason = %q, should mention Pin", res.DowngradeReason)
	}
	if fresh.closed {
		t.Error("auto mode must NOT Close the link when Pin fails — keep it live unpinned")
	}
}

func TestResolveXDPLink_Require_PinFails_HardError(t *testing.T) {
	pinRoot := newBpffsPinRoot(t)
	fresh := &fakeLink{name: "fresh", pinErr: fmt.Errorf("simulated pin failure")}
	ops := &fakeOps{
		statErr:    os.ErrNotExist,
		attachLink: fresh,
	}
	_, err := resolveXDPLink(nil, "ens38", ModeRequire, pinRoot, ops)
	if err == nil {
		t.Fatal("require mode must hard-fail on Pin error")
	}
	if !errors.Is(err, ErrLinkPinningUnsupported) {
		t.Errorf("error should wrap ErrLinkPinningUnsupported, got %v", err)
	}
	if !fresh.closed {
		t.Error("require mode must Close() the link on Pin failure before returning")
	}
}

func TestResolveXDPLink_Require_BpffsProbeFails_HardError(t *testing.T) {
	// Pick a path whose ancestor is deliberately not bpffs (tmpfs /tmp).
	badRoot := filepath.Join(t.TempDir(), "fake-bpffs")
	ops := &fakeOps{}
	_, err := resolveXDPLink(nil, "ens38", ModeRequire, badRoot, ops)
	if err == nil {
		t.Fatal("require mode must hard-fail when bpffs probe fails")
	}
	if !errors.Is(err, ErrLinkPinningUnsupported) {
		t.Errorf("error should wrap ErrLinkPinningUnsupported, got %v", err)
	}
	if len(ops.attachCalls) != 0 {
		t.Error("require mode must NOT attempt AttachXDP when pinning precondition fails")
	}
}

func TestResolveXDPLink_Auto_BpffsProbeFails_DowngradeAndAttach(t *testing.T) {
	badRoot := filepath.Join(t.TempDir(), "fake-bpffs")
	fresh := &fakeLink{name: "fresh"}
	ops := &fakeOps{attachLink: fresh}
	res, err := resolveXDPLink(nil, "ens38", ModeAuto, badRoot, ops)
	if err != nil {
		t.Fatalf("auto mode should downgrade, not error: %v", err)
	}
	if res.EffectiveMode != ModeDisable {
		t.Errorf("EffectiveMode = %q, want disable (bpffs probe downgrade)", res.EffectiveMode)
	}
	if !strings.Contains(res.DowngradeReason, "bpffs") {
		t.Errorf("DowngradeReason = %q, should mention bpffs", res.DowngradeReason)
	}
	if len(ops.attachCalls) != 1 {
		t.Errorf("AttachXDP should be called once on downgrade path, got %d", len(ops.attachCalls))
	}
}

func TestResolveXDPLink_Require_AttachFailsOnPre59Kernel_TaggedError(t *testing.T) {
	pinRoot := newBpffsPinRoot(t)
	ops := &fakeOps{
		statErr:   os.ErrNotExist,
		attachErr: ebpf.ErrNotSupported,
	}
	_, err := resolveXDPLink(nil, "ens38", ModeRequire, pinRoot, ops)
	if err == nil {
		t.Fatal("expected AttachXDP failure to surface as error")
	}
	if !errors.Is(err, ErrLinkPinningUnsupported) {
		t.Errorf("error from pre-5.9 attach should wrap ErrLinkPinningUnsupported, got %v", err)
	}
	// Detection also works for raw ENOTSUP / EOPNOTSUPP syscall errors.
	for _, raw := range []error{syscall.ENOTSUP, syscall.EOPNOTSUPP} {
		if !IsXDPLinkUnsupported(raw) {
			t.Errorf("IsXDPLinkUnsupported(%v) = false, want true", raw)
		}
	}
	// And EINVAL must NOT be treated as unsupported (false-positive hazard).
	if IsXDPLinkUnsupported(syscall.EINVAL) {
		t.Error("IsXDPLinkUnsupported(EINVAL) = true; should be false — EINVAL is ambiguous")
	}
}

// TestLinkPinPathFor_Stable anchors the path convention. Changing it is
// an operator-visible break: any rollback / manual cleanup script that
// hardcodes /sys/fs/bpf/xdrop/link_ens38 must keep working.
func TestLinkPinPathFor_Stable(t *testing.T) {
	cases := []struct {
		root, iface, want string
	}{
		{"/sys/fs/bpf/xdrop", "ens38", "/sys/fs/bpf/xdrop/link_ens38"},
		{"/sys/fs/bpf/xdrop", "eth0", "/sys/fs/bpf/xdrop/link_eth0"},
		{"/tmp/pin", "lo", "/tmp/pin/link_lo"},
	}
	for _, c := range cases {
		if got := LinkPinPathFor(c.root, c.iface); got != c.want {
			t.Errorf("LinkPinPathFor(%q, %q) = %q, want %q", c.root, c.iface, got, c.want)
		}
	}
}

// realLinkOps RemovePin should tolerate a missing file — unlinking
// nothing is not an error (used both in the disable sweep and after
// Update failures).
func TestRealLinkOps_RemovePin_MissingFileNotError(t *testing.T) {
	ops := realLinkOps{}
	miss := filepath.Join(t.TempDir(), "nonexistent-pin")
	if err := ops.RemovePin(miss); err != nil {
		t.Errorf("RemovePin on missing file returned error: %v", err)
	}
	// A real file that exists should get unlinked.
	f := filepath.Join(t.TempDir(), "real-file")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ops.RemovePin(f); err != nil {
		t.Errorf("RemovePin on real file returned error: %v", err)
	}
	if _, err := os.Stat(f); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("file still present after RemovePin: %v", err)
	}
}
