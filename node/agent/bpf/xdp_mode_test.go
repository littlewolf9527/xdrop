package bpf

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

type td073Link struct {
	owner *td073Ops
	name  string
}

func (l *td073Link) Update(*ebpf.Program) error {
	l.owner.events = append(l.owner.events, l.name+".update")
	if l.owner.fails("update") {
		return errors.New("update rejected")
	}
	return nil
}
func (l *td073Link) Pin(string) error {
	l.owner.events = append(l.owner.events, l.name+".pin")
	if l.owner.fails("pin") {
		return errors.New("pin rejected")
	}
	return nil
}
func (l *td073Link) Unpin() error {
	l.owner.cleanup = append(l.owner.cleanup, l.name+".unpin")
	l.owner.events = append(l.owner.events, l.name+".unpin")
	if l.owner.fails("cleanup") {
		return errors.New("unpin rejected")
	}
	return nil
}
func (l *td073Link) Close() error {
	l.owner.cleanup = append(l.owner.cleanup, l.name+".close")
	l.owner.events = append(l.owner.events, l.name+".close")
	if l.owner.fails("cleanup") || (l.name == "old" && l.owner.fails("oldclose")) {
		return errors.New("close rejected")
	}
	return nil
}

type td073Ops struct {
	fault           string
	pinned          bool
	reports         []XDPAttachment
	reads           int
	attached        []XDPMode
	cleanup, events []string
}

func (o *td073Ops) fails(name string) bool {
	return strings.Contains(","+o.fault+",", ","+name+",")
}

func (o *td073Ops) ProbeBPFFS(string) error {
	o.events = append(o.events, "probe")
	if o.fails("probe") {
		return errors.New("bpffs rejected")
	}
	return nil
}
func (o *td073Ops) MkdirAll(string, os.FileMode) error {
	o.events = append(o.events, "mkdir")
	if o.fails("mkdir") {
		return errors.New("mkdir rejected")
	}
	return nil
}
func (o *td073Ops) StatPin(string) error {
	o.events = append(o.events, "stat")
	if o.pinned {
		return nil
	}
	return os.ErrNotExist
}
func (o *td073Ops) LoadPinned(string) (XDPLink, error) {
	o.events = append(o.events, "load")
	if o.fails("load") {
		return nil, errors.New("load rejected")
	}
	return &td073Link{o, "old"}, nil
}
func (o *td073Ops) RemovePin(string) error {
	o.events = append(o.events, "remove")
	if o.fails("erofs") {
		return syscall.EROFS
	}
	if o.fails("remove") {
		return errors.New("remove rejected")
	}
	return nil
}
func (o *td073Ops) PreDetach(string) { o.events = append(o.events, "detach") }
func (o *td073Ops) AttachXDP(_ *ebpf.Program, _ string, mode XDPMode) (XDPLink, error) {
	o.attached = append(o.attached, mode)
	o.events = append(o.events, "attach")
	if o.fails("attach") {
		return nil, errors.New("kernel attach rejected")
	}
	return &td073Link{o, "fresh"}, nil
}
func (o *td073Ops) ReadXDP(string) (XDPAttachment, error) {
	o.reads++
	o.events = append(o.events, "read")
	if o.fails("read") || (o.fails("read2") && o.reads == 2) {
		return XDPAttachment{}, errors.New("read rejected")
	}
	if o.reads > len(o.reports) {
		return XDPAttachment{}, errors.New("unexpected read")
	}
	return o.reports[o.reads-1], nil
}
func (o *td073Ops) ProgramID(*ebpf.Program) (uint32, error) {
	o.events = append(o.events, "id")
	if o.fails("id") {
		return 0, errors.New("program info rejected")
	}
	if o.fails("zeroid") {
		return 0, nil
	}
	return 41, nil
}

func TestTD073Cases(t *testing.T) {
	n := XDPAttachment{Attached: 1, ProgID: 41, DriverID: 41}
	g := XDPAttachment{Attached: 2, ProgID: 41, GenericID: 41}
	multi := XDPAttachment{Attached: 4, DriverID: 41, GenericID: 42}
	offload := XDPAttachment{Attached: 3, ProgID: 41, OffloadID: 41}
	wrong := XDPAttachment{Attached: 1, ProgID: 42}
	missing := XDPAttachment{Attached: 1}
	type row struct {
		id              string
		request         XDPMode
		pin             Mode
		old             bool
		fault           string
		snapshots       []XDPAttachment
		code, mode      string
		reused          bool
		attaches, reads int
		cleanup         string
		remount, warn   bool
	}
	// The first 25 IDs are the sealed PLAN list. Additional rows never replace them.
	cases := []row{
		{"C01", XDPNative, ModeDisable, false, "", []XDPAttachment{n}, "", "native", false, 1, 1, "", false, false},
		{"C02", XDPNative, ModeDisable, false, "attach", nil, "xdp_attach_failed", "", false, 1, 0, "", false, false},
		{"C03", XDPGeneric, ModeDisable, false, "", []XDPAttachment{g}, "", "generic", false, 1, 1, "", false, false},
		{"C04", XDPAuto, ModeDisable, false, "", []XDPAttachment{g}, "", "generic", false, 1, 1, "", false, true},
		{"C05", XDPAuto, ModeDisable, false, "", []XDPAttachment{n}, "", "native", false, 1, 1, "", false, false},
		{"C06", XDPNative, ModeAuto, false, "probe", []XDPAttachment{n}, "", "native", false, 1, 1, "", false, false},
		{"C07", XDPNative, ModeRequire, false, "probe", nil, "xdp_bpffs_failed", "", false, 0, 0, "", false, false},
		{"C08", XDPNative, ModeAuto, false, "mkdir", []XDPAttachment{n}, "", "native", false, 1, 1, "", false, false},
		{"C09", XDPNative, ModeRequire, false, "mkdir", nil, "xdp_mkdir_failed", "", false, 0, 0, "", false, false},
		{"C10", XDPNative, ModeAuto, true, "", []XDPAttachment{n}, "", "native", true, 0, 1, "", false, false},
		{"C11", XDPNative, ModeAuto, true, "", []XDPAttachment{g, n}, "", "native", false, 1, 2, "old.unpin old.close", true, false},
		{"C12", XDPNative, ModeAuto, true, "attach", []XDPAttachment{g}, "xdp_attach_failed", "", false, 1, 1, "old.unpin old.close", true, false},
		{"C13", XDPAuto, ModeAuto, true, "", []XDPAttachment{g}, "", "generic", true, 0, 1, "", false, true},
		{"C14", XDPGeneric, ModeAuto, true, "", []XDPAttachment{n, g}, "", "generic", false, 1, 2, "old.unpin old.close", true, false},
		{"C15", XDPNative, ModeAuto, true, "update", []XDPAttachment{n}, "", "native", false, 1, 1, "old.close", false, false},
		{"C16", XDPNative, ModeAuto, true, "load", []XDPAttachment{n}, "", "native", false, 1, 1, "", false, false},
		{"C17", XDPNative, ModeAuto, false, "pin", []XDPAttachment{n}, "", "native", false, 1, 1, "", false, false},
		{"C18", XDPNative, ModeRequire, false, "pin", nil, "xdp_pin_failed", "", false, 1, 0, "fresh.close", false, false},
		{"C19", XDPNative, ModeAuto, false, "read", nil, "xdp_readback_failed", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C20", XDPNative, ModeAuto, false, "", []XDPAttachment{wrong}, "xdp_prog_mismatch", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C21", XDPAuto, ModeAuto, false, "", []XDPAttachment{{}}, "xdp_none", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C22", XDPAuto, ModeAuto, false, "", []XDPAttachment{multi}, "xdp_multi", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C23", XDPAuto, ModeAuto, false, "", []XDPAttachment{offload}, "xdp_offload", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C24", XDPNative, ModeAuto, false, "", []XDPAttachment{g}, "xdp_mode_mismatch", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C25", XDPAuto, ModeAuto, true, "", []XDPAttachment{multi}, "xdp_multi", "", false, 0, 1, "old.unpin old.close", false, false},
		{"C26", XDPAuto, ModeAuto, false, "", []XDPAttachment{missing}, "xdp_prog_id_missing", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C27", XDPAuto, ModeAuto, false, "zeroid", []XDPAttachment{n}, "xdp_prog_id_missing", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C28", XDPAuto, ModeAuto, false, "id", []XDPAttachment{n}, "xdp_prog_id_missing", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C29", XDPGeneric, ModeAuto, false, "", []XDPAttachment{n}, "xdp_mode_mismatch", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C30", XDPNative, ModeAuto, true, "read", nil, "xdp_readback_failed", "", false, 0, 1, "old.unpin old.close", false, false},
		{"C31", XDPNative, ModeAuto, true, "", []XDPAttachment{wrong}, "xdp_prog_mismatch", "", false, 0, 1, "old.unpin old.close", false, false},
		{"C32", XDPNative, ModeAuto, true, "", []XDPAttachment{g, wrong}, "xdp_prog_mismatch", "", false, 1, 2, "old.unpin old.close fresh.unpin fresh.close", true, false},
		{"C33", XDPNative, ModeAuto, true, "", []XDPAttachment{g, g}, "xdp_mode_mismatch", "", false, 1, 2, "old.unpin old.close fresh.unpin fresh.close", true, false},
		{"C34", XDPAuto, ModeAuto, false, "cleanup", []XDPAttachment{multi}, "xdp_multi", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C35", XDPNative, ModeDisable, false, "read", nil, "xdp_readback_failed", "", false, 1, 1, "fresh.close", false, false},
		{"C36", XDPAuto, ModeAuto, true, "cleanup", []XDPAttachment{multi}, "xdp_multi", "", false, 0, 1, "old.unpin old.close", false, false},
		{"C37", XDPNative, ModeAuto, true, "cleanup", []XDPAttachment{g}, "xdp_cleanup_failed", "", false, 0, 1, "old.unpin old.close", true, false},
		{"C38", XDPAuto, ModeAuto, false, "", []XDPAttachment{{Attached: 99}}, "xdp_attached_unknown", "", false, 1, 1, "fresh.unpin fresh.close", false, false},
		{"C39", XDPAuto, ModeAuto, true, "", []XDPAttachment{n}, "", "native", true, 0, 1, "", false, false},
		{"C40", XDPGeneric, ModeAuto, true, "", []XDPAttachment{g}, "", "generic", true, 0, 1, "", false, false},
	}
	// Cross-check every pinning fallback with each requested mode.
	for _, request := range []XDPMode{XDPAuto, XDPNative, XDPGeneric} {
		snapshot, mode := n, "native"
		if request == XDPGeneric {
			snapshot, mode = g, "generic"
		}
		for _, fault := range []string{"probe", "mkdir", "pin", "load", "update"} {
			old, cleanup := fault == "load" || fault == "update", ""
			if fault == "update" {
				cleanup = "old.close"
			}
			cases = append(cases, row{fmt.Sprintf("C%02d", len(cases)+1), request, ModeAuto, old, fault, []XDPAttachment{snapshot}, "", mode, false, 1, 1, cleanup, false, false})
		}
		for _, fault := range []string{"probe", "mkdir", "pin"} {
			code, attaches, cleanup := "xdp_bpffs_failed", 0, ""
			if fault == "mkdir" {
				code = "xdp_mkdir_failed"
			}
			if fault == "pin" {
				code, attaches, cleanup = "xdp_pin_failed", 1, "fresh.close"
			}
			cases = append(cases, row{fmt.Sprintf("C%02d", len(cases)+1), request, ModeRequire, false, fault, nil, code, "", false, attaches, 0, cleanup, false, false})
		}
	}
	// Blind-review closure: actual resolver branches crossed with all requests.
	// Expectations are explicit scenario data, independent of production helpers.
	for _, request := range []XDPMode{XDPAuto, XDPNative, XDPGeneric} {
		snapshot, attached := n, "native"
		if request == XDPGeneric {
			snapshot, attached = g, "generic"
		}
		add := func(pin Mode, old bool, fault string, reports []XDPAttachment, code, mode string, reused bool, attaches, reads int, cleanup string, remount bool) {
			cases = append(cases, row{fmt.Sprintf("C%02d", len(cases)+1), request, pin, old, fault, reports, code, mode, reused, attaches, reads, cleanup, remount, false})
		}
		add(ModeDisable, true, "", []XDPAttachment{snapshot}, "", attached, false, 1, 1, "old.close", false)
		add(ModeDisable, true, "load", []XDPAttachment{snapshot}, "", attached, false, 1, 1, "", false)
		add(ModeDisable, true, "cleanup", []XDPAttachment{snapshot}, "", attached, false, 1, 1, "old.close", false)
		add(ModeDisable, true, "load,remove", []XDPAttachment{snapshot}, "", attached, false, 1, 1, "", false)
		for _, pin := range []Mode{ModeDisable, ModeAuto, ModeRequire} {
			add(pin, false, "", []XDPAttachment{snapshot}, "", attached, false, 1, 1, "", false)
			add(pin, false, "attach", nil, "xdp_attach_failed", "", false, 1, 0, "", false)
		}
		for _, pin := range []Mode{ModeAuto, ModeRequire} {
			add(pin, true, "", []XDPAttachment{snapshot}, "", attached, true, 0, 1, "", false)
			add(pin, true, "load", []XDPAttachment{snapshot}, "", attached, false, 1, 1, "", false)
			add(pin, true, "update", []XDPAttachment{snapshot}, "", attached, false, 1, 1, "old.close", false)
			add(pin, true, "update,cleanup", []XDPAttachment{snapshot}, "", attached, false, 1, 1, "old.close", false)
			add(pin, true, "load,remove", []XDPAttachment{snapshot}, "", attached, false, 1, 1, "", false)
		}
		for _, fault := range []string{"probe,attach", "mkdir,attach"} {
			add(ModeAuto, false, fault, nil, "xdp_attach_failed", "", false, 1, 0, "", false)
		}
		add(ModeRequire, false, "pin,cleanup", nil, "xdp_pin_failed", "", false, 1, 0, "fresh.close", false)
		// Distinct owned-link shapes: unpinned fresh, pinned fresh, updated reuse.
		for _, shape := range []string{"unpinned", "pinned", "reuse"} {
			pin, old, attaches, cleanup := ModeAuto, false, 1, "fresh.unpin fresh.close"
			if shape == "unpinned" {
				pin, cleanup = ModeDisable, "fresh.close"
			}
			if shape == "reuse" {
				old, attaches, cleanup = true, 0, "old.unpin old.close"
			}
			for _, failure := range []struct {
				fault  string
				report XDPAttachment
				code   string
			}{
				{"read", snapshot, "xdp_readback_failed"},
				{"", wrong, "xdp_prog_mismatch"},
				{"", missing, "xdp_prog_id_missing"},
				{"zeroid", snapshot, "xdp_prog_id_missing"},
				{"id", snapshot, "xdp_prog_id_missing"},
				{"", XDPAttachment{}, "xdp_none"},
				{"", multi, "xdp_multi"},
				{"", offload, "xdp_offload"},
				{"", XDPAttachment{Attached: 99}, "xdp_attached_unknown"},
				{"read,cleanup", snapshot, "xdp_readback_failed"},
			} {
				add(pin, old, failure.fault, []XDPAttachment{failure.report}, failure.code, "", false, attaches, 1, cleanup, false)
			}
		}
		for _, fault := range []string{"probe,read", "mkdir,read", "pin,read"} {
			add(ModeAuto, false, fault, nil, "xdp_readback_failed", "", false, 1, 1, "fresh.close", false)
		}
		if request != XDPAuto {
			opposite := g
			if request == XDPGeneric {
				opposite = n
			}
			add(ModeDisable, false, "", []XDPAttachment{opposite}, "xdp_mode_mismatch", "", false, 1, 1, "fresh.close", false)
			for _, pin := range []Mode{ModeAuto, ModeRequire} {
				add(pin, true, "", []XDPAttachment{opposite, snapshot}, "", attached, false, 1, 2, "old.unpin old.close", true)
				add(pin, true, "attach", []XDPAttachment{opposite}, "xdp_attach_failed", "", false, 1, 1, "old.unpin old.close", true)
				add(pin, true, "cleanup", []XDPAttachment{opposite}, "xdp_cleanup_failed", "", false, 0, 1, "old.unpin old.close", true)
				add(pin, true, "read2", []XDPAttachment{opposite, snapshot}, "xdp_readback_failed", "", false, 1, 2, "old.unpin old.close fresh.unpin fresh.close", true)
				add(pin, true, "", []XDPAttachment{opposite, wrong}, "xdp_prog_mismatch", "", false, 1, 2, "old.unpin old.close fresh.unpin fresh.close", true)
				add(pin, true, "", []XDPAttachment{opposite, opposite}, "xdp_mode_mismatch", "", false, 1, 2, "old.unpin old.close fresh.unpin fresh.close", true)
			}
		}
	}
	cases = append(cases,
		row{"C259", XDPMode("invalid"), ModeAuto, false, "", nil, "xdp_mode_invalid", "", false, 0, 0, "", false, false},
		row{"C260", XDPAuto, "", false, "", []XDPAttachment{n}, "", "native", false, 1, 1, "", false, false},
		row{"C261", XDPNative, "", false, "", []XDPAttachment{n}, "", "native", false, 1, 1, "", false, false},
		row{"C262", XDPGeneric, "", false, "", []XDPAttachment{g}, "", "generic", false, 1, 1, "", false, false},
		row{"C263", "", ModeAuto, false, "", []XDPAttachment{n}, "", "native", false, 1, 1, "", false, false},
	)
	cases = append(cases,
		row{"C264", XDPAuto, ModeAuto, true, "update,remove", []XDPAttachment{n}, "", "native", false, 1, 1, "old.close", false, false},
		row{"C265", XDPNative, ModeAuto, true, "update,remove", []XDPAttachment{n}, "", "native", false, 1, 1, "old.close", false, false},
		row{"C266", XDPGeneric, ModeAuto, true, "update,remove", []XDPAttachment{g}, "", "generic", false, 1, 1, "old.close", false, false},
	)
	// HEAD compatibility: old-link cleanup is best effort before a fresh attach.
	cases = append(cases,
		row{"C267", XDPAuto, ModeDisable, true, "oldclose,erofs", []XDPAttachment{n}, "", "native", false, 1, 1, "old.close", false, false},
		row{"C268", XDPNative, ModeDisable, true, "oldclose,erofs", []XDPAttachment{n}, "", "native", false, 1, 1, "old.close", false, false},
		row{"C269", XDPGeneric, ModeDisable, true, "oldclose,erofs", []XDPAttachment{g}, "", "generic", false, 1, 1, "old.close", false, false},
		row{"C270", XDPAuto, ModeAuto, true, "update,oldclose", []XDPAttachment{n}, "", "native", false, 1, 1, "old.close", false, false},
		row{"C271", XDPNative, ModeAuto, true, "update,oldclose", []XDPAttachment{n}, "", "native", false, 1, 1, "old.close", false, false},
		row{"C272", XDPGeneric, ModeAuto, true, "update,oldclose", []XDPAttachment{g}, "", "generic", false, 1, 1, "old.close", false, false},
	)
	const expectedCases = 272
	if len(cases) != expectedCases {
		t.Fatalf("case list=%d want %d", len(cases), expectedCases)
	}
	ran := 0
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			ran++
			o := &td073Ops{fault: c.fault, pinned: c.old, reports: c.snapshots}
			var output bytes.Buffer
			writer := log.Writer()
			log.SetOutput(&output)
			defer log.SetOutput(writer)
			res, err := resolveXDPLink(nil, "td073v0", c.pin, c.request, "/private/td073", o)
			if (err != nil) != (c.code != "") {
				t.Errorf("error=%v want code %q", err, c.code)
			}
			if code := XDPFailureReason(err); code != c.code {
				t.Errorf("reason code=%q want %q", code, c.code)
			}
			mode, reused := "", false
			if res != nil {
				mode, reused = res.AttachMode, res.Reused
			}
			if mode != c.mode || reused != c.reused {
				t.Errorf("AttachMode=%q Reused=%v want %q %v", mode, reused, c.mode, c.reused)
			}
			if c.code != "" && res != nil {
				t.Error("failed resolver returned an owned link")
			}
			if len(o.attached) != c.attaches || o.reads != c.reads {
				t.Errorf("attach/read=%d/%d want %d/%d", len(o.attached), o.reads, c.attaches, c.reads)
			}
			wantRequest := c.request
			if wantRequest == "" {
				wantRequest = XDPAuto
			}
			for _, requested := range o.attached {
				if requested != wantRequest {
					t.Errorf("attach mode=%q want %q", requested, wantRequest)
				}
			}
			if got := strings.Join(o.cleanup, " "); got != c.cleanup {
				t.Errorf("owned link cleanup=%q want %q", got, c.cleanup)
			}
			if got := strings.Contains(output.String(), "模式变更，重挂，过滤中断"); got != c.remount {
				t.Errorf("remount=%v want %v", got, c.remount)
			}
			if got := strings.Contains(output.String(), "WARN: td073v0 requested=auto attached=generic，性能约低一个量级"); got != c.warn {
				t.Errorf("generic warning=%v want %v", got, c.warn)
			}
			if err == nil && (o.fails("probe") || o.fails("mkdir") || o.fails("pin") || c.pin == ModeDisable) {
				if res.PinPath != "" || res.EffectiveMode != ModeDisable {
					t.Errorf("pin downgrade: %+v", res)
				}
			}
			if err == nil && c.pin != ModeDisable && !o.fails("probe") && !o.fails("mkdir") && !o.fails("pin") {
				if res.PinPath == "" || res.EffectiveMode != ModeAuto {
					t.Errorf("pinned result lost: %+v", res)
				}
			}
			if o.fails("attach") && !strings.Contains(fmt.Sprint(err), "kernel attach rejected") {
				t.Errorf("kernel error lost: %v", err)
			}
			if o.fails("cleanup") {
				for _, owner := range []string{"old", "fresh"} {
					if owner == "old" && (c.pin == ModeDisable || o.fails("update")) {
						continue // HEAD ignores Close errors on the pre-existing link.
					}
					for _, cause := range []string{"unpin rejected", "close rejected"} {
						if strings.Contains(c.cleanup, owner+"."+strings.TrimSuffix(cause, " rejected")) && !strings.Contains(fmt.Sprint(err), cause) {
							t.Errorf("cleanup cause lost: %s: %v", cause, err)
						}
					}
				}
			}
			events := strings.Join(o.events, " ")
			if c.pin == ModeDisable && c.old {
				if !strings.Contains(events, "stat load") {
					t.Errorf("disable must inspect old pin: %s", events)
				}
				if !strings.Contains(events, "remove detach attach") {
					t.Errorf("disable must unlink before attach: %s", events)
				}
				if !o.fails("load") && !strings.Contains(events, "load old.close remove detach attach") {
					t.Errorf("disable old cleanup must preserve HEAD order: %s", events)
				}
			}
			if o.fails("remove") && !strings.Contains(output.String(), "remove rejected") {
				t.Errorf("pin unlink diagnostic lost: %s", output.String())
			}
			if o.fails("erofs") && (!strings.Contains(output.String(), "WARN:") || !strings.Contains(output.String(), syscall.EROFS.Error())) {
				t.Errorf("read-only pin unlink diagnostic lost: %s", output.String())
			}
			if o.fails("update") {
				if !strings.Contains(output.String(), "update rejected") {
					t.Errorf("update warning lost: %s", output.String())
				}
				if !strings.Contains(events, "old.update old.close remove detach attach") {
					t.Errorf("update failure must preserve HEAD fallback order: %s", events)
				}
			}
			if c.old && c.pin != ModeDisable && !o.fails("load") && !o.fails("update") && c.reads > 0 && !strings.Contains(events, "load old.update read") {
				t.Errorf("reuse must update before read: %s", events)
			}
			if c.remount && c.attaches > 0 && !strings.Contains(events, "read id old.unpin old.close detach attach") {
				t.Errorf("remount order: %s", events)
			}
			if c.code == "xdp_multi" || c.code == "xdp_none" || c.code == "xdp_offload" {
				if strings.Contains(events, " id") {
					t.Errorf("classification must reject before identity: %s", events)
				}
			}
			t.Logf("%s requested=%s pinning=%s fault=%s events=%s", c.id, c.request, c.pin, c.fault, events)
		})
	}
	if ran != expectedCases {
		t.Fatalf("ran=%d want %d", ran, expectedCases)
	}
	fmt.Printf("TD073_CASES ran=%d skip=0\n", ran)
}
