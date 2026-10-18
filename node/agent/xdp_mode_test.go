package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"

	xdropbpf "github.com/littlewolf9527/xdrop/node/agent/bpf"
)

func TestTD073NativeFailureDiagnostic(t *testing.T) {
	if os.Getenv("TD073_DIAGNOSTIC_CHILD") == "1" {
		logXDPAttachFailure("td073v0", "native", &xdropbpf.XDPError{Reason: "xdp_attach_failed", Err: errors.New("kernel-native-rejection")})
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestTD073NativeFailureDiagnostic$")
	cmd.Env = append(os.Environ(), "TD073_DIAGNOSTIC_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("native failure must exit")
	}
	for _, want := range []string{"驱动不支持 native 或驱动故障", "kernel-native-rejection", "requested=native"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q: %s", want, out)
		}
	}
	if strings.Contains(string(out), "requires Linux") {
		t.Errorf("wrong kernel-version hint: %s", out)
	}
}

func TestTD073StartupLogs(t *testing.T) {
	var output bytes.Buffer
	writer := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(writer)
	for _, r := range []*xdropbpf.ResolvedXDPLink{
		{Reused: true, PinPath: "/private/td073/link_td073v0", AttachMode: "generic"},
		{PinPath: "/private/td073/link_td073v0", AttachMode: "generic"},
		{AttachMode: "generic"},
	} {
		output.Reset()
		logXDPAttachOutcome("td073v0", "filter", "auto", r)
		if !strings.Contains(output.String(), "requested=auto attached=generic") {
			t.Fatalf("startup snapshot missing: %s", output.String())
		}
	}
	output.Reset()
	warnXDPFFModes("td073v0", "td073v1", &xdropbpf.ResolvedXDPLink{AttachMode: "native"}, &xdropbpf.ResolvedXDPLink{AttachMode: "generic"})
	for _, want := range []string{"WARN", "td073v0=native", "td073v1=generic"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("FF warning missing %q: %s", want, output.String())
		}
	}
	output.Reset()
	warnXDPFFModes("td073v0", "td073v1", &xdropbpf.ResolvedXDPLink{AttachMode: "native"}, &xdropbpf.ResolvedXDPLink{AttachMode: "native"})
	if output.Len() != 0 {
		t.Errorf("equal modes should not warn: %s", output.String())
	}
}
