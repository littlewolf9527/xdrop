//go:build linux && integration

package bpf

import (
	"github.com/cilium/ebpf"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// Reuses TestTD074Verifier's LogLevelStats / processed-insns measurement.
// Kernel acceptance remains mandatory; the count is verifier work, not ELF length.
func TestCloseoutGate7(t *testing.T) {
	td074Environment(t)
	spec, err := ebpf.LoadCollectionSpec(os.Getenv("XDROP_BPF_ELF"))
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Programs) != 1 || spec.Programs["xdp_firewall_main"] == nil {
		t.Fatal("gate7 program identity")
	}
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinNone {
			t.Fatalf("gate7 unexpected pin: %s", name)
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}})
	if err != nil {
		t.Fatalf("gate7 verifier load: %+v", err)
	}
	defer coll.Close()
	raw := coll.Programs["xdp_firewall_main"].VerifierLog
	t.Logf("CLOSEOUT_VERIFIER_RAW\n%s", raw)
	matches := regexp.MustCompile(`processed ([0-9]+) insns`).FindAllStringSubmatch(raw, -1)
	if len(matches) != 1 {
		t.Fatalf("gate7 processed summaries=%d", len(matches))
	}
	n, err := strconv.Atoi(matches[0][1])
	if err != nil || n <= 0 || n > 1000000 {
		t.Fatalf("gate7 kernel instruction budget: %d error=%v", n, err)
	}
	t.Logf("CLOSEOUT_GATE7 prog=xdp_firewall_main insns=%d", n)
}
