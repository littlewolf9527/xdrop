package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/config"
	"github.com/spf13/viper"
)

type td149Map struct {
	calls int
	value uint64
	fail  bool
}

func (m *td149Map) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	if key != uint32(12) || flags != ebpf.UpdateExist {
		return fmt.Errorf("slot=%v flags=%v", key, flags)
	}
	m.calls++
	m.value = value.(uint64)
	if m.fail {
		return errors.New("fixture write failure")
	}
	return nil
}

func TestTD149WriteSlots(t *testing.T) {
	for _, pass := range []bool{false, true} {
		t.Run(fmt.Sprintf("pass=%t", pass), func(t *testing.T) {
			a, b := &td149Map{}, &td149Map{}
			var logs bytes.Buffer
			old := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(old) })
			want := uint64(0)
			if pass {
				want = 1
			}
			if err := configureIPv6DeepChain(a, b, pass); err != nil {
				t.Fatal(err)
			}
			line := fmt.Sprintf("bpf.ipv6_deep_chain_drop=%t (slot 12=%d)", !pass, want)
			if a.calls != 1 || b.calls != 1 || a.value != want || b.value != want || strings.Count(logs.String(), line) != 1 {
				t.Fatalf("A=%+v B=%+v log=%s", a, b, logs.String())
			}
			t.Logf("TD149_WRITE A=%d B=%d log=%s", a.value, b.value, line)
		})
	}
	for _, side := range []string{"A", "B"} {
		t.Run("error="+side, func(t *testing.T) {
			a, b := &td149Map{fail: side == "A"}, &td149Map{fail: side == "B"}
			if err := configureIPv6DeepChain(a, b, false); err == nil {
				t.Fatal("map error swallowed")
			}
		})
	}
}

// TestTD149StartupInterpretation runs config.Load -> ipv6DeepChainPass (the
// expression main uses) -> configureIPv6DeepChain, so a flipped default cannot
// hide behind a test-side copy of the rule (blind review r1 P2-1).
func TestTD149StartupInterpretation(t *testing.T) {
	for _, c := range []struct {
		name, value string
		want        uint64
	}{{"missing", "", 0}, {"true", "true", 0}, {"false", "false", 1}} {
		t.Run(c.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			yaml := "bpf: {}\n"
			if c.value != "" {
				yaml = "bpf:\n  ipv6_deep_chain_drop: " + c.value + "\n"
			}
			path := filepath.Join(t.TempDir(), "td149.yaml")
			if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			a, b := &td149Map{}, &td149Map{}
			old := log.Writer()
			log.SetOutput(&bytes.Buffer{})
			t.Cleanup(func() { log.SetOutput(old) })
			if err := configureIPv6DeepChain(a, b, ipv6DeepChainPass(cfg.BPF)); err != nil {
				t.Fatal(err)
			}
			if a.calls != 1 || b.calls != 1 || a.value != c.want || b.value != c.want {
				t.Fatalf("A=%+v B=%+v want slot 12=%d", a, b, c.want)
			}
		})
	}
}
