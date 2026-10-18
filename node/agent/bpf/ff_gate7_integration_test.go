//go:build linux && integration

package bpf

import (
	"crypto/sha256"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestFFGate7(t *testing.T) {
	td074Environment(t)
	beforeSource, afterSource := os.Getenv("FF_BEFORE_SOURCE"), os.Getenv("FF_AFTER_SOURCE")
	if beforeSource != "d39805f4910e4245004cf1157056c0ad749ef379" || afterSource == "" {
		t.Fatal("FF gate7 requires explicit source identities")
	}
	for _, entry := range []struct{ name, before, after string }{{"gate", "FF_BEFORE_GATE_ELF", "XDROP_GATE_ELF"}, {"main", "FF_BEFORE_MAIN_ELF", "XDROP_BPF_ELF"}} {
		t.Run(entry.name, func(t *testing.T) {
			var insns, stacks [2]int
			var hashes [2]string
			for i, env := range []string{entry.before, entry.after} {
				c := afGate7Load(t, env)
				if len(c.Programs) != 1 {
					t.Fatal("AF gate7 entry roster")
				}
				name := "xdp_firewall_main"
				if entry.name == "gate" {
					name = "xdp_whitelist_gate"
				}
				p := c.Programs[name]
				if p == nil {
					t.Fatal("AF gate7 wrong program")
				}
				t.Logf("FF_VERIFIER_RAW env=%s\n%s", env, p.VerifierLog)
				ins := regexp.MustCompile(`processed ([0-9]+) insns`).FindAllStringSubmatch(p.VerifierLog, -1)
				stack := regexp.MustCompile(`(?m)^stack depth ([0-9]+(?:\+[0-9]+)*)\s*$`).FindAllStringSubmatch(p.VerifierLog, -1)
				if len(ins) != 1 || len(stack) != 1 {
					t.Fatal("AF gate7 absent/duplicate verifier summaries")
				}
				insns[i], _ = strconv.Atoi(ins[0][1])
				for _, f := range strings.Split(stack[0][1], "+") {
					v, _ := strconv.Atoi(f)
					stacks[i] += v
				}
				raw, err := os.ReadFile(os.Getenv(env))
				if err != nil {
					t.Fatal(err)
				}
				hashes[i] = fmt.Sprintf("%x", sha256.Sum256(raw))
				c.Close()
			}
			t.Logf("FF_GATE7 program=%s source_before=%s source_after=%s before_sha=%s after_sha=%s before=%d after=%d delta=%d stack_before=%d stack_after=%d stack_delta=%d", entry.name, beforeSource, afterSource, hashes[0], hashes[1], insns[0], insns[1], insns[1]-insns[0], stacks[0], stacks[1], stacks[1]-stacks[0])
			if insns[0] <= 0 || insns[1] <= 0 || (entry.name == "gate" && (insns[1] > 500000 || insns[1]-insns[0] > 20000 || stacks[1]-stacks[0] > 64)) || (entry.name == "main" && insns[1] > 1000000) {
				t.Fatal("AF gate7 budget exceeded")
			}
		})
	}
}
