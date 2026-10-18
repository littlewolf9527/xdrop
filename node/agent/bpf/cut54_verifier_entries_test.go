package bpf

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func cut54VerifierEntrySets(getenv func(string) string) (before, after []string, err error) {
	parse := func(key string) ([]string, error) {
		raw := getenv(key)
		if raw == "" {
			return nil, fmt.Errorf("%s required: entry sets must be explicit", key)
		}
		names := strings.Split(raw, ",")
		seen := map[string]bool{}
		for _, name := range names {
			if name == "" || seen[name] || strings.TrimSpace(name) != name {
				return nil, fmt.Errorf("invalid entry set %s", key)
			}
			seen[name] = true
		}
		return names, nil
	}
	before, err = parse("XDROP_VERIFIER_BEFORE_ENTRIES")
	if err != nil {
		return
	}
	after, err = parse("XDROP_VERIFIER_AFTER_ENTRIES")
	if err != nil {
		return
	}
	retired, e := parse("XDROP_VERIFIER_RETIRED_ENTRIES")
	if e != nil {
		err = e
		return
	}
	if len(before) != 2 || len(after) != 1 || len(retired) != 1 || after[0] != "xdp_firewall_main" || retired[0] != "xdp_anomaly_verify" {
		err = fmt.Errorf("entry partition must retain main and explicitly retire anomaly")
		return
	}
	expected := map[string]bool{after[0]: true, retired[0]: true}
	for _, name := range before {
		if !expected[name] {
			err = fmt.Errorf("unknown baseline entry %s", name)
			return
		}
	}
	return
}
func cut54VerifierEntries(t *testing.T) ([]string, []string) {
	t.Helper()
	before, after, err := cut54VerifierEntrySets(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	return before, after
}
func TestCut54VerifierEntryPartition(t *testing.T) {
	base := map[string]string{"XDROP_VERIFIER_BEFORE_ENTRIES": "xdp_firewall_main,xdp_anomaly_verify", "XDROP_VERIFIER_AFTER_ENTRIES": "xdp_firewall_main", "XDROP_VERIFIER_RETIRED_ENTRIES": "xdp_anomaly_verify"}
	cells := 0
	for _, key := range []string{"", "XDROP_VERIFIER_BEFORE_ENTRIES", "XDROP_VERIFIER_AFTER_ENTRIES", "XDROP_VERIFIER_RETIRED_ENTRIES"} {
		_, _, err := cut54VerifierEntrySets(func(name string) string {
			if name == key {
				return ""
			}
			return base[name]
		})
		if (err != nil) != (key != "") {
			t.Fatalf("entry partition omitted=%q error=%v; missing declarations must fail, never skip", key, err)
		}
		cells++
	}
	for _, replacement := range []string{"xdp_anomaly_verify", "xdp_firewall_main,xdp_anomaly_verify", "xdp_firewall_main,xdp_firewall_main"} {
		_, _, err := cut54VerifierEntrySets(func(name string) string {
			if name == "XDROP_VERIFIER_AFTER_ENTRIES" {
				return replacement
			}
			return base[name]
		})
		if err == nil {
			t.Fatalf("invalid after entries accepted: %s", replacement)
		}
		cells++
	}
	t.Logf("CUT54_VERIFIER_ENTRIES cells=%d missing_retired=fail", cells)
}

// The actual testing wrapper must reject a missing retirement declaration.
// A child process distinguishes Fatal from Skip without invoking the kernel.
func TestCut54VerifierMissingEntriesFailClosed(t *testing.T) {
	if os.Getenv("XDROP_CUT54_VERIFIER_CHILD") == "1" {
		cut54VerifierEntries(t)
		t.Fatal("missing retired declaration returned normally")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestCut54VerifierMissingEntriesFailClosed$", "-test.v")
	command.Env = append(os.Environ(), "XDROP_CUT54_VERIFIER_CHILD=1", "XDROP_VERIFIER_BEFORE_ENTRIES=xdp_firewall_main,xdp_anomaly_verify", "XDROP_VERIFIER_AFTER_ENTRIES=xdp_firewall_main", "XDROP_VERIFIER_RETIRED_ENTRIES=")
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "--- FAIL: TestCut54VerifierMissingEntriesFailClosed") || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "XDROP_VERIFIER_RETIRED_ENTRIES required") {
		t.Fatalf("missing retired declaration must FAIL, never SKIP: error=%v output=%s", err, output)
	}
	t.Log("CUT54_VERIFIER_FAIL_CLOSED missing_retired=FAIL wrapper_executed=1 skips=0")
}
