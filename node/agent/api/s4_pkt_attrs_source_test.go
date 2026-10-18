package api

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// B1 cut 5-4: both surviving caller constructions and their complete AST generation.
func TestS4PacketAttrsSourceLock(t *testing.T) {
	path := "../../bpf/xdrop_main.c"
	if root := os.Getenv("S4_SOURCE_ROOT"); root != "" {
		if !filepath.IsAbs(root) {
			t.Fatal("S4 source root must be absolute")
		}
		path = filepath.Join(root, "node/bpf/xdrop_main.c")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(path), "../.."))
	if err != nil {
		t.Fatal(err)
	}
	instrument, err := filepath.Abs("../../bpf/tools/s2b_c_replay.py")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", instrument, "--root", root, "--output", t.TempDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("B1 lookup generation AST contract: %v\n%s", err, output)
	}
	var record struct {
		Functions  map[string]any `json:"functions"`
		Generation string         `json:"semantic_generation"`
	}
	if err := json.Unmarshal(output, &record); err != nil || len(record.Functions) != 6 || record.Generation != "b1cut54" {
		t.Fatalf("B1 AST evidence missing: %v\n%s", err, output)
	}
	for _, retired := range []string{"lookup_rule_anomaly", "lookup_cidr_rule_anomaly"} {
		if _, exists := record.Functions[retired]; exists {
			t.Fatalf("retired lookup remains in AST evidence: %s", retired)
		}
	}
	source := string(raw)
	for name, snippet := range map[string]string{
		"exact": `  struct pkt_attrs attrs = {
      .pkt_len = pkt_len,
      .tcp_flags = tcp_flags,
      .pkt_anomaly = pkt_anomaly,
      .ttl = ttl,
      .dscp = dscp,
      .icmp_type = icmp_type,
      .icmp_code = icmp_code,
      .frag_class = frag_class,
      .icmp_valid = icmp_valid,
      .l4_valid = l4_valid, .pad = {0},
      .out = {.winner = COND_NO_WINNER, .action = 0, .pad = {0, 0},
              .rate = 0, .rule_id = 0},
  };
  struct rule_value *rule = lookup_rule(&key, &matched_key,
      &attrs, rule_sel, config_slot);`,
		"cidr": `    struct pkt_attrs cidr_attrs = {
        .pkt_len = pkt_len,
        .tcp_flags = tcp_flags,
        .pkt_anomaly = pkt_anomaly,
        .ttl = ttl,
        .dscp = dscp,
        .icmp_type = icmp_type,
        .icmp_code = icmp_code,
        .frag_class = frag_class,
        .icmp_valid = icmp_valid,
        .l4_valid = l4_valid, .pad = {0},
        .out = {.winner = COND_NO_WINNER, .action = 0, .pad = {0, 0},
                .rate = 0, .rule_id = 0},
    };
    struct rule_value *cidr_rule =
        lookup_cidr_rule(&ck, &cidr_matched_key,
            &cidr_attrs, rule_sel, config_slot);`,
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(source, snippet) {
				t.Fatal("S4 caller text missing: " + name)
			}
		})
	}
}
