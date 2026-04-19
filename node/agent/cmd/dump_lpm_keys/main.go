// Phase 0 tool: capture the exact byte layout of LPM trie keys as produced
// by `github.com/dropbox/goebpf`'s CreateLPMtrieKey + KeyValueToBytes path.
//
// The captured fixtures serve as ground truth for NEW-UT-02 in the migration
// plan (docs/proposals/goebpf-to-cilium-migration.md §8.1.2). After the
// cutover, xdrop's hand-rolled makeLPMv4Key / makeLPMv6Key functions must
// produce byte-for-byte identical output.
//
// Usage:
//   go run ./cmd/dump_lpm_keys > node/agent/cidr/testdata/lpm_keys_goebpf.json
//
// This tool is only meaningful while the goebpf import is still present;
// it becomes obsolete after Phase 2 cutover and can then be deleted.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/dropbox/goebpf"
)

var cidrs = []string{
	"0.0.0.0/0",
	"10.0.0.0/8",
	"192.0.2.0/24",
	"192.0.2.128/25",
	"::/0",
	"fd00::/8",
	"2001:db8::/32",
	"2001:db8::1/128",
}

type entry struct {
	CIDR   string `json:"cidr"`
	Family int    `json:"family"` // 4 or 6
	KeyLen int    `json:"key_len"`
	HexKey string `json:"hex_key"` // binary layout written to LPM trie map
}

func keyLen(cidr string) int {
	// IPv4 LPM key: u32 prefix_len + 4 bytes IP = 8
	// IPv6 LPM key: u32 prefix_len + 16 bytes IP = 20
	if strings.Contains(cidr, ":") {
		return 20
	}
	return 8
}

func main() {
	out := make([]entry, 0, len(cidrs))
	for _, c := range cidrs {
		ipnet := goebpf.CreateLPMtrieKey(c)
		if ipnet == nil {
			fmt.Fprintf(os.Stderr, "CreateLPMtrieKey(%q) returned nil\n", c)
			os.Exit(1)
		}
		size := keyLen(c)
		b, err := goebpf.KeyValueToBytes(ipnet, size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "KeyValueToBytes(%q): %v\n", c, err)
			os.Exit(1)
		}
		fam := 4
		if size == 20 {
			fam = 6
		}
		out = append(out, entry{
			CIDR:   c,
			Family: fam,
			KeyLen: len(b),
			HexKey: hex.EncodeToString(b),
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
}
