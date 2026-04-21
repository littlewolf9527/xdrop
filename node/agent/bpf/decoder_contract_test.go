//go:build integration
// +build integration

// decoder_contract_test.go — xdrop-side consumer of the cross-repo byte-compat
// contract fixtures (xsight/shared/decoder/testdata/packet-fixtures.json).
//
// This is a Phase 0 skeleton. Each decoder phase (1/2/4) fills in its specific
// assertions: for each fixture that exercises the phase's decoder, the test
// loads the fixture bytes, downloads a corresponding xdrop rule, feeds the
// packet through an XDP BPF_PROG_TEST_RUN, and asserts the rule hits/misses
// match expected_decoders.
//
// Build tag `integration` keeps this test out of normal `go test ./...` runs.
// Activate via: go test -tags=integration -run DecoderContract ./node/agent/bpf/...
//
// The test SKIPS gracefully when:
//   - CAP_BPF / root not available → test rig can't load BPF programs
//   - packet-fixtures.json not found at any candidate path → xSight repo not
//     colocated and no local snapshot exists (Phase 0 tolerates this;
//     Phase 1+ will require at least one path to resolve)
//
// Neither xdrop normal build nor xdrop unit tests depend on this file.
package bpf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fixtureRecord mirrors the on-disk JSON schema. Kept minimal — only fields
// this test needs right now. Future phases extend freely.
type fixtureRecord struct {
	Name                  string   `json:"name"`
	Hex                   string   `json:"hex"`
	FrameType             string   `json:"frame_type"`
	ExpectedDecoders      []string `json:"expected_decoders"`
	ExpectedIsInvalid     bool     `json:"expected_is_invalid"`
	ExpectedIsBadFragment bool     `json:"expected_is_bad_fragment"`
	Notes                 string   `json:"notes"`
}

type fixtureFile struct {
	Version  int             `json:"version"`
	Fixtures []fixtureRecord `json:"fixtures"`
}

// fixtureSearchPaths are candidate locations for packet-fixtures.json in order
// of preference. First existing path wins.
//
//   1. XSIGHT_FIXTURES env var: explicit override for CI / custom layouts.
//   2. Sibling xsight repo assuming workspace layout (yecao-tools/{xsight,xdrop}).
//   3. Local snapshot under xdrop/docs/ (some Phase 1+ code may commit a copy).
func fixtureSearchPaths() []string {
	var paths []string
	if p := os.Getenv("XSIGHT_FIXTURES"); p != "" {
		paths = append(paths, p)
	}
	paths = append(paths,
		filepath.Join("..", "..", "..", "..", "xsight", "shared", "decoder", "testdata", "packet-fixtures.json"),
		filepath.Join("..", "..", "..", "docs", "testdata", "packet-fixtures.json"),
	)
	return paths
}

// loadFixtures finds and parses the fixture JSON. Returns nil, "" on miss so
// callers can t.Skip with a helpful diagnostic.
func loadFixtures(t *testing.T) (*fixtureFile, string) {
	t.Helper()
	for _, p := range fixtureSearchPaths() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var f fixtureFile
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatalf("%s: malformed JSON: %v", p, err)
		}
		if f.Version == 0 {
			// Scaffold version — not yet generated.
			continue
		}
		return &f, p
	}
	return nil, ""
}

func TestDecoderContractFixtureSkeleton(t *testing.T) {
	ff, path := loadFixtures(t)
	if ff == nil {
		t.Skip("packet-fixtures.json not found or still scaffold; " +
			"generate it on the xSight side: cd <xsight>/shared/decoder/testdata && go run generate.go")
	}
	if len(ff.Fixtures) == 0 {
		t.Fatalf("loaded %s but fixture list empty", path)
	}
	t.Logf("loaded %d fixtures from %s", len(ff.Fixtures), path)

	// Phase 0 skeleton: just iterate and confirm schema coverage. Phase 1/2/4
	// will replace the body with BPF_PROG_TEST_RUN assertions.
	for _, fx := range ff.Fixtures {
		fx := fx
		t.Run(fx.Name, func(t *testing.T) {
			if fx.Hex == "" {
				t.Errorf("fixture %q has empty hex", fx.Name)
			}
			if fx.FrameType != "ip" && fx.FrameType != "ethernet" {
				t.Errorf("fixture %q: unexpected frame_type %q", fx.Name, fx.FrameType)
			}
			// Phase 1: add gre/esp/igmp drop-rule assertions
			// Phase 2: add tcp_ack/tcp_rst/tcp_fin drop-rule assertions
			// Phase 4: add bad_fragment / invalid anomaly assertions
			t.Skipf("phase-specific contract assertion not yet implemented (notes: %s)", fx.Notes)
		})
	}
}
