// p1_sync_whitelist_json_test.go — regression tests for P1: SyncWhitelistEntry JSON tags.
//
// Root cause: SyncWhitelistEntry had no JSON tags, so Go's JSON decoder could not
// map snake_case Controller keys (src_ip, dst_ip, src_port, dst_port) to the
// Go struct fields (SrcIP, DstIP, SrcPort, DstPort). Only "id" and "protocol"
// decoded correctly because they are case-insensitively equal to "ID" / "Protocol".
//
// Fix: add json:"..." tags to all fields in SyncWhitelistEntry.
//
// These tests verify the JSON contract between Controller and Node without
// requiring BPF/CAP_BPF — they directly unmarshal snake_case payloads.
package api

import (
	"encoding/json"
	"testing"
)

// snakeCasePayload mimics the JSON that Controller.ToNodeWhitelist() produces.
type snakeCasePayload struct {
	Entries []map[string]interface{} `json:"entries"`
}

func unmarshalEntries(t *testing.T, entries []map[string]interface{}) []SyncWhitelistEntry {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{"entries": entries})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var req struct {
		Entries []SyncWhitelistEntry `json:"entries"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return req.Entries
}

// P1-R1: src_ip-only entry must decode SrcIP — without json tags this was zero-valued,
// causing DoWhitelistAtomicSync to see an empty key and return "unsupported combo" (HTTP 400).
func TestSyncWhitelistEntry_P1_SrcIPOnly(t *testing.T) {
	entries := unmarshalEntries(t, []map[string]interface{}{
		{"id": "wl1", "src_ip": "192.0.2.1"},
	})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.ID != "wl1" {
		t.Errorf("ID = %q, want %q", e.ID, "wl1")
	}
	if e.SrcIP != "192.0.2.1" {
		t.Errorf("SrcIP = %q, want %q; json tag likely missing", e.SrcIP, "192.0.2.1")
	}
	if e.DstIP != "" || e.SrcPort != 0 || e.DstPort != 0 || e.Protocol != "" {
		t.Errorf("unexpected field bleed: dst_ip=%q src_port=%d dst_port=%d proto=%q",
			e.DstIP, e.SrcPort, e.DstPort, e.Protocol)
	}
}

// P1-R2: src_ip+protocol entry must decode BOTH fields — without json tags,
// src_ip was dropped and the rule silently degraded to protocol-only,
// causing over-broad whitelisting (fail-open).
func TestSyncWhitelistEntry_P1_SrcIPPlusProtocol(t *testing.T) {
	entries := unmarshalEntries(t, []map[string]interface{}{
		{"id": "wl2", "src_ip": "192.0.2.2", "protocol": "udp"},
	})
	e := entries[0]
	if e.SrcIP != "192.0.2.2" {
		t.Errorf("SrcIP = %q, want %q; combo would degrade to protocol-only without json tag", e.SrcIP, "192.0.2.2")
	}
	if e.Protocol != "udp" {
		t.Errorf("Protocol = %q, want %q", e.Protocol, "udp")
	}
}

// P1-R3: dst_ip+dst_port+protocol entry must decode all three fields.
func TestSyncWhitelistEntry_P1_DstIPDstPortProtocol(t *testing.T) {
	entries := unmarshalEntries(t, []map[string]interface{}{
		{"id": "wl3", "dst_ip": "198.51.100.5", "dst_port": 443, "protocol": "tcp"},
	})
	e := entries[0]
	if e.DstIP != "198.51.100.5" {
		t.Errorf("DstIP = %q, want %q", e.DstIP, "198.51.100.5")
	}
	if e.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", e.DstPort)
	}
	if e.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want %q", e.Protocol, "tcp")
	}
}

// P1-R4: full 5-tuple entry — all five fields must round-trip.
func TestSyncWhitelistEntry_P1_Full5Tuple(t *testing.T) {
	entries := unmarshalEntries(t, []map[string]interface{}{
		{
			"id":       "wl4",
			"src_ip":   "192.0.2.10",
			"dst_ip":   "198.51.100.20",
			"src_port": 1234,
			"dst_port": 80,
			"protocol": "tcp",
		},
	})
	e := entries[0]
	if e.SrcIP != "192.0.2.10" {
		t.Errorf("SrcIP = %q, want %q", e.SrcIP, "192.0.2.10")
	}
	if e.DstIP != "198.51.100.20" {
		t.Errorf("DstIP = %q, want %q", e.DstIP, "198.51.100.20")
	}
	if e.SrcPort != 1234 {
		t.Errorf("SrcPort = %d, want 1234", e.SrcPort)
	}
	if e.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", e.DstPort)
	}
	if e.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want %q", e.Protocol, "tcp")
	}
}
