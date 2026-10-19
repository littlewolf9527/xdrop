package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/node/agent/condexpr"
)

// Capture every cut55Map, including writes that leave identical row bytes.
type td124MapState struct {
	rows            map[string]string
	writes, deletes int
}

func td124MapStates(f *cut55Fixture) map[string]td124MapState {
	out := make(map[string]td124MapState)
	capture := func(name string, m *cut55Map) {
		s := td124MapState{rows: make(map[string]string), writes: m.writes, deletes: m.deletes}
		for key, value := range m.rows {
			s.rows[key] = string(value)
		}
		out[name] = s
	}
	for slot, tables := range f.tables {
		for kind, table := range tables {
			capture(fmt.Sprintf("slot_%d_table_%d", slot, kind), table)
		}
		capture(fmt.Sprintf("slot_%d_config", slot), f.configs[slot])
	}
	capture("selector", f.selector)
	return out
}

func TestTD124CommitKeyRejectsWithoutWrites(t *testing.T) {
	for _, tc := range []struct {
		name       string
		key        Rule
		validFirst bool
	}{
		{"G1_CIDR_registered", Rule{DstCIDR: "192.0.2.0/24", DstPort: 80, Protocol: "icmp"}, false},
		{"G1_exact", Rule{DstIP: "192.0.2.1", DstPort: 80, Protocol: "icmp"}, false},
		{"G1_c_CIDR_unregistered", Rule{DstCIDR: "198.51.100.0/24", DstPort: 80, Protocol: "icmp"}, false},
		{"G1_batch_valid_then_invalid", Rule{DstCIDR: "192.0.2.0/24", DstPort: 80, Protocol: "icmp"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := cut55Memory(t)
			x := Rule{ID: "td124-X", LogicalID: 1, DstCIDR: "192.0.2.0/24", Protocol: "all", Action: "drop"}
			y := Rule{ID: "td124-Y", LogicalID: 2, DstIP: "192.0.2.1", Protocol: "all", Action: "drop"}
			cut55Commit(t, f.h, cut55Group(t, f.h, x, x), cut55Group(t, f.h, y, y))
			storedX, ok := f.h.cidrRules[x.ID]
			if !ok || !reflect.DeepEqual(f.h.storedCIDRRuleToRule(x.ID, storedX), x) {
				t.Fatalf("%s: seed X does not round trip", tc.name)
			}
			xPhysical := cidrRuleKeyToBytes(storedX.Key)
			for slot := range f.tables {
				if _, ok := f.tables[slot][mirrorCIDR].rows[string(xPhysical)]; !ok {
					t.Fatalf("%s: seed X physical row absent on slot %d", tc.name, slot)
				}
			}
			if tc.name == "G1_c_CIDR_unregistered" {
				if _, known := f.h.cidrMgr.GetDstID(tc.key.DstCIDR); known {
					t.Fatalf("%s: prefix must be unregistered", tc.name)
				}
			}
			before := td124MapStates(f)
			snapshots := [2]string{cut55Snapshot(f, 0), cut55Snapshot(f, 1)}
			active, receipts := f.h.activeRuleSlot.Load(), f.receipts
			groups := []CommitGroup{cut55Group(t, f.h, tc.key)}
			if tc.validFirst {
				r := Rule{ID: "td124-pending", LogicalID: 3, DstIP: "203.0.113.1", Protocol: "tcp", Action: "drop"}
				groups = append([]CommitGroup{cut55Group(t, f.h, r, r)}, groups...)
			}
			w := cut55HTTP(t, f.h, groups)
			var result CommitResult
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("%s: decode response: %v", tc.name, err)
			}
			if w.Code != http.StatusBadRequest || result.Code != mutationInvalid {
				t.Errorf("%s: want 400 validation_rejected, got %d %s", tc.name, w.Code, w.Body.String())
			}
			if len(result.Groups) != 1 || result.Groups[0].Index != len(groups)-1 || result.Groups[0].Code != mutationInvalid {
				t.Errorf("%s: wrong rejected group: %+v", tc.name, result.Groups)
			}
			for slot := range f.tables {
				if got := cut55Snapshot(f, slot); got != snapshots[slot] {
					t.Errorf("%s: slot %d four-table bytes changed", tc.name, slot)
				}
				if _, ok := f.tables[slot][mirrorCIDR].rows[string(xPhysical)]; !ok {
					t.Errorf("%s: X physical row removed on slot %d", tc.name, slot)
				}
			}
			for name, got := range td124MapStates(f) {
				if !reflect.DeepEqual(got, before[name]) {
					t.Errorf("%s: %s bytes or writes/deletes changed", tc.name, name)
				}
			}
			if f.h.activeRuleSlot.Load() != active || f.receipts != receipts {
				t.Errorf("%s: active selector or receipts changed", tc.name)
			}
			// Equivalent to the rule content returned by ListRules, without its real maps.
			gotX, ok := f.h.cidrRules[x.ID]
			if !ok || !reflect.DeepEqual(f.h.storedCIDRRuleToRule(x.ID, gotX), x) || len(f.h.cidrRules) != 1 {
				t.Errorf("%s: X missing or its fields changed in memory", tc.name)
			}
			gotY, ok := f.h.rules[y.ID]
			if !ok || !reflect.DeepEqual(f.h.storedRuleToRule(y.ID, gotY), y) || len(f.h.rules) != 1 {
				t.Errorf("%s: exact rule memory changed", tc.name)
			}
		})
	}
}

func TestTD124CanonicalCommitKey(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     groupIdentity
		wantErr bool
	}{
		{"G2_cidr_icmp_port_rejected", groupIdentity{Kind: "cidr", DstCIDR: "192.0.2.0/24", DstPort: 80, Protocol: "icmp"}, true},
		{"G2_exact_gre_src_port_rejected", groupIdentity{Kind: "exact", DstIP: "192.0.2.1", SrcPort: 1, Protocol: "gre"}, true},
		{"G2_cidr_esp_zero_ports_accepted", groupIdentity{Kind: "cidr", DstCIDR: "192.0.2.0/24", Protocol: "esp"}, false},
		{"G2_cidr_tcp_port_accepted", groupIdentity{Kind: "cidr", DstCIDR: "192.0.2.0/24", DstPort: 80, Protocol: "tcp"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.key)
			if err != nil {
				t.Fatal(err)
			}
			got, err := (&Handlers{}).canonicalCommitKey(raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("%s: wantErr=%v, got %v", tc.name, tc.wantErr, err)
			}
			if tc.wantErr {
				want := fmt.Sprintf("protocol=%s does not carry ports (src_port/dst_port must be 0); got src_port=%d dst_port=%d", tc.key.Protocol, tc.key.SrcPort, tc.key.DstPort)
				if err.Error() != want {
					t.Errorf("%s: error=%q want=%q", tc.name, err, want)
				}
			} else if got != tc.key {
				t.Errorf("%s: canonical key changed: %+v", tc.name, got)
			}
		})
	}
}

func TestTD124CommitPhysicalKey(t *testing.T) {
	f := cut55Memory(t)
	x := Rule{ID: "td124-X", LogicalID: 1, DstCIDR: "192.0.2.0/24", Protocol: "all", Action: "drop"}
	cut55Commit(t, f.h, cut55Group(t, f.h, x, x))
	for _, tc := range []struct {
		name    string
		key     groupIdentity
		wantErr bool
		known   bool
	}{
		{"G3_registered_invalid", groupIdentity{Kind: "cidr", DstCIDR: x.DstCIDR, DstPort: 80, Protocol: "icmp"}, true, false},
		{"G3_registered_valid", groupIdentity{Kind: "cidr", DstCIDR: x.DstCIDR, Protocol: "all"}, false, true},
		{"G3_unregistered_dst", groupIdentity{Kind: "cidr", DstCIDR: "198.51.100.0/24", DstPort: 80, Protocol: "icmp"}, false, false},
		{"G3_unregistered_src", groupIdentity{Kind: "cidr", SrcCIDR: "198.51.100.0/24", Protocol: "all"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, known, err := f.h.commitPhysicalKey(tc.key)
			if (err != nil) != tc.wantErr || known != tc.known {
				t.Errorf("%s: known=%v err=%v; want known=%v wantErr=%v", tc.name, known, err, tc.known, tc.wantErr)
			}
			if !tc.known && key != nil {
				t.Errorf("%s: want nil key, got %x", tc.name, key)
			}
			if tc.known && !bytes.Equal(key, cidrRuleKeyToBytes(f.h.cidrRules[x.ID].Key)) {
				t.Errorf("%s: key differs from G0 physical key", tc.name)
			}
			if tc.wantErr && err != nil && err.Error() != "protocol=icmp does not carry ports (src_port/dst_port must be 0); got src_port=0 dst_port=80" {
				t.Errorf("%s: original error was not preserved: %v", tc.name, err)
			}
		})
	}
}

// Frozen 3fad693 oracle: only the identifiers have a test-specific prefix.
var td124OldPortlessProtocolsNode = map[string]bool{
	"icmp":   true,
	"icmpv6": true,
	"igmp":   true,
	"gre":    true,
	"esp":    true,
}

func td124OldValidatePortProtocolCompatNode(protocol string, srcPort, dstPort uint16) error {
	if !td124OldPortlessProtocolsNode[strings.ToLower(protocol)] {
		return nil
	}
	if srcPort == 0 && dstPort == 0 {
		return nil
	}
	return fmt.Errorf(
		"protocol=%s does not carry ports (src_port/dst_port must be 0); got src_port=%d dst_port=%d",
		protocol, srcPort, dstPort)
}

func TestTD124PortProtocolParity(t *testing.T) {
	ports := [][2]uint16{{0, 0}, {1, 0}, {0, 1}, {65535, 65535}}
	for _, protocol := range []string{"", "all", "tcp", "udp", "icmp", "icmpv6", "igmp", "gre", "esp", "TCP", "Gre", "ICMPv6", "sctp", "bogus"} {
		for _, pair := range ports {
			t.Run(fmt.Sprintf("G4_old_table/protocol_%s/ports_%d_%d", protocol, pair[0], pair[1]), func(t *testing.T) {
				got := validatePortProtocolCompatNode(protocol, pair[0], pair[1])
				want := td124OldValidatePortProtocolCompatNode(protocol, pair[0], pair[1])
				if (got != nil) != (want != nil) {
					t.Fatalf("new=%v old=%v", got, want)
				}
				if want != nil && got.Error() != want.Error() {
					t.Errorf("new=%q old=%q", got, want)
				}
			})
		}
	}
	names := make(map[string]bool)
	for protocol := 0; protocol <= 255; protocol++ {
		names[protocolToString(uint8(protocol))] = true
	}
	var protocols []string
	for protocol := range names {
		protocols = append(protocols, protocol)
	}
	sort.Strings(protocols)
	for _, protocol := range protocols {
		for _, pair := range ports {
			t.Run(fmt.Sprintf("G4_condexpr/protocol_%s/ports_%d_%d", protocol, pair[0], pair[1]), func(t *testing.T) {
				got := validatePortProtocolCompatNode(protocol, pair[0], pair[1])
				_, want := condexpr.NormalizeTuple(condexpr.Tuple{Protocol: protocol, SrcPort: int(pair[0]), DstPort: int(pair[1])})
				if (got != nil) != (want != nil) {
					t.Errorf("node=%v condexpr=%v", got, want)
				}
			})
		}
	}
}
