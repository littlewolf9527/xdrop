package api

import "testing"

func TestTD035TCPReqEncoding(t *testing.T) {
	for _, tc := range []struct {
		name, proto, flags, icmpType, icmpCode string
		tcp, icmp                              uint8
	}{
		{"no-flags", "tcp", "", "", "", 0, 0},
		{"syn", "tcp", "SYN", "", "", 1, 0},
		{"not-syn", "tcp", "!SYN", "", "", 1, 0},
		{"icmp-type", "icmp", "", "8", "", 0, 1},
		{"icmp-code", "icmp", "", "", "0", 0, 1},
		{"icmp-unconstrained", "icmp", "", "", "", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Rule{ID: "td035", LogicalID: 1, Protocol: tc.proto, Action: "drop", TcpFlags: tc.flags}
			if tc.icmpType != "" {
				r.ICMPType = &tc.icmpType
			}
			if tc.icmpCode != "" {
				r.ICMPCode = &tc.icmpCode
			}
			row, err := EncodeConditionValue([]Rule{r})
			if err != nil {
				t.Fatal(err)
			}
			if row.TCPReq != tc.tcp || row.ICMPReq != tc.icmp || row.Pad != [1]uint8{} {
				t.Fatalf("TD035_ENCODE TCPReq=%d ICMPReq=%d Pad=%v want=%d/%d/zero", row.TCPReq, row.ICMPReq, row.Pad, tc.tcp, tc.icmp)
			}
			t.Logf("TD035_ENCODE name=%s TCPReq=%d ICMPReq=%d", tc.name, row.TCPReq, row.ICMPReq)
		})
	}
	row, err := EncodeConditionValue([]Rule{
		{ID: "plain", LogicalID: 3, Protocol: "tcp", Action: "drop"},
		{ID: "syn", LogicalID: 1, Protocol: "tcp", Action: "drop", TcpFlags: "SYN"},
		{ID: "not-syn", LogicalID: 2, Protocol: "tcp", Action: "drop", TcpFlags: "!SYN"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.Active != 7 || row.TCPReq != 3 || row.ICMPReq != 0 || row.RuleID != [4]uint32{1, 2, 3, 0} {
		t.Fatalf("TD035_ENCODE candidates active=%d TCPReq=%d ICMPReq=%d IDs=%v want=7/3/0/[1 2 3 0]", row.Active, row.TCPReq, row.ICMPReq, row.RuleID)
	}
}

func TestTD035IPv6BadFragmentScope(t *testing.T) {
	for _, tc := range []struct{ ip, cidr string }{
		{ip: "2001:db8::1"}, {cidr: "2001:db8::/64"},
	} {
		if err := validateNodeAnomalyFields(AnomalyBadFragment, "drop", "", tc.ip, "", tc.cidr); err == nil {
			t.Fatal("TD035 IPv6 bad_fragment target must remain rejected")
		}
	}
	if err := validateNodeAnomalyFields(AnomalyBadFragment, "drop", "", "198.51.100.1", "", ""); err != nil {
		t.Fatalf("TD035 IPv4 bad_fragment guard: %v", err)
	}
}
