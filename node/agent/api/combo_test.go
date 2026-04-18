package api

import "testing"

func TestValidateComboType(t *testing.T) {
	tests := []struct {
		name      string
		comboType int
		wantErr   bool
	}{
		{"valid zero", 0, false},
		{"valid max", ComboBitmapSize - 1, false},
		{"ComboUnknown rejected", ComboUnknown, true},
		{"negative rejected", -5, true},
		{"equal to bitmap size rejected", ComboBitmapSize, true},
		{"beyond bitmap rejected", 100, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateComboType(tc.comboType)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateComboType(%d) error = %v, wantErr %v", tc.comboType, err, tc.wantErr)
			}
		})
	}
}

func TestGetComboType_AllZeroReturnsUnknown(t *testing.T) {
	var key RuleKey
	if got := getComboType(key); got != ComboUnknown {
		t.Errorf("getComboType(zero-key) = %d, want ComboUnknown (%d)", got, ComboUnknown)
	}
}

func TestGetCIDRComboType_AllZeroReturnsUnknown(t *testing.T) {
	var key CIDRRuleKey
	if got := getCIDRComboType(key); got != ComboUnknown {
		t.Errorf("getCIDRComboType(zero-key) = %d, want ComboUnknown (%d)", got, ComboUnknown)
	}
}

func TestGetComboType_KnownCases(t *testing.T) {
	var srcIP IPAddr
	srcIP[0] = 10
	var dstIP IPAddr
	dstIP[0] = 192

	tests := []struct {
		name string
		key  RuleKey
		want int
	}{
		{"exact 5-tuple", RuleKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: 80, DstPort: 443, Protocol: 6}, ComboExact5Tuple},
		{"src_ip only", RuleKey{SrcIP: srcIP}, ComboSrcIPOnly},
		{"dst_ip only", RuleKey{DstIP: dstIP}, ComboDstIPOnly},
		{"protocol only", RuleKey{Protocol: 6}, ComboProtoOnly},
		{"src_port only", RuleKey{SrcPort: 80}, ComboSrcPortOnly},
		{"dst_port only", RuleKey{DstPort: 443}, ComboDstPortOnly},
		{"ports only", RuleKey{SrcPort: 80, DstPort: 443}, ComboPortsOnly},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getComboType(tc.key)
			if got != tc.want {
				t.Errorf("getComboType(%+v) = %d, want %d", tc.key, got, tc.want)
			}
		})
	}
}
