package api

import (
	"strings"
	"testing"
)

// Compare legacy predicates directly with H membership, without priorities or
// the compiler/evaluator as the expected-value oracle.
func TestCut53LegacyPredicateValueParity(t *testing.T) {
	h := &Handlers{}
	encode := func(r Rule) ConditionValue {
		t.Helper()
		p, err := h.prepareAtomicRule(r)
		if err != nil {
			t.Fatal(err)
		}
		v, err := EncodeConditionValue([]Rule{p.Rule})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	base := Rule{ID: "legacy", LogicalID: 17, SrcIP: "192.0.2.1", Protocol: "tcp", Action: "drop"}
	flagValues := 0
	names := []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
	// Each flag independently is unconstrained, required off, or required on.
	for state := 0; state < 6561; state++ {
		r, mask, value, digits := base, uint8(0), uint8(0), state
		var words []string
		for bit, name := range names {
			switch digits % 3 {
			case 1:
				mask |= 1 << bit
				words = append(words, "!"+name)
			case 2:
				mask |= 1 << bit
				value |= 1 << bit
				words = append(words, name)
			}
			digits /= 3
		}
		r.TcpFlags = strings.Join(words, ",")
		row := encode(r)
		for v := 0; v < 256; v++ {
			got := (row.Tab[2][v/2]>>uint(4*(v%2)))&1 != 0
			if got != (uint8(v)&mask == value) {
				t.Fatalf("legacy flags state=%d value=%d H=%v mask=%x expected=%x", state, v, got, mask, value)
			}
			flagValues++
		}
	}
	lengthValues := 0
	for _, bounds := range [][2]uint16{{0, 0}, {0, 65535}, {0, 39}, {40, 0}, {36, 100}, {1, 65535}, {65535, 65535}} {
		r := base
		r.PktLenMin, r.PktLenMax = bounds[0], bounds[1]
		row := encode(r)
		for n := 0; n < 65536; n++ {
			got := false
			for _, span := range row.Len[0] {
				got = got || uint16(n) >= span.Lo && uint16(n) <= span.Hi
			}
			want := (bounds[0] == 0 || uint16(n) >= bounds[0]) && (bounds[1] == 0 || uint16(n) <= bounds[1])
			if got != want {
				t.Fatalf("legacy length bounds=%v value=%d H=%v want=%v", bounds, n, got, want)
			}
			lengthValues++
		}
	}
	anomalyValues := 0
	for mask := uint8(0); mask < 4; mask++ {
		r := base
		r.MatchAnomaly = mask
		row := encode(r)
		for v := uint8(0); v < 16; v++ {
			got := (row.Tab[5][v/2]>>uint(4*(v%2)))&1 != 0
			if got != (mask == 0 || v&mask != 0) {
				t.Fatalf("legacy anomaly mask=%d value=%d H=%v", mask, v, got)
			}
			anomalyValues++
		}
	}
	t.Logf("CUT53_LEGACY_PREDICATES flag_rules=6561 flag_values=%d length_rules=7 length_values=%d anomaly_rules=4 anomaly_values=%d", flagValues, lengthValues, anomalyValues)
}
