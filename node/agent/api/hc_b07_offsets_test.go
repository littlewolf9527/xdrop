package api

import (
	"testing"
	"unsafe"
)

func TestHCB07Offsets(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want uintptr
	}{
		{"Action", conditionActionOffset, unsafe.Offsetof(ConditionValue{}.Action)},
		{"Rate", conditionRateOffset, unsafe.Offsetof(ConditionValue{}.Rate)},
		{"RuleID", conditionRuleIDOffset, unsafe.Offsetof(ConditionValue{}.RuleID)},
		{"Flags", ruleFlagsOffset, unsafe.Offsetof(RuleValue{}.Pad2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if uintptr(tc.got) != tc.want {
				t.Fatalf("offset=%d struct=%d", tc.got, tc.want)
			}
		})
	}
}
