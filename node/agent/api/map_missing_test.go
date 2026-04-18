package api

import (
	"fmt"
	"testing"
)

// TestIsMapEntryMissing locks in the string-based ENOENT detection used to
// suppress "delete of non-existent key" warnings on rate_limit rule delete
// (lazy-populated rl_states map — see BUG-017 polish).
func TestIsMapEntryMissing(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"ENOENT goebpf format", fmt.Errorf("ebpf_map_delete_elem() failed: No such file or directory"), true},
		{"ENOENT bare", fmt.Errorf("No such file or directory"), true},
		{"EINVAL", fmt.Errorf("ebpf_map_delete_elem() failed: Invalid argument"), false},
		{"EPERM", fmt.Errorf("ebpf_map_delete_elem() failed: Operation not permitted"), false},
		{"random error", fmt.Errorf("something bad happened"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMapEntryMissing(tc.err); got != tc.want {
				t.Errorf("isMapEntryMissing(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
