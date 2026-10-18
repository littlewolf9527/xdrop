package ratelimit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTD074DivisorSources(t *testing.T) {
	integer := func(n int) *int { return &n }
	for _, tc := range []struct {
		name, online string
		missing      bool
		possible     int
		possibleErr  bool
		override     int
		want         Snapshot
		wantError    string
	}{
		{name: "range", online: "0-7", possible: 16, want: Snapshot{8, "auto", integer(8), integer(16)}},
		{name: "comma", online: "0-3,6", possible: 16, want: Snapshot{5, "auto", integer(5), integer(16)}},
		{name: "affinity-four", online: "0-2,5", possible: 16, want: Snapshot{4, "auto", integer(4), integer(16)}},
		{name: "affinity-seven", online: "0-6", possible: 16, want: Snapshot{7, "auto", integer(7), integer(16)}},
		{name: "empty", online: "", possible: 16, want: Snapshot{16, "possible", nil, integer(16)}},
		{name: "garbled", online: "garbled", possible: 32, want: Snapshot{32, "possible", nil, integer(32)}},
		{name: "missing-16", missing: true, possible: 16, want: Snapshot{16, "possible", nil, integer(16)}},
		{name: "missing-32", missing: true, possible: 32, want: Snapshot{32, "possible", nil, integer(32)}},
		{name: "both-failed", missing: true, possibleErr: true, wantError: "online"},
		{name: "online-4097", online: "0-4096", possible: 8192, wantError: "exceeds 4096"},
		{name: "possible-4097", missing: true, possible: 4097, wantError: "exceeds 4096"},
		{name: "override-zero", online: "0-7", possible: 16, override: 0, want: Snapshot{8, "auto", integer(8), integer(16)}},
		{name: "override-one", online: "0-7", possible: 16, override: 1, want: Snapshot{1, "config", integer(8), integer(16)}},
		{name: "override-max", online: "0-7", possible: 16, override: 4096, want: Snapshot{4096, "config", integer(8), integer(16)}},
		{name: "override-unknown", missing: true, possibleErr: true, override: 1, want: Snapshot{1, "config", nil, nil}},
		{name: "online-only", online: "0-7\n", possibleErr: true, want: Snapshot{8, "auto", integer(8), nil}},
		{name: "invalid-override", override: 4097, wantError: "bpf.rate_limit_divisor"},
		{name: "negative-override", override: -1, wantError: "bpf.rate_limit_divisor"},
		{name: "possible-zero", missing: true, possible: 0, wantError: "possible"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "online")
			if !tc.missing {
				if err := os.WriteFile(path, []byte(tc.online), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Resolve(path, func() (int, error) {
				if tc.possibleErr {
					return 0, errors.New("injected possible failure")
				}
				return tc.possible, nil
			}, tc.override)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("TD074_DIVISOR %s error=%v want=%q", tc.name, err, tc.wantError)
				}
				if tc.name == "both-failed" && !strings.Contains(err.Error(), "possible") {
					t.Fatal("TD074_DIVISOR both sources must be named")
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("TD074_DIVISOR %s got=%+v online=%v possible=%v want=%+v err=%v", tc.name, got, got.OnlineCPUs, got.PossibleCPUs, tc.want, err)
			}
			value := func(p *int) string {
				if p == nil {
					return "unknown"
				}
				return fmt.Sprint(*p)
			}
			wantLine := fmt.Sprintf("[rate_limit] divisor=%d source=%s online_cpus=%s possible_cpus=%s", tc.want.Divisor, tc.want.Source, value(tc.want.OnlineCPUs), value(tc.want.PossibleCPUs))
			if got.LogLine() != wantLine {
				t.Fatalf("TD074_LOG got=%q want=%q", got.LogLine(), wantLine)
			}
		})
	}
}

func TestTD074OnlineListRejections(t *testing.T) {
	for _, s := range []string{"0,0", "2-1", "0-3,2", "0-", "-1", "0,,1", "0-2-3", "0, 1"} {
		if _, err := parseOnline(s); err == nil {
			t.Errorf("online invalid list accepted: %q", s)
		}
	}
}
