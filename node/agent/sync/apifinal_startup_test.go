package sync

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestAPIFinalStartupWithoutPull(t *testing.T) {
	raw, err := os.ReadFile("../main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, forbidden := range []string{"SyncOnStartup", "NewControllerSync", "ControllerURL", "ControllerSyncKey"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("startup retained %s", forbidden)
		}
	}
	clear, serve := strings.Index(s, "PreparePinnedStartup("), strings.Index(s, "gin.Default()")
	if clear < 0 || serve < 0 || clear >= serve {
		t.Fatal("startup clear must precede router")
	}
	t.Log("CLOSEOUT_STARTUP reverse_pull=0 clear_before_api=1")
}

// Match the entry-specific production errors, never merely HTTP 409.
func closeoutCapacityRejected(path string, status int, body interface{}) bool {
	reply, ok := body.(map[string]interface{})
	if !ok || status != 409 || reply["code"] != "table_full" {
		return false
	}
	message, ok := reply["error"].(string)
	if !ok {
		return false
	}
	switch path {
	case "/api/v1/sync/atomic":
		// api/logical_ledger.go:logicalTableFullError.Error
		const format = "logical state capacity %d exceeds %d; batch not published"
		var used, capacity int
		n, err := fmt.Sscanf(message, format, &used, &capacity)
		return err == nil && n == 2 && capacity >= 0 && used > capacity && message == fmt.Sprintf(format, used, capacity)
	case "/api/v1/rules/commit":
		// api/commit.go:admitCommitLogicalLocked -> commit_preflight.go:commitCapacityError
		const format = "logical_state capacity exceeded by %d rows"
		var excess int
		n, err := fmt.Sscanf(message, format, &excess)
		return err == nil && n == 1 && excess > 0 && message == fmt.Sprintf(format, excess)
	}
	return false
}

func TestCloseoutCapacityWitness(t *testing.T) {
	positive, negative := 0, 0
	for _, row := range []struct{ path, message, other string }{
		{"/api/v1/sync/atomic", "logical state capacity 2 exceeds 1; batch not published", "logical_state capacity exceeded by 1 rows"},
		{"/api/v1/rules/commit", "logical_state capacity exceeded by 1 rows", "logical state capacity 2 exceeds 1; batch not published"},
	} {
		cases := []struct {
			name, path, code, message string
			status                    int
			want                      bool
		}{
			{"positive", row.path, "table_full", row.message, 409, true},
			{"wrong_status", row.path, "table_full", row.message, 400, false},
			{"wrong_code", row.path, "validation_rejected", row.message, 409, false},
			{"other_entry_format", row.path, "table_full", row.other, 409, false},
			{"only_409", row.path, "table_full", "physical table full", 409, false},
			{"suffix", row.path, "table_full", row.message + " extra", 409, false},
			{"wrong_entry", "/api/v1/health", "table_full", row.message, 409, false},
		}
		for _, c := range cases {
			t.Run(row.path+"/"+c.name, func(t *testing.T) {
				body := map[string]interface{}{"code": c.code, "error": c.message}
				if got := closeoutCapacityRejected(c.path, c.status, body); got != c.want {
					t.Fatalf("capacity witness got=%v want=%v body=%v", got, c.want, body)
				}
			})
			if c.want {
				positive++
			} else {
				negative++
			}
		}
	}
	t.Logf("CLOSEOUT_CAPACITY_WITNESS positive=%d negative=%d entry_formats=2", positive, negative)
}
