package api

import (
	"encoding/json"
	"fmt"
	"github.com/cilium/ebpf"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestTD160RuleJSON(t *testing.T) {
	b, err := json.Marshal(Rule{})
	if err != nil || !strings.Contains(string(b), `"logical_id":0`) || !strings.Contains(string(b), `"protocol":""`) {
		t.Fatal("zero Rule must expose logical_id and protocol", err)
	}
	t.Setenv("P11_WRITE_GOLDEN", "") // Force the existing comparator into read-only mode.
	b, err = os.ReadFile("../testdata/sync-jia/rules_2_p11.json")
	if err != nil {
		t.Fatal(err)
	}
	ips := regexp.MustCompile(`src_ip\\":\\"([^\\]+)`).FindAllSubmatch(b, -1)
	if len(ips) != 2 {
		t.Fatal("sealed fixture must supply two legacy addresses")
	}
	// Replay TestJiaHandlerGolden inputs; reuse sealed addresses without new IP literals.
	rules := []Rule{{ID: "r", LogicalID: 17, SrcIP: string(ips[0][1]), Protocol: "tcp", Action: "rate_limit", RateLimit: 100}, {ID: "r2", LogicalID: 18, SrcIP: string(ips[1][1]), Action: "drop"}}
	f := cut55Memory(t)                                      // cut55_commit_test.go; prefix_ab_test.go supplies native atomic HTTP.
	f.h.blacklist, f.h.blacklistB = &ebpf.Map{}, &ebpf.Map{} // Zero key sizes reject before any syscall.
	r := cut53MemoryRouter(f.h)
	r.GET("/api/v1/rules", f.h.ListRules)
	hcB03Body(t, prefixABAtomicHTTP(t, f, nil), 200)
	for n := 1; n <= 2; n++ {
		hcB03Body(t, prefixABAtomicHTTP(t, f, rules[:n]), 200)
		t.Run(fmt.Sprintf("rules_%d_p11", n), func(t *testing.T) {
			cut53P3Golden(t, fmt.Sprintf("rules_%d_p11", n), "TestJiaHandlerGolden/SnapshotsAndWhitelist", cut53Request(t, r, "GET", "/api/v1/rules?page=1&limit=1000", nil))
		})
	}
}
