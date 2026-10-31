package api

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// TD-164 G6: per-claim expiry must not change any machine-facing JSON shape.
func TestTD164ResponseShape(t *testing.T) {
	keys := func(v any) string {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	rule := "action,comment,cond_key,created_at,created_by,dscp,dst_cidr,dst_ip,dst_port,enabled,expires_at,fragment,group_key,icmp_code,icmp_type,id,kind,logical_id,match_anomaly,pkt_len,protocol,rate_limit,src_cidr,src_ip,src_port,tcp_flags,ttl,updated_at,updated_by"
	if got := keys(RuleDTO{}); got != rule {
		t.Fatalf("G6 rule keys %s", got)
	}
	if got := keys(CreateResponse{}); got != sortedJoin(rule+",epoch,existing,gen,nodes") {
		t.Fatalf("G6 create reply keys %s", got)
	}
	existing, gen := true, uint64(1)
	if got := keys(BatchItem{Rule: &RuleDTO{}, Existing: &existing, Gen: &gen}); got != "existing,gen,index,rule" {
		t.Fatalf("G6 batch item keys %s", got)
	}
}

func sortedJoin(csv string) string {
	parts := strings.Split(csv, ",")
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
