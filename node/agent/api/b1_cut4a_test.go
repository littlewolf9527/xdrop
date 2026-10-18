package api

import (
	"encoding/json"
	"fmt"
	"testing"
)

var cut4Fields = []string{"ttl", "dscp", "icmp_type", "icmp_code", "fragment", "pkt_len"}

func cut4AssertMetadata(t *testing.T, obj interface{}, field, raw string, id uint32) {
	t.Helper()
	b, e := json.Marshal(obj)
	if e != nil {
		t.Fatal(e)
	}
	var m map[string]json.RawMessage
	json.Unmarshal(b, &m)
	v, has := m[field]
	if has != (raw != "null") || has && string(v) != raw {
		t.Fatalf("%T %s=%s want=%s JSON=%s", obj, field, v, raw, b)
	}
	v, has = m["logical_id"]
	if !has || string(v) != fmt.Sprint(id) {
		t.Fatalf("%T logical_id=%s want=%d", obj, v, id)
	}
}

func TestB1Cut4ACarriers(t *testing.T) {
	h := &Handlers{}
	for _, field := range cut4Fields {
		for _, raw := range []string{"null", `""`, `"64"`} {
			t.Run(field+"/"+raw, func(t *testing.T) {
				var r Rule
				if e := json.Unmarshal([]byte(`{"id":"r","src_ip":"192.0.2.1","action":"drop","logical_id":17,"`+field+`":`+raw+`}`), &r); e != nil {
					t.Fatal(e)
				}
				cut4AssertMetadata(t, r, field, raw, 17)
				// Decode SyncRule independently too: tags must preserve snake_case keys.
				wire, _ := json.Marshal(r)
				var decoded SyncRule
				if e := json.Unmarshal(wire, &decoded); e != nil {
					t.Fatal(e)
				}
				cut4AssertMetadata(t, decoded, field, raw, 17)
				stored := ruleToStored(RuleKey{}, r)
				cut4AssertMetadata(t, stored, field, raw, 17)
				cut4AssertMetadata(t, h.storedRuleToRule("r", stored), field, raw, 17)
				cidr := ruleToStoredCIDR(CIDRRuleKey{}, "192.0.2.0/24", "", r)
				cut4AssertMetadata(t, cidr, field, raw, 17)
				cut4AssertMetadata(t, h.storedCIDRRuleToRule("r", cidr), field, raw, 17)

			})
		}
	}
}
