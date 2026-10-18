package api

import (
	"encoding/json"
	"github.com/littlewolf9527/xdrop/node/agent/condexpr"
	"reflect"
	"sort"
	"strings"
	"testing"
)

var cut4BExpressionKeys = []string{"ttl", "dscp", "icmp_type", "icmp_code", "fragment", "pkt_len"}

func cut4BRegistry(t *testing.T) []condexpr.Attribute {
	t.Helper()
	attrs := condexpr.ExpressionAttributes()
	var keys []string
	for _, a := range attrs {
		keys = append(keys, a.Key)
	}
	if !reflect.DeepEqual(keys, cut4BExpressionKeys) {
		t.Fatalf("registry expression view=%v want=%v", keys, cut4BExpressionKeys)
	}
	return attrs
}
func cut4BDeclare(t *testing.T, values ...interface{}) {
	t.Helper()
	cut4BRegistry(t)
	// Independent inventory of all old fields, not a registry-based filter.
	legacy := strings.Fields("ID Name SrcIP DstIP SrcCIDR DstCIDR SrcPort DstPort Protocol Action RateLimit PktLenMin PktLenMax TcpFlags MatchAnomaly Source Comment Enabled CreatedAt ExpiresAt UpdatedAt LogicalID Decoder ExpiresIn Stats Key")
	ignore := map[string]bool{}
	for _, s := range legacy {
		ignore[s] = true
	}
	want := append([]string(nil), cut4BExpressionKeys...)
	sort.Strings(want)
	for _, v := range values {
		typ := reflect.TypeOf(v)
		var got []string
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if ignore[f.Name] {
				continue
			}
			key := strings.Split(f.Tag.Get("json"), ",")[0]
			got = append(got, key)
			if f.Type != reflect.TypeOf((*string)(nil)) {
				t.Fatalf("%s.%s type=%s want *string", typ.Name(), f.Name, f.Type)
			}
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s condition field set=%v want=%v", typ.Name(), got, want)
		}
	}
}
func cut4BAssertState(t *testing.T, v interface{}, key string, raw string) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var m map[string]json.RawMessage
	if e = json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	got, has := m[key]
	if has != (raw != "null") || has && string(got) != raw {
		t.Fatalf("%T %s state=%s presence=%v want=%s", v, key, got, has, raw)
	}
}

func TestB1RegistryDeclarations(t *testing.T) {
	cut4BDeclare(t, Rule{}, SyncRule{}, StoredRule{}, StoredCIDRRule{})
}
func TestB1RegistryBehavior(t *testing.T) {
	h := &Handlers{}
	for _, a := range cut4BRegistry(t) {
		for _, raw := range []string{"null", `""`, `"64"`} {
			var r Rule
			if e := json.Unmarshal([]byte(`{"`+a.Key+`":`+raw+`}`), &r); e != nil {
				t.Fatal(e)
			}
			// Each reverse function gets independently constructed input, avoiding a
			// shared omission on both forward and reverse sides masking a defect.
			var sr SyncRule
			var stored StoredRule
			var cidr StoredCIDRRule
			payload := []byte(`{"` + a.Key + `":` + raw + `}`)
			json.Unmarshal(payload, &sr)
			json.Unmarshal(payload, &stored)
			json.Unmarshal(payload, &cidr)
			outputs := []interface{}{ruleToStored(RuleKey{}, r), ruleToStoredCIDR(CIDRRuleKey{}, "192.0.2.0/24", "", r), h.storedRuleToRule("r", stored), h.storedCIDRRuleToRule("r", cidr)}
			for _, v := range outputs {
				cut4BAssertState(t, v, a.Key, raw)
			}
		}
	}
}
