package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/controller/core/rules"
)

func c5aTemplateAudit(name, body string) map[string]any {
	h := sha256.Sum256([]byte(body))
	return map[string]any{"name": name, "body": hex.EncodeToString(h[:])[:16]}
}
func c5aTemplateSecrets(t *testing.T) {
	f := c4bFresh(t, c4bCorpus())
	marker := "TEST_ONLY_TEMPLATE_BODY_<marker>\n\"end\""
	tpl := decoded[TemplateDTO](t, f.call(t, "POST", "/templates", f.cookie, c4aJSON(TemplateInput{"marker", marker}), 201))
	var stored string
	require(t, f.db.Reader().QueryRow("SELECT body FROM templates WHERE id=?", tpl.ID).Scan(&stored) == nil && stored == marker, "allowed table carrier")
	response := decoded[[]TemplateDTO](t, f.call(t, "GET", "/templates", f.cookie, "", 200))
	require(t, len(response) == 1 && response[0].Body == marker, "allowed response carrier")
	events := c4bEvents(t, f)
	samples := 0
	for _, ev := range events {
		for _, raw := range []json.RawMessage{ev.Before, ev.After} {
			if len(raw) == 0 {
				continue
			}
			var value any
			require(t, json.Unmarshal(raw, &value) == nil, "audit JSON")
			require(t, !strings.Contains(fmt.Sprint(value), marker), "template body in decoded audit")
			samples++
		}
		if ev.Action == "template.create" {
			c4bEqualJSON(t, ev.After, c5aTemplateAudit("marker", marker))
		}
	}
	require(t, samples > 0 && !bytes.Contains(f.logs.Bytes(), []byte(marker)), "template forbidden carriers")
	t.Logf("template_allowed_table=1 response=1 audit_samples=%d log_matches=0", samples)
}
func TestC5AAPI(t *testing.T) {
	t.Run("C5A-admin-routes", func(t *testing.T) {
		f := c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
		key := f.issue(t, "admin-denial")
		f.call(t, "PUT", "/users/alice/role", f.cookie, `{"role":"operator"}`, 204)
		routes := []string{"POST /nodes", "PATCH /nodes/n1", "DELETE /nodes/n1", "POST /nodes/n1/test", "POST /nodes/test", "POST /users", "DELETE /users/bob", "PUT /users/bob/password", "PUT /users/bob/role", "GET /credentials", "POST /credentials", "DELETE /credentials/absent", "PUT /settings", "POST /templates", "PUT /templates/absent", "DELETE /templates/absent", "GET /audit/export"}
		counts := map[string]int{}
		for _, identity := range []struct{ name, value string }{{"operator", f.cookie}, {"machine", key.Key}} {
			for _, route := range routes {
				parts := strings.SplitN(route, " ", 2)
				before := c4aSnapshot(t, f.db)
				e := decoded[Error](t, f.call(t, parts[0], parts[1], identity.value, `{}`, 403))
				require(t, e.Code == "admin_required" && reflect.DeepEqual(before, c4aSnapshot(t, f.db)), "admin guard", identity.name, route)
				counts[identity.name]++
			}
		}
		require(t, len(routes) == 17 && counts["operator"] == 17 && counts["machine"] == 17, "independent admin route counts")
		t.Log("independent_admin_routes=17 operator_denied=17 machine_denied=17")
	})
	t.Run("C5A-role-live", func(t *testing.T) {
		f := c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
		missing := decoded[Error](t, f.call(t, "POST", "/users", f.cookie, c4aJSON(LoginInput{"missing", f.pw}), 400))
		require(t, missing.Code == "invalid_field" && missing.Field == "role", "missing role")
		f.call(t, "PUT", "/users/alice/role", f.cookie, `{"role":"operator"}`, 204)
		me := decoded[IdentityDTO](t, f.call(t, "GET", "/auth/me", f.cookie, "", 200))
		require(t, me.Role == "operator", "live role")
		denied := decoded[Error](t, f.call(t, "PUT", "/settings", f.cookie, `{"session_hours":2}`, 403))
		require(t, denied.Code == "admin_required", "live authority")
		bob := f.login(t, "bob", f.pw)
		f.call(t, "PUT", "/users/alice/role", bob, `{"role":"admin"}`, 204)
		require(t, decoded[IdentityDTO](t, f.call(t, "GET", "/auth/me", f.cookie, "", 200)).Role == "admin", "same session restored")
		users := decoded[[]UserDTO](t, f.call(t, "GET", "/users", f.cookie, "", 200))
		require(t, len(users) == 2 && users[0].Role == "admin" && users[1].Role == "admin", "user roles")
	})
	t.Run("C5A-settings-bounds", func(t *testing.T) {
		f := c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
		for field, values := range map[string][]any{"history_retention_days": {0, 91}, "session_hours": {0, 721}, "audit_retention_days": {0, 3651}, "reconcile_interval_minutes": {0, 1441}, "default_language": {"", "de-DE"}} {
			for _, value := range values {
				before := c4aSnapshot(t, f.db)
				e := decoded[Error](t, f.call(t, "PUT", "/settings", f.cookie, c4aJSON(map[string]any{field: value}), 400))
				require(t, e.Code == "invalid_field" && e.Field == field && reflect.DeepEqual(before, c4aSnapshot(t, f.db)), "setting bounds", field)
			}
		}
		result := decoded[SettingsDTO](t, f.call(t, "PUT", "/settings", f.cookie, `{"reconcile_interval_minutes":1,"default_language":"ja-JP"}`, 200))
		require(t, result.SessionHours == 24 && result.AuditRetentionDays == 180 && result.ReconcileIntervalMinutes == 1 && result.DefaultLanguage == "ja-JP", "four settings partial update")
	})
	t.Run("C5A-prefs", func(t *testing.T) {
		f := c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
		require(t, f.call(t, "GET", "/auth/me/prefs", f.cookie, "", 200).Body.String() == "{}", "empty prefs")
		for _, body := range []string{"[]", "null", "1", `{"x":"` + strings.Repeat("x", 8192) + `"}`} {
			e := decoded[Error](t, f.call(t, "PUT", "/auth/me/prefs", f.cookie, body, 400))
			require(t, e.Code == "invalid_field", "prefs validation")
		}
		auditBefore := c4aCount(t, f.db, "SELECT COUNT(*) FROM audit")
		boundary := `{"x":"` + strings.Repeat("x", 8184) + `"}`
		require(t, len(boundary) == 8192 && json.Valid([]byte(boundary)), "exact prefs boundary fixture")
		f.call(t, "PUT", "/auth/me/prefs", f.cookie, boundary, 204)
		require(t, f.call(t, "GET", "/auth/me/prefs", f.cookie, "", 200).Body.String() == boundary, "8192 byte prefs round trip")
		oversized := boundary[:len(boundary)-2] + `x"}`
		require(t, len(oversized) == 8193 && json.Valid([]byte(oversized)), "exact oversized prefs fixture")
		e := decoded[Error](t, f.call(t, "PUT", "/auth/me/prefs", f.cookie, oversized, 400))
		require(t, e.Code == "invalid_field" && f.call(t, "GET", "/auth/me/prefs", f.cookie, "", 200).Body.String() == boundary, "8193 byte prefs rejected without overwrite")
		t.Log("prefs_boundary_bytes=8192 accepted=1 readback_equal=1 rejected_bytes=8193")
		f.call(t, "PUT", "/auth/me/prefs", f.cookie, `{"language":"ja-JP","layout":[2,1]}`, 204)
		f.call(t, "PUT", "/auth/me/prefs", f.cookie, `{"theme":"dark"}`, 204)
		require(t, f.call(t, "GET", "/auth/me/prefs", f.cookie, "", 200).Body.String() == `{"theme":"dark"}` && c4aCount(t, f.db, "SELECT COUNT(*) FROM audit") == auditBefore, "prefs replace without audit")
		key := f.issue(t, "prefs")
		f.call(t, "GET", "/auth/me/prefs", key.Key, "", 403)
		f.call(t, "PUT", "/auth/me/prefs", key.Key, `{}`, 403)
		bob := f.login(t, "bob", f.pw)
		f.call(t, "DELETE", "/users/alice", bob, "", 204)
		require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM user_prefs") == 0, "prefs cascade")
	})
	t.Run("C5A-templates", func(t *testing.T) {
		f := c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
		full := strings.Repeat("x", 65536)
		tpl := decoded[TemplateDTO](t, f.call(t, "POST", "/templates", f.cookie, c4aJSON(TemplateInput{"first", full}), 201))
		require(t, len(tpl.ID) == 36 && strings.HasPrefix(tpl.ID, "tpl_"), "template ID")
		e := decoded[Error](t, f.call(t, "POST", "/templates", f.cookie, c4aJSON(TemplateInput{"first", "duplicate"}), 409))
		require(t, e.Code == "rule_conflict", "unique template name")
		for _, input := range []TemplateInput{{"", "body"}, {strings.Repeat("字", 65), "body"}, {"large", full + "x"}} {
			e := decoded[Error](t, f.call(t, "POST", "/templates", f.cookie, c4aJSON(input), 400))
			require(t, e.Code == "invalid_field", "template bounds")
		}
		for i := 1; i < 100; i++ {
			_, e := f.acc.PutTemplate(rules.Actor{Kind: rules.UI, Name: "alice"}, "", fmt.Sprintf("template-%d", i), "TEST_ONLY_BODY")
			require(t, e == nil, "fill template capacity", i)
		}
		e = decoded[Error](t, f.call(t, "POST", "/templates", f.cookie, c4aJSON(TemplateInput{"overflow", "body"}), 409))
		require(t, e.Code == "table_full" && e.Table == "templates", "template cap")
		f.call(t, "PUT", "/users/alice/role", f.cookie, `{"role":"operator"}`, 204)
		require(t, len(decoded[[]TemplateDTO](t, f.call(t, "GET", "/templates", f.cookie, "", 200))) == 100, "operator reads templates")
		f.call(t, "POST", "/templates", f.cookie, `{}`, 403)
		f.call(t, "PUT", "/templates/"+tpl.ID, f.cookie, `{}`, 403)
		f.call(t, "DELETE", "/templates/"+tpl.ID, f.cookie, "", 403)
	})
	t.Run("C5A-template-missing", func(t *testing.T) {
		f := c4aFresh(t, &c4aCorpus{samples: map[string][][]byte{}})
		f.call(t, "POST", "/templates", f.cookie, c4aJSON(TemplateInput{"present", "TEST_ONLY_EXISTING_BODY"}), 201)
		before := c4aSnapshot(t, f.db)
		auditBefore := c4aCount(t, f.db, "SELECT COUNT(*) FROM audit")
		require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM templates") == 1 && auditBefore > 0, "nonempty template and audit witnesses")
		missing := "tpl_" + strings.Repeat("0", 32)
		require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM templates WHERE id='"+missing+"'") == 0, "absent template fixture")
		e := decoded[Error](t, f.call(t, "PUT", "/templates/"+missing, f.cookie, c4aJSON(TemplateInput{"missing", "TEST_ONLY_NEW_BODY"}), 404))
		require(t, e.Code == "not_found", "missing template update")
		require(t, c4aCount(t, f.db, "SELECT COUNT(*) FROM templates") == 1 && c4aCount(t, f.db, "SELECT COUNT(*) FROM audit") == auditBefore && reflect.DeepEqual(before, c4aSnapshot(t, f.db)), "missing update changed table contents or audit count")
	})
	t.Run("C5A-template-secrets", c5aTemplateSecrets)
	t.Run("C5A-validate-wire", func(t *testing.T) {
		f := fresh(t)
		before := c4aSnapshot(t, f.db)
		e := decoded[Error](t, request(t, f.e, "POST", "/api/v1/rules/batch?validate=1", "ui", `{"items":[{"dst_ip":"192.0.2.1","unknown":1}]}`, 400))
		require(t, e.Code == "bad_request" && reflect.DeepEqual(before, c4aSnapshot(t, f.db)), "unknown field whole rejection")
		input := `{"items":[{"dst_ip":"192.0.2.1"},{"dst_ip":"192.0.2.1"},{"dst_ip":"192.0.2.1","action":"rate_limit","rate_limit":1},{"dst_cidr":"198.51.100.0/25"},{"dst_cidr":"198.51.100.0/26"},`
		for i := 1; i <= 5; i++ {
			input += fmt.Sprintf(`{"dst_ip":"203.0.113.1","ttl":"%d"}`, i)
			if i < 5 {
				input += ","
			}
		}
		input += "]}"
		w := request(t, f.e, "POST", "/api/v1/rules/batch?validate=1", "ui", input, 200)
		require(t, !strings.Contains(w.Body.String(), "validate_"), "wire temporary IDs")
		out := decoded[BatchResponse](t, w)
		require(t, len(out.Results) == 10, "wire results")
		for _, i := range []int{0, 1, 3, 5, 6, 7, 8} {
			r := out.Results[i]
			require(t, r.Rule != nil && r.Rule.ID == "" && r.Gen == nil, "unassigned IDs/gen", i)
		}
		require(t, *out.Results[1].Existing && out.Results[2].Error.Code == "rule_conflict" && out.Results[2].Error.RuleID == "batch:0", "wire existing/conflict")
		require(t, out.Results[4].Error.Code == "cidr_overlap" && reflect.DeepEqual(out.Results[4].Error.RuleIDs, []string{"batch:3", "batch:4"}), "wire overlap references")
		require(t, out.Results[9].Error.Code == "condition_capacity" && reflect.DeepEqual(out.Results[9].Error.RuleIDs, []string{"batch:5", "batch:6", "batch:7", "batch:8", "batch:9"}), "wire candidate references")
		require(t, reflect.DeepEqual(before, c4aSnapshot(t, f.db)), "wire preview writes")
	})
}
