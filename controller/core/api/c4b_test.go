package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

const c4bAt = "2026-10-12T00:00:00Z"

var c4bActions = strings.Fields("rule.create rule.claim rule.update rule.release rule.delete rule.expire whitelist.create whitelist.delete auth.login auth.login_failed auth.logout user.create user.delete user.password credential.issue credential.revoke settings.update node.sync node.reconcile user.role template.create template.update template.delete node.create node.update node.delete")

type c4bFixture struct {
	*c4aFixture
	closable bool
	corpus   *c4bCollection
}

type c4bSecret struct{ category, value string }
type c4bCollection struct {
	*c4aCorpus
	values          []c4bSecret
	issuedResponses int
}

func (c *c4bCollection) remember(category string, values ...string) {
	for _, value := range values {
		c.values = append(c.values, c4bSecret{category, value})
	}
}
func (f *c4bFixture) login(t *testing.T, name, password string) string {
	t.Helper()
	token := f.c4aFixture.login(t, name, password)
	f.corpus.remember("password", password)
	f.corpus.remember("session", token)
	return token
}
func (f *c4bFixture) issue(t *testing.T, name string) IssuedDTO {
	t.Helper()
	w := f.call(t, "POST", "/credentials", f.cookie, c4aJSON(CredentialInput{name}), 201)
	v := decoded[IssuedDTO](t, w)
	require(t, len(v.Key) > 21, "credential length")
	f.corpus.remember("key", v.Key)
	f.corpus.remember("secret", v.Key[21:])
	return v
}
func (f *c4bFixture) call(t *testing.T, method, path, identity, body string, status int) *httptest.ResponseRecorder {
	t.Helper()
	w := f.c4aFixture.call(t, method, path, identity, body, status)
	if method == "POST" && path == "/credentials" {
		var object map[string]json.RawMessage
		require(t, json.Unmarshal(w.Body.Bytes(), &object) == nil && object != nil, "issued response object")
		delete(object, "key")
		b, err := json.Marshal(object)
		require(t, err == nil, "issued response serialization")
		f.corpus.add("responses", b)
		f.corpus.issuedResponses++
	}
	return w
}
func (f *c4bFixture) collectHashes(t *testing.T) {
	t.Helper()
	users, e := store.Users(f.db.Reader())
	require(t, e == nil, "hash scan users")
	for _, u := range users {
		f.corpus.remember("password_hash", u.PasswordHash)
	}
	credentials, e := store.Credentials(f.db.Reader())
	require(t, e == nil, "hash scan keys")
	for _, c := range credentials {
		f.corpus.remember("secret_hash", c.SecretHash)
	}
}
func c4bFresh(t *testing.T, corpus *c4bCollection) *c4bFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, e := store.Open(path)
	require(t, e == nil, "open")
	nodes := &stubNodes{}
	logs := &bytes.Buffer{}
	f := &c4bFixture{c4aFixture: &c4aFixture{fixture: &fixture{db: db, s: rules.New(db, nodes), n: nodes, logs: logs}, acc: auth.New(db), path: path, pw: c4aSecret(t), now: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), corpus: corpus.c4aCorpus}, closable: true, corpus: corpus}
	f.acc.Now = func() time.Time { return f.now }
	f.s.Now = func() time.Time { return f.now }
	f.e = New(f.s, nodes, AccountAuthenticator(f.acc), log.New(logs, "", 0), Options{Accounts: f.acc})
	require(t, f.acc.CreateUser(rules.Actor{Kind: rules.System, Name: "cli"}, "alice", f.pw, "admin") == nil, "seed user")
	corpus.remember("password", f.pw)
	f.cookie = f.login(t, "alice", f.pw)
	t.Cleanup(func() {
		corpus.add("logs", logs.Bytes())
		for _, suffix := range []string{"", "-wal"} {
			b, e := os.ReadFile(path + suffix)
			require(t, e == nil, "collect", suffix)
			kind := "database"
			if suffix != "" {
				kind = "wal"
			}
			corpus.add(kind, b)
		}
		if f.closable {
			db.Close()
		}
	})
	return f
}
func c4bCorpus() *c4bCollection {
	return &c4bCollection{c4aCorpus: &c4aCorpus{samples: map[string][][]byte{}}}
}
func c4bSQL(t *testing.T, f *c4bFixture, query string, args ...any) {
	t.Helper()
	_, e := f.db.Exec(query, args...)
	require(t, e == nil, "fixture SQL", e)
}
func c4bEvents(t *testing.T, f *c4bFixture) []store.AuditEvent {
	t.Helper()
	rows, e := store.AuditAfter(f.db.Reader(), "", "", "", 0, 10000)
	require(t, e == nil, "audit read")
	return rows
}
func c4bEqualJSON(t *testing.T, raw json.RawMessage, want any) {
	t.Helper()
	var got any
	if len(raw) > 0 {
		require(t, json.Unmarshal(raw, &got) == nil, "audit JSON")
	}
	encoded, e := json.Marshal(want)
	require(t, e == nil, "expected JSON")
	var expected any
	require(t, json.Unmarshal(encoded, &expected) == nil, "expected decode")
	require(t, reflect.DeepEqual(got, expected), "audit content mismatch (values withheld)")
}
func c4bRuleExpected(r RuleDTO, owner, comment string, claimants ...string) map[string]any {
	claims := []any{}
	for _, claim := range claimants {
		claims = append(claims, map[string]any{"claimant": claim, "claim_ref": ""})
	}
	match := map[string]any{"src_ip": "", "dst_ip": "192.0.2.10", "src_cidr": "", "dst_cidr": "", "src_port": 0, "dst_port": 80, "protocol": "tcp", "ttl": nil, "dscp": nil, "icmp_type": nil, "icmp_code": nil, "fragment": nil, "pkt_len": nil, "tcp_flags": "", "match_anomaly": 0, "action": "drop", "rate_limit": 0}
	return map[string]any{"id": r.ID, "logical_id": r.LogicalID, "match": match, "enabled": true, "comment": comment, "expires_at": r.ExpiresAt, "created_by": owner, "updated_by": owner, "claimants": claims}
}
func c4bUser(name, by string) map[string]any {
	return map[string]any{"username": name, "created_at": c4bAt, "created_by": by, "password_changed_at": c4bAt}
}
func c4bCredential(id string) map[string]any {
	return map[string]any{"id": id, "name": "key-test", "retire_at": nil, "revoked_at": nil}
}
func c4bTrigger(t *testing.T, f *c4bFixture, action string, observed *bool) {
	t.Helper()
	var before, after any
	retired := []any{}
	actor, source, target, at := "user:alice", "192.0.2.1", "", c4bAt
	method, path, input, status := "", "", "", 200
	if strings.HasPrefix(action, "rule.") {
		identity, owner, claimant := f.cookie, "user:alice", "ui"
		if action == "rule.release" || action == "rule.claim" {
			v := f.issue(t, "key-test")
			identity, owner, claimant = v.Key, "cred:key-test", "cred:key-test"
		}
		body := body(80)
		if action == "rule.expire" {
			body = strings.TrimSuffix(body, "}") + `,"expires_in":"1s"}`
		}
		var r RuleDTO
		if action != "rule.create" {
			r = decoded[CreateResponse](t, f.call(t, "POST", "/rules", identity, body, 201)).RuleDTO
			before = c4bRuleExpected(r, owner, "", claimant)
			target = "rule:" + r.ID
		}
		c4bSQL(t, f, "DELETE FROM audit")
		switch action {
		case "rule.create":
			r = decoded[CreateResponse](t, f.call(t, "POST", "/rules", identity, body, 201)).RuleDTO
			target = "rule:" + r.ID
			after = c4bRuleExpected(r, owner, "", claimant)
		case "rule.claim":
			f.call(t, "POST", "/rules", f.cookie, body, 200)
			after = c4bRuleExpected(r, owner, "", claimant, "ui")
		case "rule.update":
			f.call(t, "PATCH", "/rules/"+r.ID, f.cookie, `{"comment":"changed"}`, 200)
			after = c4bRuleExpected(r, owner, "changed", claimant)
		case "rule.release":
			actor = "cred:key-test"
			f.call(t, "DELETE", "/rules/"+r.ID, identity, "", 204)
		case "rule.delete":
			f.call(t, "DELETE", "/rules/"+r.ID, f.cookie, "", 204)
		case "rule.expire":
			actor, source, at = "system:expiry", "", "2026-10-12T00:00:02Z"
			require(t, f.s.ExpireDue(f.now.Add(2*time.Second)) == nil, "expiry")
		}
	} else {
		switch action {
		case "whitelist.create", "whitelist.delete":
			input = `{"dst_ip":"192.0.2.5","comment":"=1+1"}`
			if action == "whitelist.delete" {
				w := decoded[WhitelistDTO](t, f.call(t, "POST", "/whitelist", f.cookie, input, 201))
				target = "whitelist:" + w.ID
				before = map[string]any{"id": w.ID, "src_ip": "", "dst_ip": "192.0.2.5", "src_port": 0, "dst_port": 0, "protocol": "all", "comment": "=1+1"}
				method, path, status = "DELETE", "/whitelist/"+w.ID, 204
			} else {
				method, path, status = "POST", "/whitelist", 201
			}
		case "auth.login":
			method, path, input = "POST", "/auth/login", c4aJSON(LoginInput{"alice", f.pw})
			target = "user:alice"
		case "auth.login_failed":
			wrong := c4aSecret(t)
			f.corpus.remember("password", wrong)
			method, path, input, status = "POST", "/auth/login", c4aJSON(LoginInput{"alice", wrong}), 401
			actor = ""
			target = "user:alice"
			after = map[string]any{"reason": "password"}
		case "auth.logout":
			method, path, status = "POST", "/auth/logout", 204
			target = "user:alice"
		case "user.create":
			method, path, input, status = "POST", "/users", c4aJSON(UserInput{LoginInput{"bob", f.pw}, "admin"}), 201
			target = "user:bob"
			after = c4bUser("bob", "user:alice")
		case "user.delete", "user.password":
			f.call(t, "POST", "/users", f.cookie, c4aJSON(UserInput{LoginInput{"bob", f.pw}, "admin"}), 201)
			target = "user:bob"
			if action == "user.delete" {
				method, path, status = "DELETE", "/users/bob", 204
				before = c4bUser("bob", "user:alice")
			} else {
				method, path, input, status = "PUT", "/users/bob/password", c4aJSON(PasswordInput{f.pw}), 204
			}
		case "user.role":
			f.call(t, "POST", "/users", f.cookie, c4aJSON(UserInput{LoginInput{"bob", f.pw}, "admin"}), 201)
			method, path, input, status = "PUT", "/users/bob/role", `{"role":"operator"}`, 204
			target = "user:bob"
			before = map[string]any{"role": "admin"}
			after = map[string]any{"role": "operator"}
		case "template.create", "template.update", "template.delete":
			method, path, input, status = "POST", "/templates", `{"name":"first","body":"TEST_ONLY_TEMPLATE_MARKER"}`, 201
			if action != "template.create" {
				tpl := decoded[TemplateDTO](t, f.call(t, method, path, f.cookie, input, status))
				target = "template:" + tpl.ID
				before = c5aTemplateAudit("first", "TEST_ONLY_TEMPLATE_MARKER")
				method, path, input, status = "PUT", "/templates/"+tpl.ID, `{"name":"second","body":"TEST_ONLY_TEMPLATE_NEXT"}`, 200
				after = c5aTemplateAudit("second", "TEST_ONLY_TEMPLATE_NEXT")
				if action == "template.delete" {
					method, status, after = "DELETE", 204, nil
				}
			}
		case "credential.issue":
			old := f.issue(t, "key-test")
			retiring := c4bCredential(old.ID)
			retiring["retire_at"] = "2026-10-13T00:00:00Z"
			retired = append(retired, retiring)
			method, path, input, status = "POST", "/credentials", `{"name":"key-test"}`, 201
		case "credential.revoke":
			v := f.issue(t, "key-test")
			method, path, status = "DELETE", "/credentials/"+v.ID, 204
			target = "credential:" + v.ID
			before = c4bCredential(v.ID)
		case "settings.update":
			method, path, input = "PUT", "/settings", `{"session_hours":12}`
			target = "settings"
			before = map[string]any{"session_hours": 24, "audit_retention_days": 180, "reconcile_interval_minutes": 15, "default_language": 3, "history_retention_days": 30}
			after = map[string]any{"session_hours": 12, "audit_retention_days": 180, "reconcile_interval_minutes": 15, "default_language": 3, "history_retention_days": 30}
		case "node.create", "node.update", "node.delete":
			s, key := c5bAttach(t, f.fixture, f.acc)
			s.Now = func() time.Time { return f.now }
			f.corpus.remember("node_key", key)
			method, path, input, status = "POST", "/nodes", c4aJSON(map[string]string{"name": "n1", "base_url": "http://192.0.2.2", "api_key": key}), 201
			target = "node:n1"
			after = map[string]any{"name": "n1", "base_url": "http://192.0.2.2", "key_changed": true}
			if action != "node.create" {
				f.call(t, method, path, f.cookie, input, status)
				before = map[string]any{"name": "n1", "base_url": "http://192.0.2.2", "key_changed": false}
				method, path, input, status = "PATCH", "/nodes/n1", `{"base_url":"http://192.0.2.3"}`, 200
				after = map[string]any{"name": "n1", "base_url": "http://192.0.2.3", "key_changed": false}
				if action == "node.delete" {
					method, input, status, after = "DELETE", "", 204, nil
				}
			}
		case "node.sync", "node.reconcile":
			method, path, status = "POST", "/nodes/n1/"+strings.TrimPrefix(action, "node."), 202
			target = "node:n1"
		}
		f.collectHashes(t)
		c4bSQL(t, f, "DELETE FROM audit")
		identity := f.cookie
		if strings.HasPrefix(action, "auth.login") {
			identity = ""
		}
		w := f.call(t, method, path, identity, input, status)
		if action == "template.create" {
			tpl := decoded[TemplateDTO](t, w)
			target = "template:" + tpl.ID
			after = c5aTemplateAudit("first", "TEST_ONLY_TEMPLATE_MARKER")
		}
		if action == "whitelist.create" {
			v := decoded[WhitelistDTO](t, w)
			target = "whitelist:" + v.ID
			after = map[string]any{"id": v.ID, "src_ip": "", "dst_ip": "192.0.2.5", "src_port": 0, "dst_port": 0, "protocol": "all", "comment": "=1+1"}
		}
		if action == "credential.issue" {
			v := decoded[IssuedDTO](t, w)
			f.corpus.remember("key", v.Key)
			f.corpus.remember("secret", v.Key[21:])
			target = "credential:" + v.ID
			after = map[string]any{"issued": c4bCredential(v.ID), "retired": retired}
		}
		if action == "auth.login" {
			for _, c := range w.Result().Cookies() {
				f.corpus.remember("session", c.Value)
			}
		}
	}
	rows := c4bEvents(t, f)
	require(t, len(rows) == 1, "exactly one event", action, len(rows))
	ev := rows[0]
	require(t, ev.ID > 0 && ev.At == at && ev.Actor == actor && ev.Source == source && ev.Action == action && ev.Target == target, "audit columns", action, ev.ID, ev.At, ev.Actor, ev.Source, ev.Action, ev.Target)
	*observed = true
	f.collectHashes(t)
	exportIdentity := f.cookie
	if action == "auth.logout" {
		exportIdentity = f.login(t, "alice", f.pw)
	}
	for _, format := range []string{"csv", "json"} {
		w := f.call(t, "GET", "/audit/export?from=2026-10-11T00:00:00Z&to=2026-10-13T00:00:00Z&format="+format, exportIdentity, "", 200)
		f.corpus.add("audit", w.Body.Bytes())
	}
	b, _ := json.Marshal(rows)
	f.corpus.add("audit", b)
	c4bEqualJSON(t, ev.Before, before)
	c4bEqualJSON(t, ev.After, after)
}

func TestC4BAPI(t *testing.T) {
	corpus := c4bCorpus()
	seen := map[string]bool{}
	t.Run("C4B-events", func(t *testing.T) {
		for _, action := range c4bActions {
			action := action
			t.Run(action, func(t *testing.T) {
				f := c4bFresh(t, corpus)
				f.closable = false
				observed := false
				done := make(chan struct{})
				go func() { defer close(done); c4bTrigger(t, f, action, &observed) }()
				select {
				case <-done:
					f.closable = true
				case <-time.After(2 * time.Second):
					t.Fatalf("action %s timed out: transaction handle witness", action)
				}
				if observed {
					seen[action] = true
				}
			})
		}
		want := map[string]bool{}
		for _, a := range c4bActions {
			want[a] = true
		}
		require(t, len(seen) == 26 && reflect.DeepEqual(seen, want), "event closed set", seen)
		t.Logf("C4B-events executed=%d expected=26 actions=%v", len(seen), c4bActions)
	})
	t.Run("C4B-secrets", func(t *testing.T) {
		c5aTemplateSecrets(t)
		require(t, len(seen) == 26, "secrets must follow all events")
		require(t, corpus.issuedResponses > 0, "issued response collection missing")
		t.Logf("C4B-secrets issued_responses=%d", corpus.issuedResponses)
		categories := map[string]int{}
		for _, secret := range corpus.values {
			require(t, secret.value != "", "empty secret value", secret.category)
			categories[secret.category]++
		}
		for _, category := range []string{"password", "key", "secret", "session", "password_hash", "secret_hash", "node_key"} {
			require(t, categories[category] > 0, "missing secret category", category)
		}
		require(t, len(categories) == 7, "secret category set")
		t.Logf("C4B-secrets categories=7 counts=%v", categories)
		for _, kind := range []string{"logs", "database", "wal", "responses", "audit"} {
			require(t, len(corpus.samples[kind]) > 0, "empty collection", kind)
			for _, b := range corpus.samples[kind] {
				for _, secret := range corpus.values {
					if (kind == "database" || kind == "wal") && (secret.category == "password_hash" || secret.category == "secret_hash") {
						continue
					}
					require(t, !bytes.Contains(b, []byte(secret.value)), "secret exposed", kind, secret.category)
				}
				if kind == "audit" {
					require(t, !bytes.Contains(b, []byte("password_hash")) && !bytes.Contains(b, []byte("secret_hash")), "hash field exposed")
				}
			}
			t.Logf("C4B-secrets kind=%s collected=%d matches=0", kind, len(corpus.samples[kind]))
		}
	})
	t.Run("C4B-source", func(t *testing.T) {
		f := c4bFresh(t, c4bCorpus())
		cases := []struct {
			peer       string
			xff        []string
			real, want string
		}{
			{"192.0.2.8:1234", []string{"198.51.100.7"}, "", "192.0.2.8"},
			{"127.0.0.1:1234", []string{"198.51.100.7, 203.0.113.9"}, "", "203.0.113.9"},
			{"[::1]:1234", []string{"198.51.100.7, 203.0.113.9"}, "", "203.0.113.9"},
			{"127.0.0.1:1234", []string{"203.0.113.9, 127.0.0.1"}, "", "203.0.113.9"},
			{"127.0.0.1:1234", nil, "198.51.100.7", "127.0.0.1"},
			{"127.0.0.1:1234", []string{"bad, 203.0.113.9"}, "", "203.0.113.9"},
			{"127.0.0.1:1234", []string{"203.0.113.9, bad"}, "", "127.0.0.1"},
			{"127.0.0.1:1234", []string{"127.0.0.1"}, "", "127.0.0.1"},
			{"127.0.0.1:1234", []string{"203.0.113.9", "198.51.100.7"}, "", "203.0.113.9"},
			{"[::1]:1234", nil, "", "::1"},
		}
		for i, tc := range cases {
			i, tc := i, tc
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				for _, login := range []bool{false, true} {
					path, input := "/settings", fmt.Sprintf(`{"session_hours":%d}`, i+1)
					method := "PUT"
					if login {
						method, path, input = "POST", "/auth/login", c4aJSON(LoginInput{"alice", f.pw})
					}
					r := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(input))
					r.RemoteAddr = tc.peer
					if !login {
						r.Header.Set("Cookie", auth.CookieName+"="+f.cookie)
					}
					for _, value := range tc.xff {
						r.Header.Add("X-Forwarded-For", value)
					}
					if tc.real != "" {
						r.Header.Set("X-Real-IP", tc.real)
					}
					w := httptest.NewRecorder()
					f.e.ServeHTTP(w, r)
					require(t, w.Code == 200, "source request", i, login, w.Code)
					rows := c4bEvents(t, f)
					require(t, rows[len(rows)-1].Source == tc.want, "source", i, login, rows[len(rows)-1].Source, tc.want)
				}
			})
		}
	})
	t.Run("C4B-noop", func(t *testing.T) {
		t.Run("rule-update", func(t *testing.T) {
			f := c4bFresh(t, c4bCorpus())
			r := decoded[CreateResponse](t, f.call(t, "POST", "/rules", f.cookie, body(80), 201))
			before, e := store.Get(f.db.Reader(), r.ID)
			require(t, e == nil && before.Enabled && before.Comment == "", "existing row witness")
			n := len(c4bEvents(t, f))
			for _, tc := range []struct {
				name, method, suffix, body string
				status                     int
			}{
				{"empty-patch", "PATCH", "", `{}`, 200},
				{"same-comment", "PATCH", "", `{"comment":""}`, 200},
				{"same-enabled", "PUT", "/enabled", `{"enabled":true}`, 200},
			} {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					f.call(t, tc.method, "/rules/"+r.ID+tc.suffix, f.cookie, tc.body, tc.status)
					after, e := store.Get(f.db.Reader(), r.ID)
					require(t, e == nil && reflect.DeepEqual(before, after), "all business fields unchanged", tc.name)
					require(t, len(c4bEvents(t, f)) == n, "no-op update audited", tc.name)
				})
			}
			f.call(t, "PATCH", "/rules/"+r.ID, f.cookie, `{"comment":"changed"}`, 200)
			rows := c4bEvents(t, f)
			require(t, len(rows) == n+1 && rows[len(rows)-1].Action == "rule.update", "changed comment audited")
		})
		f := c4bFresh(t, c4bCorpus())
		v := f.issue(t, "noop")
		r := decoded[CreateResponse](t, f.call(t, "POST", "/rules", v.Key, `{"dst_ip":"192.0.2.10","expires_in":"1h"}`, 201)).RuleDTO
		f.call(t, "POST", "/whitelist", f.cookie, `{"dst_ip":"192.0.2.2"}`, 201)
		f.call(t, "DELETE", "/credentials/"+v.ID, f.cookie, "", 204)
		for _, tc := range []struct {
			method, path, input string
			status              int
		}{{"POST", "/whitelist", `{"dst_ip":"192.0.2.2"}`, 200}, {"DELETE", "/whitelist/missing", "", 204}, {"DELETE", "/credentials/" + v.ID, "", 204}, {"PUT", "/settings", `{"session_hours":24}`, 200}, {"PUT", "/settings", `{}`, 200}} {
			before := len(c4bEvents(t, f))
			f.call(t, tc.method, tc.path, f.cookie, tc.input, tc.status)
			require(t, len(c4bEvents(t, f)) == before, "no-op audit", tc.path)
		}
		v = f.issue(t, "noop")
		before := len(c4bEvents(t, f))
		f.call(t, "DELETE", "/rules/"+r.ID+"?claim_ref=missing", v.Key, "", 204)
		require(t, len(c4bEvents(t, f)) == before, "missing claim audited")
		renewed := decoded[CreateResponse](t, f.call(t, "POST", "/rules", v.Key, `{"dst_ip":"192.0.2.10","expires_in":"2h"}`, 200)).RuleDTO
		require(t, *renewed.ExpiresAt > *r.ExpiresAt, "expiry extension witness")
		require(t, len(c4bEvents(t, f)) == before, "renewal audited")
	})
	t.Run("C4B-atomic", func(t *testing.T) {
		for _, operation := range []string{"rules", "auth", "sync"} {
			operation := operation
			t.Run(operation, func(t *testing.T) {
				f := c4bFresh(t, c4bCorpus())
				before := c4aSnapshot(t, f.db)
				c4bSQL(t, f, "DROP TABLE audit")
				switch operation {
				case "rules":
					f.call(t, "POST", "/rules", f.cookie, body(80), 500)
				case "auth":
					f.call(t, "POST", "/users", f.cookie, c4aJSON(UserInput{LoginInput{"bob", f.pw}, "admin"}), 500)
				case "sync":
					require(t, len(f.n.Status()) == 1 && f.n.Status()[0].Name == "n1", "node exists")
					f.call(t, "POST", "/nodes/n1/sync", f.cookie, "", 500)
					require(t, f.n.syncs == 0, "sync triggered before audit")
				}
				c4bSQL(t, f, `CREATE TABLE audit(id INTEGER PRIMARY KEY,at TEXT,actor TEXT,source TEXT,action TEXT,target TEXT,before TEXT,after TEXT)`)
				filtered := [][]string{}
				for _, row := range before {
					if row[0] != "audit" {
						filtered = append(filtered, row)
					}
				}
				require(t, reflect.DeepEqual(filtered, c4aSnapshot(t, f.db)), "business wrote despite failed audit", operation)
			})
		}
	})
	t.Run("C4B-retention", func(t *testing.T) {
		f := c4bFresh(t, c4bCorpus())
		for _, days := range []int{0, 3651} {
			before := c4aSnapshot(t, f.db)
			w := f.call(t, "PUT", "/settings", f.cookie, fmt.Sprintf(`{"session_hours":12,"audit_retention_days":%d}`, days), 400)
			e := decoded[Error](t, w)
			require(t, e.Code == "invalid_field" && e.Field == "audit_retention_days" && reflect.DeepEqual(before, c4aSnapshot(t, f.db)), "invalid retention atomicity")
		}
		for _, tc := range []struct {
			input       string
			hours, days int
		}{{`{"audit_retention_days":1}`, 24, 1}, {`{"session_hours":12}`, 12, 1}, {`{}`, 12, 1}} {
			w := f.call(t, "PUT", "/settings", f.cookie, tc.input, 200)
			out := decoded[SettingsDTO](t, w)
			require(t, out.SessionHours == tc.hours && out.AuditRetentionDays == tc.days, "partial settings")
			s, e := store.ReadSettings(f.db.Reader())
			require(t, e == nil && s.SessionHours == tc.hours && s.AuditRetentionDays == tc.days, "stored partial settings")
		}
	})
	t.Run("C4B-read", c4bRead)
	t.Run("C4B-export", c4bExport)
	t.Run("PERF-c4b", c4bPerf)
}

func c4bSeed(t *testing.T, f *c4bFixture, n int) []store.AuditEvent {
	t.Helper()
	c4bSQL(t, f, "DELETE FROM audit")
	tx, e := f.db.Begin()
	require(t, e == nil, "seed transaction")
	defer tx.Rollback()
	for i := 0; i < n; i++ {
		at := f.now.Add(time.Duration(i/100) * time.Second).Format(store.TimeFormat)
		e := store.InsertAudit(tx, store.AuditEvent{At: at, Actor: "user:alice", Source: "192.0.2.1", Action: "node.sync", Target: fmt.Sprint(i)})
		require(t, e == nil, "seed")
	}
	require(t, tx.Commit() == nil, "seed commit")
	rows, e := store.AuditAfter(f.db.Reader(), "", "", "", 0, n+1)
	require(t, e == nil && len(rows) == n, "seed count")
	return rows
}
func c4bRead(t *testing.T) {
	f := c4bFresh(t, c4bCorpus())
	key := f.issue(t, "read").Key
	seeded := c4bSeed(t, f, 2500)
	seen := []int64{}
	cursor := ""
	for {
		w := f.call(t, "GET", "/audit?limit=1000&cursor="+url.QueryEscape(cursor), f.cookie, "", 200)
		var page struct {
			Items []AuditDTO `json:"items"`
			Next  string     `json:"next_cursor"`
		}
		require(t, json.Unmarshal(w.Body.Bytes(), &page) == nil, "page")
		for _, e := range page.Items {
			seen = append(seen, e.ID)
		}
		cursor = page.Next
		if cursor == "" {
			break
		}
		require(t, len(seen) <= 2500, "cursor loop")
	}
	want := []int64{}
	for i := len(seeded) - 1; i >= 0; i-- {
		want = append(want, seeded[i].ID)
	}
	require(t, reflect.DeepEqual(seen, want), "pagination order and completeness")
	for _, bounds := range []struct {
		query string
		n     int
	}{{"from=" + c4bAt + "&to=2026-10-12T00:00:01Z", 100}, {"from=2026-10-12T00:00:01Z&to=2026-10-12T00:00:02Z", 100}, {"to=" + c4bAt, 0}} {
		w := f.call(t, "GET", "/audit?limit=1000&"+bounds.query, f.cookie, "", 200)
		var page struct {
			Items []AuditDTO `json:"items"`
		}
		require(t, json.Unmarshal(w.Body.Bytes(), &page) == nil && len(page.Items) == bounds.n, "range bounds")
		for _, e := range page.Items {
			require(t, e.At != strings.TrimPrefix(strings.Split(bounds.query, "to=")[1], "&"), "exclusive to")
		}
	}
	for _, query := range []string{"limit=0", "limit=1001", "limit=bad", "from=bad", "to=bad", "cursor=bad"} {
		w := f.call(t, "GET", "/audit?"+query, f.cookie, "", 400)
		require(t, decoded[Error](t, w).Code == "invalid_field", "query error code")
	}
	f.call(t, "GET", "/audit", key, "", 403)
	f.call(t, "GET", "/audit/export?from="+c4bAt+"&to=2026-10-13T00:00:00Z&format=csv", key, "", 403)
	t.Log("C4B-read seeded=2500 traversed=2500 pages=3 ordered=true")
}

type c4bBrokenWriter struct {
	header    http.Header
	remaining int
}

func (w *c4bBrokenWriter) Header() http.Header { return w.header }
func (w *c4bBrokenWriter) WriteHeader(int)     {}
func (w *c4bBrokenWriter) Write(b []byte) (int, error) {
	if len(b) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, errors.New("test response write failure")
	}
	w.remaining -= len(b)
	return len(b), nil
}
func c4bExport(t *testing.T) {
	f := c4bFresh(t, c4bCorpus())
	seeded := c4bSeed(t, f, 2500)
	w := f.call(t, "POST", "/whitelist", f.cookie, `{"dst_ip":"192.0.2.6","comment":"=1+1"}`, 201)
	require(t, w.Code == 201, "JSON comment witness")
	seeded = c4bEvents(t, f)
	path := "/audit/export?from=" + c4bAt + "&to=2026-10-13T00:00:00Z&format="
	for _, format := range []string{"csv", "json"} {
		w := f.call(t, "GET", path+format, f.cookie, "", 200)
		require(t, strings.Contains(w.Header().Get("Content-Disposition"), "attachment") && strings.Contains(w.Header().Get("Content-Disposition"), "."+format+`"`), "download headers")
		if format == "json" {
			var got []store.AuditEvent
			expected := append([]store.AuditEvent{}, seeded...)
			for i := range expected {
				if expected[i].Before == nil {
					expected[i].Before = json.RawMessage(`null`)
				}
				if expected[i].After == nil {
					expected[i].After = json.RawMessage(`null`)
				}
			}
			require(t, json.Unmarshal(w.Body.Bytes(), &got) == nil && reflect.DeepEqual(got, expected), "JSON row set and raw content")
		} else {
			rows, e := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
			require(t, e == nil && len(rows) == len(seeded)+1, "CSV row count")
			require(t, reflect.DeepEqual(rows[0], strings.Split("id,at,actor,source,action,target,before,after", ",")), "CSV headers")
			for i, ev := range seeded {
				want := []string{fmt.Sprint(ev.ID), ev.At, ev.Actor, ev.Source, ev.Action, ev.Target, string(ev.Before), string(ev.After)}
				require(t, reflect.DeepEqual(rows[i+1], want), "CSV original JSON", i)
			}
		}
	}
	for _, prefix := range []string{"=", "+", "-", "@", "\t", "\r"} {
		require(t, csvCell(prefix+"sample") == "'"+prefix+"sample", "CSV escaping", prefix)
	}
	for _, v := range []string{"", "plain", "1", `{"comment":"=1+1"}`} {
		require(t, csvCell(v) == v, "CSV unchanged cell")
	}
	for _, query := range []string{"", "?format=csv", "?from=" + c4bAt + "&format=json", "?from=" + c4bAt + "&to=2026-10-13T00:00:00Z&format=xml"} {
		w := f.call(t, "GET", "/audit/export"+query, f.cookie, "", 400)
		require(t, decoded[Error](t, w).Code == "invalid_field", "export invalid parameters")
	}
	for _, format := range []string{"json", "csv"} {
		func() {
			defer func() { require(t, recover() == http.ErrAbortHandler, "export must propagate abort", format) }()
			r := httptest.NewRequest("GET", "/api/v1"+path+format, nil)
			r.Header.Set("Cookie", auth.CookieName+"="+f.cookie)
			f.e.ServeHTTP(&c4bBrokenWriter{header: http.Header{}, remaining: 100}, r)
		}()
	}
	a := &API{log: log.New(f.logs, "", 0)}
	engine := gin.New()
	engine.Use(a.recovery())
	engine.GET("/written", func(c *gin.Context) { c.String(200, "prefix"); panic("test ordinary panic") })
	ordinary := httptest.NewRecorder()
	engine.ServeHTTP(ordinary, httptest.NewRequest("GET", "/written", nil))
	require(t, ordinary.Code == 200 && ordinary.Body.String() == "prefix" && strings.Contains(f.logs.String(), "test ordinary panic"), "ordinary panic behavior")
	t.Log("C4B-export seed=2500 csv_json_equal=true escaped_prefixes=6 abort_formats=2")
}
func c4bPerf(t *testing.T) {
	f := c4bFresh(t, c4bCorpus())
	c4bSeed(t, f, 100000)
	for _, window := range []string{"", "?from=2026-10-12T00:05:00Z&to=2026-10-12T00:10:00Z"} {
		samples := []time.Duration{}
		for i := 0; i < 200; i++ {
			start := time.Now()
			f.call(t, "GET", "/audit"+window, f.cookie, "", 200)
			samples = append(samples, time.Since(start))
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		p99 := samples[197]
		t.Logf("PERF-c4b window=%t seed=100000 samples=%d p99=%s", window != "", len(samples), p99)
		require(t, len(samples) == 200 && p99 < 50*time.Millisecond, "audit read performance")
	}
	items := []string{}
	for i := 0; i < 500; i++ {
		items = append(items, body(i+100))
	}
	start := time.Now()
	w := f.call(t, "POST", "/rules/batch", f.cookie, `{"items":[`+strings.Join(items, ",")+`]}`, 200)
	result := decoded[BatchResponse](t, w)
	require(t, len(result.Results) == 500, "batch count")
	for _, r := range result.Results {
		require(t, r.Error == nil, "batch item")
	}
	t.Logf("C4B-batch items=500 elapsed=%s reporting_only=true", time.Since(start))
}
