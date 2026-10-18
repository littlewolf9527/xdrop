package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"golang.org/x/crypto/bcrypt"
)

func c5aV3(t *testing.T, path, password, token string) {
	t.Helper()
	raw, err := sql.Open("sqlite3", path)
	require(t, err == nil, "v3 open")
	defer raw.Close()
	_, err = raw.Exec(c5aV3DDL)
	require(t, err == nil, "v3 DDL")
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require(t, err == nil, "v3 password fixture")
	now := time.Now().UTC().Format(store.TimeFormat)
	_, err = raw.Exec("INSERT INTO users VALUES(1,'v3-admin',?,?,?,?)", string(hash), now, "cli", now)
	require(t, err == nil, "v3 user")
	digest := sha256.Sum256([]byte(token))
	_, err = raw.Exec("INSERT INTO sessions VALUES(?,1,?)", hex.EncodeToString(digest[:]), now)
	require(t, err == nil, "v3 session")
	_, err = raw.Exec("INSERT INTO audit(at,actor,source,action,target) VALUES(?,'system:cli','','user.create','user:v3-admin')", now)
	require(t, err == nil, "v3 audit")
	var version int
	require(t, raw.QueryRow("SELECT version FROM schema_version").Scan(&version) == nil && version == 3, "true v3 fixture")
}

func TestC5AMigrationSession(t *testing.T) {
	path, password, token := filepath.Join(t.TempDir(), "v3.db"), c4aSecret(t), c4aSecret(t)
	c5aV3(t, path, password, token)
	db, err := store.Open(path)
	require(t, err == nil, "migration")
	defer db.Close()
	acc := auth.New(db)
	require(t, err == nil && acc != nil, "auth")
	req, err := http.NewRequest("GET", "/api/v1/auth/me", nil)
	require(t, err == nil, "request")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	actor, e := acc.Authenticate(req)
	require(t, e == nil && actor.Kind == rules.UI && actor.Name == "v3-admin" && actor.Admin, "v3 session still authenticates as admin")
	fresh, _, e := acc.Login("v3-admin", password, "")
	require(t, e == nil && fresh != "", "old password still authenticates")
	t.Log("v3_session_authenticated=1 old_password_authenticated=1")
}

func TestC5ALab(t *testing.T) {
	t.Run("L-c5a", func(t *testing.T) {
		if os.Getenv("XDROP_CTLCUT3_LAB") == "" {
			t.Skip("requires owned lab namespaces and native binaries")
		}
		root := t.TempDir()
		dbpath, password, token := filepath.Join(root, "controller.db"), c4aSecret(t), c4aSecret(t)
		c5aV3(t, dbpath, password, token)
		base, agentURL := os.Getenv("XDROP_CTLCUT3_URL"), os.Getenv("XDROP_CTLCUT2_AGENT_URL")
		logs, keyfile := os.Getenv("XDROP_CTLCUT2_LOG_DIR"), os.Getenv("XDROP_CTLCUT2_KEY_FILE")
		labProcessStart(t, os.Getenv("XDROP_CTLCUT2_AGENT"), os.Getenv("XDROP_CTLCUT2_AGENT_CONFIG"), filepath.Join(logs, "L-c5a-agent.log"))
		path := filepath.Join(root, "controller.example.yaml")
		config := "listen: " + strings.TrimPrefix(base, "http://") + "\ndatabase: " + dbpath + "\nsecret_key_file: " + filepath.Join(root, "master.key") + "\n"
		require(t, os.WriteFile(path, []byte(config), 0600) == nil, "lab config")
		labNodeInit(t, os.Getenv("XDROP_CTLCUT3_CONTROLLER"), path, "lab", agentURL, keyfile)
		labProcessStart(t, os.Getenv("XDROP_CTLCUT3_CONTROLLER"), path, filepath.Join(logs, "L-c5a-controller.log"))
		s := labAccount(base)
		s.record(t, "password", password)
		s.record(t, "token", token)
		call := func(method, path, cookie, body string, want int) []byte {
			t.Helper()
			b, code, _, _, err := labRaw(base, method, path, cookie, "", body, nil)
			require(t, err == nil && code == want, "lab request", method, path, code)
			return b
		}
		var me IdentityDTO
		require(t, json.Unmarshal(call("GET", "/auth/me", token, "", 200), &me) == nil && me.Role == "admin", "v3 session preserved")
		raw, err := sql.Open("sqlite3", dbpath)
		require(t, err == nil, "upgraded database")
		var version int
		require(t, raw.QueryRow("SELECT version FROM schema_version").Scan(&version) == nil && version == 6, "binary v3 upgrade")
		require(t, raw.Close() == nil, "close inspection")
		operatorPassword := c4aSecret(t)
		s.record(t, "password", operatorPassword)
		call("POST", "/users", s.cookie, c4aJSON(UserInput{LoginInput{"operator", operatorPassword}, "operator"}), 201)
		cookies := map[string]string{}
		for _, input := range []LoginInput{{"v3-admin", password}, {"operator", operatorPassword}} {
			_, code, cs, _, err := labRaw(base, "POST", "/auth/login", "", "", c4aJSON(input), nil)
			require(t, err == nil && code == 200 && len(cs) == 1, "two role login")
			cookies[input.Username] = cs[0].Value
			s.record(t, "token", cs[0].Value)
		}
		var denied Error
		require(t, json.Unmarshal(call("PUT", "/settings", cookies["operator"], `{"session_hours":2}`, 403), &denied) == nil && denied.Code == "admin_required", "operator admin denial")
		sample := func() ReconcileDTO {
			var system SystemDTO
			require(t, json.Unmarshal(call("GET", "/system", cookies["v3-admin"], "", 200), &system) == nil && len(system.Nodes) == 1, "system sample")
			return system.Nodes[0].RuleReconcile
		}
		var previous ReconcileDTO
		stable, until := time.Time{}, time.Now().Add(17*time.Minute)
		for time.Now().Before(until) {
			current := sample()
			if current.LastAt != "" && current.Result != "" && current.Result != "void" {
				if current.LastAt != previous.LastAt {
					stable = time.Now()
				}
				previous = current
				if !stable.IsZero() && time.Since(stable) >= 2*time.Second {
					break
				}
			}
			time.Sleep(time.Second)
		}
		require(t, !stable.IsZero() && time.Since(stable) >= 2*time.Second, "initial scheduled reconcile must stabilize")
		changedAt := time.Now().UTC()
		call("PUT", "/settings", cookies["v3-admin"], `{"reconcile_interval_minutes":1}`, 200)
		advanced := false
		var after ReconcileDTO
		var elapsed time.Duration
		until = changedAt.Add(130 * time.Second)
		for time.Now().Before(until) {
			current := sample()
			at, err := time.Parse(time.RFC3339, current.LastAt)
			if err == nil && at.After(changedAt) && current.LastAt != previous.LastAt && current.Result == "equal" {
				advanced = true
				after, elapsed = current, time.Since(changedAt)
				break
			}
			time.Sleep(time.Second)
		}
		require(t, advanced, "shortened scheduled reconcile did not advance with valid result")
		labAccountScan(t)
		t.Logf("L-c5a-evidence changed_at=%s before_last_at=%s after_last_at=%s after_result=%s deadline_s=130 elapsed_s=%.6f", changedAt.Format(time.RFC3339Nano), previous.LastAt, after.LastAt, after.Result, elapsed.Seconds())
		t.Log("L-c5a migrate_v3=1 roles=2 admin_denied=1 interval_minutes=1 scheduled_reconcile=1 manual_actions=0")
	})
}

const c5aV3DDL = `
CREATE TABLE rules (
 id TEXT PRIMARY KEY,
 logical_id INTEGER NOT NULL UNIQUE CHECK(logical_id > 0),
 kind TEXT NOT NULL,
 src_ip TEXT NOT NULL DEFAULT '', dst_ip TEXT NOT NULL DEFAULT '',
 src_cidr TEXT NOT NULL DEFAULT '', dst_cidr TEXT NOT NULL DEFAULT '',
 src_port INTEGER NOT NULL DEFAULT 0, dst_port INTEGER NOT NULL DEFAULT 0,
 protocol TEXT NOT NULL DEFAULT '',
 ttl TEXT, dscp TEXT, icmp_type TEXT, icmp_code TEXT, fragment TEXT, pkt_len TEXT,
 tcp_flags TEXT NOT NULL DEFAULT '', match_anomaly INTEGER NOT NULL DEFAULT 0,
 group_key TEXT NOT NULL, cond_key TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('drop','rate_limit')),
 rate_limit INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL,
 comment TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 expires_at TEXT, created_by TEXT NOT NULL, updated_by TEXT NOT NULL
);
CREATE UNIQUE INDEX rules_identity ON rules(group_key, cond_key);
CREATE INDEX rules_group ON rules(group_key);
CREATE INDEX rules_expiry ON rules(expires_at);
CREATE TABLE logical_id_hw (id INTEGER PRIMARY KEY CHECK(id = 1), high_water INTEGER NOT NULL);
INSERT INTO logical_id_hw VALUES(1,0);
CREATE TABLE whitelist (
 id TEXT PRIMARY KEY, src_ip TEXT NOT NULL DEFAULT '', dst_ip TEXT NOT NULL DEFAULT '',
 src_port INTEGER NOT NULL DEFAULT 0, dst_port INTEGER NOT NULL DEFAULT 0,
 protocol TEXT NOT NULL DEFAULT '', wl_key TEXT NOT NULL UNIQUE,
 comment TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, created_by TEXT NOT NULL
);
CREATE TABLE claims (
 rule_id TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
 claimant TEXT NOT NULL, claim_ref TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
 PRIMARY KEY(rule_id, claimant, claim_ref)
);
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL, created_by TEXT NOT NULL, password_changed_at TEXT NOT NULL);
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL);
CREATE INDEX sessions_user ON sessions(user_id); CREATE INDEX sessions_created ON sessions(created_at);
CREATE TABLE credentials (id TEXT PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT NOT NULL,
 created_at TEXT NOT NULL, created_by TEXT NOT NULL, retire_at TEXT, revoked_at TEXT, revoked_by TEXT);
CREATE INDEX credentials_name ON credentials(name);
CREATE TABLE settings (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT INTO settings VALUES('session_hours', 24);
CREATE TABLE audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, source TEXT NOT NULL,
 action TEXT NOT NULL, target TEXT NOT NULL, before TEXT, after TEXT);
CREATE INDEX audit_at ON audit(at);
INSERT INTO settings VALUES('audit_retention_days', 180);CREATE TABLE schema_version(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);INSERT INTO schema_version VALUES(1,3);`
