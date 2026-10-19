// Package auth validates server sessions and named machine credentials.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"golang.org/x/crypto/bcrypt"
)

const CookieName = "xdrop_session"
const rotateOverlap = 24 * time.Hour

const (
	maxSessionHours             = 720
	maxAuditRetentionDays       = 3650
	maxHistoryRetentionDays     = 90
	maxReconcileIntervalMinutes = 1440
	maxDefaultLanguage          = 3
)

var validName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var keyShape = regexp.MustCompile(`^xdk_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$`)
var comparePassword = bcrypt.CompareHashAndPassword

// ValidName reports whether name is allowed for a new user, credential or node.
func ValidName(name string) bool {
	return validName.MatchString(name) && name != "." && name != ".."
}

type throttle struct {
	failures int
	next     time.Time
	checking bool
}
type Service struct {
	db         *store.DB
	Now        func() time.Time
	OnSettings func(store.Settings)
	dummy      []byte
	mu         sync.Mutex
	delays     map[string]*throttle
}

func New(db *store.DB) *Service {
	p, err := random(32)
	if err != nil {
		panic("authentication initialization failed")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		panic("authentication initialization failed")
	}
	return &Service{db: db, Now: time.Now, dummy: hash, delays: map[string]*throttle{}}
}
func random(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}
func digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func failure(code string) *rules.Error { return &rules.Error{Code: code, Message: code} }
func internal(err error) *rules.Error {
	if err != nil {
		return failure("internal")
	}
	return nil
}
func invalid(field string) *rules.Error {
	return &rules.Error{Code: "invalid_field", Message: "invalid field", Field: field}
}
func passwordHash(password string) (string, *rules.Error) {
	if len(password) < 10 || len(password) > 72 {
		return "", invalid("password")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), internal(err)
}
func (s *Service) now() time.Time { return s.Now().UTC().Truncate(time.Second) }
func active(c store.Credential, now string) bool {
	return c.RevokedAt == nil && (c.RetireAt == nil || now < *c.RetireAt)
}
func (s *Service) Authenticate(r *http.Request) (rules.Actor, *rules.Error) {
	var headers []string
	present := false
	cookieCount := 0
	for name, values := range r.Header {
		if strings.EqualFold(name, "Authorization") {
			present = true
			headers = append(headers, values...)
		}
		if strings.EqualFold(name, "Cookie") {
			for _, value := range values {
				for _, part := range strings.Split(value, ";") {
					name := strings.TrimSpace(strings.SplitN(strings.TrimSpace(part), "=", 2)[0])
					if name == CookieName {
						cookieCount++
					}
				}
			}
		}
	}
	cookies := []string{}
	for _, c := range r.Cookies() {
		if c.Name == CookieName {
			cookies = append(cookies, c.Value)
		}
	}
	deny := failure("unauthenticated")
	if (present && cookieCount != 0) || cookieCount > 1 || (cookieCount == 1 && len(cookies) != 1) {
		return rules.Actor{}, deny
	}
	if present {
		if len(headers) != 1 || len(headers[0]) < 7 || !strings.EqualFold(headers[0][:7], "Bearer ") {
			return rules.Actor{}, deny
		}
		m := keyShape.FindStringSubmatch(headers[0][7:])
		if m == nil {
			return rules.Actor{}, deny
		}
		c, err := store.FindCredential(s.db.Reader(), m[1])
		if err != nil || !active(c, s.now().Format(store.TimeFormat)) || subtle.ConstantTimeCompare([]byte(digest(m[2])), []byte(c.SecretHash)) != 1 {
			return rules.Actor{}, deny
		}
		return rules.Actor{Kind: rules.Machine, Name: c.Name}, nil
	}
	if len(cookies) == 1 {
		row, err := store.FindSession(s.db.Reader(), digest(cookies[0]))
		at, parseErr := time.Parse(store.TimeFormat, row.CreatedAt)
		if err == nil && parseErr == nil && s.now().Before(at.Add(time.Duration(row.Hours)*time.Hour)) {
			return rules.Actor{Kind: rules.UI, Name: row.Username, Admin: row.Role == "admin"}, nil
		}
	}
	return rules.Actor{}, deny
}

// On throttling, the time result is the next retry time; on success it is expiry.
func (s *Service) Login(username, password, source string) (token string, expires time.Time, e *rules.Error) {
	u, err := store.FindUser(s.db.Reader(), username)
	if errors.Is(err, sql.ErrNoRows) {
		_ = comparePassword(s.dummy, []byte(password))
		return "", time.Time{}, s.loginFailed("", source, "unknown_user", s.now())
	}
	if err != nil {
		return "", time.Time{}, internal(err)
	}
	retry, e := s.checkPassword(u, password, source, func(now time.Time) *rules.Error {
		token, err = random(32)
		if err != nil {
			return internal(err)
		}
		now = now.UTC().Truncate(time.Second)
		e := s.write(func(tx *sql.Tx) *rules.Error {
			hours, err := store.SessionHours(tx)
			if err != nil {
				return internal(err)
			}
			if err := store.DeleteExpiredSessions(tx, now.Add(-time.Duration(hours)*time.Hour).Format(store.TimeFormat)); err != nil {
				return internal(err)
			}
			inserted, err := store.InsertSession(tx, digest(token), u, now.Format(store.TimeFormat))
			if err != nil {
				return internal(err)
			}
			if !inserted {
				return failure("invalid_credentials")
			}
			expires = now.Add(time.Duration(hours) * time.Hour)
			return audit(tx, rules.Actor{Kind: rules.UI, Name: username, Source: source}, "auth.login", "user:"+username, nil, nil, now.Format(store.TimeFormat))
		})
		if e != nil {
			if e.Code == "invalid_credentials" {
				e = s.loginFailed("user:"+username, source, "stale", now)
			}
		}
		return e
	})
	if e != nil {
		return "", retry, e
	}
	return token, expires, nil
}
func (s *Service) checkPassword(u store.User, password, source string, checked func(time.Time) *rules.Error) (time.Time, *rules.Error) {
	now := s.Now()
	s.mu.Lock()
	d := s.delays[u.Username]
	if d == nil {
		d = &throttle{}
		s.delays[u.Username] = d
	}
	if now.Before(d.next) || d.checking {
		next := d.next
		if !now.Before(next) {
			next = now.Add(time.Second)
		}
		s.mu.Unlock()
		return next, failure("login_throttled")
	}
	d.checking = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); d.checking = false; s.mu.Unlock() }()
	err := comparePassword([]byte(u.PasswordHash), []byte(password))
	if len(password) > 72 {
		err = bcrypt.ErrPasswordTooLong
	}
	now = s.Now()
	s.mu.Lock()
	if err != nil {
		if d.failures < 7 {
			d.failures++
		}
		seconds := 1 << (d.failures - 1)
		if seconds > 60 {
			seconds = 60
		}
		d.next = now.Add(time.Duration(seconds) * time.Second)
	} else {
		delete(s.delays, u.Username)
	}
	s.mu.Unlock()
	if err != nil {
		return time.Time{}, s.loginFailed("user:"+u.Username, source, "password", now)
	}
	return time.Time{}, checked(now)
}
func (s *Service) write(f func(*sql.Tx) *rules.Error) *rules.Error {
	tx, err := s.db.Begin()
	if err != nil {
		return internal(err)
	}
	defer tx.Rollback()
	if e := f(tx); e != nil {
		return e
	}
	return internal(tx.Commit())
}
func (s *Service) Logout(a rules.Actor, token string) *rules.Error {
	return s.write(func(tx *sql.Tx) *rules.Error {
		if _, err := store.FindSession(tx, digest(token)); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return internal(err)
		}
		if err := store.DeleteSession(tx, digest(token)); err != nil {
			return internal(err)
		}
		return audit(tx, a, "auth.logout", a.Who(), nil, nil, s.now().Format(store.TimeFormat))
	})
}
func (s *Service) Users() ([]store.User, *rules.Error) {
	rows, err := store.Users(s.db.Reader())
	return rows, internal(err)
}
func (s *Service) CreateUser(a rules.Actor, name, password, role string) *rules.Error {
	if !ValidName(name) {
		return invalid("username")
	}
	if role != "admin" && role != "operator" {
		return invalid("role")
	}
	hash, e := passwordHash(password)
	if e != nil {
		return e
	}
	at := s.now().Format(store.TimeFormat)
	return s.write(func(tx *sql.Tx) *rules.Error {
		u := store.User{Username: name, PasswordHash: hash, CreatedAt: at, CreatedBy: a.Who(), PasswordChangedAt: at, Role: role}
		err := store.InsertUser(tx, u)
		if store.Unique(err) {
			return failure("user_exists")
		}
		if err != nil {
			return internal(err)
		}
		return audit(tx, a, "user.create", "user:"+name, nil, userView(u), at)
	})
}
func findUser(q store.Queryer, name string) (store.User, *rules.Error) {
	u, err := store.FindUser(q, name)
	if errors.Is(err, sql.ErrNoRows) {
		return u, failure("user_not_found")
	}
	return u, internal(err)
}
func (s *Service) DeleteUser(a rules.Actor, name string) *rules.Error {
	e := s.write(func(tx *sql.Tx) *rules.Error {
		u, e := findUser(tx, name)
		if e != nil {
			return e
		}
		n, err := store.UserCount(tx)
		if err != nil {
			return internal(err)
		}
		if n == 1 {
			return failure("last_user")
		}
		if e := protectAdmin(tx, u); e != nil {
			return e
		}
		if err := store.DeleteUser(tx, u.ID); err != nil {
			return internal(err)
		}
		return audit(tx, a, "user.delete", "user:"+name, userView(u), nil, s.now().Format(store.TimeFormat))
	})
	if e == nil {
		s.mu.Lock()
		delete(s.delays, name)
		s.mu.Unlock()
	}
	return e
}
func (s *Service) SetPassword(a rules.Actor, name, password string) *rules.Error {
	hash, e := passwordHash(password)
	if e != nil {
		return e
	}
	at := s.now().Format(store.TimeFormat)
	return s.write(func(tx *sql.Tx) *rules.Error {
		u, e := findUser(tx, name)
		if e != nil {
			return e
		}
		if err := store.SetPassword(tx, u.ID, hash, at); err != nil {
			return internal(err)
		}
		if err := store.DeleteUserSessions(tx, u.ID); err != nil {
			return internal(err)
		}
		return audit(tx, a, "user.password", "user:"+name, nil, nil, at)
	})
}
func (s *Service) ChangeOwnPassword(a rules.Actor, current, next, source string) (time.Time, *rules.Error) {
	hash, e := passwordHash(next)
	if e != nil {
		return time.Time{}, e
	}
	u, e := findUser(s.db.Reader(), a.Name)
	if e != nil {
		return time.Time{}, e
	}
	return s.checkPassword(u, current, source, func(now time.Time) *rules.Error {
		now = now.UTC().Truncate(time.Second)
		at := now.Format(store.TimeFormat)
		e := s.write(func(tx *sql.Tx) *rules.Error {
			changed, err := store.SetPasswordIf(tx, u.ID, u.PasswordHash, hash, at)
			if err != nil {
				return internal(err)
			}
			if !changed {
				return failure("invalid_credentials")
			}
			if err := store.DeleteUserSessions(tx, u.ID); err != nil {
				return internal(err)
			}
			return audit(tx, a, "user.password", "user:"+a.Name, nil, nil, at)
		})
		if e != nil && e.Code == "invalid_credentials" {
			return s.loginFailed("user:"+a.Name, source, "stale", now)
		}
		return e
	})
}
func (s *Service) Settings() (store.Settings, *rules.Error) {
	n, err := store.ReadSettings(s.db.Reader())
	return n, internal(err)
}

type SettingsPatch struct {
	HistoryRetentionDays     *int    `json:"history_retention_days"`
	SessionHours             *int    `json:"session_hours"`
	AuditRetentionDays       *int    `json:"audit_retention_days"`
	ReconcileIntervalMinutes *int    `json:"reconcile_interval_minutes"`
	DefaultLanguage          *string `json:"default_language"`
}

func (s *Service) UpdateSettings(a rules.Actor, in SettingsPatch) *rules.Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var after store.Settings
	e := s.write(func(tx *sql.Tx) *rules.Error {
		before, err := store.ReadSettings(tx)
		if err != nil {
			return internal(err)
		}
		after = before
		var language *int
		if in.DefaultLanguage != nil {
			n := store.LanguageCode(*in.DefaultLanguage)
			language = &n
		}
		for _, p := range []struct {
			input, output *int
			max           int
			field         string
			set           func(store.Queryer, int) error
		}{
			{in.SessionHours, &after.SessionHours, maxSessionHours, "session_hours", store.SetSessionHours},
			{in.AuditRetentionDays, &after.AuditRetentionDays, maxAuditRetentionDays, "audit_retention_days", store.SetAuditRetentionDays},
			{in.HistoryRetentionDays, &after.HistoryRetentionDays, maxHistoryRetentionDays, "history_retention_days", store.SetHistoryRetentionDays},
			{in.ReconcileIntervalMinutes, &after.ReconcileIntervalMinutes, maxReconcileIntervalMinutes, "reconcile_interval_minutes", store.SetReconcileIntervalMinutes},
			{language, &after.DefaultLanguage, maxDefaultLanguage, "default_language", store.SetDefaultLanguage},
		} {
			if p.input != nil {
				if *p.input < 1 || *p.input > p.max {
					return invalid(p.field)
				}
				if *p.output != *p.input {
					if err := p.set(tx, *p.input); err != nil {
						return internal(err)
					}
					*p.output = *p.input
				}
			}
		}
		if before == after {
			return nil
		}
		return audit(tx, a, "settings.update", "settings", before, after, s.now().Format(store.TimeFormat))
	})
	if e == nil && s.OnSettings != nil {
		s.OnSettings(after)
	}
	return e
}

func protectAdmin(tx *sql.Tx, u store.User) *rules.Error {
	if u.Role != "admin" {
		return nil
	}
	n, err := store.AdminCount(tx)
	if err != nil {
		return internal(err)
	}
	if n == 1 {
		return failure("last_admin")
	}
	return nil
}
func (s *Service) SetRole(a rules.Actor, name, role string) *rules.Error {
	if role != "admin" && role != "operator" {
		return invalid("role")
	}
	return s.write(func(tx *sql.Tx) *rules.Error {
		u, e := findUser(tx, name)
		if e != nil || u.Role == role {
			return e
		}
		if e := protectAdmin(tx, u); e != nil {
			return e
		}
		if err := store.SetRole(tx, u.ID, role); err != nil {
			return internal(err)
		}
		return audit(tx, a, "user.role", "user:"+name, map[string]string{"role": u.Role}, map[string]string{"role": role}, s.now().Format(store.TimeFormat))
	})
}
func (s *Service) Prefs(a rules.Actor) (string, *rules.Error) {
	u, e := findUser(s.db.Reader(), a.Name)
	if e != nil {
		return "", e
	}
	body, err := store.Prefs(s.db.Reader(), u.ID)
	return body, internal(err)
}
func (s *Service) PutPrefs(a rules.Actor, body []byte) *rules.Error {
	var object map[string]json.RawMessage
	if len(body) > 8192 || json.Unmarshal(body, &object) != nil || object == nil {
		return invalid("body")
	}
	return s.write(func(tx *sql.Tx) *rules.Error {
		u, e := findUser(tx, a.Name)
		if e != nil {
			return e
		}
		return internal(store.PutPrefs(tx, u.ID, string(body), s.now().Format(store.TimeFormat)))
	})
}
func (s *Service) Templates() ([]store.Template, *rules.Error) {
	rows, err := store.Templates(s.db.Reader())
	return rows, internal(err)
}
func templateView(t store.Template) map[string]string {
	return map[string]string{"name": t.Name, "body": digest(t.Body)[:16]}
}
func (s *Service) PutTemplate(a rules.Actor, id, name, body string) (t store.Template, e *rules.Error) {
	if n := utf8.RuneCountInString(name); n < 1 || n > 64 {
		return t, invalid("name")
	}
	if len(body) > 65536 {
		return t, invalid("body")
	}
	e = s.write(func(tx *sql.Tx) *rules.Error {
		at, action := s.now().Format(store.TimeFormat), "template.create"
		var before any
		if id == "" {
			n, err := store.TemplateCount(tx)
			if err != nil {
				return internal(err)
			}
			if n >= 100 {
				return &rules.Error{Code: "table_full", Table: "templates", Message: "template capacity exceeded"}
			}
			var bytes [16]byte
			if _, err := rand.Read(bytes[:]); err != nil {
				return internal(err)
			}
			t = store.Template{ID: "tpl_" + hex.EncodeToString(bytes[:]), CreatedAt: at, CreatedBy: a.Who()}
		} else {
			var err error
			t, err = store.FindTemplate(tx, id)
			if errors.Is(err, sql.ErrNoRows) {
				return failure("not_found")
			}
			if err != nil {
				return internal(err)
			}
			if t.Name == name && t.Body == body {
				return nil
			}
			before, action = templateView(t), "template.update"
		}
		t.Name, t.Body, t.UpdatedAt, t.UpdatedBy = name, body, at, a.Who()
		err := store.PutTemplate(tx, t)
		if store.Unique(err) {
			return failure("rule_conflict")
		}
		if err != nil {
			return internal(err)
		}
		return audit(tx, a, action, "template:"+t.ID, before, templateView(t), at)
	})
	return
}
func (s *Service) DeleteTemplate(a rules.Actor, id string) *rules.Error {
	return s.write(func(tx *sql.Tx) *rules.Error {
		t, err := store.FindTemplate(tx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return failure("not_found")
		}
		if err != nil {
			return internal(err)
		}
		if err := store.DeleteTemplate(tx, id); err != nil {
			return internal(err)
		}
		return audit(tx, a, "template.delete", "template:"+id, templateView(t), nil, s.now().Format(store.TimeFormat))
	})
}
func (s *Service) Credentials() ([]store.Credential, *rules.Error) {
	rows, err := store.Credentials(s.db.Reader())
	return rows, internal(err)
}
func (s *Service) CredentialActive(c store.Credential) bool {
	return active(c, s.now().Format(store.TimeFormat))
}
func (s *Service) IssueCredential(a rules.Actor, name string) (c store.Credential, key string, retired []store.Credential, e *rules.Error) {
	if !ValidName(name) {
		return c, "", nil, invalid("name")
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return c, "", nil, internal(err)
	}
	secret, err := random(32)
	if err != nil {
		return c, "", nil, internal(err)
	}
	now := s.now()
	at, end := now.Format(store.TimeFormat), now.Add(rotateOverlap).Format(store.TimeFormat)
	c = store.Credential{ID: hex.EncodeToString(id), Name: name, SecretHash: digest(secret), CreatedAt: at, CreatedBy: a.Who()}
	retired = []store.Credential{}
	e = s.write(func(tx *sql.Tx) *rules.Error {
		rows, err := store.Credentials(tx)
		if err != nil {
			return internal(err)
		}
		for _, old := range rows {
			if old.Name == name && active(old, at) && (old.RetireAt == nil || *old.RetireAt > end) {
				if err := store.RetireCredential(tx, old.ID, end); err != nil {
					return internal(err)
				}
				old.RetireAt = &end
				retired = append(retired, old)
			}
		}
		if err := store.InsertCredential(tx, c); err != nil {
			return internal(err)
		}
		views := []credentialAuditView{}
		for _, old := range retired {
			views = append(views, credentialView(old))
		}
		return audit(tx, a, "credential.issue", "credential:"+c.ID, nil, struct {
			Issued  credentialAuditView   `json:"issued"`
			Retired []credentialAuditView `json:"retired"`
		}{credentialView(c), views}, at)
	})
	if e == nil {
		key = "xdk_" + c.ID + "_" + secret
	}
	return
}
func (s *Service) RevokeCredential(a rules.Actor, id string) *rules.Error {
	return s.write(func(tx *sql.Tx) *rules.Error {
		before, err := store.FindCredential(tx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return failure("credential_not_found")
		}
		if err != nil {
			return internal(err)
		}
		at := s.now().Format(store.TimeFormat)
		changed, err := store.RevokeCredential(tx, id, at, a.Who())
		if err != nil || !changed {
			return internal(err)
		}
		return audit(tx, a, "credential.revoke", "credential:"+id, credentialView(before), nil, at)
	})
}

type userAuditView struct {
	Username          string `json:"username"`
	CreatedAt         string `json:"created_at"`
	CreatedBy         string `json:"created_by"`
	PasswordChangedAt string `json:"password_changed_at"`
}

func userView(u store.User) userAuditView {
	return userAuditView{u.Username, u.CreatedAt, u.CreatedBy, u.PasswordChangedAt}
}

type credentialAuditView struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	RetireAt  *string `json:"retire_at"`
	RevokedAt *string `json:"revoked_at"`
}

func credentialView(c store.Credential) credentialAuditView {
	return credentialAuditView{c.ID, c.Name, c.RetireAt, c.RevokedAt}
}
func audit(tx *sql.Tx, a rules.Actor, action, target string, before, after any, at string) *rules.Error {
	b, err := json.Marshal(before)
	if err != nil {
		return internal(err)
	}
	c, err := json.Marshal(after)
	if err != nil {
		return internal(err)
	}
	if string(b) == "null" {
		b = nil
	}
	if string(c) == "null" {
		c = nil
	}
	return internal(store.InsertAudit(tx, store.AuditEvent{At: at, Actor: a.Who(), Source: a.Source, Action: action, Target: target, Before: b, After: c}))
}
func (s *Service) loginFailed(target, source, reason string, at time.Time) *rules.Error {
	e := s.write(func(tx *sql.Tx) *rules.Error {
		return audit(tx, rules.Actor{Source: source}, "auth.login_failed", target, nil, struct {
			Reason string `json:"reason"`
		}{reason}, at.UTC().Format(store.TimeFormat))
	})
	if e != nil {
		return e
	}
	return failure("invalid_credentials")
}
