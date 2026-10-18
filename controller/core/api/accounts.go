package api

import (
	"io"
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type UserInput struct {
	LoginInput
	Role string `json:"role"`
}
type RoleInput struct {
	Role string `json:"role"`
}
type TemplateInput struct {
	Name string `json:"name"`
	Body string `json:"body"`
}
type TemplateDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Body      string `json:"body"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
	UpdatedAt string `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

func templateDTO(t store.Template) TemplateDTO {
	return TemplateDTO{t.ID, t.Name, t.Body, t.CreatedAt, t.CreatedBy, t.UpdatedAt, t.UpdatedBy}
}

type PasswordInput struct {
	Password string `json:"password"`
}
type OwnPasswordInput struct {
	CurrentPassword string `json:"current_password"`
	PasswordInput
}
type CredentialInput struct {
	Name string `json:"name"`
}
type LoginDTO struct {
	Username  string `json:"username"`
	ExpiresAt string `json:"expires_at"`
}
type IdentityDTO struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Role string `json:"role"`
}
type UserDTO struct {
	Username          string `json:"username"`
	CreatedAt         string `json:"created_at"`
	CreatedBy         string `json:"created_by"`
	PasswordChangedAt string `json:"password_changed_at"`
	Role              string `json:"role"`
}
type CredentialDTO struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	CreatedAt string  `json:"created_at"`
	CreatedBy string  `json:"created_by"`
	RetireAt  *string `json:"retire_at"`
	RevokedAt *string `json:"revoked_at"`
	RevokedBy *string `json:"revoked_by"`
	Active    bool    `json:"active"`
}
type RetiredDTO struct {
	ID       string `json:"id"`
	RetireAt string `json:"retire_at"`
}
type IssuedDTO struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Key       string       `json:"key"`
	CreatedAt string       `json:"created_at"`
	Retired   []RetiredDTO `json:"retired"`
}
type SettingsDTO struct {
	HistoryRetentionDays     int    `json:"history_retention_days"`
	SessionHours             int    `json:"session_hours"`
	AuditRetentionDays       int    `json:"audit_retention_days"`
	ReconcileIntervalMinutes int    `json:"reconcile_interval_minutes"`
	DefaultLanguage          string `json:"default_language"`
}

func AccountAuthenticator(acc *auth.Service) Authenticator {
	return func(r *http.Request) (rules.Actor, *Error) {
		actor, err := acc.Authenticate(r)
		if err != nil {
			return actor, &Error{Code: err.Code, Message: err.Message}
		}
		return actor, nil
	}
}
func (a *API) accountRoutes() []route {
	routes := []route{
		{"PUT", "/auth/me/password", "ui", a.changeOwnPassword},
		{"POST", "/auth/login", "public", a.login}, {"POST", "/auth/logout", "ui", a.logout}, {"GET", "/auth/me", "all", a.me},
		{"GET", "/users", "ui", a.users}, {"POST", "/users", "admin", a.createUser}, {"DELETE", "/users/:name", "admin", a.deleteUser}, {"PUT", "/users/:name/password", "admin", a.setPassword},
		{"GET", "/credentials", "admin", a.credentials}, {"POST", "/credentials", "admin", a.issueCredential}, {"DELETE", "/credentials/:id", "admin", a.revokeCredential},
		{"GET", "/settings", "ui", a.settings}, {"PUT", "/settings", "admin", a.updateSettings},
		{"PUT", "/users/:name/role", "admin", a.setRole},
		{"GET", "/auth/me/prefs", "ui", a.prefs}, {"PUT", "/auth/me/prefs", "ui", a.putPrefs},
		{"GET", "/templates", "ui", a.templates}, {"POST", "/templates", "admin", a.putTemplate},
		{"PUT", "/templates/:id", "admin", a.putTemplate}, {"DELETE", "/templates/:id", "admin", a.deleteTemplate},
	}
	if a.systemOptions.Accounts == nil {
		for i := range routes {
			routes[i].handler = func(c *gin.Context) { a.fail(c, &Error{Code: "internal"}) }
		}
	}
	return routes
}
func sessionCookie(value string, age int) *http.Cookie {
	return &http.Cookie{Name: auth.CookieName, Value: value, Path: "/api/v1", MaxAge: age, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}
func (a *API) login(c *gin.Context) {
	var in LoginInput
	if !a.decode(c, &in, requestBytes) {
		return
	}
	acc := a.systemOptions.Accounts
	token, expires, e := acc.Login(in.Username, in.Password, sourceIP(c))
	if e != nil && e.Code == "login_throttled" {
		retry := int(math.Ceil(expires.Sub(acc.Now()).Seconds()))
		if retry < 1 {
			retry = 1
		}
		c.Header("Retry-After", strconv.Itoa(retry))
	}
	if a.serviceError(c, e) {
		return
	}
	hours, e := acc.Settings()
	if a.serviceError(c, e) {
		return
	}
	http.SetCookie(c.Writer, sessionCookie(token, hours.SessionHours*3600))
	c.JSON(200, LoginDTO{in.Username, expires.Format(store.TimeFormat)})
}
func (a *API) logout(c *gin.Context) {
	cookie, err := c.Request.Cookie(auth.CookieName)
	if err != nil {
		a.fail(c, &Error{Code: "unauthenticated"})
		return
	}
	if a.serviceError(c, a.systemOptions.Accounts.Logout(actor(c), cookie.Value)) {
		return
	}
	http.SetCookie(c.Writer, sessionCookie("", -1))
	c.Status(204)
}
func (a *API) changeOwnPassword(c *gin.Context) {
	var in OwnPasswordInput
	if !a.decode(c, &in, requestBytes) {
		return
	}
	acc := a.systemOptions.Accounts
	next, e := acc.ChangeOwnPassword(actor(c), in.CurrentPassword, in.Password, sourceIP(c))
	if e != nil && e.Code == "login_throttled" {
		retry := int(math.Ceil(next.Sub(acc.Now()).Seconds()))
		if retry < 1 {
			retry = 1
		}
		c.Header("Retry-After", strconv.Itoa(retry))
	}
	if a.serviceError(c, e) {
		return
	}
	http.SetCookie(c.Writer, sessionCookie("", -1))
	c.Status(204)
}
func (a *API) me(c *gin.Context) {
	u := actor(c)
	kind, role := "machine", ""
	if u.Kind == rules.UI {
		kind = "user"
		role = "operator"
		if u.Admin {
			role = "admin"
		}
	}
	c.JSON(200, IdentityDTO{kind, u.Name, role})
}
func (a *API) users(c *gin.Context) {
	rows, e := a.systemOptions.Accounts.Users()
	if a.serviceError(c, e) {
		return
	}
	out := []UserDTO{}
	for _, u := range rows {
		out = append(out, UserDTO{u.Username, u.CreatedAt, u.CreatedBy, u.PasswordChangedAt, u.Role})
	}
	c.JSON(200, out)
}
func (a *API) createUser(c *gin.Context) {
	var in UserInput
	if !a.decode(c, &in, requestBytes) || a.serviceError(c, a.systemOptions.Accounts.CreateUser(actor(c), in.Username, in.Password, in.Role)) {
		return
	}
	c.Status(201)
}
func (a *API) deleteUser(c *gin.Context) {
	if !a.serviceError(c, a.systemOptions.Accounts.DeleteUser(actor(c), c.Param("name"))) {
		c.Status(204)
	}
}
func (a *API) setPassword(c *gin.Context) {
	var in PasswordInput
	if !a.decode(c, &in, requestBytes) || a.serviceError(c, a.systemOptions.Accounts.SetPassword(actor(c), c.Param("name"), in.Password)) {
		return
	}
	c.Status(204)
}
func (a *API) credentials(c *gin.Context) {
	acc := a.systemOptions.Accounts
	rows, e := acc.Credentials()
	if a.serviceError(c, e) {
		return
	}
	out := []CredentialDTO{}
	for _, v := range rows {
		out = append(out, CredentialDTO{v.ID, v.Name, v.CreatedAt, v.CreatedBy, v.RetireAt, v.RevokedAt, v.RevokedBy, acc.CredentialActive(v)})
	}
	c.JSON(200, out)
}
func (a *API) issueCredential(c *gin.Context) {
	var in CredentialInput
	if !a.decode(c, &in, requestBytes) {
		return
	}
	v, key, retired, e := a.systemOptions.Accounts.IssueCredential(actor(c), in.Name)
	if a.serviceError(c, e) {
		return
	}
	out := IssuedDTO{v.ID, v.Name, key, v.CreatedAt, []RetiredDTO{}}
	for _, old := range retired {
		out.Retired = append(out.Retired, RetiredDTO{old.ID, *old.RetireAt})
	}
	c.JSON(201, out)
}
func (a *API) revokeCredential(c *gin.Context) {
	if !a.serviceError(c, a.systemOptions.Accounts.RevokeCredential(actor(c), c.Param("id"))) {
		c.Status(204)
	}
}
func (a *API) settings(c *gin.Context) {
	hours, e := a.systemOptions.Accounts.Settings()
	if !a.serviceError(c, e) {
		c.JSON(200, SettingsDTO{HistoryRetentionDays: hours.HistoryRetentionDays, SessionHours: hours.SessionHours, AuditRetentionDays: hours.AuditRetentionDays, ReconcileIntervalMinutes: hours.ReconcileIntervalMinutes, DefaultLanguage: store.Language(hours.DefaultLanguage)})
	}
}
func (a *API) updateSettings(c *gin.Context) {
	var in auth.SettingsPatch
	if !a.decode(c, &in, requestBytes) || a.serviceError(c, a.systemOptions.Accounts.UpdateSettings(actor(c), in)) {
		return
	}
	a.settings(c)
}
func (a *API) setRole(c *gin.Context) {
	var in RoleInput
	if !a.decode(c, &in, requestBytes) || a.serviceError(c, a.systemOptions.Accounts.SetRole(actor(c), c.Param("name"), in.Role)) {
		return
	}
	c.Status(204)
}
func (a *API) prefs(c *gin.Context) {
	body, e := a.systemOptions.Accounts.Prefs(actor(c))
	if !a.serviceError(c, e) {
		c.Data(200, "application/json", []byte(body))
	}
}
func (a *API) putPrefs(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 8193))
	if err != nil {
		a.fail(c, &Error{Code: "invalid_field", Field: "body"})
		return
	}
	if !a.serviceError(c, a.systemOptions.Accounts.PutPrefs(actor(c), body)) {
		c.Status(204)
	}
}
func (a *API) templates(c *gin.Context) {
	rows, e := a.systemOptions.Accounts.Templates()
	if a.serviceError(c, e) {
		return
	}
	out := []TemplateDTO{}
	for _, t := range rows {
		out = append(out, templateDTO(t))
	}
	c.JSON(200, out)
}
func (a *API) putTemplate(c *gin.Context) {
	var in TemplateInput
	if !a.decode(c, &in, requestBytes) {
		return
	}
	t, e := a.systemOptions.Accounts.PutTemplate(actor(c), c.Param("id"), in.Name, in.Body)
	if a.serviceError(c, e) {
		return
	}
	status := 200
	if c.Request.Method == "POST" {
		status = 201
	}
	c.JSON(status, templateDTO(t))
}
func (a *API) deleteTemplate(c *gin.Context) {
	if !a.serviceError(c, a.systemOptions.Accounts.DeleteTemplate(actor(c), c.Param("id"))) {
		c.Status(204)
	}
}
