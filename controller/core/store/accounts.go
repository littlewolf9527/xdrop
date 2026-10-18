package store

import "database/sql"

const schemaV4 = `
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin','operator'));
CREATE TABLE user_prefs (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, body TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE templates (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, body TEXT NOT NULL,
 created_at TEXT NOT NULL, created_by TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);
INSERT INTO settings VALUES('reconcile_interval_minutes',15),('default_language',3);`

const schemaV2 = `
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL, created_by TEXT NOT NULL, password_changed_at TEXT NOT NULL);
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL);
CREATE INDEX sessions_user ON sessions(user_id); CREATE INDEX sessions_created ON sessions(created_at);
CREATE TABLE credentials (id TEXT PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT NOT NULL,
 created_at TEXT NOT NULL, created_by TEXT NOT NULL, retire_at TEXT, revoked_at TEXT, revoked_by TEXT);
CREATE INDEX credentials_name ON credentials(name);
CREATE TABLE settings (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT INTO settings VALUES('session_hours', 24);`

type User struct {
	ID                                                              int64
	Username, PasswordHash, CreatedAt, CreatedBy, PasswordChangedAt string
	Role                                                            string
}
type Session struct {
	Username, CreatedAt string
	Hours               int
	Role                string
}
type Credential struct {
	ID, Name, SecretHash, CreatedAt, CreatedBy string
	RetireAt, RevokedAt, RevokedBy             *string
}

const userColumns = "id,username,password_hash,created_at,created_by,password_changed_at,role"
const credentialColumns = "id,name,secret_hash,created_at,created_by,retire_at,revoked_at,revoked_by"

func scanUser(s interface{ Scan(...any) error }) (u User, err error) {
	err = s.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt, &u.CreatedBy, &u.PasswordChangedAt, &u.Role)
	return
}
func FindUser(q Queryer, name string) (User, error) {
	return scanUser(q.QueryRow("SELECT "+userColumns+" FROM users WHERE username=?", name))
}
func Users(q Queryer) ([]User, error) {
	rows, err := q.Query("SELECT " + userColumns + " FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func InsertUser(q Queryer, u User) error {
	_, err := q.Exec("INSERT INTO users(username,password_hash,created_at,created_by,password_changed_at,role) VALUES(?,?,?,?,?,?)", u.Username, u.PasswordHash, u.CreatedAt, u.CreatedBy, u.PasswordChangedAt, u.Role)
	return err
}
func DeleteUser(q Queryer, id int64) error {
	_, err := q.Exec("DELETE FROM users WHERE id=?", id)
	return err
}
func UserCount(q Queryer) (n int, err error) {
	err = q.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return
}
func SetPassword(q Queryer, id int64, hash, at string) error {
	_, err := q.Exec("UPDATE users SET password_hash=?,password_changed_at=? WHERE id=?", hash, at, id)
	return err
}
func InsertSession(q Queryer, hash string, u User, at string) (bool, error) {
	r, err := q.Exec("INSERT INTO sessions(token_hash,user_id,created_at) SELECT ?,id,? FROM users WHERE id=? AND password_hash=?", hash, at, u.ID, u.PasswordHash)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func SetPasswordIf(q Queryer, id int64, oldHash, newHash, at string) (bool, error) {
	r, err := q.Exec("UPDATE users SET password_hash=?,password_changed_at=? WHERE id=? AND password_hash=?", newHash, at, id, oldHash)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func FindSession(q Queryer, hash string) (s Session, err error) {
	err = q.QueryRow("SELECT users.username,sessions.created_at,(SELECT value FROM settings WHERE key='session_hours'),users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=?", hash).Scan(&s.Username, &s.CreatedAt, &s.Hours, &s.Role)
	return
}
func DeleteSession(q Queryer, hash string) error {
	_, err := q.Exec("DELETE FROM sessions WHERE token_hash=?", hash)
	return err
}
func DeleteUserSessions(q Queryer, id int64) error {
	_, err := q.Exec("DELETE FROM sessions WHERE user_id=?", id)
	return err
}
func DeleteExpiredSessions(q Queryer, cutoff string) error {
	_, err := q.Exec("DELETE FROM sessions WHERE created_at<=?", cutoff)
	return err
}
func SessionHours(q Queryer) (n int, err error) {
	err = q.QueryRow("SELECT value FROM settings WHERE key='session_hours'").Scan(&n)
	return
}
func SetSessionHours(q Queryer, hours int) error {
	_, err := q.Exec("UPDATE settings SET value=? WHERE key='session_hours'", hours)
	return err
}
func scanCredential(s interface{ Scan(...any) error }) (c Credential, err error) {
	err = s.Scan(&c.ID, &c.Name, &c.SecretHash, &c.CreatedAt, &c.CreatedBy, &c.RetireAt, &c.RevokedAt, &c.RevokedBy)
	return
}
func FindCredential(q Queryer, id string) (Credential, error) {
	return scanCredential(q.QueryRow("SELECT "+credentialColumns+" FROM credentials WHERE id=?", id))
}
func Credentials(q Queryer) ([]Credential, error) {
	rows, err := q.Query("SELECT " + credentialColumns + " FROM credentials ORDER BY created_at,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func InsertCredential(q Queryer, c Credential) error {
	_, err := q.Exec("INSERT INTO credentials(id,name,secret_hash,created_at,created_by) VALUES(?,?,?,?,?)", c.ID, c.Name, c.SecretHash, c.CreatedAt, c.CreatedBy)
	return err
}
func RetireCredential(q Queryer, id, at string) error {
	_, err := q.Exec("UPDATE credentials SET retire_at=? WHERE id=?", at, id)
	return err
}
func RevokeCredential(q Queryer, id, at, by string) (bool, error) {
	return changed(q.Exec("UPDATE credentials SET revoked_at=?,revoked_by=? WHERE id=? AND revoked_at IS NULL", at, by, id))
}

func SetRole(q Queryer, id int64, role string) error {
	_, err := q.Exec("UPDATE users SET role=? WHERE id=?", role, id)
	return err
}
func AdminCount(q Queryer) (n int, err error) {
	err = q.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin'").Scan(&n)
	return
}
func LogicalHighWater(q Queryer) (n int64, err error) {
	err = q.QueryRow("SELECT high_water FROM logical_id_hw WHERE id=1").Scan(&n)
	return
}
func Prefs(q Queryer, id int64) (body string, err error) {
	err = q.QueryRow("SELECT body FROM user_prefs WHERE user_id=?", id).Scan(&body)
	if err == sql.ErrNoRows {
		return "{}", nil
	}
	return
}
func PutPrefs(q Queryer, id int64, body, at string) error {
	_, err := q.Exec("INSERT INTO user_prefs VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET body=excluded.body,updated_at=excluded.updated_at", id, body, at)
	return err
}

type Template struct{ ID, Name, Body, CreatedAt, CreatedBy, UpdatedAt, UpdatedBy string }

const templateColumns = "id,name,body,created_at,created_by,updated_at,updated_by"

func scanTemplate(s interface{ Scan(...any) error }) (t Template, err error) {
	err = s.Scan(&t.ID, &t.Name, &t.Body, &t.CreatedAt, &t.CreatedBy, &t.UpdatedAt, &t.UpdatedBy)
	return
}
func FindTemplate(q Queryer, id string) (Template, error) {
	return scanTemplate(q.QueryRow("SELECT "+templateColumns+" FROM templates WHERE id=?", id))
}
func Templates(q Queryer) ([]Template, error) {
	rows, err := q.Query("SELECT " + templateColumns + " FROM templates ORDER BY name,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Template{}
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func TemplateCount(q Queryer) (n int, err error) {
	err = q.QueryRow("SELECT COUNT(*) FROM templates").Scan(&n)
	return
}
func PutTemplate(q Queryer, t Template) error {
	_, err := q.Exec("INSERT INTO templates("+templateColumns+") VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,body=excluded.body,updated_at=excluded.updated_at,updated_by=excluded.updated_by", t.ID, t.Name, t.Body, t.CreatedAt, t.CreatedBy, t.UpdatedAt, t.UpdatedBy)
	return err
}
func DeleteTemplate(q Queryer, id string) error {
	_, err := q.Exec("DELETE FROM templates WHERE id=?", id)
	return err
}
