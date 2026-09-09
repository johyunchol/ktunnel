// Package store is the SQLite-backed record of users, tokens, subdomain
// reservations and live sessions. Both the daemon and the admin CLI open the
// same file; WAL mode lets them do so concurrently.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, so CGO_ENABLED=0 still works
)

var ErrNotFound = errors.New("not found")

// sessionStaleAfter is how long a session may go without a heartbeat before
// it is considered gone. frps pings every 30s and gives up after 90s.
const sessionStaleAfter = 120 * time.Second

type Store struct{ db *sql.DB }

type User struct {
	ID                     int64
	Name                   string
	CreatedAt              time.Time
	Disabled               bool
	MaxTunnels             int
	WebPasswordHash        string
	PasswordChangeRequired bool
	WebAuthVersion         int64
}

type Token struct {
	ID         int64
	UserID     int64
	UserName   string
	Label      string
	Prefix     string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero if never
	RevokedAt  time.Time // zero if active
}

func (t Token) Active() bool { return t.RevokedAt.IsZero() }

type Reservation struct {
	Subdomain string
	UserID    int64
	UserName  string
	CreatedAt time.Time
}

type Session struct {
	ID         int64
	UserID     int64
	UserName   string
	TokenID    int64
	TokenLabel string
	RunID      string
	Hostname   string
	OS         string
	Arch       string
	ClientAddr string
	StartedAt  time.Time
	LastSeenAt time.Time
	EndedAt    time.Time
	Killed     bool
}

type Proxy struct {
	ID         int64
	SessionID  int64
	UserID     int64
	UserName   string
	RunID      string
	Name       string
	Type       string
	Subdomain  string
	RemotePort int
	StartedAt  time.Time
	EndedAt    time.Time
}

type AuditEntry struct {
	ID       int64
	At       time.Time
	UserName string
	Action   string
	Detail   string
}

const schema = `
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL,
  disabled    INTEGER NOT NULL DEFAULT 0,
  max_tunnels INTEGER NOT NULL DEFAULT 5,
  web_password_hash TEXT NOT NULL DEFAULT '',
  password_change_required INTEGER NOT NULL DEFAULT 0,
  web_auth_version INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
  id           INTEGER PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id),
  label        TEXT NOT NULL,
  hash         TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at   INTEGER,
  kicked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reservations (
  subdomain  TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id           INTEGER PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id),
  token_id     INTEGER NOT NULL REFERENCES tokens(id),
  run_id       TEXT NOT NULL DEFAULT '',
  hostname     TEXT NOT NULL DEFAULT '',
  os           TEXT NOT NULL DEFAULT '',
  arch         TEXT NOT NULL DEFAULT '',
  client_addr  TEXT NOT NULL DEFAULT '',
  started_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  ended_at     INTEGER,
  killed       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS proxies (
  id          INTEGER PRIMARY KEY,
  session_id  INTEGER NOT NULL REFERENCES sessions(id),
  user_id     INTEGER NOT NULL REFERENCES users(id),
  run_id      TEXT NOT NULL DEFAULT '',
  name        TEXT NOT NULL,
  type        TEXT NOT NULL,
  subdomain   TEXT NOT NULL DEFAULT '',
  remote_port INTEGER NOT NULL DEFAULT 0,
  started_at  INTEGER NOT NULL,
  ended_at    INTEGER
);
CREATE INDEX IF NOT EXISTS proxies_active ON proxies(ended_at) WHERE ended_at IS NULL;
CREATE TABLE IF NOT EXISTS audit (
  id      INTEGER PRIMARY KEY,
  at      INTEGER NOT NULL,
  user_id INTEGER,
  action  TEXT NOT NULL,
  detail  TEXT NOT NULL DEFAULT ''
);
`

func Open(path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite is single-writer; serialising here avoids SQLITE_BUSY
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	// Columns added after the first release; harmless when already present.
	for _, stmt := range []string{
		`ALTER TABLE tokens ADD COLUMN kicked_until INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN web_password_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN password_change_required INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN web_auth_version INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().Unix() }

func ts(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.Unix(v.Int64, 0)
}

// ---------- settings ----------

func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)
	                     ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// SetAdminWebPassword atomically stores the legacy admin hash and advances
// the durable web-auth version used to invalidate administrator sessions.
func (s *Store) SetAdminWebPassword(hash string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO settings(key, value) VALUES('admin_password_hash', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, hash); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO settings(key, value) VALUES('admin_web_auth_version', '1')
		ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)`); err != nil {
		return err
	}
	return tx.Commit()
}

// AdminWebCredential reads the administrator hash and auth version together.
func (s *Store) AdminWebCredential() (hash string, version int64, err error) {
	var versionText string
	err = s.db.QueryRow(`SELECT
		COALESCE((SELECT value FROM settings WHERE key = 'admin_password_hash'), ''),
		COALESCE((SELECT value FROM settings WHERE key = 'admin_web_auth_version'), '0')`).Scan(&hash, &versionText)
	if err != nil {
		return "", 0, err
	}
	version, err = strconv.ParseInt(versionText, 10, 64)
	if err != nil || version < 0 {
		return "", 0, fmt.Errorf("invalid admin web auth version %q", versionText)
	}
	return
}

// SetAdminWebPasswordIfVersion changes the administrator password only if no
// CLI or other web request has changed it since the caller verified it.
func (s *Store) SetAdminWebPasswordIfVersion(hash string, expectedVersion int64) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var current int64
	if err = tx.QueryRow(`SELECT COALESCE(CAST((SELECT value FROM settings WHERE key = 'admin_web_auth_version') AS INTEGER), 0)`).Scan(&current); err != nil {
		return false, err
	}
	if current != expectedVersion {
		return false, nil
	}
	if _, err = tx.Exec(`INSERT INTO settings(key, value) VALUES('admin_password_hash', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, hash); err != nil {
		return false, err
	}
	if _, err = tx.Exec(`INSERT INTO settings(key, value) VALUES('admin_web_auth_version', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, strconv.FormatInt(expectedVersion+1, 10)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// ServerInfo returns the relay details that get baked into new tokens.
func (s *Store) ServerInfo() (ServerInfo, error) {
	addr, _ := s.Setting("server_addr")
	portStr, _ := s.Setting("server_port")
	domain, _ := s.Setting("domain")
	if addr == "" || domain == "" {
		return ServerInfo{}, errors.New("server address/domain not configured - run: ktunneld admin set-server")
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 7000
	}
	return ServerInfo{Addr: addr, Port: port, Domain: domain}, nil
}

func (s *Store) SetServerInfo(info ServerInfo) error {
	for k, v := range map[string]string{
		"server_addr": info.Addr,
		"server_port": strconv.Itoa(info.Port),
		"domain":      info.Domain,
	} {
		if err := s.SetSetting(k, v); err != nil {
			return err
		}
	}
	return nil
}

// TCPPortRange is the window of remote ports tcp tunnels may claim.
func (s *Store) TCPPortRange() (lo, hi int) {
	v, _ := s.Setting("tcp_port_range")
	if a, b, ok := strings.Cut(v, "-"); ok {
		lo, _ = strconv.Atoi(a)
		hi, _ = strconv.Atoi(b)
	}
	if lo == 0 || hi == 0 || lo > hi {
		return 20000, 29999
	}
	return lo, hi
}

// ---------- users ----------

const userCols = `id, name, created_at, disabled, max_tunnels, web_password_hash, password_change_required, web_auth_version`

func scanUser(r interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created int64
	var disabled, changeRequired int
	if err := r.Scan(&u.ID, &u.Name, &created, &disabled, &u.MaxTunnels, &u.WebPasswordHash, &changeRequired, &u.WebAuthVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.CreatedAt = time.Unix(created, 0)
	u.Disabled = disabled == 1
	u.PasswordChangeRequired = changeRequired == 1
	return &u, nil
}

func (s *Store) CreateUser(name string, maxTunnels int) (*User, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("user name is required")
	}
	if strings.EqualFold(name, "admin") {
		return nil, errors.New("admin is a reserved user name")
	}
	if maxTunnels <= 0 {
		maxTunnels = 5
	}
	res, err := s.db.Exec(`INSERT INTO users(name, created_at, max_tunnels) VALUES(?, ?, ?)`,
		name, now(), maxTunnels)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("user %q already exists", name)
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.User(id)
}

func (s *Store) User(id int64) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *Store) UserByName(name string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE name = ?`, name))
}

func (s *Store) Users() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) SetUserDisabled(id int64, disabled bool) error {
	_, err := s.db.Exec(`UPDATE users SET disabled = ?, web_auth_version = web_auth_version + 1 WHERE id = ?`, boolInt(disabled), id)
	return err
}

// SetUserWebPassword replaces a user's web credential. Tunnel tokens are not
// affected. Incrementing web_auth_version invalidates that user's web sessions.
func (s *Store) SetUserWebPassword(id int64, hash string, changeRequired bool) error {
	res, err := s.db.Exec(`UPDATE users
		SET web_password_hash = ?, password_change_required = ?, web_auth_version = web_auth_version + 1
		WHERE id = ?`, hash, boolInt(changeRequired), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserWebPasswordIfVersion prevents a self-service password change from
// overwriting an administrator reset that happened after credential checking.
func (s *Store) SetUserWebPasswordIfVersion(id, expectedVersion int64, hash string, changeRequired bool) (bool, error) {
	res, err := s.db.Exec(`UPDATE users
		SET web_password_hash = ?, password_change_required = ?, web_auth_version = web_auth_version + 1
		WHERE id = ? AND web_auth_version = ?`, hash, boolInt(changeRequired), id, expectedVersion)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) SetUserMaxTunnels(id int64, n int) error {
	_, err := s.db.Exec(`UPDATE users SET max_tunnels = ? WHERE id = ?`, n, id)
	return err
}

// ---------- tokens ----------

const tokenCols = `t.id, t.user_id, u.name, t.label, t.prefix, t.created_at, t.last_used_at, t.revoked_at`

func scanToken(r interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	var created int64
	var lastUsed, revoked sql.NullInt64
	if err := r.Scan(&t.ID, &t.UserID, &t.UserName, &t.Label, &t.Prefix, &created, &lastUsed, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt = time.Unix(created, 0)
	t.LastUsedAt = ts(lastUsed)
	t.RevokedAt = ts(revoked)
	return &t, nil
}

// IssueToken mints a token for a user. The plaintext is returned once and
// never stored.
func (s *Store) IssueToken(userID int64, label string) (plaintext string, tok *Token, err error) {
	info, err := s.ServerInfo()
	if err != nil {
		return "", nil, err
	}
	if label = strings.TrimSpace(label); label == "" {
		label = "default"
	}
	plaintext, hash, prefix, err := NewToken(info)
	if err != nil {
		return "", nil, err
	}
	res, err := s.db.Exec(`INSERT INTO tokens(user_id, label, hash, prefix, created_at) VALUES(?, ?, ?, ?, ?)`,
		userID, label, hash, prefix, now())
	if err != nil {
		return "", nil, err
	}
	id, _ := res.LastInsertId()
	tok, err = s.Token(id)
	return plaintext, tok, err
}

func (s *Store) Token(id int64) (*Token, error) {
	return scanToken(s.db.QueryRow(`SELECT `+tokenCols+` FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.id = ?`, id))
}

// TokenByPrefix resolves a token from the short prefix shown in listings.
func (s *Store) TokenByPrefix(prefix string) (*Token, error) {
	rows, err := s.db.Query(`SELECT `+tokenCols+` FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.prefix LIKE ?`, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var found *Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		if found != nil {
			return nil, fmt.Errorf("prefix %q is ambiguous", prefix)
		}
		found = t
	}
	if found == nil {
		return nil, ErrNotFound
	}
	return found, nil
}

// Authenticate resolves a presented token to an active token and its user.
func (s *Store) Authenticate(plaintext string) (*Token, *User, error) {
	tok, err := scanToken(s.db.QueryRow(`SELECT `+tokenCols+` FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.hash = ?`,
		HashToken(plaintext)))
	if err != nil {
		return nil, nil, err
	}
	if !tok.Active() {
		return nil, nil, errors.New("token has been revoked")
	}
	// A kill is a kick, not a revoke: the client is refused for a cooldown so
	// that frpc's automatic reconnect does not immediately undo it.
	var kickedUntil int64
	_ = s.db.QueryRow(`SELECT kicked_until FROM tokens WHERE id = ?`, tok.ID).Scan(&kickedUntil)
	if remaining := kickedUntil - now(); remaining > 0 {
		return nil, nil, fmt.Errorf("disconnected by administrator - try again in %d min", remaining/60+1)
	}
	u, err := s.User(tok.UserID)
	if err != nil {
		return nil, nil, err
	}
	if u.Disabled {
		return nil, nil, errors.New("account is disabled")
	}
	_, _ = s.db.Exec(`UPDATE tokens SET last_used_at = ? WHERE id = ?`, now(), tok.ID)
	return tok, u, nil
}

func (s *Store) Tokens(userID int64) ([]Token, error) {
	q := `SELECT ` + tokenCols + ` FROM tokens t JOIN users u ON u.id = t.user_id`
	var args []any
	if userID > 0 {
		q += ` WHERE t.user_id = ?`
		args = append(args, userID)
	}
	rows, err := s.db.Query(q+` ORDER BY t.created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *Store) RevokeToken(id int64) error {
	res, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	// Live sessions on this token are cut off at their next heartbeat.
	_, err = s.db.Exec(`UPDATE sessions SET killed = 1 WHERE token_id = ? AND ended_at IS NULL`, id)
	return err
}

// RevokeTokenForUser revokes a token only when it belongs to userID. The
// ownership predicate is kept in SQL to prevent IDOR mistakes in callers.
func (s *Store) RevokeTokenForUser(id, userID int64) error {
	res, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`, now(), id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, err = s.db.Exec(`UPDATE sessions SET killed = 1 WHERE token_id = ? AND user_id = ? AND ended_at IS NULL`, id, userID)
	return err
}

// ---------- reservations ----------

func (s *Store) Reserve(subdomain string, userID int64) error {
	if strings.EqualFold(strings.TrimSpace(subdomain), "ktunnel") {
		return errors.New("ktunnel is reserved for the web portal")
	}
	_, err := s.db.Exec(`INSERT INTO reservations(subdomain, user_id, created_at) VALUES(?, ?, ?)`,
		strings.ToLower(strings.TrimSpace(subdomain)), userID, now())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("%q is already reserved", subdomain)
	}
	return err
}

func (s *Store) Release(subdomain string) error {
	res, err := s.db.Exec(`DELETE FROM reservations WHERE subdomain = ?`, strings.ToLower(subdomain))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Reservation(subdomain string) (*Reservation, error) {
	var r Reservation
	var created int64
	err := s.db.QueryRow(`SELECT r.subdomain, r.user_id, u.name, r.created_at
	                      FROM reservations r JOIN users u ON u.id = r.user_id WHERE r.subdomain = ?`,
		strings.ToLower(subdomain)).Scan(&r.Subdomain, &r.UserID, &r.UserName, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt = time.Unix(created, 0)
	return &r, nil
}

func (s *Store) Reservations(userID int64) ([]Reservation, error) {
	q := `SELECT r.subdomain, r.user_id, u.name, r.created_at FROM reservations r JOIN users u ON u.id = r.user_id`
	var args []any
	if userID > 0 {
		q += ` WHERE r.user_id = ?`
		args = append(args, userID)
	}
	rows, err := s.db.Query(q+` ORDER BY r.subdomain`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Reservation
	for rows.Next() {
		var r Reservation
		var created int64
		if err := rows.Scan(&r.Subdomain, &r.UserID, &r.UserName, &created); err != nil {
			return nil, err
		}
		r.CreatedAt = time.Unix(created, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------- sessions ----------

const sessionCols = `s.id, s.user_id, u.name, s.token_id, t.label, s.run_id, s.hostname, s.os, s.arch,
                     s.client_addr, s.started_at, s.last_seen_at, s.ended_at, s.killed`

func scanSession(r interface{ Scan(...any) error }) (*Session, error) {
	var x Session
	var started, seen int64
	var ended sql.NullInt64
	var killed int
	if err := r.Scan(&x.ID, &x.UserID, &x.UserName, &x.TokenID, &x.TokenLabel, &x.RunID, &x.Hostname, &x.OS, &x.Arch,
		&x.ClientAddr, &started, &seen, &ended, &killed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	x.StartedAt = time.Unix(started, 0)
	x.LastSeenAt = time.Unix(seen, 0)
	x.EndedAt = ts(ended)
	x.Killed = killed == 1
	return &x, nil
}

func (s *Store) CreateSession(userID, tokenID int64, hostname, osName, arch, clientAddr string) (*Session, error) {
	n := now()
	res, err := s.db.Exec(`INSERT INTO sessions(user_id, token_id, hostname, os, arch, client_addr, started_at, last_seen_at)
	                       VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, userID, tokenID, hostname, osName, arch, clientAddr, n, n)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.Session(id)
}

func (s *Store) Session(id int64) (*Session, error) {
	return scanSession(s.db.QueryRow(`SELECT `+sessionCols+` FROM sessions s
		JOIN users u ON u.id = s.user_id JOIN tokens t ON t.id = s.token_id WHERE s.id = ?`, id))
}

// TouchSession records a heartbeat and, the first time it is known, the run id
// frps assigned to the connection.
func (s *Store) TouchSession(id int64, runID string) error {
	_, err := s.db.Exec(`UPDATE sessions SET last_seen_at = ?, run_id = CASE WHEN run_id = '' THEN ? ELSE run_id END WHERE id = ?`,
		now(), runID, id)
	return err
}

// KickCooldown is how long a killed session's token is refused at login, so
// the client's automatic reconnect cannot undo the kill.
const KickCooldown = 5 * time.Minute

func (s *Store) KillSession(id int64) error {
	res, err := s.db.Exec(`UPDATE sessions SET killed = 1 WHERE id = ? AND ended_at IS NULL`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, err = s.db.Exec(`UPDATE tokens SET kicked_until = ? WHERE id = (SELECT token_id FROM sessions WHERE id = ?)`,
		time.Now().Add(KickCooldown).Unix(), id)
	return err
}

func (s *Store) EndSession(id int64) error {
	_, err := s.db.Exec(`UPDATE sessions SET ended_at = ? WHERE id = ? AND ended_at IS NULL`, now(), id)
	return err
}

// ActiveSessions lists sessions that have not ended and were seen recently.
func (s *Store) ActiveSessions() ([]Session, error) {
	cutoff := time.Now().Add(-sessionStaleAfter).Unix()
	rows, err := s.db.Query(`SELECT `+sessionCols+` FROM sessions s
		JOIN users u ON u.id = s.user_id JOIN tokens t ON t.id = s.token_id
		WHERE s.ended_at IS NULL AND s.last_seen_at >= ? ORDER BY s.started_at DESC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		x, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *x)
	}
	return out, rows.Err()
}

// ExpireStaleSessions closes sessions that stopped heartbeating, and any
// proxies still attached to them.
func (s *Store) ExpireStaleSessions(ctx context.Context) error {
	cutoff := time.Now().Add(-sessionStaleAfter).Unix()
	n := now()
	if _, err := s.db.ExecContext(ctx, `UPDATE proxies SET ended_at = ? WHERE ended_at IS NULL AND session_id IN
		(SELECT id FROM sessions WHERE ended_at IS NULL AND last_seen_at < ?)`, n, cutoff); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET ended_at = ? WHERE ended_at IS NULL AND last_seen_at < ?`, n, cutoff)
	return err
}

// ---------- proxies ----------

func (s *Store) AddProxy(sessionID, userID int64, runID, name, typ, subdomain string, remotePort int) error {
	_, err := s.db.Exec(`INSERT INTO proxies(session_id, user_id, run_id, name, type, subdomain, remote_port, started_at)
	                     VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, sessionID, userID, runID, name, typ, subdomain, remotePort, now())
	return err
}

func (s *Store) EndProxy(sessionID int64, name string) error {
	_, err := s.db.Exec(`UPDATE proxies SET ended_at = ? WHERE session_id = ? AND name = ? AND ended_at IS NULL`,
		now(), sessionID, name)
	return err
}

func (s *Store) CountActiveProxies(userID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE user_id = ? AND ended_at IS NULL`, userID).Scan(&n)
	return n, err
}

// SubdomainInUse reports whether a live proxy already serves the subdomain.
func (s *Store) SubdomainInUse(subdomain string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE subdomain = ? AND ended_at IS NULL`, subdomain).Scan(&n)
	return n > 0, err
}

// ActiveProxyHolder returns who currently serves a subdomain, if anyone.
func (s *Store) ActiveProxyHolder(subdomain string) (userID, sessionID int64, ok bool, err error) {
	err = s.db.QueryRow(`SELECT user_id, session_id FROM proxies WHERE subdomain = ? AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1`,
		subdomain).Scan(&userID, &sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, false, nil
	}
	return userID, sessionID, err == nil, err
}

// EndProxiesForSubdomain closes every live proxy on a subdomain. Used when
// the same user reconnects after an ungraceful drop and frps has not yet
// reported the old proxy closed.
func (s *Store) EndProxiesForSubdomain(subdomain string) error {
	_, err := s.db.Exec(`UPDATE proxies SET ended_at = ? WHERE subdomain = ? AND ended_at IS NULL`, now(), subdomain)
	return err
}

func (s *Store) ActiveProxies() ([]Proxy, error) {
	rows, err := s.db.Query(`SELECT p.id, p.session_id, p.user_id, u.name, p.run_id, p.name, p.type, p.subdomain, p.remote_port, p.started_at
		FROM proxies p JOIN users u ON u.id = p.user_id WHERE p.ended_at IS NULL ORDER BY p.started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proxy
	for rows.Next() {
		var p Proxy
		var started int64
		if err := rows.Scan(&p.ID, &p.SessionID, &p.UserID, &p.UserName, &p.RunID, &p.Name, &p.Type, &p.Subdomain, &p.RemotePort, &started); err != nil {
			return nil, err
		}
		p.StartedAt = time.Unix(started, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

// SessionBySubdomain finds the live session serving a subdomain.
func (s *Store) SessionBySubdomain(subdomain string) (*Session, error) {
	var id int64
	err := s.db.QueryRow(`SELECT session_id FROM proxies WHERE subdomain = ? AND ended_at IS NULL LIMIT 1`, subdomain).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.Session(id)
}

// ---------- audit ----------

func (s *Store) Audit(userID int64, action, detail string) {
	var uid any
	if userID > 0 {
		uid = userID
	}
	_, _ = s.db.Exec(`INSERT INTO audit(at, user_id, action, detail) VALUES(?, ?, ?, ?)`, now(), uid, action, detail)
}

func (s *Store) AuditLog(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`SELECT a.id, a.at, COALESCE(u.name, ''), a.action, a.detail
		FROM audit a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.UserName, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
