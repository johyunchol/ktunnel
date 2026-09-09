package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenMigratesLegacyUsersWithoutBreakingTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	const plaintext = "legacy-tunnel-token"
	_, err = db.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, max_tunnels INTEGER NOT NULL DEFAULT 5);
		CREATE TABLE tokens (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), label TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER);
		INSERT INTO settings(key,value) VALUES('admin_password_hash','legacy-admin-hash');`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO users(id,name,created_at,max_tunnels) VALUES(7,'legacy',?,3)`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO tokens(id,user_id,label,hash,prefix,created_at) VALUES(11,7,'existing-device',?,'legacy-prefix',?)`, HashToken(plaintext), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.User(7)
	if err != nil {
		t.Fatal(err)
	}
	if u.WebPasswordHash != "" || u.PasswordChangeRequired || u.WebAuthVersion != 0 {
		t.Fatalf("bad migrated defaults: %#v", u)
	}
	if u.Name != "legacy" || u.MaxTunnels != 3 {
		t.Fatalf("legacy user changed: %#v", u)
	}
	adminHash, err := st.Setting("admin_password_hash")
	if err != nil || adminHash != "legacy-admin-hash" {
		t.Fatalf("admin setting=%q err=%v", adminHash, err)
	}
	tok, err := st.Token(11)
	if err != nil || tok.Label != "existing-device" || tok.Prefix != "legacy-prefix" {
		t.Fatalf("legacy token=%#v err=%v", tok, err)
	}
	if gotTok, gotUser, err := st.Authenticate(plaintext); err != nil || gotUser.ID != u.ID || gotTok.ID != 11 {
		t.Fatalf("legacy token auth user=%#v err=%v", gotUser, err)
	}
}

func TestUserPasswordCompareAndSwapPreservesAdministratorReset(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, _ := st.CreateUser("alice", 5)
	if err = st.SetUserWebPassword(u.ID, "old-hash", true); err != nil {
		t.Fatal(err)
	}
	verified, _ := st.User(u.ID)
	if err = st.SetUserWebPassword(u.ID, "admin-reset-hash", true); err != nil {
		t.Fatal(err)
	}
	changed, err := st.SetUserWebPasswordIfVersion(u.ID, verified.WebAuthVersion, "stale-self-change", false)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("stale self-change overwrote administrator reset")
	}
	after, _ := st.User(u.ID)
	if after.WebPasswordHash != "admin-reset-hash" || !after.PasswordChangeRequired {
		t.Fatalf("reset lost: %#v", after)
	}
}

func TestAdminPasswordCompareAndSwapPreservesCLIReset(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.SetAdminWebPassword("old-hash"); err != nil {
		t.Fatal(err)
	}
	_, verifiedVersion, _ := st.AdminWebCredential()
	if err = st.SetAdminWebPassword("cli-reset-hash"); err != nil {
		t.Fatal(err)
	}
	changed, err := st.SetAdminWebPasswordIfVersion("stale-web-change", verifiedVersion)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("stale web change overwrote CLI reset")
	}
	hash, _, _ := st.AdminWebCredential()
	if hash != "cli-reset-hash" {
		t.Fatalf("CLI reset lost: %q", hash)
	}
}

func TestReservedPortalNames(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = st.CreateUser("admin", 5); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("admin error=%v", err)
	}
	u, _ := st.CreateUser("alice", 5)
	if err = st.Reserve("ktunnel", u.ID); err == nil || !strings.Contains(err.Error(), "web portal") {
		t.Fatalf("ktunnel error=%v", err)
	}
}
