package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

func TestOpenCreatesAndTightensDatabasePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "private.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("new database mode=%v, want 0600", info.Mode().Perm())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("existing database mode=%v, want 0600", info.Mode().Perm())
	}
}

func TestOpenDoesNotBreakHistoricalActiveDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "duplicates.db")
	st, user, session := proxyTestStore(t, path, "alice", 5)
	if _, err := st.db.Exec(`DROP INDEX proxies_active_subdomain_unique`); err != nil {
		t.Fatal(err)
	}
	if err := st.AddProxy(session.ID, user.ID, "run-1", "one", "http", "duplicate", 0); err != nil {
		t.Fatal(err)
	}
	if err := st.AddProxy(session.ID, user.ID, "run-1", "two", "http", "duplicate", 0); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatalf("opening legacy duplicate rows: %v", err)
	}
	defer st.Close()
	if got, err := st.CountActiveProxies(user.ID); err != nil || got != 2 {
		t.Fatalf("historical active rows=%d err=%v, want 2", got, err)
	}
}

func TestConcurrentProxyAdmissionCannotExceedQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.db")
	st1, user, session1 := proxyTestStore(t, path, "alice", 1)
	defer st1.Close()
	_, _, session2 := addProxyTestSession(t, st1, user)
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()

	errs := concurrentAdmissions(
		func() error { _, err := st1.AdmitProxy(session1.ID, "run-1", "one", "http", "one", 0); return err },
		func() error { _, err := st2.AdmitProxy(session2.ID, "run-2", "two", "http", "two", 0); return err },
	)
	assertOneAdmissionAndOneDenial(t, errs, "tunnel limit reached (1)")
	if got, err := st1.CountActiveProxies(user.ID); err != nil || got != 1 {
		t.Fatalf("active proxies=%d err=%v, want 1", got, err)
	}
}

func TestConcurrentProxyAdmissionCannotDuplicateSubdomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subdomain.db")
	st1, _, session1 := proxyTestStore(t, path, "alice", 5)
	defer st1.Close()
	user2, err := st1.CreateUser("bob", 5)
	if err != nil {
		t.Fatal(err)
	}
	_, _, session2 := addProxyTestSession(t, st1, user2)
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()

	errs := concurrentAdmissions(
		func() error { _, err := st1.AdmitProxy(session1.ID, "run-1", "one", "http", "shared", 0); return err },
		func() error { _, err := st2.AdmitProxy(session2.ID, "run-2", "two", "http", "shared", 0); return err },
	)
	assertOneAdmissionAndOneDenial(t, errs, `subdomain "shared" is already in use`)
	proxies, err := st1.ActiveProxies()
	if err != nil || len(proxies) != 1 || proxies[0].Subdomain != "shared" {
		t.Fatalf("active proxies=%#v err=%v", proxies, err)
	}
}

func TestConcurrentProxyAdmissionCannotDuplicateTCPPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp.db")
	st1, _, session1 := proxyTestStore(t, path, "alice", 5)
	defer st1.Close()
	user2, err := st1.CreateUser("bob", 5)
	if err != nil {
		t.Fatal(err)
	}
	_, _, session2 := addProxyTestSession(t, st1, user2)
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()

	errs := concurrentAdmissions(
		func() error { _, err := st1.AdmitProxy(session1.ID, "run-1", "one", "tcp", "", 20022); return err },
		func() error { _, err := st2.AdmitProxy(session2.ID, "run-2", "two", "tcp", "", 20022); return err },
	)
	assertOneAdmissionAndOneDenial(t, errs, "remote port 20022 is already in use")
	proxies, err := st1.ActiveProxies()
	if err != nil || len(proxies) != 1 || proxies[0].RemotePort != 20022 {
		t.Fatalf("active proxies=%#v err=%v", proxies, err)
	}
}

func TestProxyAdmissionTakeoverReplacesSameUsersStaleSessionWithinQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "takeover.db")
	st, user, oldSession := proxyTestStore(t, path, "alice", 1)
	defer st.Close()
	_, _, newSession := addProxyTestSession(t, st, user)
	if _, err := st.AdmitProxy(oldSession.ID, "old-run", "old", "http", "service", 0); err != nil {
		t.Fatal(err)
	}
	admission, err := st.AdmitProxy(newSession.ID, "new-run", "new", "http", "service", 0)
	if err != nil {
		t.Fatal(err)
	}
	if admission.TakeoverSessionID != oldSession.ID {
		t.Fatalf("takeover session=%d, want %d", admission.TakeoverSessionID, oldSession.ID)
	}
	proxies, err := st.ActiveProxies()
	if err != nil || len(proxies) != 1 || proxies[0].SessionID != newSession.ID {
		t.Fatalf("active proxies=%#v err=%v", proxies, err)
	}
}

func proxyTestStore(t *testing.T, path, name string, maxTunnels int) (*Store, *User, *Session) {
	t.Helper()
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetServerInfo(ServerInfo{Addr: "relay.example", Port: 7000, Domain: "example.test"}); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(name, maxTunnels)
	if err != nil {
		t.Fatal(err)
	}
	_, _, session := addProxyTestSession(t, st, user)
	return st, user, session
}

func addProxyTestSession(t *testing.T, st *Store, user *User) (string, *Token, *Session) {
	t.Helper()
	plaintext, token, err := st.IssueToken(user.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	session, err := st.CreateSession(user.ID, token.ID, "host", "linux", "amd64", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return plaintext, token, session
}

func concurrentAdmissions(fns ...func() error) []error {
	ready := sync.WaitGroup{}
	ready.Add(len(fns))
	start := make(chan struct{})
	out := make(chan error, len(fns))
	for _, fn := range fns {
		go func(fn func() error) {
			ready.Done()
			<-start
			out <- fn()
		}(fn)
	}
	ready.Wait()
	close(start)
	errs := make([]error, 0, len(fns))
	for range fns {
		errs = append(errs, <-out)
	}
	return errs
}

func assertOneAdmissionAndOneDenial(t *testing.T, errs []error, reason string) {
	t.Helper()
	var admitted, denied int
	for _, err := range errs {
		if err == nil {
			admitted++
			continue
		}
		var policy *ProxyDeniedError
		if errors.As(err, &policy) && policy.Reason == reason {
			denied++
			continue
		}
		t.Fatalf("unexpected admission error: %v", err)
	}
	if admitted != 1 || denied != 1 {
		t.Fatalf("admitted=%d denied=%d errors=%v", admitted, denied, errs)
	}
}
