package web

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johyunchol/ktunnel/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func newTestServer(t *testing.T, password string) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ktunnel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err = st.SetSetting(settingPwdHash, string(h)); err != nil {
		t.Fatal(err)
	}
	s, err := New(st, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func addWebUser(t *testing.T, s *Server, name, password string, must bool) *store.User {
	t.Helper()
	u, e := s.st.CreateUser(name, 5)
	if e != nil {
		t.Fatal(e)
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if e = s.st.SetUserWebPassword(u.ID, string(h), must); e != nil {
		t.Fatal(e)
	}
	u, _ = s.st.User(u.ID)
	return u
}
func submitLogin(t *testing.T, s *Server, ip, user, password string) *httptest.ResponseRecorder {
	t.Helper()
	f := url.Values{"username": {user}, "password": {password}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func redirectError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	u, e := url.Parse(w.Header().Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	return u.Query().Get("error")
}
func loginSession(t *testing.T, s *Server, user, password string) (*http.Cookie, webSession) {
	t.Helper()
	w := submitLogin(t, s, "192.0.2.1", user, password)
	cs := w.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("cookies=%d body=%s", len(cs), w.Body.String())
	}
	s.mu.Lock()
	sess := s.sessions[cs[0].Value]
	s.mu.Unlock()
	return cs[0], sess
}
func request(s *Server, method, path string, c *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestAdminAndUserLogin(t *testing.T) {
	s := newTestServer(t, "admin-password")
	addWebUser(t, s, "alice", "alice-password", false)
	w := submitLogin(t, s, "192.0.2.2", "admin", "admin-password")
	if w.Header().Get("Location") != "/" {
		t.Fatalf("admin redirect=%q", w.Header().Get("Location"))
	}
	w = submitLogin(t, s, "192.0.2.3", "alice", "alice-password")
	if w.Header().Get("Location") != "/me" {
		t.Fatalf("user redirect=%q", w.Header().Get("Location"))
	}
}

func TestMalformedAdminAuthVersionFailsClosed(t *testing.T) {
	s := newTestServer(t, "admin-password")
	s.sessions["legacy"] = webSession{expires: time.Now().Add(time.Hour), csrf: "csrf", isAdmin: true, username: "admin", authVersion: 0}
	if err := s.st.SetSetting(settingAdminAuthVersion, "malformed"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.currentSession(reqWithCookie(&http.Cookie{Name: cookieName, Value: "legacy"})); ok {
		t.Fatal("malformed version authorized existing session")
	}
	w := submitLogin(t, s, "192.0.2.72", "admin", "admin-password")
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("malformed version allowed new admin login")
	}
	if got := redirectError(t, w); got != "아이디 또는 비밀번호가 올바르지 않습니다." {
		t.Fatalf("error=%q", got)
	}
}
func TestLoginFailureIsGenericForMissingPasswordDisabledAndWrongPassword(t *testing.T) {
	s := newTestServer(t, "admin-password")
	noPassword, e := s.st.CreateUser("empty", 5)
	if e != nil {
		t.Fatal(e)
	}
	disabled := addWebUser(t, s, "disabled", "valid-password", false)
	_ = s.st.SetUserDisabled(disabled.ID, true)
	_ = noPassword
	for i, tc := range []struct{ u, p string }{{"missing", "anything"}, {"empty", "anything"}, {"disabled", "valid-password"}, {"admin", "wrong-password"}} {
		w := submitLogin(t, s, "192.0.2."+string(rune('A'+i)), tc.u, tc.p)
		if got := redirectError(t, w); got != "아이디 또는 비밀번호가 올바르지 않습니다." {
			t.Fatalf("%s error=%q", tc.u, got)
		}
	}
}
func TestLoginLockoutLimitsConcurrentBurst(t *testing.T) {
	s := newTestServer(t, "admin-password")
	const n = 40
	start := make(chan struct{})
	out := make(chan bool, n)
	var ready sync.WaitGroup
	ready.Add(n)
	for i := 0; i < n; i++ {
		go func() { ready.Done(); <-start; out <- s.beginLoginAttempt("192.0.2.9", "admin", time.Now()) }()
	}
	ready.Wait()
	close(start)
	allowed := 0
	for i := 0; i < n; i++ {
		if <-out {
			allowed++
		}
	}
	if allowed != maxLoginFails {
		t.Fatalf("allowed=%d", allowed)
	}
}

func TestUniqueUsernameRotationHitsIPThrottleAndStateIsBounded(t *testing.T) {
	s := newTestServer(t, "admin-password")
	now := time.Now()
	allowed := 0
	for i := 0; i < maxIPLoginAttempts+50; i++ {
		if s.beginLoginAttempt("192.0.2.70", fmt.Sprintf("guess-%d", i), now) {
			allowed++
		}
	}
	if allowed != maxIPLoginAttempts {
		t.Fatalf("allowed=%d, want %d", allowed, maxIPLoginAttempts)
	}
	if len(s.fails) > maxLoginFailEntries || len(s.ipFails) > maxLoginFailEntries {
		t.Fatalf("unbounded state: principal=%d ip=%d", len(s.fails), len(s.ipFails))
	}

	for i := 0; i < maxLoginFailEntries*2; i++ {
		s.beginLoginAttempt(fmt.Sprintf("198.51.100.%d", i), fmt.Sprintf("user-%d", i), now)
	}
	if len(s.fails) > maxLoginFailEntries || len(s.ipFails) > maxLoginFailEntries {
		t.Fatalf("hard cap exceeded: principal=%d ip=%d", len(s.fails), len(s.ipFails))
	}
}

func TestExpiredLoginFailureEntriesArePruned(t *testing.T) {
	s := newTestServer(t, "admin-password")
	now := time.Now()
	stale := loginFail{count: 1, lastSeen: now.Add(-loginFailRetention - time.Second), until: now.Add(-time.Second)}
	s.fails["stale-principal"] = stale
	s.ipFails["stale-ip"] = stale
	if !s.beginLoginAttempt("192.0.2.71", "admin", now) {
		t.Fatal("fresh attempt rejected")
	}
	if _, ok := s.fails["stale-principal"]; ok {
		t.Fatal("stale principal not pruned")
	}
	if _, ok := s.ipFails["stale-ip"]; ok {
		t.Fatal("stale IP not pruned")
	}
}

func TestSuccessfulLoginDoesNotResetAnotherAccountsLockoutBucket(t *testing.T) {
	s := newTestServer(t, "admin-password")
	addWebUser(t, s, "alice", "alice-password", false)
	const ip = "192.0.2.44"
	for i := 0; i < maxLoginFails-1; i++ {
		submitLogin(t, s, ip, "admin", "wrong-password")
	}
	if got := submitLogin(t, s, ip, "alice", "alice-password").Header().Get("Location"); got != "/me" {
		t.Fatalf("alice login=%q", got)
	}
	if got := redirectError(t, submitLogin(t, s, ip, "admin", "wrong-password")); got != "아이디 또는 비밀번호가 올바르지 않습니다." {
		t.Fatalf("fifth failure=%q", got)
	}
	if got := redirectError(t, submitLogin(t, s, ip, "admin", "admin-password")); !strings.Contains(got, "로그인 시도가 너무 많습니다") {
		t.Fatalf("admin bucket was reset: %q", got)
	}
}

func TestSuccessfulLoginResetsOnlyItsOwnBucket(t *testing.T) {
	s := newTestServer(t, "admin-password")
	addWebUser(t, s, "alice", "alice-password", false)
	const ip = "192.0.2.45"
	for i := 0; i < maxLoginFails-1; i++ {
		submitLogin(t, s, ip, "alice", "wrong-password")
	}
	if got := submitLogin(t, s, ip, "alice", "alice-password").Header().Get("Location"); got != "/me" {
		t.Fatalf("login=%q", got)
	}
	if got := redirectError(t, submitLogin(t, s, ip, "alice", "wrong-password")); got != "아이디 또는 비밀번호가 올바르지 않습니다." {
		t.Fatalf("fresh failure=%q", got)
	}
	key := loginFailureKey(ip, "alice")
	s.mu.Lock()
	count := s.fails[key].count
	s.mu.Unlock()
	if count != 1 {
		t.Fatalf("failure count=%d, want 1", count)
	}
}

func TestLoginOriginGuard(t *testing.T) {
	s := newTestServer(t, "admin-password")
	form := url.Values{"username": {"admin"}, "password": {"admin-password"}}
	for _, tc := range []struct {
		name, origin string
		want         int
	}{
		{"hostile", "https://evil.example", http.StatusForbidden},
		{"same origin", "http://example.com", http.StatusSeeOther},
		{"non-browser without origin", "", http.StatusSeeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
func TestForcedPasswordChangeAndSessionInvalidation(t *testing.T) {
	s := newTestServer(t, "admin-password")
	u := addWebUser(t, s, "alice", "temporary-password", true)
	c, sess := loginSession(t, s, "alice", "temporary-password")
	w := request(s, http.MethodGet, "/me", c, nil)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/account") {
		t.Fatalf("forced status/location=%d %q", w.Code, w.Header().Get("Location"))
	}
	w = request(s, http.MethodGet, "/account", c, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "임시 비밀번호") {
		t.Fatalf("forced account page=%d %s", w.Code, w.Body.String())
	}
	f := url.Values{"csrf": {sess.csrf}, "current_password": {"temporary-password"}, "new_password": {"new-password"}, "confirm_password": {"new-password"}}
	w = request(s, http.MethodPost, "/account/password", c, f)
	if w.Header().Get("Location") != "/login?msg="+url.QueryEscape("비밀번호를 변경했습니다. 다시 로그인해 주세요.") {
		t.Fatalf("change redirect=%q", w.Header().Get("Location"))
	}
	if _, ok := s.currentSession(reqWithCookie(c)); ok {
		t.Fatal("old session remains valid")
	}
	fresh, _ := s.st.User(u.ID)
	if fresh.PasswordChangeRequired {
		t.Fatal("force flag remains")
	}
}

func TestForcedChangeRejectsCurrentPassword(t *testing.T) {
	s := newTestServer(t, "admin-password")
	u := addWebUser(t, s, "alice", "temporary-password", true)
	c, sess := loginSession(t, s, "alice", "temporary-password")
	f := url.Values{"csrf": {sess.csrf}, "current_password": {"temporary-password"}, "new_password": {"temporary-password"}, "confirm_password": {"temporary-password"}}
	w := request(s, http.MethodPost, "/account/password", c, f)
	if got := redirectError(t, w); got != "새 비밀번호는 현재 비밀번호와 달라야 합니다" {
		t.Fatalf("error=%q", got)
	}
	after, _ := s.st.User(u.ID)
	if !after.PasswordChangeRequired {
		t.Fatal("same password cleared force-change")
	}
	if _, ok := s.currentSession(reqWithCookie(c)); !ok {
		t.Fatal("rejected change invalidated session")
	}
}

func TestAuthenticatedPostsRequireCSRF(t *testing.T) {
	s := newTestServer(t, "admin-password")
	addWebUser(t, s, "alice", "alice-password", false)
	c, _ := loginSession(t, s, "alice", "alice-password")
	f := url.Values{"current_password": {"alice-password"}, "new_password": {"new-password"}, "confirm_password": {"new-password"}}
	w := request(s, http.MethodPost, "/account/password", c, f)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestSecretResponsesAreNotCached(t *testing.T) {
	s := newTestServer(t, "admin-password")
	if err := s.st.SetServerInfo(store.ServerInfo{Addr: "relay", Port: 7000, Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	c, sess := loginSession(t, s, "admin", "admin-password")
	create := url.Values{"csrf": {sess.csrf}, "name": {"alice"}, "max_tunnels": {"5"}}
	w := request(s, http.MethodPost, "/users", c, create)
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "임시 비밀번호가 발급되었습니다") {
		t.Fatalf("temp response cache/body=%q %s", w.Header().Get("Cache-Control"), w.Body.String())
	}
	u, _ := s.st.UserByName("alice")
	issue := url.Values{"csrf": {sess.csrf}, "label": {"laptop"}}
	w = request(s, http.MethodPost, "/users/"+strconv.FormatInt(u.ID, 10)+"/tokens", c, issue)
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "토큰이 발급되었습니다") {
		t.Fatalf("token response cache/body=%q %s", w.Header().Get("Cache-Control"), w.Body.String())
	}
}
func reqWithCookie(c *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(c)
	return r
}
func TestRoleDenialAndDisabledSession(t *testing.T) {
	s := newTestServer(t, "admin-password")
	u := addWebUser(t, s, "alice", "alice-password", false)
	c, _ := loginSession(t, s, "alice", "alice-password")
	w := request(s, http.MethodGet, "/users", c, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("user admin status=%d", w.Code)
	}
	_ = s.st.SetUserDisabled(u.ID, true)
	w = request(s, http.MethodGet, "/me", c, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("disabled session=%d %q", w.Code, w.Header().Get("Location"))
	}
}
func TestUserCannotRevokeAnotherUsersToken(t *testing.T) {
	s := newTestServer(t, "admin-password")
	alice := addWebUser(t, s, "alice", "alice-password", false)
	bob := addWebUser(t, s, "bob", "bobby-password", false)
	_ = alice
	if e := s.st.SetServerInfo(store.ServerInfo{Addr: "relay", Port: 7000, Domain: "example.com"}); e != nil {
		t.Fatal(e)
	}
	plain, tok, e := s.st.IssueToken(bob.ID, "bob-device")
	if e != nil {
		t.Fatal(e)
	}
	c, sess := loginSession(t, s, "alice", "alice-password")
	f := url.Values{"csrf": {sess.csrf}}
	w := request(s, http.MethodPost, "/me/tokens/"+strconv.FormatInt(tok.ID, 10)+"/revoke", c, f)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d", w.Code)
	}
	if _, _, e = s.st.Authenticate(plain); e != nil {
		t.Fatalf("other token changed: %v", e)
	}
}
func TestPasswordResetInvalidatesOnlyTargetUser(t *testing.T) {
	s := newTestServer(t, "admin-password")
	alice := addWebUser(t, s, "alice", "alice-password", false)
	addWebUser(t, s, "bob", "bobby-password", false)
	ac, _ := loginSession(t, s, "alice", "alice-password")
	bc, _ := loginSession(t, s, "bob", "bobby-password")
	if e := s.setUserPassword(alice.ID, "reset-password", true); e != nil {
		t.Fatal(e)
	}
	if _, ok := s.currentSession(reqWithCookie(ac)); ok {
		t.Fatal("target session valid")
	}
	if _, ok := s.currentSession(reqWithCookie(bc)); !ok {
		t.Fatal("unrelated session invalidated")
	}
}

func TestAdminPasswordRotationInvalidatesOnlyAdministrators(t *testing.T) {
	s := newTestServer(t, "admin-password")
	addWebUser(t, s, "alice", "alice-password", false)
	adminCookie, _ := loginSession(t, s, "admin", "admin-password")
	userCookie, _ := loginSession(t, s, "alice", "alice-password")
	if err := SetAdminPassword(s.st, "new-admin-password"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.currentSession(reqWithCookie(adminCookie)); ok {
		t.Fatal("administrator session remained valid")
	}
	if _, ok := s.currentSession(reqWithCookie(userCookie)); !ok {
		t.Fatal("user session was invalidated")
	}
}
func TestVerifiedCredentialCannotCreateSessionAfterRotation(t *testing.T) {
	s := newTestServer(t, "admin-password")
	u := addWebUser(t, s, "alice", "alice-password", false)
	cred := s.credentialForUsername("alice")
	if e := s.setUserPassword(u.ID, "new-password", false); e != nil {
		t.Fatal(e)
	}
	if s.createSession("stale", "ip", cred) {
		t.Fatal("stale verified credential created session")
	}
}
func TestWebPasswordDoesNotAffectTunnelToken(t *testing.T) {
	s := newTestServer(t, "admin-password")
	u := addWebUser(t, s, "alice", "alice-password", false)
	_ = s.st.SetServerInfo(store.ServerInfo{Addr: "relay", Port: 7000, Domain: "example.com"})
	plain, _, e := s.st.IssueToken(u.ID, "device")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.setUserPassword(u.ID, "new-password", false); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.st.Authenticate(plain); e != nil {
		t.Fatalf("tunnel auth failed: %v", e)
	}
}
func TestKoreanLoginAndNotFound(t *testing.T) {
	s := newTestServer(t, "admin-password")
	w := request(s, http.MethodGet, "/login", nil, nil)
	body := w.Body.String()
	if !strings.Contains(body, `<html lang="ko">`) || !strings.Contains(body, "관리자 또는 사용자 계정") {
		t.Fatalf("login not Korean: %s", body)
	}
	w = request(s, http.MethodGet, "/missing", nil, nil)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "찾을 수 없습니다") {
		t.Fatalf("404=%d %s", w.Code, w.Body.String())
	}
}

func TestPasswordLengthBoundaries(t *testing.T) {
	if err := validPassword("12345678"); err != nil {
		t.Fatalf("8 characters rejected: %v", err)
	}
	if err := validPassword("1234567"); err == nil {
		t.Fatal("7 characters accepted")
	}
	if err := validPassword(strings.Repeat("a", 73)); err == nil {
		t.Fatal("73 bcrypt bytes accepted")
	}
}
