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
	return newTestServerWithConfig(t, password, Config{TrustedProxyCIDRs: []string{"127.0.0.0/8", "::1/128"}})
}

func newTestServerWithConfig(t *testing.T, password string, cfg Config) *Server {
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
	s, err := NewWithConfig(st, log.New(io.Discard, "", 0), cfg)
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
	csrfCookie := issueLoginCSRF(t, s, "/login")
	f := url.Values{"username": {user}, "password": {password}, "login_csrf": {csrfCookie.Value}}
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ip + ":1234"
	r.AddCookie(csrfCookie)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func issueLoginCSRF(t *testing.T, s *Server, target string) *http.Cookie {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.Name == loginCSRFCookieName {
			return c
		}
	}
	t.Fatalf("login GET did not issue CSRF cookie: status=%d body=%s", w.Code, w.Body.String())
	return nil
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
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("session cookie missing: cookies=%v body=%s", w.Result().Cookies(), w.Body.String())
	}
	s.mu.Lock()
	sess := s.sessions[sessionCookie.Value]
	s.mu.Unlock()
	return sessionCookie, sess
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

func TestOversizedLoginUsernameDoesNotAllocateFailureEntry(t *testing.T) {
	s := newTestServer(t, "admin-password")
	w := submitLogin(t, s, "192.0.2.44", strings.Repeat("a", maxLoginUsernameBytes+1), "wrong")
	if w.Code != http.StatusSeeOther || redirectError(t, w) == "" {
		t.Fatalf("status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.fails) != 0 || len(s.ipFails) != 0 {
		t.Fatalf("oversized username allocated lockout state: fails=%d ipFails=%d", len(s.fails), len(s.ipFails))
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
	csrfCookie := issueLoginCSRF(t, s, "http://example.com/login")
	form := url.Values{"username": {"admin"}, "password": {"admin-password"}, "login_csrf": {csrfCookie.Value}}
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
			r.AddCookie(csrfCookie)
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

func TestLoginCSRFCookieAndValidation(t *testing.T) {
	s := newTestServer(t, "admin-password")
	get := httptest.NewRequest(http.MethodGet, "https://example.com/login", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, get)
	var csrfCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == loginCSRFCookieName {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("GET /login did not issue login CSRF cookie")
	}
	if csrfCookie.Value == "" || csrfCookie.Path != "/" || csrfCookie.Domain != "" || !csrfCookie.Secure || !csrfCookie.HttpOnly || csrfCookie.SameSite != http.SameSiteStrictMode || csrfCookie.MaxAge != int(loginCSRFTTL/time.Second) {
		t.Fatalf("unexpected login CSRF cookie: %#v", csrfCookie)
	}
	if !csrfCookie.Expires.After(time.Now()) || csrfCookie.Expires.After(time.Now().Add(loginCSRFTTL+time.Minute)) {
		t.Fatalf("unexpected login CSRF expiry: %v", csrfCookie.Expires)
	}
	if !strings.Contains(w.Body.String(), `name="login_csrf" value="`+csrfCookie.Value+`"`) {
		t.Fatal("login form does not contain the cookie's CSRF token")
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q", got)
	}
	back := httptest.NewRequest(http.MethodGet, "https://example.com/login", nil)
	back.AddCookie(csrfCookie)
	backW := httptest.NewRecorder()
	s.Handler().ServeHTTP(backW, back)
	if len(backW.Result().Cookies()) != 0 || !strings.Contains(backW.Body.String(), `value="`+csrfCookie.Value+`"`) {
		t.Fatal("repeated login GET did not reuse the valid CSRF token")
	}

	post := func(origin string, cookie *http.Cookie, tokens []string, queryToken string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"username": {"admin"}, "password": {"admin-password"}}
		for _, token := range tokens {
			form.Add("login_csrf", token)
		}
		target := "https://example.com/login"
		if queryToken != "" {
			target += "?login_csrf=" + url.QueryEscape(queryToken)
		}
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		result := httptest.NewRecorder()
		s.Handler().ServeHTTP(result, r)
		return result
	}

	otherCookie := issueLoginCSRF(t, s, "https://example.com/login")
	invalid := []struct {
		name, origin, query string
		cookie              *http.Cookie
		tokens              []string
	}{
		{"missing both", "null", "", nil, nil},
		{"cookie only", "null", "", csrfCookie, nil},
		{"form only", "null", "", nil, []string{csrfCookie.Value}},
		{"mismatch", "null", "", csrfCookie, []string{otherCookie.Value}},
		{"query only", "null", csrfCookie.Value, csrfCookie, nil},
		{"duplicate body", "null", "", csrfCookie, []string{csrfCookie.Value, csrfCookie.Value}},
		{"hostile origin with valid token", "https://evil.example", "", csrfCookie, []string{csrfCookie.Value}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if got := post(tc.origin, tc.cookie, tc.tokens, tc.query); got.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", got.Code, got.Body.String())
			}
		})
	}
	if len(s.sessions) != 0 || len(s.fails) != 0 || len(s.ipFails) != 0 {
		t.Fatalf("invalid CSRF requests changed state: sessions=%d fails=%d ipFails=%d", len(s.sessions), len(s.fails), len(s.ipFails))
	}
	for _, tc := range []struct{ name, origin string }{
		{"same origin", "https://example.com/"},
		{"null origin", "null"},
		{"origin omitted", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := post(tc.origin, csrfCookie, []string{csrfCookie.Value}, "")
			if got.Code != http.StatusSeeOther {
				t.Fatalf("status=%d body=%s", got.Code, got.Body.String())
			}
			var cleared bool
			for _, c := range got.Result().Cookies() {
				if c.Name == loginCSRFCookieName && c.MaxAge < 0 {
					cleared = true
				}
			}
			if !cleared {
				t.Fatal("successful login did not clear login CSRF cookie")
			}
		})
	}
}

func TestSecurityHeadersCoverSuccessRedirectAndErrors(t *testing.T) {
	s := newTestServer(t, "admin-password")
	wants := map[string]string{
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Permissions-Policy":      "camera=()",
	}
	for _, path := range []string{"/login", "/", "/missing", "/static/style.css"} {
		t.Run(path, func(t *testing.T) {
			w := request(s, http.MethodGet, path, nil, nil)
			for header, want := range wants {
				if got := w.Header().Get(header); !strings.Contains(got, want) {
					t.Errorf("%s=%q, want it to contain %q", header, got, want)
				}
			}
		})
	}
}

func TestSessionCookieUsesHostPrefixAndProductionAttributes(t *testing.T) {
	s := newTestServer(t, "admin-password")
	w := submitLogin(t, s, "192.0.2.80", "admin", "admin-password")
	cookies := w.Result().Cookies()
	var c *http.Cookie
	for _, candidate := range cookies {
		if candidate.Name == cookieName {
			c = candidate
			break
		}
	}
	if c == nil {
		t.Fatalf("session cookie missing: cookies=%v", cookies)
	}
	if c.Name != "__Host-ktunneld_session" || c.Path != "/" || c.Domain != "" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe session cookie: %#v", c)
	}

	clear := httptest.NewRecorder()
	clearSessionCookie(clear)
	deleted := clear.Result().Cookies()[0]
	if deleted.Name != cookieName || deleted.Path != "/" || deleted.Domain != "" || !deleted.HttpOnly || !deleted.Secure || deleted.SameSite != http.SameSiteStrictMode || deleted.MaxAge >= 0 {
		t.Fatalf("unsafe cookie deletion: %#v", deleted)
	}
}

func TestForwardedHeadersRequireTrustedProxy(t *testing.T) {
	s := newTestServer(t, "admin-password")
	untrusted := httptest.NewRequest(http.MethodPost, "http://portal.example/login", nil)
	untrusted.RemoteAddr = "192.0.2.90:1234"
	untrusted.Header.Set("X-Real-IP", "203.0.113.1")
	untrusted.Header.Set("X-Forwarded-Proto", "https")
	if got := s.clientIP(untrusted); got != "192.0.2.90" {
		t.Fatalf("untrusted client IP=%q", got)
	}
	if got := s.externalScheme(untrusted); got != "http" {
		t.Fatalf("untrusted external scheme=%q", got)
	}
	untrusted.Header.Set("Origin", "https://portal.example")
	if s.loginOriginAllowed(untrusted) {
		t.Fatal("untrusted X-Forwarded-Proto made a spoofed HTTPS origin valid")
	}

	trusted := httptest.NewRequest(http.MethodPost, "http://portal.example/login", nil)
	trusted.RemoteAddr = "127.0.0.1:1234"
	trusted.Header.Set("X-Real-IP", "203.0.113.2")
	trusted.Header.Set("X-Forwarded-Proto", "https")
	if got := s.clientIP(trusted); got != "203.0.113.2" {
		t.Fatalf("trusted client IP=%q", got)
	}
	if got := s.externalScheme(trusted); got != "https" {
		t.Fatalf("trusted external scheme=%q", got)
	}
}

func TestInvalidWebSecurityConfigIsRejected(t *testing.T) {
	for _, cfg := range []Config{
		{CanonicalHost: "https://portal.example"},
		{TrustedProxyCIDRs: []string{"not-a-network"}},
	} {
		st, err := store.Open(filepath.Join(t.TempDir(), "ktunnel.db"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = NewWithConfig(st, log.New(io.Discard, "", 0), cfg); err == nil {
			_ = st.Close()
			t.Fatalf("accepted invalid config: %#v", cfg)
		}
		_ = st.Close()
	}
}

func TestOversizedWebPostIsRejectedBeforeHandler(t *testing.T) {
	s := newTestServer(t, "admin-password")
	body := "username=admin&password=" + strings.Repeat("x", maxWebRequestBody)
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(s.sessions) != 0 || len(s.fails) != 0 {
		t.Fatalf("oversized request reached login handler: sessions=%d failures=%d", len(s.sessions), len(s.fails))
	}
}

func TestSessionCreationPrunesExpiredAndCapsPrincipal(t *testing.T) {
	s := newTestServer(t, "admin-password")
	cred := s.credentialForUsername("admin")
	now := time.Now()
	s.sessions["expired"] = webSession{expires: now.Add(-time.Second)}
	for i := 0; i < maxSessionsPerPrincipal; i++ {
		s.sessions[fmt.Sprintf("existing-%d", i)] = webSession{isAdmin: true, expires: now.Add(time.Duration(i+1) * time.Minute)}
	}
	if !s.createSession("new", "lock", cred) {
		t.Fatal("valid credential did not create session")
	}
	if _, ok := s.sessions["expired"]; ok {
		t.Fatal("expired session was not pruned")
	}
	if _, ok := s.sessions["existing-0"]; ok {
		t.Fatal("oldest live session was not evicted at capacity")
	}
	if _, ok := s.sessions["new"]; !ok {
		t.Fatal("new session missing")
	}
	if len(s.sessions) != maxSessionsPerPrincipal {
		t.Fatalf("sessions=%d, want %d", len(s.sessions), maxSessionsPerPrincipal)
	}
}

func TestGlobalSessionCapDoesNotEvictAnotherPrincipal(t *testing.T) {
	s := newTestServer(t, "admin-password")
	cred := s.credentialForUsername("admin")
	for i := 0; i < maxWebSessions; i++ {
		s.sessions[fmt.Sprintf("user-%d", i)] = webSession{userID: int64(i + 1), expires: time.Now().Add(time.Hour)}
	}
	if s.createSession("admin", "lock", cred) {
		t.Fatal("session created beyond global cap")
	}
	if len(s.sessions) != maxWebSessions {
		t.Fatalf("sessions=%d, want %d", len(s.sessions), maxWebSessions)
	}
	if _, ok := s.sessions["user-0"]; !ok {
		t.Fatal("another principal's session was evicted")
	}
}

func TestCanonicalHostAndOriginFailClosed(t *testing.T) {
	s := newTestServerWithConfig(t, "admin-password", Config{
		CanonicalHost:     "portal.example",
		TrustedProxyCIDRs: []string{"127.0.0.0/8"},
	})

	badHost := httptest.NewRequest(http.MethodGet, "http://evil.example/login", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, badHost)
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("bad host status=%d", w.Code)
	}

	form := url.Values{"username": {"admin"}, "password": {"admin-password"}}
	csrfCookie := issueLoginCSRF(t, s, "http://portal.example/login")
	form.Set("login_csrf", csrfCookie.Value)
	for _, tc := range []struct {
		name, origin, forwardedProto string
		want                         int
	}{
		{"canonical HTTPS", "https://portal.example", "https", http.StatusSeeOther},
		{"canonical HTTPS trailing slash", "https://portal.example/", "https", http.StatusSeeOther},
		{"canonical HTTPS explicit default port", "https://PORTAL.example:443/", "https", http.StatusSeeOther},
		{"spoofed origin host", "https://evil.example", "https", http.StatusForbidden},
		{"wrong origin scheme", "http://portal.example", "https", http.StatusForbidden},
		{"nondefault port", "https://portal.example:444/", "https", http.StatusForbidden},
		{"non-root path", "https://portal.example/login", "https", http.StatusForbidden},
		{"query", "https://portal.example/?mobile=1", "https", http.StatusForbidden},
		{"empty query marker", "https://portal.example/?", "https", http.StatusForbidden},
		{"fragment", "https://portal.example/#login", "https", http.StatusForbidden},
		{"userinfo", "https://user@portal.example/", "https", http.StatusForbidden},
		{"opaque null origin with CSRF", "null", "https", http.StatusSeeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://portal.example/login", strings.NewReader(form.Encode()))
			r.RemoteAddr = "127.0.0.1:1234"
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-Forwarded-Proto", tc.forwardedProto)
			r.AddCookie(csrfCookie)
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
	if !strings.Contains(w.Body.String(), `<div class="secret-value"><div class="secret-text"><code>`) {
		t.Fatal("temporary password is missing the scrollable secret wrapper")
	}
	u, _ := s.st.UserByName("alice")
	issue := url.Values{"csrf": {sess.csrf}, "label": {"laptop"}}
	w = request(s, http.MethodPost, "/users/"+strconv.FormatInt(u.ID, 10)+"/tokens", c, issue)
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "토큰이 발급되었습니다") {
		t.Fatalf("token response cache/body=%q %s", w.Header().Get("Cache-Control"), w.Body.String())
	}
	assertTokenCopyControl(t, w.Body.String())
}

func TestUserIssuedTokenRendersCopyControl(t *testing.T) {
	s := newTestServer(t, "admin-password")
	if err := s.st.SetServerInfo(store.ServerInfo{Addr: "relay", Port: 7000, Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	addWebUser(t, s, "alice", "alice-password", false)
	c, sess := loginSession(t, s, "alice", "alice-password")
	w := request(s, http.MethodPost, "/me/tokens", c, url.Values{
		"csrf":  {sess.csrf},
		"label": {"phone"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	assertTokenCopyControl(t, w.Body.String())
}

func assertTokenCopyControl(t *testing.T, body string) {
	t.Helper()
	for _, want := range []string{
		`id="new-token"`,
		`type="button"`,
		`data-copy-target="new-token"`,
		`aria-describedby="new-token-copy-status"`,
		`role="status"`,
		`aria-live="polite"`,
		`토큰 복사`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("issued token page does not contain %q", want)
		}
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
