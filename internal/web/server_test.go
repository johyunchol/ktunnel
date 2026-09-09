package web

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/johyunchol/ktunnel/internal/store"
)

func newTestServer(t *testing.T, password string) *Server {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "ktunnel.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := st.SetSetting(settingPwdHash, string(hash)); err != nil {
		t.Fatalf("set password: %v", err)
	}

	srv, err := New(st, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	return srv
}

func submitLogin(t *testing.T, srv *Server, ip, password string) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{"password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.Form = form
	req.PostForm = form
	req.RemoteAddr = ip + ":12345"
	rec := httptest.NewRecorder()

	srv.loginSubmit(rec, req)
	return rec
}

func redirectError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	return location.Query().Get("error")
}

func TestLoginLocksAfterMaximumFailures(t *testing.T) {
	srv := newTestServer(t, "correct-password")
	const ip = "192.0.2.10"

	for i := 0; i < maxLoginFails; i++ {
		rec := submitLogin(t, srv, ip, "wrong-password")
		if got := redirectError(t, rec); got != "wrong password" {
			t.Fatalf("attempt %d error = %q, want %q", i+1, got, "wrong password")
		}
	}

	rec := submitLogin(t, srv, ip, "correct-password")
	if got := redirectError(t, rec); got != "too many attempts - wait a minute" {
		t.Fatalf("locked attempt error = %q, want lockout error", got)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("locked attempt set %d cookies, want none", len(cookies))
	}
}

func TestBeginLoginAttemptLimitsConcurrentBurst(t *testing.T) {
	srv := newTestServer(t, "correct-password")
	const (
		ip       = "192.0.2.15"
		attempts = 40
	)
	now := time.Now()
	start := make(chan struct{})
	results := make(chan bool, attempts)
	var ready sync.WaitGroup
	ready.Add(attempts)

	for i := 0; i < attempts; i++ {
		go func() {
			ready.Done()
			<-start
			results <- srv.beginLoginAttempt(ip, now)
		}()
	}
	ready.Wait()
	close(start)

	allowed := 0
	for i := 0; i < attempts; i++ {
		if <-results {
			allowed++
		}
	}
	if allowed != maxLoginFails {
		t.Fatalf("allowed concurrent attempts = %d, want %d", allowed, maxLoginFails)
	}
}

func TestSuccessfulLoginClearsFailures(t *testing.T) {
	srv := newTestServer(t, "correct-password")
	const ip = "192.0.2.20"

	for i := 0; i < maxLoginFails-1; i++ {
		submitLogin(t, srv, ip, "wrong-password")
	}
	rec := submitLogin(t, srv, ip, "correct-password")
	if location := rec.Header().Get("Location"); location != "/" {
		t.Fatalf("successful login redirected to %q, want /", location)
	}

	rec = submitLogin(t, srv, ip, "wrong-password")
	if got := redirectError(t, rec); got != "wrong password" {
		t.Fatalf("failure after successful login error = %q, want fresh failure", got)
	}
	if got := srv.fails[ip].count; got != 1 {
		t.Fatalf("failure count after successful login = %d, want 1", got)
	}
}

func TestExpiredLoginLockoutStartsFreshFailureCount(t *testing.T) {
	srv := newTestServer(t, "correct-password")
	const ip = "192.0.2.30"
	srv.fails[ip] = loginFail{count: maxLoginFails, until: time.Now().Add(-time.Second)}

	rec := submitLogin(t, srv, ip, "wrong-password")
	if got := redirectError(t, rec); got != "wrong password" {
		t.Fatalf("first failure after lockout error = %q, want wrong password", got)
	}
	if got := srv.fails[ip].count; got != 1 {
		t.Fatalf("failure count after expired lockout = %d, want 1", got)
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		realIP     string
		forwarded  string
		remoteAddr string
		want       string
	}{
		{name: "real IP takes precedence", realIP: " 192.0.2.1 ", forwarded: "198.51.100.1", remoteAddr: "203.0.113.1:1234", want: "192.0.2.1"},
		{name: "last forwarded hop", forwarded: "198.51.100.1, 192.0.2.2 ", remoteAddr: "203.0.113.1:1234", want: "192.0.2.2"},
		{name: "remote address fallback", remoteAddr: "203.0.113.1:1234", want: "203.0.113.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			req.Header.Set("X-Real-IP", tt.realIP)
			req.Header.Set("X-Forwarded-For", tt.forwarded)
			req.RemoteAddr = tt.remoteAddr
			if got := clientIP(req); got != tt.want {
				t.Fatalf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPasswordChange(t *testing.T) {
	srv := newTestServer(t, "current-password")
	srv.sessions["current"] = webSession{expires: time.Now().Add(time.Hour), csrf: "current-csrf"}
	srv.sessions["other"] = webSession{expires: time.Now().Add(time.Hour), csrf: "other-csrf"}

	form := url.Values{
		"csrf":             {"current-csrf"},
		"current_password": {"current-password"},
		"new_password":     {"new-password"},
		"confirm_password": {"new-password"},
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "current"})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if got := rec.Header().Get("Location"); got != "/login?msg=password+changed+-+sign+in+again" {
		t.Fatalf("redirect = %q, want login success message", got)
	}
	cleared := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == cookieName && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("session cookie was not cleared")
	}
	srv.mu.Lock()
	remainingSessions := len(srv.sessions)
	srv.mu.Unlock()
	if remainingSessions != 0 {
		t.Fatalf("remaining sessions = %d, want 0", remainingSessions)
	}

	hash, err := srv.st.Setting(settingPwdHash)
	if err != nil {
		t.Fatalf("get password hash: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("new-password")); err != nil {
		t.Fatalf("new password does not match stored hash: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("current-password")); err == nil {
		t.Fatal("old password still matches stored hash")
	}

	entries, err := srv.st.AuditLog(10)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(entries) != 1 || entries[0].Action != "admin.password.change" || entries[0].Detail != "via dashboard" {
		t.Fatalf("audit entries = %#v, want password change entry", entries)
	}

	login := httptest.NewRequest(http.MethodGet, rec.Header().Get("Location"), nil)
	loginRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRec, login)
	if !strings.Contains(loginRec.Body.String(), "password changed - sign in again") {
		t.Fatal("login page does not show password change success message")
	}
}

func TestCreateSessionRejectsPasswordVerifiedBeforeChange(t *testing.T) {
	srv := newTestServer(t, "current-password")
	verifiedVersion := srv.passwordVersion
	changed := make(chan struct{})
	go func() {
		srv.mu.Lock()
		srv.passwordVersion++
		srv.sessions = map[string]webSession{}
		srv.mu.Unlock()
		close(changed)
	}()
	<-changed

	if srv.createSession("obsolete", "192.0.2.40", verifiedVersion) {
		t.Fatal("created session after password changed")
	}
	if len(srv.sessions) != 0 {
		t.Fatalf("sessions = %d, want 0", len(srv.sessions))
	}
}

func TestPasswordChangeValidation(t *testing.T) {
	tests := []struct {
		name         string
		current      string
		newPassword  string
		confirmation string
		wantError    string
	}{
		{name: "wrong current password", current: "wrong-password", newPassword: "new-password", confirmation: "new-password", wantError: "current password is incorrect"},
		{name: "confirmation mismatch", current: "current-password", newPassword: "new-password", confirmation: "different-password", wantError: "new passwords do not match"},
		{name: "new password too short", current: "current-password", newPassword: "short", confirmation: "short", wantError: "password must be at least 8 characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, "current-password")
			srv.sessions["current"] = webSession{expires: time.Now().Add(time.Hour), csrf: "csrf-token"}
			form := url.Values{
				"csrf":             {"csrf-token"},
				"current_password": {tt.current},
				"new_password":     {tt.newPassword},
				"confirm_password": {tt.confirmation},
			}
			req := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: cookieName, Value: "current"})
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
			}
			if got := redirectError(t, rec); got != tt.wantError {
				t.Fatalf("error = %q, want %q", got, tt.wantError)
			}
			hash, err := srv.st.Setting(settingPwdHash)
			if err != nil {
				t.Fatalf("get password hash: %v", err)
			}
			if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("current-password")); err != nil {
				t.Fatalf("password changed after validation error: %v", err)
			}
			if len(srv.sessions) != 1 {
				t.Fatalf("sessions = %d, want 1", len(srv.sessions))
			}
			entries, err := srv.st.AuditLog(10)
			if err != nil {
				t.Fatalf("read audit log: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf("audit entries = %d, want 0", len(entries))
			}
		})
	}
}

func TestSettingsRequireAuthenticationAndCSRF(t *testing.T) {
	srv := newTestServer(t, "current-password")

	get := httptest.NewRequest(http.MethodGet, "/settings", nil)
	getRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRec, get)
	if getRec.Code != http.StatusSeeOther || getRec.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated GET status/location = %d %q, want 303 /login", getRec.Code, getRec.Header().Get("Location"))
	}

	srv.sessions["current"] = webSession{expires: time.Now().Add(time.Hour), csrf: "csrf-token"}
	form := url.Values{
		"current_password": {"current-password"},
		"new_password":     {"new-password"},
		"confirm_password": {"new-password"},
	}
	post := httptest.NewRequest(http.MethodPost, "/settings/password", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: cookieName, Value: "current"})
	postRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(postRec, post)
	if postRec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF status = %d, want %d", postRec.Code, http.StatusForbidden)
	}

	hash, err := srv.st.Setting(settingPwdHash)
	if err != nil {
		t.Fatalf("get password hash: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("current-password")); err != nil {
		t.Fatalf("password changed without CSRF token: %v", err)
	}
}
