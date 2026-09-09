package web

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
