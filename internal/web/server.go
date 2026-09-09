// Package web is the admin dashboard: users, tokens, reservations, live
// tunnels and the audit log. It is server-rendered with html/template and a
// single admin password, and expects to sit behind a TLS-terminating proxy.
package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/johyunchol/ktunnel/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

const (
	cookieName     = "ktunneld_session"
	sessionTTL     = 12 * time.Hour
	maxLoginFails  = 5
	loginLockout   = 60 * time.Second
	settingPwdHash = "admin_password_hash"
)

type webSession struct {
	expires time.Time
	csrf    string
}

type loginFail struct {
	count int
	until time.Time
}

type Server struct {
	st     *store.Store
	logger *log.Logger
	pages  map[string]*template.Template

	mu       sync.Mutex
	sessions map[string]webSession
	fails    map[string]loginFail
}

func New(st *store.Store, logger *log.Logger) (*Server, error) {
	funcs := template.FuncMap{
		"ago":  ago,
		"when": when,
	}
	pages := map[string]*template.Template{}
	for _, name := range []string{"login", "index", "users", "user", "audit"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		pages[name] = t
	}
	return &Server{
		st:       st,
		logger:   logger,
		pages:    pages,
		sessions: map[string]webSession{},
		fails:    map[string]loginFail{},
	}, nil
}

// SetAdminPassword stores a bcrypt hash of the dashboard password.
func SetAdminPassword(st *store.Store, password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return st.SetSetting(settingPwdHash, string(hash))
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServer(http.FS(assets)))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.auth(s.logout))

	mux.HandleFunc("GET /{$}", s.auth(s.index))
	mux.HandleFunc("GET /users", s.auth(s.users))
	mux.HandleFunc("POST /users", s.auth(s.userCreate))
	mux.HandleFunc("GET /users/{id}", s.auth(s.user))
	mux.HandleFunc("POST /users/{id}/disable", s.auth(s.userSetDisabled(true)))
	mux.HandleFunc("POST /users/{id}/enable", s.auth(s.userSetDisabled(false)))
	mux.HandleFunc("POST /users/{id}/limit", s.auth(s.userLimit))
	mux.HandleFunc("POST /users/{id}/tokens", s.auth(s.tokenIssue))
	mux.HandleFunc("POST /users/{id}/reservations", s.auth(s.reservationAdd))
	mux.HandleFunc("POST /tokens/{id}/revoke", s.auth(s.tokenRevoke))
	mux.HandleFunc("POST /reservations/{sub}/release", s.auth(s.reservationRelease))
	mux.HandleFunc("POST /sessions/{id}/kill", s.auth(s.sessionKill))
	mux.HandleFunc("GET /audit", s.auth(s.audit))
	return mux
}

// ---------- auth ----------

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.currentSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(sess.csrf)) != 1 {
			http.Error(w, "invalid form token - reload and try again", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) currentSession(r *http.Request) (webSession, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return webSession{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok || time.Now().After(sess.expires) {
		delete(s.sessions, c.Value)
		return webSession{}, false
	}
	return sess, true
}

func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// clientIP is the key for login lockout. X-Real-IP is what the fronting
// nginx block sets from $remote_addr and cannot be influenced by the client;
// X-Forwarded-For's first hop can be, so it is only a fallback for proxies
// that overwrite rather than append.
func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		hops := strings.Split(xff, ",")
		return strings.TrimSpace(hops[len(hops)-1])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	hash, _ := s.st.Setting(settingPwdHash)
	s.render(w, "login", map[string]any{
		"Title":      "Sign in",
		"NoPassword": hash == "",
		"Error":      r.URL.Query().Get("error"),
	})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.beginLoginAttempt(ip, time.Now()) {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("too many attempts - wait a minute"), http.StatusSeeOther)
		return
	}

	hash, _ := s.st.Setting(settingPwdHash)
	if hash == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.FormValue("password"))) != nil {
		s.logger.Printf("dashboard login failed from %s", ip)
		http.Redirect(w, r, "/login?error="+url.QueryEscape("wrong password"), http.StatusSeeOther)
		return
	}

	id := randomHex(32)
	s.mu.Lock()
	delete(s.fails, ip)
	s.sessions[id] = webSession{expires: time.Now().Add(sessionTTL), csrf: randomHex(16)}
	s.mu.Unlock()
	// Strict, not Lax: every tunnel lives on a sibling subdomain, and to the
	// browser evil.example.com and tunnel-admin.example.com are the same site.
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/", HttpOnly: true,
		Secure: secureRequest(r), SameSite: http.SameSiteStrictMode,
		Expires: time.Now().Add(sessionTTL),
	})
	s.logger.Printf("dashboard login from %s", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) beginLoginAttempt(ip string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f := s.fails[ip]
	if f.count >= maxLoginFails {
		if now.Before(f.until) {
			return false
		}
		f = loginFail{}
	}
	f.count++
	if f.count >= maxLoginFails {
		f.until = now.Add(loginLockout)
	}
	s.fails[ip] = f

	return true
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------- pages ----------

func (s *Server) render(w http.ResponseWriter, page string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages[page].ExecuteTemplate(w, "layout.html", data); err != nil {
		s.logger.Printf("render %s: %v", page, err)
	}
}

func (s *Server) base(r *http.Request, title string) map[string]any {
	sess, _ := s.currentSession(r)
	return map[string]any{
		"Title": title,
		"CSRF":  sess.csrf,
		"Msg":   r.URL.Query().Get("msg"),
		"Error": r.URL.Query().Get("error"),
		"Path":  r.URL.Path,
	}
}

func redirectMsg(w http.ResponseWriter, r *http.Request, to, msg string, err error) {
	q := url.Values{}
	if err != nil {
		q.Set("error", err.Error())
	} else if msg != "" {
		q.Set("msg", msg)
	}
	if len(q) > 0 {
		to += "?" + q.Encode()
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	data := s.base(r, "Overview")
	data["Proxies"], _ = s.st.ActiveProxies()
	data["Sessions"], _ = s.st.ActiveSessions()
	users, _ := s.st.Users()
	data["UserCount"] = len(users)
	if info, err := s.st.ServerInfo(); err == nil {
		data["Domain"] = info.Domain
	}
	s.render(w, "index", data)
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	data := s.base(r, "Users")
	data["Users"], _ = s.st.Users()
	s.render(w, "users", data)
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.FormValue("max_tunnels"))
	u, err := s.st.CreateUser(r.FormValue("name"), limit)
	if err != nil {
		redirectMsg(w, r, "/users", "", err)
		return
	}
	s.st.Audit(u.ID, "user.create", "via dashboard")
	redirectMsg(w, r, "/users/"+strconv.FormatInt(u.ID, 10), "user created", nil)
}

func (s *Server) userID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func (s *Server) user(w http.ResponseWriter, r *http.Request) {
	id, err := s.userID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	u, err := s.st.User(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.renderUser(w, r, u, "")
}

func (s *Server) renderUser(w http.ResponseWriter, r *http.Request, u *store.User, newToken string) {
	data := s.base(r, u.Name)
	data["User"] = u
	data["Tokens"], _ = s.st.Tokens(u.ID)
	data["Reservations"], _ = s.st.Reservations(u.ID)
	data["NewToken"] = newToken
	if info, err := s.st.ServerInfo(); err == nil {
		data["Domain"] = info.Domain
	}
	s.render(w, "user", data)
}

func (s *Server) userSetDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.userID(r)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		err = s.st.SetUserDisabled(id, disabled)
		action, msg := "user.enable", "user enabled"
		if disabled {
			action, msg = "user.disable", "user disabled - live sessions drop at their next heartbeat"
		}
		s.st.Audit(id, action, "via dashboard")
		redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), msg, err)
	}
}

func (s *Server) userLimit(w http.ResponseWriter, r *http.Request) {
	id, err := s.userID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	n, err := strconv.Atoi(r.FormValue("max_tunnels"))
	if err != nil || n < 1 {
		redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), "", fmt.Errorf("limit must be a positive number"))
		return
	}
	err = s.st.SetUserMaxTunnels(id, n)
	redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), "limit updated", err)
}

func (s *Server) tokenIssue(w http.ResponseWriter, r *http.Request) {
	id, err := s.userID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	u, err := s.st.User(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	plaintext, tok, err := s.st.IssueToken(u.ID, r.FormValue("label"))
	if err != nil {
		redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), "", err)
		return
	}
	s.st.Audit(u.ID, "token.issue", fmt.Sprintf("%s (%s) via dashboard", tok.Label, tok.Prefix))
	// Rendered directly rather than via redirect: the plaintext must never
	// appear in a URL, and this is the only time it exists.
	s.renderUser(w, r, u, plaintext)
}

func (s *Server) tokenRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tok, err := s.st.Token(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	err = s.st.RevokeToken(id)
	s.st.Audit(tok.UserID, "token.revoke", fmt.Sprintf("%s (%s) via dashboard", tok.Label, tok.Prefix))
	redirectMsg(w, r, "/users/"+strconv.FormatInt(tok.UserID, 10), "token revoked", err)
}

func (s *Server) reservationAdd(w http.ResponseWriter, r *http.Request) {
	id, err := s.userID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sub := strings.ToLower(strings.TrimSpace(r.FormValue("subdomain")))
	err = s.st.Reserve(sub, id)
	if err == nil {
		s.st.Audit(id, "reserve", sub)
	}
	redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), "reserved "+sub, err)
}

func (s *Server) reservationRelease(w http.ResponseWriter, r *http.Request) {
	sub := r.PathValue("sub")
	res, err := s.st.Reservation(sub)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	err = s.st.Release(sub)
	s.st.Audit(res.UserID, "release", sub)
	redirectMsg(w, r, "/users/"+strconv.FormatInt(res.UserID, 10), "released "+sub, err)
}

func (s *Server) sessionKill(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sess, err := s.st.Session(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	err = s.st.KillSession(id)
	s.st.Audit(sess.UserID, "session.kill", fmt.Sprintf("%s (%s) via dashboard", sess.Hostname, sess.ClientAddr))
	redirectMsg(w, r, "/", "session will drop at its next heartbeat (≤30s)", err)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	data := s.base(r, "Audit log")
	data["Entries"], _ = s.st.AuditLog(200)
	s.render(w, "audit", data)
}

// ---------- template helpers ----------

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm ago", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func when(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("2006-01-02 15:04")
}
