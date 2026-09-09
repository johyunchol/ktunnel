// Package web serves the role-aware ktunnel web portal.
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
	"unicode/utf8"

	"github.com/johyunchol/ktunnel/internal/store"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*.html static/*
var assets embed.FS

const (
	cookieName              = "ktunneld_session"
	sessionTTL              = 12 * time.Hour
	maxLoginFails           = 5
	maxIPLoginAttempts      = 20
	loginLockout            = 60 * time.Second
	loginFailRetention      = 5 * time.Minute
	maxLoginFailEntries     = 1024
	settingPwdHash          = "admin_password_hash"
	settingAdminAuthVersion = "admin_web_auth_version"
	adminUsername           = "admin"
)

type webSession struct {
	expires     time.Time
	csrf        string
	isAdmin     bool
	userID      int64
	username    string
	authVersion int64
	mustChange  bool
}
type credential struct {
	hash        string
	isAdmin     bool
	userID      int64
	username    string
	authVersion int64
	mustChange  bool
	disabled    bool
}
type loginFail struct {
	count    int
	until    time.Time
	lastSeen time.Time
}
type Server struct {
	st        *store.Store
	logger    *log.Logger
	pages     map[string]*template.Template
	mu        sync.Mutex
	sessions  map[string]webSession
	fails     map[string]loginFail
	ipFails   map[string]loginFail
	dummyHash string
}

func New(st *store.Store, logger *log.Logger) (*Server, error) {
	funcs := template.FuncMap{"ago": ago, "when": when, "initial": initial, "action": actionKorean, "hasPrefix": strings.HasPrefix}
	pages := map[string]*template.Template{}
	for _, name := range []string{"login", "index", "users", "user", "audit", "settings", "me", "account"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		pages[name] = t
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("prepare login verifier: %w", err)
	}
	return &Server{st: st, logger: logger, pages: pages, sessions: map[string]webSession{}, fails: map[string]loginFail{}, ipFails: map[string]loginFail{}, dummyHash: string(dummy)}, nil
}

func validPassword(password string) error {
	if utf8.RuneCountInString(password) < 8 {
		return fmt.Errorf("비밀번호는 8자 이상이어야 합니다")
	}
	if len([]byte(password)) > 72 {
		return fmt.Errorf("비밀번호는 UTF-8 기준 72바이트 이하여야 합니다")
	}
	return nil
}
func passwordHash(password string) (string, error) {
	if err := validPassword(password); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

// SetAdminPassword keeps the legacy CLI setting and bumps the web session version.
func SetAdminPassword(st *store.Store, password string) error {
	h, err := passwordHash(password)
	if err != nil {
		return err
	}
	return st.SetAdminWebPassword(h)
}

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.Handle("GET /static/", http.FileServer(http.FS(assets)))
	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("POST /login", s.loginSubmit)
	m.HandleFunc("POST /logout", s.auth(s.logout))
	m.HandleFunc("GET /{$}", s.auth(s.home))
	m.HandleFunc("GET /users", s.admin(s.users))
	m.HandleFunc("POST /users", s.admin(s.userCreate))
	m.HandleFunc("GET /users/{id}", s.admin(s.user))
	m.HandleFunc("POST /users/{id}/disable", s.admin(s.userSetDisabled(true)))
	m.HandleFunc("POST /users/{id}/enable", s.admin(s.userSetDisabled(false)))
	m.HandleFunc("POST /users/{id}/limit", s.admin(s.userLimit))
	m.HandleFunc("POST /users/{id}/password", s.admin(s.userPasswordReset))
	m.HandleFunc("POST /users/{id}/tokens", s.admin(s.tokenIssue))
	m.HandleFunc("POST /users/{id}/reservations", s.admin(s.reservationAdd))
	m.HandleFunc("POST /tokens/{id}/revoke", s.admin(s.tokenRevoke))
	m.HandleFunc("POST /reservations/{sub}/release", s.admin(s.reservationRelease))
	m.HandleFunc("POST /sessions/{id}/kill", s.admin(s.sessionKill))
	m.HandleFunc("GET /audit", s.admin(s.audit))
	m.HandleFunc("GET /settings", s.admin(s.settings))
	m.HandleFunc("POST /settings/password", s.admin(s.adminPasswordChange))
	m.HandleFunc("GET /me", s.userOnly(s.me))
	m.HandleFunc("POST /me/tokens", s.userOnly(s.myTokenIssue))
	m.HandleFunc("POST /me/tokens/{id}/revoke", s.userOnly(s.myTokenRevoke))
	m.HandleFunc("GET /account", s.userOnly(s.account))
	m.HandleFunc("POST /account/password", s.userOnly(s.userPasswordChange))
	m.HandleFunc("/", s.notFound)
	return m
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.currentSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(sess.csrf)) != 1 {
			http.Error(w, "잘못된 요청입니다. 페이지를 새로고침한 뒤 다시 시도해 주세요.", http.StatusForbidden)
			return
		}
		if sess.mustChange && r.URL.Path != "/account" && r.URL.Path != "/account/password" && r.URL.Path != "/logout" {
			http.Redirect(w, r, "/account?msg="+url.QueryEscape("계속하려면 임시 비밀번호를 변경해 주세요."), http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}
func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := s.currentSession(r)
		if !sess.isAdmin {
			http.Error(w, "관리자만 접근할 수 있습니다.", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}
func (s *Server) userOnly(next http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := s.currentSession(r)
		if sess.isAdmin {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next(w, r)
	})
}

func (s *Server) currentSession(r *http.Request) (webSession, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return webSession{}, false
	}
	s.mu.Lock()
	sess, ok := s.sessions[c.Value]
	s.mu.Unlock()
	if !ok || time.Now().After(sess.expires) || !s.sessionCredentialCurrent(sess) {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
		return webSession{}, false
	}
	return sess, true
}
func (s *Server) sessionCredentialCurrent(sess webSession) bool {
	if sess.isAdmin {
		hash, version, err := s.st.AdminWebCredential()
		return err == nil && hash != "" && sess.authVersion == version
	}
	u, err := s.st.User(sess.userID)
	return err == nil && !u.Disabled && u.WebPasswordHash != "" && u.WebAuthVersion == sess.authVersion
}
func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		h := strings.Split(xff, ",")
		return strings.TrimSpace(h[len(h)-1])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
func randomHex(n int) string    { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func temporaryPassword() string { return randomHex(10) }

func (s *Server) credentialForUsername(username string) credential {
	if username == adminUsername {
		h, version, err := s.st.AdminWebCredential()
		if err != nil || h == "" {
			return credential{}
		}
		return credential{hash: h, isAdmin: true, username: adminUsername, authVersion: version}
	}
	u, err := s.st.UserByName(username)
	if err != nil {
		return credential{}
	}
	return credential{hash: u.WebPasswordHash, userID: u.ID, username: u.Name, authVersion: u.WebAuthVersion, mustChange: u.PasswordChangeRequired, disabled: u.Disabled}
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.currentSession(r); ok {
		to := "/me"
		if sess.isAdmin {
			to = "/"
		}
		http.Redirect(w, r, to, http.StatusSeeOther)
		return
	}
	h, _ := s.st.Setting(settingPwdHash)
	s.render(w, "login", map[string]any{"Title": "로그인", "NoPassword": h == "", "Msg": r.URL.Query().Get("msg"), "Error": r.URL.Query().Get("error")})
}
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !loginOriginAllowed(r) {
		http.Error(w, "허용되지 않은 로그인 요청입니다.", http.StatusForbidden)
		return
	}
	ip := clientIP(r)
	username := strings.TrimSpace(r.FormValue("username"))
	lockKey := loginFailureKey(ip, username)
	if !s.beginLoginAttempt(ip, username, time.Now()) {
		redirectMsg(w, r, "/login", "", fmt.Errorf("로그인 시도가 너무 많습니다. 잠시 후 다시 시도해 주세요."))
		return
	}
	cred := s.credentialForUsername(username)
	compareHash := cred.hash
	if compareHash == "" {
		compareHash = s.dummyHash
	}
	passwordWrong := bcrypt.CompareHashAndPassword([]byte(compareHash), []byte(r.FormValue("password"))) != nil
	if cred.hash == "" || cred.disabled || passwordWrong {
		s.logger.Printf("web login failed from %s", ip)
		redirectMsg(w, r, "/login", "", fmt.Errorf("아이디 또는 비밀번호가 올바르지 않습니다."))
		return
	}
	id := randomHex(32)
	if !s.createSession(id, lockKey, cred) {
		redirectMsg(w, r, "/login", "", fmt.Errorf("로그인 정보가 변경되었습니다. 다시 시도해 주세요."))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(sessionTTL)})
	to := "/me"
	if cred.isAdmin {
		to = "/"
	} else if cred.mustChange {
		to = "/account?msg=" + url.QueryEscape("계속하려면 임시 비밀번호를 변경해 주세요.")
	}
	s.logger.Printf("web login for %s from %s", username, ip)
	http.Redirect(w, r, to, http.StatusSeeOther)
}
func loginOriginAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		// Non-browser clients do not send Origin. Browser form submissions do,
		// and are required to match the externally visible host and scheme.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || !strings.EqualFold(u.Host, r.Host) {
		return false
	}
	wantScheme := "http"
	if secureRequest(r) {
		wantScheme = "https"
	}
	return strings.EqualFold(u.Scheme, wantScheme)
}
func loginFailureKey(ip, username string) string {
	return ip + "\x00" + strings.ToLower(strings.TrimSpace(username))
}

func (s *Server) createSession(id, lockKey string, cred credential) bool {
	current := s.credentialForUsername(cred.username)
	if current.hash == "" || current.hash != cred.hash || current.disabled || current.isAdmin != cred.isAdmin || current.userID != cred.userID || current.authVersion != cred.authVersion {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.fails, lockKey)
	s.sessions[id] = webSession{expires: time.Now().Add(sessionTTL), csrf: randomHex(16), isAdmin: cred.isAdmin, userID: cred.userID, username: cred.username, authVersion: cred.authVersion, mustChange: cred.mustChange}
	return true
}
func (s *Server) beginLoginAttempt(ip, username string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLoginFailures(now)
	if !allowLoginAttempt(s.ipFails, ip, maxIPLoginAttempts, now) {
		return false
	}
	return allowLoginAttempt(s.fails, loginFailureKey(ip, username), maxLoginFails, now)
}

func allowLoginAttempt(buckets map[string]loginFail, key string, limit int, now time.Time) bool {
	f, exists := buckets[key]
	if !exists && len(buckets) >= maxLoginFailEntries {
		return false
	}
	if f.count >= limit {
		if now.Before(f.until) {
			return false
		}
		f = loginFail{}
	}
	f.count++
	f.lastSeen = now
	if f.count >= limit {
		f.until = now.Add(loginLockout)
	}
	buckets[key] = f
	return true
}

func (s *Server) pruneLoginFailures(now time.Time) {
	prune := func(buckets map[string]loginFail) {
		for key, f := range buckets {
			if !now.Before(f.until) && now.Sub(f.lastSeen) > loginFailRetention {
				delete(buckets, key)
			}
		}
	}
	prune(s.fails)
	prune(s.ipFails)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}
func (s *Server) invalidatePrincipal(isAdmin bool, userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.isAdmin == isAdmin && (isAdmin || sess.userID == userID) {
			delete(s.sessions, id)
		}
	}
}

func (s *Server) render(w http.ResponseWriter, page string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.pages[page].ExecuteTemplate(w, "layout.html", data); err != nil {
		s.logger.Printf("render %s: %v", page, err)
	}
}
func (s *Server) base(r *http.Request, title string) map[string]any {
	sess, _ := s.currentSession(r)
	return map[string]any{"Title": title, "CSRF": sess.csrf, "Msg": r.URL.Query().Get("msg"), "Error": r.URL.Query().Get("error"), "Path": r.URL.Path, "IsAdmin": sess.isAdmin, "Username": sess.username, "MustChange": sess.mustChange}
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

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.currentSession(r)
	if !sess.isAdmin {
		http.Redirect(w, r, "/me", http.StatusSeeOther)
		return
	}
	s.index(w, r)
}
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	d := s.base(r, "현황")
	d["Proxies"], _ = s.st.ActiveProxies()
	d["Sessions"], _ = s.st.ActiveSessions()
	us, _ := s.st.Users()
	d["UserCount"] = len(us)
	if i, e := s.st.ServerInfo(); e == nil {
		d["Domain"] = i.Domain
	}
	s.render(w, "index", d)
}
func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	d := s.base(r, "사용자")
	d["Users"], _ = s.st.Users()
	s.render(w, "users", d)
}
func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	pw := r.FormValue("temporary_password")
	if pw == "" {
		pw = temporaryPassword()
	}
	if e := validPassword(pw); e != nil {
		redirectMsg(w, r, "/users", "", e)
		return
	}
	limit, _ := strconv.Atoi(r.FormValue("max_tunnels"))
	u, e := s.st.CreateUser(r.FormValue("name"), limit)
	if e != nil {
		redirectMsg(w, r, "/users", "", koreanStoreError(e))
		return
	}
	if e = s.setUserPassword(u.ID, pw, true); e != nil {
		redirectMsg(w, r, "/users/"+strconv.FormatInt(u.ID, 10), "", e)
		return
	}
	s.st.Audit(u.ID, "user.create", "웹 관리 화면에서 생성")
	s.renderUser(w, r, u, "", pw)
}
func (s *Server) userID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}
func (s *Server) user(w http.ResponseWriter, r *http.Request) {
	id, e := s.userID(r)
	if e != nil {
		s.notFound(w, r)
		return
	}
	u, e := s.st.User(id)
	if e != nil {
		s.notFound(w, r)
		return
	}
	s.renderUser(w, r, u, "", "")
}
func (s *Server) renderUser(w http.ResponseWriter, r *http.Request, u *store.User, newToken, newPassword string) {
	if fresh, e := s.st.User(u.ID); e == nil {
		u = fresh
	}
	d := s.base(r, u.Name)
	d["User"] = u
	d["Tokens"], _ = s.st.Tokens(u.ID)
	d["Reservations"], _ = s.st.Reservations(u.ID)
	d["NewToken"] = newToken
	d["NewPassword"] = newPassword
	if i, e := s.st.ServerInfo(); e == nil {
		d["Domain"] = i.Domain
	}
	s.render(w, "user", d)
}
func (s *Server) userSetDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, e := s.userID(r)
		if e != nil {
			s.notFound(w, r)
			return
		}
		e = s.st.SetUserDisabled(id, disabled)
		s.invalidatePrincipal(false, id)
		action, msg := "user.enable", "사용자 계정을 활성화했습니다."
		if disabled {
			action, msg = "user.disable", "사용자 계정을 비활성화했습니다."
		}
		if e == nil {
			s.st.Audit(id, action, "웹 관리 화면에서 변경")
		}
		redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), msg, e)
	}
}
func (s *Server) userLimit(w http.ResponseWriter, r *http.Request) {
	id, e := s.userID(r)
	if e != nil {
		s.notFound(w, r)
		return
	}
	n, e := strconv.Atoi(r.FormValue("max_tunnels"))
	if e != nil || n < 1 {
		redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), "", fmt.Errorf("동시 터널 수는 1 이상이어야 합니다"))
		return
	}
	e = s.st.SetUserMaxTunnels(id, n)
	redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), "터널 한도를 변경했습니다.", e)
}
func (s *Server) setUserPassword(id int64, password string, must bool) error {
	h, e := passwordHash(password)
	if e != nil {
		return e
	}
	return s.st.SetUserWebPassword(id, h, must)
}
func (s *Server) userPasswordReset(w http.ResponseWriter, r *http.Request) {
	id, e := s.userID(r)
	if e != nil {
		s.notFound(w, r)
		return
	}
	u, e := s.st.User(id)
	if e != nil {
		s.notFound(w, r)
		return
	}
	pw := r.FormValue("temporary_password")
	if pw == "" {
		pw = temporaryPassword()
	}
	if e = s.setUserPassword(id, pw, true); e != nil {
		redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), "", e)
		return
	}
	s.invalidatePrincipal(false, id)
	s.st.Audit(id, "user.password.reset", "임시 비밀번호 발급")
	s.renderUser(w, r, u, "", pw)
}
func (s *Server) tokenIssue(w http.ResponseWriter, r *http.Request) {
	id, e := s.userID(r)
	if e != nil {
		s.notFound(w, r)
		return
	}
	u, e := s.st.User(id)
	if e != nil {
		s.notFound(w, r)
		return
	}
	plain, tok, e := s.st.IssueToken(u.ID, r.FormValue("label"))
	if e != nil {
		redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), "", koreanStoreError(e))
		return
	}
	s.st.Audit(u.ID, "token.issue", fmt.Sprintf("%s (%s), 관리자 발급", tok.Label, tok.Prefix))
	s.renderUser(w, r, u, plain, "")
}
func (s *Server) tokenRevoke(w http.ResponseWriter, r *http.Request) {
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil {
		s.notFound(w, r)
		return
	}
	tok, e := s.st.Token(id)
	if e != nil {
		s.notFound(w, r)
		return
	}
	e = s.st.RevokeToken(id)
	if e == nil {
		s.st.Audit(tok.UserID, "token.revoke", fmt.Sprintf("%s (%s), 관리자 폐기", tok.Label, tok.Prefix))
	}
	redirectMsg(w, r, "/users/"+strconv.FormatInt(tok.UserID, 10), "토큰을 폐기했습니다.", e)
}
func (s *Server) reservationAdd(w http.ResponseWriter, r *http.Request) {
	id, e := s.userID(r)
	if e != nil {
		s.notFound(w, r)
		return
	}
	sub := strings.ToLower(strings.TrimSpace(r.FormValue("subdomain")))
	e = s.st.Reserve(sub, id)
	if e == nil {
		s.st.Audit(id, "reserve", sub)
	}
	redirectMsg(w, r, "/users/"+strconv.FormatInt(id, 10), sub+" 서브도메인을 예약했습니다.", koreanStoreError(e))
}
func (s *Server) reservationRelease(w http.ResponseWriter, r *http.Request) {
	sub := r.PathValue("sub")
	res, e := s.st.Reservation(sub)
	if e != nil {
		s.notFound(w, r)
		return
	}
	e = s.st.Release(sub)
	if e == nil {
		s.st.Audit(res.UserID, "release", sub)
	}
	redirectMsg(w, r, "/users/"+strconv.FormatInt(res.UserID, 10), sub+" 예약을 해제했습니다.", koreanStoreError(e))
}
func (s *Server) sessionKill(w http.ResponseWriter, r *http.Request) {
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil {
		s.notFound(w, r)
		return
	}
	sess, e := s.st.Session(id)
	if e != nil {
		s.notFound(w, r)
		return
	}
	e = s.st.KillSession(id)
	if e == nil {
		s.st.Audit(sess.UserID, "session.kill", fmt.Sprintf("%s (%s), 관리자 종료", sess.Hostname, sess.ClientAddr))
	}
	redirectMsg(w, r, "/", "연결이 다음 확인 주기(최대 30초)에 종료됩니다.", e)
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	d := s.base(r, "감사 로그")
	d["Entries"], _ = s.st.AuditLog(200)
	s.render(w, "audit", d)
}
func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	s.render(w, "settings", s.base(r, "설정"))
}
func (s *Server) adminPasswordChange(w http.ResponseWriter, r *http.Request) {
	h, version, _ := s.st.AdminWebCredential()
	if bcrypt.CompareHashAndPassword([]byte(h), []byte(r.FormValue("current_password"))) != nil {
		redirectMsg(w, r, "/settings", "", fmt.Errorf("현재 비밀번호가 올바르지 않습니다"))
		return
	}
	if r.FormValue("new_password") != r.FormValue("confirm_password") {
		redirectMsg(w, r, "/settings", "", fmt.Errorf("새 비밀번호와 확인 값이 일치하지 않습니다"))
		return
	}
	if r.FormValue("new_password") == r.FormValue("current_password") {
		redirectMsg(w, r, "/settings", "", fmt.Errorf("새 비밀번호는 현재 비밀번호와 달라야 합니다"))
		return
	}
	newHash, e := passwordHash(r.FormValue("new_password"))
	if e != nil {
		redirectMsg(w, r, "/settings", "", e)
		return
	}
	changed, e := s.st.SetAdminWebPasswordIfVersion(newHash, version)
	if e != nil {
		redirectMsg(w, r, "/settings", "", koreanStoreError(e))
		return
	}
	if !changed {
		redirectMsg(w, r, "/settings", "", fmt.Errorf("비밀번호가 다른 곳에서 변경되었습니다. 다시 로그인해 주세요"))
		return
	}
	s.st.Audit(0, "admin.password.change", "웹 관리 화면에서 변경")
	s.invalidatePrincipal(true, 0)
	clearSessionCookie(w)
	redirectMsg(w, r, "/login", "비밀번호를 변경했습니다. 다시 로그인해 주세요.", nil)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) { s.renderMe(w, r, "") }
func (s *Server) renderMe(w http.ResponseWriter, r *http.Request, newToken string) {
	sess, _ := s.currentSession(r)
	u, e := s.st.User(sess.userID)
	if e != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	d := s.base(r, "내 터널")
	d["User"] = u
	d["Tokens"], _ = s.st.Tokens(u.ID)
	d["Reservations"], _ = s.st.Reservations(u.ID)
	d["NewToken"] = newToken
	var mineS []store.Session
	allS, _ := s.st.ActiveSessions()
	for _, x := range allS {
		if x.UserID == u.ID {
			mineS = append(mineS, x)
		}
	}
	d["Sessions"] = mineS
	var mineP []store.Proxy
	allP, _ := s.st.ActiveProxies()
	for _, x := range allP {
		if x.UserID == u.ID {
			mineP = append(mineP, x)
		}
	}
	d["Proxies"] = mineP
	if i, e := s.st.ServerInfo(); e == nil {
		d["Domain"] = i.Domain
	}
	s.render(w, "me", d)
}
func (s *Server) myTokenIssue(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.currentSession(r)
	plain, tok, e := s.st.IssueToken(sess.userID, r.FormValue("label"))
	if e != nil {
		redirectMsg(w, r, "/me", "", koreanStoreError(e))
		return
	}
	s.st.Audit(sess.userID, "token.issue", fmt.Sprintf("%s (%s), 사용자 직접 발급", tok.Label, tok.Prefix))
	s.renderMe(w, r, plain)
}
func (s *Server) myTokenRevoke(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.currentSession(r)
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil {
		s.notFound(w, r)
		return
	}
	if e = s.st.RevokeTokenForUser(id, sess.userID); e != nil {
		s.notFound(w, r)
		return
	}
	s.st.Audit(sess.userID, "token.revoke", "사용자 직접 폐기")
	redirectMsg(w, r, "/me", "토큰을 폐기했습니다.", nil)
}
func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	s.render(w, "account", s.base(r, "계정 설정"))
}
func (s *Server) userPasswordChange(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.currentSession(r)
	u, e := s.st.User(sess.userID)
	if e != nil {
		s.notFound(w, r)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.WebPasswordHash), []byte(r.FormValue("current_password"))) != nil {
		redirectMsg(w, r, "/account", "", fmt.Errorf("현재 비밀번호가 올바르지 않습니다"))
		return
	}
	if r.FormValue("new_password") != r.FormValue("confirm_password") {
		redirectMsg(w, r, "/account", "", fmt.Errorf("새 비밀번호와 확인 값이 일치하지 않습니다"))
		return
	}
	if r.FormValue("new_password") == r.FormValue("current_password") {
		redirectMsg(w, r, "/account", "", fmt.Errorf("새 비밀번호는 현재 비밀번호와 달라야 합니다"))
		return
	}
	newHash, e := passwordHash(r.FormValue("new_password"))
	if e != nil {
		redirectMsg(w, r, "/account", "", e)
		return
	}
	changed, e := s.st.SetUserWebPasswordIfVersion(u.ID, u.WebAuthVersion, newHash, false)
	if e != nil {
		redirectMsg(w, r, "/account", "", koreanStoreError(e))
		return
	}
	if !changed {
		redirectMsg(w, r, "/account", "", fmt.Errorf("비밀번호가 관리자에 의해 변경되었습니다. 다시 로그인해 주세요"))
		return
	}
	s.st.Audit(u.ID, "user.password.change", "사용자 직접 변경")
	s.invalidatePrincipal(false, u.ID)
	clearSessionCookie(w)
	redirectMsg(w, r, "/login", "비밀번호를 변경했습니다. 다시 로그인해 주세요.", nil)
}
func (s *Server) notFound(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "요청한 페이지를 찾을 수 없습니다.", http.StatusNotFound)
}
func koreanStoreError(err error) error {
	if err == nil {
		return nil
	}
	m := err.Error()
	switch {
	case strings.Contains(m, "user name is required"):
		return fmt.Errorf("사용자 아이디를 입력해 주세요")
	case strings.Contains(m, "reserved user name"):
		return fmt.Errorf("admin은 사용할 수 없는 아이디입니다")
	case strings.Contains(m, "already exists"):
		return fmt.Errorf("이미 사용 중인 아이디입니다")
	case strings.Contains(m, "already reserved"):
		return fmt.Errorf("이미 예약된 주소입니다")
	case strings.Contains(m, "web portal"):
		return fmt.Errorf("ktunnel은 웹 포털 주소로 예약되어 있습니다")
	case strings.Contains(m, "server address/domain not configured"):
		return fmt.Errorf("터널 서버 설정이 완료되지 않았습니다")
	case err == store.ErrNotFound:
		return fmt.Errorf("요청한 항목을 찾을 수 없습니다")
	}
	return fmt.Errorf("요청을 처리하지 못했습니다")
}
func ago(t time.Time) string {
	if t.IsZero() {
		return "기록 없음"
	}
	d := time.Since(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d초 전", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d분 전", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d시간 %d분 전", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%d일 전", int(d.Hours()/24))
	}
}
func when(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("2006-01-02 15:04")
}
func initial(v string) string {
	for _, r := range v {
		return string(r)
	}
	return ""
}

func actionKorean(v string) string {
	labels := map[string]string{
		"user.create": "사용자 생성", "user.enable": "사용자 활성화", "user.disable": "사용자 비활성화",
		"user.password.reset": "임시 비밀번호 발급", "user.password.change": "사용자 비밀번호 변경",
		"admin.password.change": "관리자 비밀번호 변경", "token.issue": "토큰 발급", "token.revoke": "토큰 폐기",
		"reserve": "주소 예약", "release": "주소 예약 해제", "session.kill": "연결 종료",
	}
	if label := labels[v]; label != "" {
		return label
	}
	return v
}
