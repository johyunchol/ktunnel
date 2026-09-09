// Package plugin implements the frps "server plugin" HTTP protocol. frps calls
// this endpoint on Login, NewProxy, Ping and CloseProxy, and we answer with
// allow / reject. This is what turns a single shared frps token into per-user
// tokens with subdomain ownership.
//
// Protocol: https://github.com/fatedier/frp/blob/dev/doc/server_plugin.md
package plugin

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/johyunchol/ktunnel/internal/store"
)

const (
	metaToken   = "token"           // set by the client: the personal token
	metaSession = "ktunnel_session" // set by us at Login, echoed by frps afterwards
	metaUser    = "ktunnel_user"
)

var subdomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

type request struct {
	Version string          `json:"version"`
	Op      string          `json:"op"`
	Content json.RawMessage `json:"content"`
}

type response struct {
	Reject       bool   `json:"reject"`
	RejectReason string `json:"reject_reason,omitempty"`
	Unchange     bool   `json:"unchange"`
	Content      any    `json:"content,omitempty"`
}

type userInfo struct {
	User  string            `json:"user"`
	Metas map[string]string `json:"metas"`
	RunID string            `json:"run_id"`
}

type newProxyContent struct {
	User          userInfo `json:"user"`
	ProxyName     string   `json:"proxy_name"`
	ProxyType     string   `json:"proxy_type"`
	SubDomain     string   `json:"subdomain"`
	CustomDomains []string `json:"custom_domains"`
	RemotePort    int      `json:"remote_port"`
}

type userOnlyContent struct {
	User      userInfo `json:"user"`
	ProxyName string   `json:"proxy_name"`
}

type Handler struct {
	Store  *store.Store
	Logger *log.Logger
}

func (h *Handler) logf(format string, args ...any) {
	if h.Logger != nil {
		h.Logger.Printf(format, args...)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var resp response
	switch req.Op {
	case "Login":
		resp = h.login(req.Content, r)
	case "NewProxy":
		resp = h.newProxy(req.Content)
	case "Ping":
		resp = h.ping(req.Content)
	case "CloseProxy":
		resp = h.closeProxy(req.Content)
	default:
		resp = response{Unchange: true}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func reject(reason string) response {
	return response{Reject: true, RejectReason: reason}
}

// login authenticates the personal token and rewrites the login so that frps
// sees the resolved user name and our session id on every later operation.
func (h *Handler) login(raw json.RawMessage, r *http.Request) response {
	var content map[string]any
	if err := json.Unmarshal(raw, &content); err != nil {
		return reject("malformed login")
	}
	metas := map[string]string{}
	if m, ok := content["metas"].(map[string]any); ok {
		for k, v := range m {
			if s, ok := v.(string); ok {
				metas[k] = s
			}
		}
	}
	token := metas[metaToken]
	if token == "" {
		return reject("no token presented - run: ktunnel login <token>")
	}

	tok, user, err := h.Store.Authenticate(token)
	if err != nil {
		h.logf("login rejected from %v: %v", content["client_address"], err)
		if err == store.ErrNotFound {
			return reject("invalid token")
		}
		return reject(err.Error())
	}

	sess, err := h.Store.CreateSession(user.ID, tok.ID,
		str(content["hostname"]), str(content["os"]), str(content["arch"]), str(content["client_address"]))
	if err != nil {
		h.logf("create session: %v", err)
		return reject("server error")
	}

	// Never let the client pick its own frps user name: it prefixes every
	// proxy name and is what NewProxy/Ping report back to us.
	content["user"] = user.Name
	metas[metaSession] = strconv.FormatInt(sess.ID, 10)
	metas[metaUser] = user.Name
	delete(metas, metaToken) // no need to keep the secret around in frps memory
	content["metas"] = metas

	h.Store.Audit(user.ID, "login", fmt.Sprintf("%s (%s/%s) from %s via token %s",
		str(content["hostname"]), str(content["os"]), str(content["arch"]), str(content["client_address"]), tok.Prefix))
	h.logf("login ok: user=%s session=%d host=%s", user.Name, sess.ID, str(content["hostname"]))
	return response{Unchange: false, Content: content}
}

// session resolves the session we stamped onto the login, rejecting anything
// that has since been killed, revoked or disabled.
func (h *Handler) session(u userInfo) (*store.Session, string) {
	idStr := u.Metas[metaSession]
	if idStr == "" {
		return nil, "session not recognised - reconnect"
	}
	id, _ := strconv.ParseInt(idStr, 10, 64)
	sess, err := h.Store.Session(id)
	if err != nil {
		return nil, "session not recognised - reconnect"
	}
	if sess.Killed || !sess.EndedAt.IsZero() {
		return nil, "session terminated by administrator"
	}
	tok, err := h.Store.Token(sess.TokenID)
	if err != nil || !tok.Active() {
		return nil, "token has been revoked"
	}
	user, err := h.Store.User(sess.UserID)
	if err != nil || user.Disabled {
		return nil, "account is disabled"
	}
	return sess, ""
}

func (h *Handler) newProxy(raw json.RawMessage) response {
	var c newProxyContent
	if err := json.Unmarshal(raw, &c); err != nil {
		return reject("malformed proxy request")
	}
	sess, why := h.session(c.User)
	if sess == nil {
		return reject(why)
	}
	_ = h.Store.TouchSession(sess.ID, c.User.RunID)

	user, err := h.Store.User(sess.UserID)
	if err != nil {
		return reject("server error")
	}
	if n, _ := h.Store.CountActiveProxies(user.ID); n >= user.MaxTunnels {
		return reject(fmt.Sprintf("tunnel limit reached (%d)", user.MaxTunnels))
	}

	switch c.ProxyType {
	case "http":
		if len(c.CustomDomains) > 0 {
			return reject("custom domains are not allowed - use a subdomain")
		}
		sub := strings.ToLower(c.SubDomain)
		if !subdomainRe.MatchString(sub) {
			return reject("invalid subdomain")
		}
		if res, err := h.Store.Reservation(sub); err == nil && res.UserID != user.ID {
			return reject(fmt.Sprintf("subdomain %q belongs to %s", sub, res.UserName))
		}
		if holder, holderSess, held, _ := h.Store.ActiveProxyHolder(sub); held {
			if holder != user.ID {
				return reject(fmt.Sprintf("subdomain %q is already in use", sub))
			}
			// Same user, different session: a reconnect after an ungraceful
			// drop, before frps reported the old proxy closed. Let the new
			// session take over rather than refusing the user their own name.
			if holderSess != sess.ID {
				_ = h.Store.EndProxiesForSubdomain(sub)
				h.logf("proxy takeover: user=%s %s (stale session %d)", user.Name, sub, holderSess)
			}
		}
		c.SubDomain = sub
	case "tcp":
		lo, hi := h.Store.TCPPortRange()
		if c.RemotePort < lo || c.RemotePort > hi {
			return reject(fmt.Sprintf("remote port must be between %d and %d", lo, hi))
		}
	default:
		return reject(fmt.Sprintf("proxy type %q is not allowed", c.ProxyType))
	}

	if err := h.Store.AddProxy(sess.ID, user.ID, c.User.RunID, c.ProxyName, c.ProxyType, c.SubDomain, c.RemotePort); err != nil {
		h.logf("add proxy: %v", err)
		return reject("server error")
	}
	target := c.SubDomain
	if c.ProxyType == "tcp" {
		target = ":" + strconv.Itoa(c.RemotePort)
	}
	h.Store.Audit(user.ID, "tunnel.open", fmt.Sprintf("%s %s", c.ProxyType, target))
	h.logf("proxy ok: user=%s %s %s", user.Name, c.ProxyType, target)
	return response{Unchange: true}
}

func (h *Handler) ping(raw json.RawMessage) response {
	var c userOnlyContent
	if err := json.Unmarshal(raw, &c); err != nil {
		return reject("malformed ping")
	}
	sess, why := h.session(c.User)
	if sess == nil {
		return reject(why)
	}
	_ = h.Store.TouchSession(sess.ID, c.User.RunID)
	return response{Unchange: true}
}

func (h *Handler) closeProxy(raw json.RawMessage) response {
	var c userOnlyContent
	if err := json.Unmarshal(raw, &c); err != nil {
		return response{Unchange: true}
	}
	if idStr := c.User.Metas[metaSession]; idStr != "" {
		id, _ := strconv.ParseInt(idStr, 10, 64)
		_ = h.Store.EndProxy(id, c.ProxyName)
		if sess, err := h.Store.Session(id); err == nil {
			h.Store.Audit(sess.UserID, "tunnel.close", c.ProxyName)
		}
	}
	return response{Unchange: true}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
