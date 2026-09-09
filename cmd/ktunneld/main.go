// ktunneld is the control plane for a self-hosted tunnel service: it answers
// frps's plugin hooks to authenticate per-user tokens and enforce subdomain
// ownership, and serves the admin dashboard. The same binary doubles as the
// admin CLI against the same SQLite file.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/johyunchol/ktunnel/internal/plugin"
	"github.com/johyunchol/ktunnel/internal/store"
	"github.com/johyunchol/ktunnel/internal/web"
)

var version = "dev"

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 15 * time.Second
	httpWriteTimeout      = 30 * time.Second
	httpIdleTimeout       = 60 * time.Second
	httpMaxHeaderBytes    = 16 << 10
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func dbPath() string {
	if v := os.Getenv("KTUNNELD_DB"); v != "" {
		return v
	}
	return "ktunneld.db"
}

func openStore() (*store.Store, error) {
	return store.Open(dbPath())
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return cmdServe(rest)
	case "admin":
		return cmdAdmin(rest)
	case "user":
		return cmdUser(rest)
	case "token":
		return cmdToken(rest)
	case "reserve":
		return cmdReserve(rest)
	case "release":
		return cmdRelease(rest)
	case "ls":
		return cmdLs()
	case "kill":
		return cmdKill(rest)
	case "version", "-v", "--version":
		fmt.Printf("ktunneld %s\n", version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q - run 'ktunneld help'", cmd)
	}
}

// ---------- serve ----------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	webAddr := fs.String("web", "127.0.0.1:7600", "dashboard listen address")
	webHost := fs.String("web-host", "", "canonical external dashboard hostname (recommended behind a proxy)")
	pluginAddr := fs.String("plugin", "127.0.0.1:7601", "frps plugin listen address (keep on loopback)")
	allowPublicListeners := fs.Bool("allow-public-listeners", false, "allow non-loopback web/plugin listeners (requires external firewalling)")
	server := fs.String("server", "", "public address clients connect to (baked into tokens)")
	port := fs.Int("port", 0, "frps bind port (baked into tokens)")
	domain := fs.String("domain", "", "wildcard domain (baked into tokens)")
	tcpRange := fs.String("tcp-range", "", "allowed remote ports for tcp tunnels, e.g. 20000-29999")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateListenAddress("web", *webAddr, *allowPublicListeners); err != nil {
		return err
	}
	if err := validateListenAddress("plugin", *pluginAddr, *allowPublicListeners); err != nil {
		return err
	}

	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	logger := log.New(os.Stdout, "", log.LstdFlags)
	dash, err := web.NewWithConfig(st, logger, web.Config{
		CanonicalHost:     *webHost,
		TrustedProxyCIDRs: []string{"127.0.0.0/8", "::1/128"},
	})
	if err != nil {
		return err
	}

	if *server != "" || *domain != "" {
		info, _ := st.ServerInfo()
		if *server != "" {
			info.Addr = *server
		}
		if *port != 0 {
			info.Port = *port
		}
		if *domain != "" {
			info.Domain = *domain
		}
		if err := st.SetServerInfo(info); err != nil {
			return err
		}
	}
	if *tcpRange != "" {
		if err := st.SetSetting("tcp_port_range", *tcpRange); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Sessions have no explicit logout in the frp protocol; sweep the ones
	// that stopped heartbeating so the dashboard stays honest.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.ExpireStaleSessions(ctx); err != nil {
					logger.Printf("expire sessions: %v", err)
				}
			}
		}
	}()

	pluginMux := http.NewServeMux()
	pluginMux.Handle("POST /frp", &plugin.Handler{Store: st, Logger: logger})
	pluginMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	servers := []*http.Server{
		newHTTPServer(*pluginAddr, pluginMux),
		newHTTPServer(*webAddr, dash.Handler()),
	}
	errCh := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *http.Server) {
			logger.Printf("listening on %s", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s: %w", s.Addr, err)
			}
		}(s)
	}
	if info, err := st.ServerInfo(); err == nil {
		logger.Printf("issuing tokens for %s:%d (*.%s)", info.Addr, info.Port, info.Domain)
	} else {
		logger.Printf("warning: %v", err)
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdownCtx)
	}
	logger.Printf("stopped")
	return nil
}

func validateListenAddress(name, addr string, allowPublic bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --%s listen address %q: %w", name, addr, err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("invalid --%s listen port %q", name, port)
	}
	ip := net.ParseIP(host)
	if allowPublic {
		return nil
	}
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--%s must use a loopback IP address; pass --allow-public-listeners only when an external firewall prevents public access", name)
	}
	return nil
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}

// ---------- admin ----------

func cmdAdmin(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ktunneld admin set-password | set-server")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "set-password":
		pw, err := readSecret("new dashboard password: ")
		if err != nil {
			return err
		}
		if err := web.SetAdminPassword(st, pw); err != nil {
			return err
		}
		st.Audit(0, "admin.password", "changed via cli")
		fmt.Println("dashboard password updated")
		return nil
	case "set-server":
		fs := flag.NewFlagSet("set-server", flag.ContinueOnError)
		server := fs.String("server", "", "public address clients connect to")
		port := fs.Int("port", 7000, "frps bind port")
		domain := fs.String("domain", "", "wildcard domain")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *server == "" || *domain == "" {
			return errors.New("--server and --domain are required")
		}
		if err := st.SetServerInfo(store.ServerInfo{Addr: *server, Port: *port, Domain: *domain}); err != nil {
			return err
		}
		fmt.Printf("tokens will point at %s:%d (*.%s)\n", *server, *port, *domain)
		return nil
	default:
		return fmt.Errorf("unknown admin command %q", args[0])
	}
}

func readSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(syscall.Stdin)) {
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(b)), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// ---------- user ----------

func cmdUser(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ktunneld user add <name> [--max N] | ls | disable <name> | enable <name>")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("user add", flag.ContinueOnError)
		max := fs.Int("max", 5, "max concurrent tunnels")
		pos, flags := splitArgs(args[1:])
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 1 {
			return errors.New("usage: ktunneld user add <name> [--max N]")
		}
		u, err := st.CreateUser(pos[0], *max)
		if err != nil {
			return err
		}
		st.Audit(u.ID, "user.create", "via cli")
		fmt.Printf("created user %s (id %d, max %d tunnels)\n", u.Name, u.ID, u.MaxTunnels)
		return nil
	case "ls":
		users, err := st.Users()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tLIMIT\tSTATUS\tCREATED")
		for _, u := range users {
			status := "active"
			if u.Disabled {
				status = "disabled"
			}
			fmt.Fprintf(tw, "%d\t%s\t%d\t%s\t%s\n", u.ID, u.Name, u.MaxTunnels, status, u.CreatedAt.Format("2006-01-02"))
		}
		return tw.Flush()
	case "disable", "enable":
		if len(args) != 2 {
			return fmt.Errorf("usage: ktunneld user %s <name>", args[0])
		}
		u, err := st.UserByName(args[1])
		if err != nil {
			return fmt.Errorf("user %q: %w", args[1], err)
		}
		disabled := args[0] == "disable"
		if err := st.SetUserDisabled(u.ID, disabled); err != nil {
			return err
		}
		st.Audit(u.ID, "user."+args[0], "via cli")
		fmt.Printf("%s %s\n", u.Name, args[0]+"d")
		return nil
	default:
		return fmt.Errorf("unknown user command %q", args[0])
	}
}

// ---------- token ----------

func cmdToken(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ktunneld token issue <user> [--label L] | ls [user] | revoke <prefix>")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "issue":
		fs := flag.NewFlagSet("token issue", flag.ContinueOnError)
		label := fs.String("label", "", "what this token is for, e.g. laptop")
		pos, flags := splitArgs(args[1:])
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 1 {
			return errors.New("usage: ktunneld token issue <user> [--label L]")
		}
		u, err := st.UserByName(pos[0])
		if err != nil {
			return fmt.Errorf("user %q: %w", pos[0], err)
		}
		plaintext, tok, err := st.IssueToken(u.ID, *label)
		if err != nil {
			return err
		}
		st.Audit(u.ID, "token.issue", fmt.Sprintf("%s (%s) via cli", tok.Label, tok.Prefix))
		fmt.Printf("\nToken for %s (%s) — shown once, store it now:\n\n  %s\n\nOn their machine:\n\n  ktunnel login %s\n\n", u.Name, tok.Label, plaintext, plaintext)
		return nil
	case "ls":
		var userID int64
		if len(args) > 1 {
			u, err := st.UserByName(args[1])
			if err != nil {
				return fmt.Errorf("user %q: %w", args[1], err)
			}
			userID = u.ID
		}
		toks, err := st.Tokens(userID)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "PREFIX\tUSER\tLABEL\tCREATED\tLAST USED\tSTATUS")
		for _, t := range toks {
			status := "active"
			if !t.Active() {
				status = "revoked " + t.RevokedAt.Format("2006-01-02")
			}
			fmt.Fprintf(tw, "%s…\t%s\t%s\t%s\t%s\t%s\n", t.Prefix, t.UserName, t.Label,
				t.CreatedAt.Format("2006-01-02"), agoOrNever(t.LastUsedAt), status)
		}
		return tw.Flush()
	case "revoke":
		if len(args) != 2 {
			return errors.New("usage: ktunneld token revoke <prefix>")
		}
		tok, err := st.TokenByPrefix(args[1])
		if err != nil {
			return fmt.Errorf("token %q: %w", args[1], err)
		}
		if err := st.RevokeToken(tok.ID); err != nil {
			return err
		}
		st.Audit(tok.UserID, "token.revoke", fmt.Sprintf("%s (%s) via cli", tok.Label, tok.Prefix))
		fmt.Printf("revoked %s's token %q - live sessions drop within 30s\n", tok.UserName, tok.Label)
		return nil
	default:
		return fmt.Errorf("unknown token command %q", args[0])
	}
}

// ---------- reservations ----------

func cmdReserve(args []string) error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()

	if len(args) == 1 && args[0] == "ls" || len(args) == 0 {
		res, err := st.Reservations(0)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "SUBDOMAIN\tUSER\tSINCE")
		for _, r := range res {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Subdomain, r.UserName, r.CreatedAt.Format("2006-01-02"))
		}
		return tw.Flush()
	}
	if len(args) != 2 {
		return errors.New("usage: ktunneld reserve <subdomain> <user>   |   ktunneld reserve ls")
	}
	u, err := st.UserByName(args[1])
	if err != nil {
		return fmt.Errorf("user %q: %w", args[1], err)
	}
	if err := st.Reserve(args[0], u.ID); err != nil {
		return err
	}
	st.Audit(u.ID, "reserve", args[0])
	fmt.Printf("%s is now reserved for %s\n", args[0], u.Name)
	return nil
}

func cmdRelease(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ktunneld release <subdomain>")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	res, err := st.Reservation(args[0])
	if err != nil {
		return fmt.Errorf("reservation %q: %w", args[0], err)
	}
	if err := st.Release(args[0]); err != nil {
		return err
	}
	st.Audit(res.UserID, "release", args[0])
	fmt.Printf("released %s\n", args[0])
	return nil
}

// ---------- ls / kill ----------

func cmdLs() error {
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	info, _ := st.ServerInfo()

	proxies, err := st.ActiveProxies()
	if err != nil {
		return err
	}
	sessions, err := st.ActiveSessions()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION\tUSER\tHOST\tFROM\tTOKEN\tUP\tSEEN")
	for _, s := range sessions {
		fmt.Fprintf(tw, "%d\t%s\t%s (%s/%s)\t%s\t%s\t%s\t%s\n", s.ID, s.UserName, s.Hostname, s.OS, s.Arch,
			s.ClientAddr, s.TokenLabel, agoOrNever(s.StartedAt), agoOrNever(s.LastSeenAt))
	}
	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "TUNNEL\tUSER\tSESSION\tUP")
	for _, p := range proxies {
		addr := fmt.Sprintf("https://%s.%s", p.Subdomain, info.Domain)
		if p.Type == "tcp" {
			addr = fmt.Sprintf("%s:%d", info.Addr, p.RemotePort)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", addr, p.UserName, p.SessionID, agoOrNever(p.StartedAt))
	}
	if len(sessions) == 0 && len(proxies) == 0 {
		fmt.Fprintln(tw, "(nothing connected)")
	}
	return tw.Flush()
}

func cmdKill(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ktunneld kill <session-id | subdomain>")
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()

	var sess *store.Session
	if id, err := strconv.ParseInt(args[0], 10, 64); err == nil {
		sess, err = st.Session(id)
		if err != nil {
			return fmt.Errorf("session %d: %w", id, err)
		}
	} else {
		sess, err = st.SessionBySubdomain(args[0])
		if err != nil {
			return fmt.Errorf("no live tunnel at %q", args[0])
		}
	}
	if err := st.KillSession(sess.ID); err != nil {
		return err
	}
	st.Audit(sess.UserID, "session.kill", fmt.Sprintf("%s (%s) via cli", sess.Hostname, sess.ClientAddr))
	fmt.Printf("session %d (%s@%s) will drop at its next heartbeat (≤30s)\n", sess.ID, sess.UserName, sess.Hostname)
	return nil
}

// ---------- helpers ----------

func agoOrNever(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// splitArgs lets flags appear before or after positional arguments.
func splitArgs(args []string) (positional, flags []string) {
	valueFlags := map[string]bool{"-max": true, "--max": true, "-label": true, "--label": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		if !strings.Contains(a, "=") && valueFlags[a] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return positional, flags
}

func usage() {
	fmt.Printf(`ktunneld %s - control plane for a self-hosted tunnel service

USAGE
  ktunneld serve [--web 127.0.0.1:7600] [--web-host portal.example.com]
                 [--plugin 127.0.0.1:7601] [--allow-public-listeners]
                 [--server HOST --port 7000 --domain example.com] [--tcp-range 20000-29999]

  ktunneld admin set-password
  ktunneld admin set-server --server HOST [--port 7000] --domain example.com

  ktunneld user add <name> [--max N]
  ktunneld user ls | disable <name> | enable <name>

  ktunneld token issue <user> [--label L]      prints the token once
  ktunneld token ls [user]
  ktunneld token revoke <prefix>

  ktunneld reserve <subdomain> <user>          only that user may open it
  ktunneld reserve ls
  ktunneld release <subdomain>

  ktunneld ls                                  live sessions and tunnels
  ktunneld kill <session-id | subdomain>       disconnect within 30s

Database: $KTUNNELD_DB (default ./ktunneld.db)
`, version)
}
