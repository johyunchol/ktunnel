package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fatedier/frp/client"
	cproxy "github.com/fatedier/frp/client/proxy"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/source"
	"github.com/fatedier/frp/pkg/util/log"
)

// Tunnel describes one exposed service.
type Tunnel struct {
	Name       string
	Type       string // "http" or "tcp"
	LocalIP    string
	LocalPort  int
	RemotePort int // tcp only
}

// PublicURL is what the user should open or connect to.
func (t Tunnel) PublicURL(cfg *Config) string {
	if t.Type == "tcp" {
		return fmt.Sprintf("%s:%d", cfg.ServerAddr, t.RemotePort)
	}
	return fmt.Sprintf("https://%s.%s", t.Name, cfg.Domain)
}

// Run connects to frps and serves the tunnel until ctx is cancelled.
//
// frp is used as a library rather than shelled out to, so ktunnel ships as a
// single binary with no frpc or Docker on the target machine.
//
// Authentication is per user: the personal token travels in the login
// metadata and ktunneld (the frps plugin) decides. There is no shared frps
// secret for clients to hold.
func (t Tunnel) Run(ctx context.Context, cfg *Config, verbose bool, onReady func()) error {
	enabled := true

	common := &v1.ClientCommonConfig{
		ServerAddr:    cfg.ServerAddr,
		ServerPort:    cfg.ServerPort,
		LoginFailExit: &enabled,
		Metadatas:     map[string]string{"token": cfg.Token},
		Transport: v1.ClientTransportConfig{
			TLS: v1.TLSClientConfig{Enable: &enabled},
			// frp disables heartbeats when TCP multiplexing is on (the
			// default) and relies on yamux keepalives instead. We need the
			// Ping hook to fire so that revoked tokens are cut off promptly.
			HeartbeatInterval: 30,
			HeartbeatTimeout:  90,
		},
	}
	common.Log.Level = "warn"
	if verbose {
		common.Log.Level = "info"
	}
	if err := common.Complete(); err != nil {
		return fmt.Errorf("invalid client config: %w", err)
	}
	// frp logs at info level by default; without this the connection chatter
	// drowns out the one line the user actually wants (the URL).
	log.InitLogger(common.Log.To, common.Log.Level, int(common.Log.MaxDays), common.Log.DisablePrintColor)

	base := v1.ProxyBaseConfig{
		Name: t.Name,
		Type: t.Type,
		ProxyBackend: v1.ProxyBackend{
			LocalIP:   t.LocalIP,
			LocalPort: t.LocalPort,
		},
	}

	var proxy v1.ProxyConfigurer
	switch t.Type {
	case "http":
		p := &v1.HTTPProxyConfig{ProxyBaseConfig: base}
		p.SubDomain = t.Name
		proxy = p
	case "tcp":
		proxy = &v1.TCPProxyConfig{ProxyBaseConfig: base, RemotePort: t.RemotePort}
	default:
		return fmt.Errorf("unsupported tunnel type %q", t.Type)
	}
	proxy.Complete()

	cs := source.NewConfigSource()
	if err := cs.ReplaceAll([]v1.ProxyConfigurer{proxy}, nil); err != nil {
		return fmt.Errorf("failed to build config source: %w", err)
	}

	svc, err := client.NewService(client.ServiceOptions{
		Common:                 common,
		ConfigSourceAggregator: source.NewAggregator(cs),
	})
	if err != nil {
		return err
	}

	// When frps rejects the proxy (reserved subdomain, limit reached, ...)
	// frpc keeps the control connection open and quietly retries. Watch the
	// proxy status so the user gets the reason and their prompt back.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- svc.Run(runCtx) }()

	// Once live, frpc reconnects on its own after any drop and never gives
	// up - even when the relay is refusing it because the token was revoked
	// or an administrator disconnected the session. A brief outage is
	// tolerated; anything longer than lostAfter means the session is gone.
	const lostAfter = 15 * time.Second

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	announced := false
	var lastRunning time.Time
	for {
		select {
		case err := <-runErr:
			return err
		case <-ticker.C:
			st, ok := svc.StatusExporter().GetProxyStatus(t.Name)
			running := ok && st.Phase == cproxy.ProxyPhaseRunning
			switch {
			case ok && st.Phase == cproxy.ProxyPhaseStartErr:
				cancel()
				<-runErr
				return fmt.Errorf("%s", strings.TrimPrefix(st.Err, "start proxy error: "))
			case running:
				lastRunning = time.Now()
				if !announced && onReady != nil {
					announced = true
					onReady()
				}
			case announced && time.Since(lastRunning) > lostAfter:
				cancel()
				<-runErr
				return fmt.Errorf("connection to the relay was lost - the token may have been revoked, the session disconnected by an administrator, or the relay is down")
			}
		}
	}
}
