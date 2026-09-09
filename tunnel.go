package main

import (
	"context"
	"fmt"

	"github.com/fatedier/frp/client"
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
func (t Tunnel) Run(ctx context.Context, cfg *Config, verbose bool) error {
	enabled := true

	common := &v1.ClientCommonConfig{
		ServerAddr:    cfg.ServerAddr,
		ServerPort:    cfg.ServerPort,
		LoginFailExit: &enabled,
		Auth: v1.AuthClientConfig{
			Method: "token",
			Token:  cfg.Token,
		},
		Transport: v1.ClientTransportConfig{
			TLS: v1.TLSClientConfig{Enable: &enabled},
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
	return svc.Run(ctx)
}
