// ktunnel exposes a local port at https://<name>.<domain> through a self-hosted
// frp relay: your hardware, your domain, no session limits.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"
)

var version = "dev" // overridden at build time via -ldflags

var subdomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit()
	case "http":
		return cmdTunnel("http", rest)
	case "tcp":
		return cmdTunnel("tcp", rest)
	case "version", "-v", "--version":
		fmt.Printf("ktunnel %s\n", version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q - run 'ktunnel help'", cmd)
	}
}

func cmdInit() error {
	in := bufio.NewReader(os.Stdin)
	fmt.Println("ktunnel setup")

	addr := prompt(in, "frps server address (e.g. nas.example.com): ")
	if addr == "" {
		return errors.New("server address is required")
	}
	portStr := prompt(in, "frps server port [7000]: ")
	port := 7000
	if portStr != "" {
		n, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port %q", portStr)
		}
		port = n
	}
	domain := prompt(in, "wildcard domain (e.g. example.com): ")
	if domain == "" {
		return errors.New("domain is required")
	}

	fmt.Print("auth token (hidden): ")
	tokenBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return errors.New("token is required")
	}

	cfg := &Config{ServerAddr: addr, ServerPort: port, Domain: domain, Token: token}
	if err := cfg.Save(); err != nil {
		return err
	}
	path, _ := configPath()
	fmt.Printf("saved -> %s\n\nTry it:  ktunnel http 3000\n", path)
	return nil
}

func cmdTunnel(kind string, args []string) error {
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "", "fixed subdomain (default: random)")
	host := fs.String("host", "127.0.0.1", "forward to another host instead of localhost")
	remote := fs.Int("remote", 0, "remote port (tcp only)")
	verbose := fs.Bool("verbose", false, "show frp client logs")
	fs.StringVar(name, "n", "", "shorthand for --name")
	fs.BoolVar(verbose, "V", false, "shorthand for --verbose")
	// Go's flag package stops at the first positional argument, which would
	// silently ignore "ktunnel http 3000 --name myapp" - the order everyone
	// actually types. Split the two apart before parsing.
	positional, flags := splitArgs(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(positional) < 1 {
		return fmt.Errorf("usage: ktunnel %s <port> [options]", kind)
	}
	port, err := strconv.Atoi(positional[0])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be a number between 1 and 65535, got %q", positional[0])
	}

	cfg, err := LoadConfig()
	if err != nil {
		return err
	}

	t := Tunnel{Type: kind, LocalIP: *host, LocalPort: port, Name: *name}
	switch kind {
	case "http":
		if t.Name == "" {
			if t.Name, err = randomName(); err != nil {
				return err
			}
		} else if !subdomainRe.MatchString(t.Name) {
			return fmt.Errorf("invalid subdomain %q (lowercase letters, digits and hyphens)", t.Name)
		}
	case "tcp":
		if *remote == 0 {
			return errors.New("tcp tunnels need --remote <port>: without HTTP's Host header there is nothing to route on")
		}
		t.RemotePort = *remote
		if t.Name == "" {
			t.Name = fmt.Sprintf("tcp-%d", *remote)
		}
	}

	fmt.Printf("\n  %s\n", t.PublicURL(cfg))
	fmt.Printf("  -> %s:%d   (%s)\n\n", t.LocalIP, t.LocalPort, t.Type)
	fmt.Println("Ctrl-C to stop.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = t.Run(ctx, cfg, *verbose)
	if ctx.Err() != nil { // cancelled by the user, not a failure
		fmt.Println("\ntunnel closed")
		return nil
	}
	return err
}

// valueFlags are the options that consume the following argument.
var valueFlags = map[string]bool{
	"-name": true, "--name": true, "-n": true,
	"-host": true, "--host": true,
	"-remote": true, "--remote": true,
}

// splitArgs separates positional arguments from flags so that they may be
// given in any order.
func splitArgs(args []string) (positional, flags []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
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

func prompt(in *bufio.Reader, label string) string {
	fmt.Print(label)
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}

func usage() {
	fmt.Print(`ktunnel - expose a local port at https://<name>.<domain>

USAGE
  ktunnel init                        configure server address, token, domain
  ktunnel http <port> [options]       expose an HTTP service
  ktunnel tcp  <port> --remote <n>    expose a raw TCP service
  ktunnel version

OPTIONS
  -n, --name <name>   fixed subdomain (default: random, e.g. brave-otter-7f3a)
      --host <addr>   forward to another host instead of 127.0.0.1
      --remote <n>    remote port, required for tcp tunnels
  -V, --verbose       show frp client logs

EXAMPLES
  ktunnel http 3000
  ktunnel http 3000 --name myapp
  ktunnel http 8080 --host 192.168.10.50
  ktunnel tcp 22 --remote 16022
`)
}
