// ktunnel exposes a local port at https://<name>.<domain> through a self-hosted
// frp relay: your hardware, your domain, no session limits.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/johyunchol/ktunnel/internal/store"
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
	case "login":
		return runThenCheck(func() error { return cmdLogin(rest) })
	case "logout":
		return runThenCheck(cmdLogout)
	case "status", "whoami":
		return runThenCheck(cmdStatus)
	case "http":
		return cmdTunnel("http", rest)
	case "tcp":
		return cmdTunnel("tcp", rest)
	case "update", "upgrade":
		return cmdUpdate(rest)
	case "version", "-v", "--version":
		return cmdVersion()
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q - run 'ktunnel help'", cmd)
	}
}

func runThenCheck(fn func() error) error {
	if err := fn(); err != nil {
		return err
	}
	passiveUpdateCheck()
	return nil
}

// cmdLogin stores a personal token. The token carries the relay address and
// domain, so it is the only thing a user needs to be handed.
func cmdLogin(args []string) error {
	token, err := readLoginToken(args, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	info, err := store.ParseToken(token)
	if err != nil {
		return fmt.Errorf("%v - ask the administrator for a token", err)
	}
	cfg := &Config{
		ServerAddr: info.Addr, ServerPort: info.Port, Domain: info.Domain, Token: token,
		TokenVersion: info.TokenVersion, TLSServerName: info.TLSServerName,
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	path, _ := configPath()
	fmt.Printf("logged in to %s (*.%s)\nsaved -> %s\n\nTry it:  ktunnel http 3000\n", info.Addr, info.Domain, path)
	if info.TokenVersion == store.TokenVersionLegacy {
		fmt.Fprintln(os.Stderr, "warning: this legacy kt1 token cannot open tunnels in ktunnel v0.6; sign in to the web portal and issue a new kt2 token")
	}
	return nil
}

var (
	loginIsTerminal   = term.IsTerminal
	loginReadPassword = term.ReadPassword
)

func readLoginToken(args []string, stdin *os.File, prompt io.Writer) (string, error) {
	if len(args) > 1 {
		return "", errors.New("usage: ktunnel login [token]")
	}
	if len(args) == 1 {
		token := strings.TrimSpace(args[0])
		if token == "" {
			return "", errors.New("token is empty")
		}
		return token, nil
	}

	fd := int(stdin.Fd())
	if loginIsTerminal(fd) {
		fmt.Fprint(prompt, "Token: ")
		value, err := loginReadPassword(fd)
		fmt.Fprintln(prompt)
		if err != nil {
			return "", fmt.Errorf("read token: %w", err)
		}
		token := strings.TrimSpace(string(value))
		if token == "" {
			return "", errors.New("token is empty")
		}
		return token, nil
	}

	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 1024), 8*1024)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("read token from stdin: %w", err)
		}
		return "", errors.New("no token on stdin")
	}
	token := strings.TrimSpace(scanner.Text())
	if token == "" {
		return "", errors.New("token is empty")
	}
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			return "", errors.New("expected exactly one token on stdin")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read token from stdin: %w", err)
	}
	return token, nil
}

func cmdLogout() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Println("logged out")
	return nil
}

func cmdStatus() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	prefix := cfg.Token
	if i := strings.LastIndex(prefix, "."); i >= 0 && len(prefix)-i > 9 {
		prefix = prefix[i+1 : i+9]
	}
	fmt.Printf("server  %s:%d\ndomain  *.%s\ntoken   %s…\n", cfg.ServerAddr, cfg.ServerPort, cfg.Domain, prefix)
	if cfg.TokenVersion == store.TokenVersionCurrent {
		fmt.Printf("tls     required (%s)\n", cfg.TLSServerName)
	} else {
		fmt.Println("tls     legacy token (request a new kt2 token before opening a tunnel)")
	}
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
	if cfg.TokenVersion != store.TokenVersionCurrent {
		return errors.New("legacy kt1 tokens are no longer accepted by this client - sign in to the web portal and issue a new kt2 token")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = t.Run(ctx, cfg, *verbose, func() {
		fmt.Println("live - Ctrl-C to stop.")
		// Tunnel startup should never wait on GitHub. The check is best-effort
		// and runs only once per day while this long-running command is alive.
		go passiveUpdateCheck()
	})
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

func usage() {
	fmt.Print(`ktunnel - expose a local port at https://<name>.<domain>

USAGE
  ktunnel login                       securely prompt for and store a token
  ktunnel login <token>               explicit argument (automation/backcompat)
  ktunnel http <port> [options]       expose an HTTP service
  ktunnel tcp  <port> --remote <n>    expose a raw TCP service
  ktunnel status                      show where you are logged in
  ktunnel logout
  ktunnel version
  ktunnel update [--check]            install the latest release (alias: upgrade)

OPTIONS
  -n, --name <name>   fixed subdomain (default: random, e.g. brave-otter-7f3a)
      --host <addr>   forward to another host instead of 127.0.0.1
      --remote <n>    remote port, required for tcp tunnels
  -V, --verbose       show frp client logs

EXAMPLES
  ktunnel login
  ktunnel http 3000
  ktunnel http 3000 --name myapp
  ktunnel http 8080 --host 192.168.10.50
  ktunnel tcp 22 --remote 20022
`)
}
