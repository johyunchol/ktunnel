package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/johyunchol/ktunnel/internal/store"
)

// Config is the per-machine profile. The token must remain recoverable for
// authenticated relay connections, so the containing directory and file are
// restricted to 0700 and 0600 respectively.
type Config struct {
	ServerAddr    string
	ServerPort    int
	Domain        string
	Token         string
	TokenVersion  string
	TLSServerName string
}

// configDir resolves to ~/.config/ktunnel on Unix (XDG, and what the shell
// version of ktunnel used) and %AppData%\ktunnel on Windows.
func configDir() (string, error) {
	if v := os.Getenv("KTUNNEL_CONFIG_DIR"); v != "" {
		return v, nil
	}
	if runtime.GOOS != "windows" {
		if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
			return filepath.Join(v, "ktunnel"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".config", "ktunnel"), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "ktunnel"), nil
}

func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config"), nil
}

func LoadConfig() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("not logged in - run: ktunnel login")
		}
		return nil, err
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return nil, fmt.Errorf("refusing unsafe config directory %s: it must be a directory, not a symlink", dir)
	}
	if runtime.GOOS != "windows" && dirInfo.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("refusing config directory with permissions %04o at %s; run: chmod 700 %q", dirInfo.Mode().Perm(), dir, dir)
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("not logged in - run: ktunnel login")
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing unsafe config at %s: it must be a regular file, not a symlink", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("refusing config with permissions %04o at %s; run: chmod 600 %q", info.Mode().Perm(), path, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("refusing config changed while opening %s", path)
	}

	cfg := &Config{ServerPort: 7000}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.TrimSpace(key) {
		case "SERVER_ADDR":
			cfg.ServerAddr = value
		case "SERVER_PORT":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.ServerPort = n
			}
		case "DOMAIN":
			cfg.Domain = value
		case "TOKEN":
			cfg.Token = value
		case "TOKEN_VERSION":
			cfg.TokenVersion = value
		case "TLS_SERVER_NAME":
			cfg.TLSServerName = value
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cfg.ServerAddr == "" || cfg.Domain == "" || cfg.Token == "" {
		return nil, fmt.Errorf("incomplete config at %s - run: ktunnel login", path)
	}
	// The token is the authenticated source of relay coordinates and TLS
	// identity. Re-derive these values so hand-edited config cannot downgrade
	// certificate verification or redirect a valid token to another host.
	tokenInfo, err := store.ParseToken(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid token in %s - run: ktunnel login", path)
	}
	cfg.ServerAddr = tokenInfo.Addr
	cfg.ServerPort = tokenInfo.Port
	cfg.Domain = tokenInfo.Domain
	cfg.TokenVersion = tokenInfo.TokenVersion
	cfg.TLSServerName = tokenInfo.TLSServerName
	return cfg, nil
}

func (c *Config) Save() error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return fmt.Errorf("refusing unsafe config directory %s: it must be a directory, not a symlink", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure config directory %s: %w", dir, err)
	}

	path := filepath.Join(dir, "config")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing unsafe config at %s: it must be a regular file, not a symlink", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	body := fmt.Sprintf(""+
		"# ktunnel configuration - written by `ktunnel login`\n"+
		"SERVER_ADDR=%q\n"+
		"SERVER_PORT=%q\n"+
		"DOMAIN=%q\n"+
		"TOKEN_VERSION=%q\n"+
		"TLS_SERVER_NAME=%q\n"+
		"TOKEN=%q\n",
		c.ServerAddr, strconv.Itoa(c.ServerPort), c.Domain, c.TokenVersion, c.TLSServerName, c.Token)

	tmp, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.WriteString(body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	keep = true
	return syncConfigDir(dir)
}

func syncConfigDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !errors.Is(err, fs.ErrInvalid) {
		return err
	}
	return nil
}
