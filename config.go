package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Config is the per-machine connection profile, stored in plain text because
// frp needs the token in the clear anyway. The file is written 0600.
type Config struct {
	ServerAddr string
	ServerPort int
	Domain     string
	Token      string
}

// configDir resolves to ~/.config/ktunnel on Unix (XDG, and what the shell
// version of ktunnel used) and %AppData%\\ktunnel on Windows.
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
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("not configured yet - run: ktunnel init")
		}
		return nil, err
	}
	defer f.Close()

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
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch key {
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
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	var missing []string
	if cfg.ServerAddr == "" {
		missing = append(missing, "SERVER_ADDR")
	}
	if cfg.Domain == "" {
		missing = append(missing, "DOMAIN")
	}
	if cfg.Token == "" {
		missing = append(missing, "TOKEN")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s missing from %s - run: ktunnel init",
			strings.Join(missing, ", "), path)
	}
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
	path := filepath.Join(dir, "config")
	body := fmt.Sprintf(""+
		"# ktunnel configuration\n"+
		"SERVER_ADDR=%q\n"+
		"SERVER_PORT=%q\n"+
		"DOMAIN=%q\n"+
		"TOKEN=%q\n",
		c.ServerAddr, strconv.Itoa(c.ServerPort), c.Domain, c.Token)
	return os.WriteFile(path, []byte(body), 0o600)
}
