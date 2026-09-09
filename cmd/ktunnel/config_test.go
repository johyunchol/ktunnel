package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/johyunchol/ktunnel/internal/store"
)

func testConfig(t *testing.T) *Config {
	t.Helper()
	token, _, _, err := store.NewToken(store.ServerInfo{
		Addr: "relay.example.com", Port: 7000, Domain: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Config{
		ServerAddr: "relay.example.com", ServerPort: 7000, Domain: "example.com", Token: token,
		TokenVersion: store.TokenVersionCurrent, TLSServerName: "relay.example.com",
	}
}

func TestConfigRoundTripDerivesKt2TLSIdentityFromToken(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KTUNNEL_CONFIG_DIR", dir)
	token, _, _, err := store.NewToken(store.ServerInfo{
		Addr: "203.0.113.10", Port: 7000, Domain: "example.com", TLSServerName: "relay.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		ServerAddr: "203.0.113.10", ServerPort: 7000, Domain: "example.com", Token: token,
		TokenVersion: store.TokenVersionCurrent, TLSServerName: "relay.example.com",
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	// These duplicated values are informational only. The token must remain the
	// source of truth if the file is edited.
	path := filepath.Join(dir, "config")
	b, _ := os.ReadFile(path)
	tampered := strings.ReplaceAll(string(b), "SERVER_ADDR=\"203.0.113.10\"", "SERVER_ADDR=\"attacker.example\"")
	tampered = strings.ReplaceAll(tampered, "TLS_SERVER_NAME=\"relay.example.com\"", "TLS_SERVER_NAME=\"attacker.example\"")
	if err := os.WriteFile(path, []byte(tampered), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ServerAddr != "203.0.113.10" || loaded.TLSServerName != "relay.example.com" || loaded.TokenVersion != store.TokenVersionCurrent {
		t.Fatalf("loaded config = %#v", loaded)
	}
}

func TestLegacyTokenCannotStartTunnel(t *testing.T) {
	server := "cmVsYXkuZXhhbXBsZS5jb206NzAwMHxleGFtcGxlLmNvbQ"
	secret := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	dir := t.TempDir()
	t.Setenv("KTUNNEL_CONFIG_DIR", dir)
	if err := (&Config{ServerAddr: "relay.example.com", ServerPort: 7000, Domain: "example.com", Token: "kt1." + server + "." + secret}).Save(); err != nil {
		t.Fatal(err)
	}
	err := cmdTunnel("http", []string{"3000"})
	if err == nil || !strings.Contains(err.Error(), "legacy kt1") || !strings.Contains(err.Error(), "kt2") {
		t.Fatalf("legacy tunnel error = %v", err)
	}
}

func TestConfigSaveSecuresDirectoryAndAtomicallyReplacesPermissiveFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses account ACLs rather than Unix permission bits")
	}
	dir := t.TempDir()
	t.Setenv("KTUNNEL_CONFIG_DIR", dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("old secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := testConfig(t).Save(); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("config directory mode = %04o, want 0700", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", got)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".config-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files left behind: %v", matches)
	}
}

func TestConfigLoadRejectsPermissiveFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses account ACLs rather than Unix permission bits")
	}
	dir := t.TempDir()
	t.Setenv("KTUNNEL_CONFIG_DIR", dir)
	if err := testConfig(t).Save(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig()
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("LoadConfig error = %v, want chmod guidance", err)
	}
}

func TestConfigLoadRejectsPermissiveDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses account ACLs rather than Unix permission bits")
	}
	dir := t.TempDir()
	t.Setenv("KTUNNEL_CONFIG_DIR", dir)
	if err := testConfig(t).Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig()
	if err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("LoadConfig error = %v, want chmod guidance", err)
	}
}

func TestConfigRejectsSymlinkWithoutChangingTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	dir := t.TempDir()
	t.Setenv("KTUNNEL_CONFIG_DIR", dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "config")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "unsafe config") {
		t.Fatalf("LoadConfig error = %v", err)
	}
	if err := testConfig(t).Save(); err == nil || !strings.Contains(err.Error(), "unsafe config") {
		t.Fatalf("Save error = %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "do not replace" {
		t.Fatalf("symlink target changed: %q", got)
	}
}

func TestConfigRejectsNonRegularPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KTUNNEL_CONFIG_DIR", dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "unsafe config") {
		t.Fatalf("LoadConfig error = %v", err)
	}
	if err := testConfig(t).Save(); err == nil || !strings.Contains(err.Error(), "unsafe config") {
		t.Fatalf("Save error = %v", err)
	}
}

func TestReadLoginTokenUsesHiddenTerminalReader(t *testing.T) {
	oldIsTerminal, oldReadPassword := loginIsTerminal, loginReadPassword
	loginIsTerminal = func(int) bool { return true }
	loginReadPassword = func(int) ([]byte, error) { return []byte("  kt2.secret  "), nil }
	t.Cleanup(func() {
		loginIsTerminal, loginReadPassword = oldIsTerminal, oldReadPassword
	})
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var prompt bytes.Buffer
	got, err := readLoginToken(nil, f, &prompt)
	if err != nil {
		t.Fatal(err)
	}
	if got != "kt2.secret" {
		t.Fatalf("token = %q", got)
	}
	if prompt.String() != "Token: \n" {
		t.Fatalf("prompt = %q", prompt.String())
	}
}

func TestReadLoginTokenFromStdin(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("kt2.from-stdin\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := readLoginToken(nil, f, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "kt2.from-stdin" {
		t.Fatalf("token = %q", got)
	}
}

func TestReadLoginTokenExplicitArgumentForCompatibility(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := readLoginToken([]string{" kt2.explicit "}, f, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "kt2.explicit" {
		t.Fatalf("token = %q", got)
	}
	if _, err := readLoginToken([]string{"one", "two"}, f, &bytes.Buffer{}); err == nil {
		t.Fatal("expected usage error for multiple arguments")
	}
}
