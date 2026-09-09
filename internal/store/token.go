package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Tokens look like kt2.<server blob>.<secret>. The middle part contains the
// relay address, port, public domain, and TLS certificate name so a user needs
// only the token. It is not secret; only the complete token is hashed at rest.
// Legacy kt1 tokens remain parseable by the server during migration.
const (
	TokenVersionCurrent = "kt2"
	TokenVersionLegacy  = "kt1"
)

// ServerInfo is what a client needs to find and authenticate the relay.
type ServerInfo struct {
	Addr          string
	Port          int
	Domain        string
	TLSServerName string
	TokenVersion  string
}

type tokenServerV2 struct {
	Addr          string `json:"a"`
	Port          int    `json:"p"`
	Domain        string `json:"d"`
	TLSServerName string `json:"s"`
}

func (s ServerInfo) encodeV2() (string, error) {
	tlsName := strings.TrimSpace(s.TLSServerName)
	if tlsName == "" {
		tlsName = strings.TrimSpace(s.Addr)
	}
	wire := tokenServerV2{
		Addr:          strings.TrimSpace(s.Addr),
		Port:          s.Port,
		Domain:        strings.TrimSpace(s.Domain),
		TLSServerName: tlsName,
	}
	if err := validateServerInfo(ServerInfo{Addr: wire.Addr, Port: wire.Port, Domain: wire.Domain, TLSServerName: wire.TLSServerName}); err != nil {
		return "", err
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// NewToken mints a current-version token for the given server. It returns the
// token (shown once), its storage hash, and a short display prefix.
func NewToken(info ServerInfo) (token, hash, prefix string, err error) {
	serverBlob, err := info.encodeV2()
	if err != nil {
		return "", "", "", fmt.Errorf("invalid token server info: %w", err)
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return "", "", "", err
	}
	sec := base64.RawURLEncoding.EncodeToString(secret)
	token = strings.Join([]string{TokenVersionCurrent, serverBlob, sec}, ".")
	return token, HashToken(token), sec[:8], nil
}

// HashToken is the storage form of a token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// ParseToken recovers the server info embedded in current and legacy tokens.
func ParseToken(token string) (ServerInfo, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return ServerInfo{}, errors.New("not a ktunnel token")
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != 32 {
		return ServerInfo{}, errors.New("malformed token")
	}
	switch parts[0] {
	case TokenVersionCurrent:
		return parseV2Server(parts[1])
	case TokenVersionLegacy:
		return parseV1Server(parts[1])
	default:
		return ServerInfo{}, errors.New("unsupported ktunnel token version")
	}
}

func parseV2Server(blob string) (ServerInfo, error) {
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		return ServerInfo{}, errors.New("malformed token")
	}
	var wire tokenServerV2
	if err := json.Unmarshal(raw, &wire); err != nil {
		return ServerInfo{}, errors.New("malformed token")
	}
	info := ServerInfo{
		Addr: strings.TrimSpace(wire.Addr), Port: wire.Port,
		Domain: strings.TrimSpace(wire.Domain), TLSServerName: strings.TrimSpace(wire.TLSServerName),
		TokenVersion: TokenVersionCurrent,
	}
	if info.TLSServerName == "" {
		return ServerInfo{}, errors.New("malformed token")
	}
	if err := validateServerInfo(info); err != nil {
		return ServerInfo{}, errors.New("malformed token")
	}
	return info, nil
}

func parseV1Server(blob string) (ServerInfo, error) {
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		return ServerInfo{}, errors.New("malformed token")
	}
	hostport, domain, ok := strings.Cut(string(raw), "|")
	if !ok || domain == "" {
		return ServerInfo{}, errors.New("malformed token")
	}
	i := strings.LastIndex(hostport, ":")
	if i < 1 {
		return ServerInfo{}, errors.New("malformed token")
	}
	port, err := strconv.Atoi(hostport[i+1:])
	if err != nil {
		return ServerInfo{}, errors.New("malformed token")
	}
	info := ServerInfo{Addr: hostport[:i], Port: port, Domain: domain, TokenVersion: TokenVersionLegacy}
	if err := validateServerInfo(info); err != nil {
		return ServerInfo{}, errors.New("malformed token")
	}
	return info, nil
}

func validateServerInfo(info ServerInfo) error {
	if info.Addr == "" || info.Domain == "" || info.Port < 1 || info.Port > 65535 {
		return errors.New("missing or invalid relay address, port, or domain")
	}
	for _, value := range []string{info.Addr, info.Domain, info.TLSServerName} {
		if strings.ContainsAny(value, "\x00\r\n\t /\\") {
			return errors.New("relay names contain invalid characters")
		}
	}
	if info.TLSServerName != "" && !validTLSName(info.TLSServerName) {
		return errors.New("invalid TLS server name")
	}
	return nil
}

func validTLSName(name string) bool {
	if net.ParseIP(name) != nil {
		return true
	}
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
