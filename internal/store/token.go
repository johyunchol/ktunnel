package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Tokens look like:
//
//	kt1.<server blob>.<secret>
//
// The middle part encodes the server address, port and domain so that a user
// only ever needs the token — `ktunnel login <token>` fills in everything else.
// It is not secret and is not hashed; only the whole token is hashed for
// storage. The separator is "." because base64url never produces it.
const tokenVersion = "kt1"

// ServerInfo is what a client needs to find the relay.
type ServerInfo struct {
	Addr   string
	Port   int
	Domain string
}

func (s ServerInfo) encode() string {
	raw := fmt.Sprintf("%s:%d|%s", s.Addr, s.Port, s.Domain)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// NewToken mints a token for the given server. It returns the token (shown to
// the user exactly once), its storage hash, and a short display prefix.
func NewToken(info ServerInfo) (token, hash, prefix string, err error) {
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return "", "", "", err
	}
	sec := base64.RawURLEncoding.EncodeToString(secret)
	token = strings.Join([]string{tokenVersion, info.encode(), sec}, ".")
	return token, HashToken(token), sec[:8], nil
}

// HashToken is the storage form of a token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// ParseToken recovers the server info embedded in a token.
func ParseToken(token string) (ServerInfo, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || parts[0] != tokenVersion {
		return ServerInfo{}, errors.New("not a ktunnel token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
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
	return ServerInfo{Addr: hostport[:i], Port: port, Domain: domain}, nil
}
