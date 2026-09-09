package store

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewTokenEmitsKt2WithTLSIdentity(t *testing.T) {
	token, hash, prefix, err := NewToken(ServerInfo{Addr: "relay.example.com", Port: 7000, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "kt2.") || len(hash) != 64 || len(prefix) != 8 {
		t.Fatalf("token=%q hash=%q prefix=%q", token, hash, prefix)
	}
	info, err := ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if info.Addr != "relay.example.com" || info.Port != 7000 || info.Domain != "example.com" || info.TLSServerName != "relay.example.com" || info.TokenVersion != TokenVersionCurrent {
		t.Fatalf("parsed info = %#v", info)
	}
}

func TestKt2ExplicitTLSServerNameRoundTrip(t *testing.T) {
	token, _, _, err := NewToken(ServerInfo{Addr: "203.0.113.10", Port: 7000, Domain: "example.com", TLSServerName: "relay.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseToken(token)
	if err != nil || info.TLSServerName != "relay.example.com" || info.Addr != "203.0.113.10" {
		t.Fatalf("parsed info=%#v err=%v", info, err)
	}
}

func TestParseLegacyKt1Token(t *testing.T) {
	server := base64.RawURLEncoding.EncodeToString([]byte("relay.example.com:7000|example.com"))
	secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	info, err := ParseToken("kt1." + server + "." + secret)
	if err != nil {
		t.Fatal(err)
	}
	if info.Addr != "relay.example.com" || info.Port != 7000 || info.Domain != "example.com" || info.TLSServerName != "" || info.TokenVersion != TokenVersionLegacy {
		t.Fatalf("parsed info = %#v", info)
	}
}

func TestParseTokenRejectsMalformedSecurityFields(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tests := []string{
		"kt2." + base64.RawURLEncoding.EncodeToString([]byte(`{"a":"relay.example.com","p":7000,"d":"example.com","s":""}`)) + "." + secret,
		"kt2." + base64.RawURLEncoding.EncodeToString([]byte(`{"a":"relay.example.com","p":0,"d":"example.com","s":"relay.example.com"}`)) + "." + secret,
		"kt2." + base64.RawURLEncoding.EncodeToString([]byte(`{"a":"relay.example.com","p":7000,"d":"example.com","s":"wrong host"}`)) + "." + secret,
		"kt3.abc." + secret,
		"kt2.abc.short",
	}
	for _, token := range tests {
		if _, err := ParseToken(token); err == nil {
			t.Fatalf("accepted malformed token %q", token)
		}
	}
}
