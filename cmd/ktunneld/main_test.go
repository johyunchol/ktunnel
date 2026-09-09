package main

import (
	"net/http"
	"testing"
)

func TestValidateListenAddress(t *testing.T) {
	for _, tc := range []struct {
		name        string
		addr        string
		allowPublic bool
		wantErr     bool
	}{
		{"IPv4 loopback", "127.0.0.1:7600", false, false},
		{"IPv6 loopback", "[::1]:7600", false, false},
		{"wildcard", ":7600", false, true},
		{"IPv4 wildcard", "0.0.0.0:7600", false, true},
		{"public IP", "192.0.2.10:7600", false, true},
		{"hostname", "localhost:7600", false, true},
		{"explicit public override", "0.0.0.0:7600", true, false},
		{"bad port", "127.0.0.1:70000", false, true},
		{"missing port", "127.0.0.1", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateListenAddress("web", tc.addr, tc.allowPublic)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateListenAddress() error=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestHTTPServerHasResourceBounds(t *testing.T) {
	s := newHTTPServer("127.0.0.1:7600", http.NotFoundHandler())
	if s.ReadHeaderTimeout != httpReadHeaderTimeout || s.ReadTimeout != httpReadTimeout || s.WriteTimeout != httpWriteTimeout || s.IdleTimeout != httpIdleTimeout {
		t.Fatalf("unexpected timeouts: read-header=%v read=%v write=%v idle=%v", s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout)
	}
	if s.MaxHeaderBytes != httpMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes=%d, want %d", s.MaxHeaderBytes, httpMaxHeaderBytes)
	}
}
