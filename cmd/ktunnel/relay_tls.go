package main

import (
	"crypto/x509"
	_ "embed"
	"errors"
	"os"
	"path/filepath"
)

// ISRG Root X1 and X2 are Let's Encrypt's public trust anchors, sourced from
// https://letsencrypt.org/certificates/. The production relay certificate must
// chain to one of these deliberately small, embedded roots.
//
//go:embed assets/isrg-root-x1.pem
var isrgRootX1 []byte

//go:embed assets/isrg-root-x2.pem
var isrgRootX2 []byte

var relayTrustAnchors = append(append([]byte{}, isrgRootX1...), isrgRootX2...)

func materializeRelayCA() (path string, cleanup func(), err error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(relayTrustAnchors) {
		return "", nil, errors.New("embedded relay trust anchor is invalid")
	}
	dir, err := os.MkdirTemp("", "ktunnel-relay-ca-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	path = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, relayTrustAnchors, 0600); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}
