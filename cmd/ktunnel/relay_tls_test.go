package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	frptransport "github.com/fatedier/frp/pkg/transport"
)

func TestMaterializedRelayTrustAnchor(t *testing.T) {
	path, cleanup, err := materializeRelayCA()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("CA mode = %o", info.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	var names []string
	for rest := b; len(rest) > 0; {
		block, next := pem.Decode(rest)
		if block == nil {
			t.Fatal("invalid trailing data in embedded CA bundle")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			t.Fatalf("embedded CA = %#v, %v", cert, err)
		}
		names = append(names, cert.Subject.CommonName)
		rest = next
	}
	if len(names) != 2 || names[0] != "ISRG Root X1" || names[1] != "ISRG Root X2" {
		t.Fatalf("embedded roots = %v", names)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("CA temp file survived cleanup: %v", err)
	}
}

func TestFRPTLSVerificationSuccessWrongHostAndUntrusted(t *testing.T) {
	ca, caKey := makeTestCertificate(t, nil, nil, "test root", true, nil)
	serverCert, serverKey := makeTestCertificate(t, ca, caKey, "relay.example.test", false, []string{"relay.example.test"})
	caPath := writeCertPEM(t, ca.Raw)
	address, stop := startTLSServer(t, serverCert.Raw, serverKey)
	defer stop()

	if err := dialWithFRPTLS(caPath, "relay.example.test", address); err != nil {
		t.Fatalf("verified TLS failed: %v", err)
	}
	if err := dialWithFRPTLS(caPath, "wrong.example.test", address); err == nil {
		t.Fatal("wrong TLS server name was accepted")
	}

	untrustedServer, untrustedServerKey := makeTestCertificate(t, nil, nil, "relay.example.test", false, []string{"relay.example.test"})
	untrustedAddress, stopUntrusted := startTLSServer(t, untrustedServer.Raw, untrustedServerKey)
	defer stopUntrusted()
	if err := dialWithFRPTLS(caPath, "relay.example.test", untrustedAddress); err == nil {
		t.Fatal("certificate from an untrusted CA was accepted")
	}
}

func makeTestCertificate(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, commonName string, isCA bool, dns []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: dns,
		IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func writeCertPEM(t *testing.T, raw []byte) string {
	t.Helper()
	path := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startTLSServer(t *testing.T, certDER []byte, key *ecdsa.PrivateKey) (string, func()) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).HandshakeContext(ctx)
			}()
		}
	}()
	return ln.Addr().String(), func() { cancel(); _ = ln.Close() }
}

func dialWithFRPTLS(caPath, serverName, address string) error {
	cfg, err := frptransport.NewClientTLSConfig("", "", caPath, serverName)
	if err != nil {
		return err
	}
	cfg.MinVersion = tls.VersionTLS12
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, cfg)
	if err == nil {
		_ = conn.Close()
	}
	return err
}
