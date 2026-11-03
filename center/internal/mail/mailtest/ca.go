// SPDX-License-Identifier: AGPL-3.0-only

// Package mailtest is the test double of the center's two mail providers: an in-process SMTP submission server with a throwaway
// certificate authority (STARTTLS or implicit TLS, AUTH PLAIN over TLS only, a transcript of the clear-text part, the captured
// messages and a set of misbehaviours) and a Postmark API stand-in. Everything listens on 127.0.0.1 with an ephemeral port; nothing
// resolves a name or leaves the machine (MOCKED: no real provider is involved).
//
// The package is for tests only, and three rules keep it that way. Only _test.go files import it (a pin in package mail reads the
// imports of every source file). It imports no package of this repository, so that the tests of package mail can use it without an
// import cycle: addresses, options and certificates cross the boundary as plain values (a *x509.CertPool, a host and a port, a
// URL) and the tests build the adapters' options themselves. And it names no official host or address: the names are
// smtp.example.test and example.test.
package mailtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// CA is a throwaway certificate authority; its certificates live for a day and its key never leaves memory.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

// serial returns a random certificate serial number.
func serial(t testing.TB) *big.Int {
	t.Helper()
	number, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return number
}

// NewCA creates an authority with the common name name.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{cert: cert, key: key, pool: pool}
}

// Pool is the root pool that trusts this authority only.
func (ca *CA) Pool() *x509.CertPool { return ca.pool }

// Leaf issues a server certificate for the DNS names; the first is the common name.
func (ca *CA) Leaf(t testing.TB, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
