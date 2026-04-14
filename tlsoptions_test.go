// tlsoptions_test.go - tests for the TLSOption builders
//
// (c) 2024- Sudhi Herle <sw-at-herle.net>
//
// Licensing Terms: Apache 2.0
// SPDX-License-Identifier: Apache-2.0
//
// If you need a commercial license for this work, please contact
// the author.
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package cert

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

func TestWithMinVersion_OverridesDefault(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)
	tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
	assert(err == nil, "X509KeyPair: %v", err)

	cfg := ServerConfig(tlsCert, nil, WithMinVersion(tls.VersionTLS13))
	assert(cfg.MinVersion == tls.VersionTLS13,
		"MinVersion = %d, want TLS 1.3 (%d)", cfg.MinVersion, tls.VersionTLS13)

	ccfg := ClientConfig(nil, nil, WithMinVersion(tls.VersionTLS13))
	assert(ccfg.MinVersion == tls.VersionTLS13,
		"client MinVersion = %d, want TLS 1.3 (%d)", ccfg.MinVersion, tls.VersionTLS13)
}

func TestWithNextProtos(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)
	tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
	assert(err == nil, "X509KeyPair: %v", err)

	cfg := ServerConfig(tlsCert, nil, WithNextProtos("h2", "http/1.1"))
	assert(len(cfg.NextProtos) == 2, "NextProtos len = %d, want 2", len(cfg.NextProtos))
	assert(cfg.NextProtos[0] == "h2", "NextProtos[0] = %q, want h2", cfg.NextProtos[0])
	assert(cfg.NextProtos[1] == "http/1.1", "NextProtos[1] = %q, want http/1.1", cfg.NextProtos[1])
}

func TestWithServerName(t *testing.T) {
	assert := newAsserter(t)
	cfg := ClientConfig(nil, nil, WithServerName("example.com"))
	assert(cfg.ServerName == "example.com",
		"ServerName = %q, want example.com", cfg.ServerName)
}

func TestWithSPKIPins_MatchesAndRejects(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)

	goodPin := sha256.Sum256(pki.LeafCert.RawSubjectPublicKeyInfo)

	// matching pin accepts when the leaf SPKI matches
	cfg := &tls.Config{}
	WithSPKIPins(goodPin[:])(cfg)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.LeafCert},
	}
	err := cfg.VerifyConnection(cs)
	assert(err == nil, "matching pin should accept: %v", err)

	// leaf mismatch rejects even when the chain is otherwise valid:
	// pin is for leaf-A (pki.LeafCert), but the presented chain has
	// leaf-B (pki.ECLeafCert) at position [0].
	csB := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			pki.ECLeafCert, pki.IntermCert, pki.RootCert,
		},
	}
	err = cfg.VerifyConnection(csB)
	assert(err != nil, "leaf-B presented while pinning leaf-A should reject")
	assert(strings.Contains(err.Error(), "no matching SPKI pin"),
		"want 'no matching SPKI pin', got %v", err)

	// mismatching pin rejects
	var badPin [32]byte
	for i := range badPin {
		badPin[i] = 0xff
	}
	cfg2 := &tls.Config{}
	WithSPKIPins(badPin[:])(cfg2)
	err = cfg2.VerifyConnection(cs)
	assert(err != nil, "mismatching pin should reject")

	// zero valid pins => fail-closed with the dedicated error
	cfg3 := &tls.Config{}
	WithSPKIPins()(cfg3)
	err = cfg3.VerifyConnection(cs)
	assert(err != nil, "zero pins should reject every handshake (fail-closed)")
	assert(strings.Contains(err.Error(), "no valid SPKI pins configured"),
		"want 'no valid SPKI pins configured', got %v", err)

	// malformed pins are skipped; matching pin still works alongside
	cfg4 := &tls.Config{}
	WithSPKIPins([]byte{0x01, 0x02}, goodPin[:])(cfg4)
	err = cfg4.VerifyConnection(cs)
	assert(err == nil, "matching pin with malformed sibling should accept: %v", err)
}

func TestWithSPKIPins_AllMalformed_Fails(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)

	cfg := &tls.Config{}
	WithSPKIPins([]byte("short"), []byte("too-short-too"))(cfg)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.LeafCert},
	}
	err := cfg.VerifyConnection(cs)
	assert(err != nil, "all-malformed pins should reject every handshake")
	assert(strings.Contains(err.Error(), "no valid SPKI pins configured"),
		"want 'no valid SPKI pins configured', got %v", err)
}

func TestWithSPKIPins_LeafOnly_NotIntermediate(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)

	// Pin the INTERMEDIATE's SPKI, not the leaf's.
	intermPin := sha256.Sum256(pki.IntermCert.RawSubjectPublicKeyInfo)

	cfg := &tls.Config{}
	WithSPKIPins(intermPin[:])(cfg)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.LeafCert, pki.IntermCert},
	}
	err := cfg.VerifyConnection(cs)
	assert(err != nil, "intermediate-only pin must reject leaf-only pinning")
	assert(strings.Contains(err.Error(), "no matching SPKI pin"),
		"want 'no matching SPKI pin', got %v", err)
}

func TestWithSPKIPins_NoPeerCerts(t *testing.T) {
	assert := newAsserter(t)

	var pin [32]byte
	for i := range pin {
		pin[i] = 0xab
	}
	cfg := &tls.Config{}
	WithSPKIPins(pin[:])(cfg)

	err := cfg.VerifyConnection(tls.ConnectionState{})
	assert(err != nil, "empty PeerCertificates should reject")
	assert(strings.Contains(err.Error(), "no peer certificates presented"),
		"want 'no peer certificates presented', got %v", err)
}

func TestWithSPKIPins_ChainsPreviousVerifyConnection(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)

	goodPin := sha256.Sum256(pki.LeafCert.RawSubjectPublicKeyInfo)

	called := false
	cfg := &tls.Config{
		VerifyConnection: func(cs tls.ConnectionState) error {
			called = true
			return nil
		},
	}
	WithSPKIPins(goodPin[:])(cfg)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{pki.LeafCert},
	}
	err := cfg.VerifyConnection(cs)
	assert(err == nil, "chained verify should succeed: %v", err)
	assert(called, "previous VerifyConnection should be called on pin match")

	// previous returns error -> propagated
	sentinel := errors.New("prev said no")
	cfg2 := &tls.Config{
		VerifyConnection: func(cs tls.ConnectionState) error {
			return sentinel
		},
	}
	WithSPKIPins(goodPin[:])(cfg2)
	err = cfg2.VerifyConnection(cs)
	assert(errors.Is(err, sentinel), "chained verify error should propagate, got %v", err)

	// previous NOT called on pin mismatch
	called2 := false
	cfg3 := &tls.Config{
		VerifyConnection: func(cs tls.ConnectionState) error {
			called2 = true
			return nil
		},
	}
	var badPin [32]byte
	WithSPKIPins(badPin[:])(cfg3)
	err = cfg3.VerifyConnection(cs)
	assert(err != nil, "pin mismatch should reject")
	assert(!called2, "previous VerifyConnection should NOT be called on pin mismatch")
}

func TestWithClientAuth(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)
	tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
	assert(err == nil, "X509KeyPair: %v", err)

	clientCA := x509.NewCertPool()
	clientCA.AddCert(pki.RootCert)

	cfg := ServerConfig(tlsCert, clientCA, WithClientAuth(tls.VerifyClientCertIfGiven))
	assert(cfg.ClientAuth == tls.VerifyClientCertIfGiven,
		"ClientAuth = %d, want VerifyClientCertIfGiven (%d)",
		cfg.ClientAuth, tls.VerifyClientCertIfGiven)
	assert(cfg.ClientCAs != nil, "ClientCAs should still be set")
}

func TestWithSessionTicketKeys(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)
	tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
	assert(err == nil, "X509KeyPair: %v", err)

	var k1, k2 [32]byte
	for i := range k1 {
		k1[i] = byte(i)
		k2[i] = byte(i + 1)
	}
	cfg := ServerConfig(tlsCert, nil, WithSessionTicketKeys(k1, k2))
	assert(len(cfg.Certificates) == 1, "Certificates should still be set")
	// SetSessionTicketKeys stores keys in an unexported field; we can't
	// introspect directly, but the call should not panic with valid keys.

	// Zero-length key set is a no-op and should not panic.
	cfg2 := ServerConfig(tlsCert, nil, WithSessionTicketKeys())
	assert(cfg2 != nil, "zero-key call should still return a config")
}
