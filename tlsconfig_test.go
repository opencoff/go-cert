// tlsconfig_test.go - tests for ServerConfig and ClientConfig
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
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestServerConfig_NoClientCA(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)
	tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
	assert(err == nil, "X509KeyPair: %v", err)

	cfg := ServerConfig(tlsCert, nil)

	assert(cfg.MinVersion == tls.VersionTLS12, "MinVersion = %d, want %d", cfg.MinVersion, tls.VersionTLS12)
	assert(len(cfg.Certificates) == 1, "Certificates length = %d, want 1", len(cfg.Certificates))
	assert(cfg.ClientAuth == tls.NoClientCert, "ClientAuth = %d, want NoClientCert (%d)", cfg.ClientAuth, tls.NoClientCert)
	assert(cfg.ClientCAs == nil, "ClientCAs should be nil when no clientCA provided")
	assert(!cfg.InsecureSkipVerify, "InsecureSkipVerify should be false")
	assert(cfg.CipherSuites == nil, "CipherSuites should be nil (stdlib defaults)")
}

func TestServerConfig_WithClientCA(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)
	tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
	assert(err == nil, "X509KeyPair: %v", err)

	clientCA := x509.NewCertPool()
	clientCA.AddCert(pki.RootCert)

	cfg := ServerConfig(tlsCert, clientCA)

	assert(cfg.ClientAuth == tls.RequireAndVerifyClientCert,
		"ClientAuth = %d, want RequireAndVerifyClientCert (%d)",
		cfg.ClientAuth, tls.RequireAndVerifyClientCert)
	assert(cfg.ClientCAs != nil, "ClientCAs should not be nil when clientCA provided")
}

func TestServerConfig_MinVersion(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)
	tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
	assert(err == nil, "X509KeyPair: %v", err)

	cfg := ServerConfig(tlsCert, nil)
	assert(cfg.MinVersion == tls.VersionTLS12, "MinVersion = %d, want TLS 1.2 (%d)", cfg.MinVersion, tls.VersionTLS12)
}

func TestClientConfig_WithRootCA(t *testing.T) {
	assert := newAsserter(t)
	rootCA := x509.NewCertPool()

	cfg := ClientConfig(rootCA, nil)

	assert(cfg.RootCAs != nil, "RootCAs should not be nil")
	assert(cfg.MinVersion == tls.VersionTLS12, "MinVersion = %d, want %d", cfg.MinVersion, tls.VersionTLS12)
	assert(len(cfg.Certificates) == 0, "Certificates length = %d, want 0", len(cfg.Certificates))
	assert(!cfg.InsecureSkipVerify, "InsecureSkipVerify should be false")
	assert(cfg.CipherSuites == nil, "CipherSuites should be nil (stdlib defaults)")
}

func TestClientConfig_NilRootCA(t *testing.T) {
	assert := newAsserter(t)
	cfg := ClientConfig(nil, nil)

	assert(cfg.RootCAs == nil, "RootCAs should be nil (system default)")
}

func TestClientConfig_WithClientCert(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)
	tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
	assert(err == nil, "X509KeyPair: %v", err)

	rootCA := x509.NewCertPool()
	cfg := ClientConfig(rootCA, &tlsCert)

	assert(len(cfg.Certificates) == 1, "Certificates length = %d, want 1", len(cfg.Certificates))
}

func TestClientConfig_MinVersion(t *testing.T) {
	assert := newAsserter(t)
	cfg := ClientConfig(nil, nil)
	assert(cfg.MinVersion == tls.VersionTLS12, "MinVersion = %d, want TLS 1.2 (%d)", cfg.MinVersion, tls.VersionTLS12)
}
