// tlsconfig.go - opinionated ServerConfig and ClientConfig builders
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
)

// ServerConfig returns an opinionated *tls.Config for a TLS server.
//   - cert is the server's certificate (from LoadCertKey).
//   - clientCA is the CA pool for verifying client certificates (for mTLS).
//     If nil, client certificate verification is disabled.
//     If non-nil, ClientAuth is set to RequireAndVerifyClientCert; callers
//     may override via WithClientAuth.
//   - opts are zero or more TLSOption values applied after the opinionated
//     defaults, so they can override them (e.g., WithMinVersion(tls.VersionTLS13)
//     replaces the default TLS 1.2 floor).
//
// Opinionated defaults:
//   - MinVersion: tls.VersionTLS12
//   - CipherSuites: not set (Go stdlib defaults are secure and preferred)
//   - InsecureSkipVerify: false (never set)
//
// The caller may further customize the returned config directly or via
// TLSOption helpers such as WithNextProtos, WithClientAuth, WithSPKIPins,
// and WithSessionTicketKeys.
func ServerConfig(cert tls.Certificate, clientCA *x509.CertPool, opts ...TLSOption) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if clientCA != nil {
		cfg.ClientCAs = clientCA
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	for _, o := range opts {
		o(cfg)
	}

	return cfg
}

// ClientConfig returns an opinionated *tls.Config for a TLS client.
//   - rootCA is the CA pool for verifying the server's certificate.
//     If nil, the system trust store is used (Go default behavior).
//   - clientCert is the client's certificate for mTLS. If nil, no
//     client certificate is presented.
//   - opts are zero or more TLSOption values applied after the opinionated
//     defaults, so they can override them (e.g., WithMinVersion(tls.VersionTLS13)
//     replaces the default TLS 1.2 floor).
//
// Opinionated defaults:
//   - MinVersion: tls.VersionTLS12
//   - CipherSuites: not set (Go stdlib defaults are secure and preferred)
//   - InsecureSkipVerify: false (never set)
//
// The caller may further customize the returned config directly or via
// TLSOption helpers such as WithServerName, WithNextProtos, and WithSPKIPins.
func ClientConfig(rootCA *x509.CertPool, clientCert *tls.Certificate, opts ...TLSOption) *tls.Config {
	cfg := &tls.Config{
		RootCAs:    rootCA,
		MinVersion: tls.VersionTLS12,
	}

	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}

	for _, o := range opts {
		o(cfg)
	}

	return cfg
}
