// tlsoptions.go - composable TLSOption helpers for ServerConfig/ClientConfig
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
	"errors"
)

// TLSOption mutates a *tls.Config after opinionated defaults have been
// applied. It lets callers layer small, composable overrides onto the
// configs returned by ServerConfig and ClientConfig.
type TLSOption func(*tls.Config)

// WithMinVersion sets cfg.MinVersion to v. No clamping is performed;
// callers are responsible for passing a meaningful value. Common values:
// tls.VersionTLS12, tls.VersionTLS13.
func WithMinVersion(v uint16) TLSOption {
	return func(cfg *tls.Config) {
		cfg.MinVersion = v
	}
}

// WithNextProtos sets cfg.NextProtos for ALPN negotiation. A typical
// use is WithNextProtos("h2", "http/1.1") to advertise HTTP/2 with a
// fallback to HTTP/1.1.
func WithNextProtos(protos ...string) TLSOption {
	return func(cfg *tls.Config) {
		cfg.NextProtos = protos
	}
}

// WithServerName sets cfg.ServerName. This is primarily a client-side
// option used for SNI and certificate verification. On a server config
// it is a no-op for most code paths but remains harmless.
func WithServerName(name string) TLSOption {
	return func(cfg *tls.Config) {
		cfg.ServerName = name
	}
}

// WithSPKIPins installs a cfg.VerifyConnection callback that rejects
// the handshake unless the leaf peer certificate's SubjectPublicKeyInfo
// SHA-256 digest matches one of the provided pins. Pinning is leaf-only:
// intermediates and roots in the chain are not considered, so a
// compromised intermediate cannot bypass the pin by issuing a new leaf.
// Each pin must be a raw 32-byte SHA-256 digest; pins of any other
// length are skipped.
//
// Error behavior:
//   - If all supplied pins are malformed (none is 32 bytes), every
//     handshake is rejected with "cert: no valid SPKI pins configured".
//   - If the handshake presents no peer certificates, it is rejected with
//     "cert: no peer certificates presented".
//   - If the leaf's SPKI hash does not match any configured pin, the
//     handshake is rejected with "cert: no matching SPKI pin".
//
// If cfg.VerifyConnection is already set when this option is applied,
// the existing callback is chained and invoked only on a successful pin
// match; pin rejection short-circuits and the previous callback is not
// called.
func WithSPKIPins(pins ...[]byte) TLSOption {
	return func(cfg *tls.Config) {
		want := make(map[[32]byte]struct{}, len(pins))
		for _, p := range pins {
			if len(p) != 32 {
				continue
			}
			var k [32]byte
			copy(k[:], p)
			want[k] = struct{}{}
		}
		if len(want) == 0 {
			cfg.VerifyConnection = func(cs tls.ConnectionState) error {
				return errors.New("cert: no valid SPKI pins configured")
			}
			return
		}
		prev := cfg.VerifyConnection
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("cert: no peer certificates presented")
			}
			leaf := cs.PeerCertificates[0]
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if _, ok := want[sum]; ok {
				if prev != nil {
					return prev(cs)
				}
				return nil
			}
			return errors.New("cert: no matching SPKI pin")
		}
	}
}

// WithClientAuth sets cfg.ClientAuth. This is a server-side option.
// ServerConfig sets ClientAuth to tls.RequireAndVerifyClientCert when a
// non-nil clientCA is provided; this option lets callers downgrade to
// tls.VerifyClientCertIfGiven, tls.RequestClientCert, or similar.
func WithClientAuth(mode tls.ClientAuthType) TLSOption {
	return func(cfg *tls.Config) {
		cfg.ClientAuth = mode
	}
}

// WithSessionTicketKeys installs the given session ticket keys via
// cfg.SetSessionTicketKeys. This is a server-side option used to rotate
// ticket keys across instances for mTLS fleets. If len(keys) == 0 the
// option is a no-op.
func WithSessionTicketKeys(keys ...[32]byte) TLSOption {
	return func(cfg *tls.Config) {
		if len(keys) == 0 {
			return
		}
		cfg.SetSessionTicketKeys(keys)
	}
}
