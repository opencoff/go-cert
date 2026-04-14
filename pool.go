// pool.go - Pool type: immutable result of Store.Finalize
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
	"crypto/x509"
)

// Pool is the immutable result of a finalized Store. It holds the
// assembled *x509.CertPool plus metadata for provenance lookups.
//
// A Pool is produced by Store.Finalize and remains valid after the
// originating Store is closed. Pool holds no file descriptors.
//
// A Pool is safe for concurrent readers. Pool retains its reference
// to the *x509.CertPool; concurrent readers may call Pool() multiple
// times.
type Pool struct {
	pool    *x509.CertPool
	sources []string
	// origin maps sha256(cert.Raw) to the source path (or bundle
	// name) that the cert was loaded from. Keying by the raw SHA
	// lets callers pass any *x509.Certificate equivalent to a
	// loaded one — the certificate bytes are compared, not pointer
	// identity.
	origin map[[32]byte]string
	count  int
}

// Pool returns the assembled *x509.CertPool for use with tls.Config.
// The returned value is the same *x509.CertPool instance this Pool
// holds; the caller takes shared read-only ownership. Mutating it
// affects any future Source lookups on this Pool and any other reader
// of the same Pool. Do not call AddCert on the returned pool.
func (p *Pool) Pool() *x509.CertPool {
	return p.pool
}

// Source returns the source description for cert — typically the file
// path or bundle it was loaded from. Returns "" if cert is nil, if
// cert is not in this Pool, or if cert came from the system trust
// store (seeded by NewSystemStore and therefore not tracked for
// provenance).
func (p *Pool) Source(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return p.origin[sum]
}

// Sources returns the human-readable summary strings accumulated
// during Store loading. Order matches the order of successful Load
// calls on the originating Store. The returned slice is a copy;
// mutating it does not affect the Pool.
func (p *Pool) Sources() []string {
	out := make([]string, len(p.sources))
	copy(out, p.sources)
	return out
}

// Count returns the number of CA certificates loaded by the Store
// that produced this Pool. System trust-store certs (if any) are
// NOT counted — use Pool() and walk its contents for that.
func (p *Pool) Count() int {
	return p.count
}
