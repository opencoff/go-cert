// expiry.go - CertExpiry helper for inspecting leaf certificate expiry
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
	"errors"
	"fmt"
	"time"
)

// CertExpiry scans the leaf and every intermediate in tc.Certificate,
// returning the certificate with the earliest NotAfter along with the
// duration remaining until that cert expires. remaining is negative
// if the returned cert has already expired.
//
// When tc.Leaf is populated, it is used in place of parsing
// tc.Certificate[0] — this saves one parse and avoids re-parsing what
// crypto/tls has already cached.
//
// Root CAs are NOT inspected here — they live in the peer's trust
// store (x509.CertPool), not in tls.Certificate.Certificate. Only the
// leaf plus shipped intermediates are considered.
//
// Returns an error when tc has no leaf at all (both Certificate is
// empty and Leaf is nil) or when any chain entry fails to parse.
//
// Tie-break: when two chain entries share the same NotAfter, the one
// closer to the leaf (lower index in tc.Certificate) is returned.
func CertExpiry(tc tls.Certificate) (cert *x509.Certificate, remaining time.Duration, err error) {
	if len(tc.Certificate) == 0 {
		if tc.Leaf == nil {
			return nil, 0, errors.New("cert: tls certificate has no leaf")
		}
		return tc.Leaf, time.Until(tc.Leaf.NotAfter), nil
	}

	var bottleneck *x509.Certificate
	for i, der := range tc.Certificate {
		var c *x509.Certificate
		if i == 0 && tc.Leaf != nil {
			c = tc.Leaf
		} else {
			parsed, perr := x509.ParseCertificate(der)
			if perr != nil {
				return nil, 0, fmt.Errorf("cert: parse chain[%d]: %w", i, perr)
			}
			c = parsed
		}
		if bottleneck == nil || c.NotAfter.Before(bottleneck.NotAfter) {
			bottleneck = c
		}
	}

	return bottleneck, time.Until(bottleneck.NotAfter), nil
}
