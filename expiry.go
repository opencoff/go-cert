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

// CertExpiry returns the NotAfter timestamp and remaining days until
// expiry of the leaf certificate in cert.
//
// daysRemaining is negative if the certificate is already expired.
// If cert.Leaf is populated, it is used; otherwise the first entry in
// cert.Certificate is parsed.
func CertExpiry(cert tls.Certificate) (notAfter time.Time, daysRemaining int, err error) {
	if cert.Leaf != nil {
		notAfter = cert.Leaf.NotAfter
	} else if len(cert.Certificate) > 0 {
		leaf, perr := x509.ParseCertificate(cert.Certificate[0])
		if perr != nil {
			return time.Time{}, 0, fmt.Errorf("cert: %w", perr)
		}
		notAfter = leaf.NotAfter
	} else {
		return time.Time{}, 0, errors.New("cert: tls certificate has no leaf")
	}

	const day = 24 * time.Hour

	remaining := time.Until(notAfter)
	daysRemaining = int(remaining / day)
	if remaining < 0 && remaining%day != 0 {
		daysRemaining--
	}
	return notAfter, daysRemaining, nil
}
