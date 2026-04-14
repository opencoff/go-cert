// expiry_test.go - tests for CertExpiry
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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"testing/synctest"
	"time"
)

func TestCertExpiry_ValidLeaf(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
		assert(err == nil, "X509KeyPair: %v", err)

		notAfter, days, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(!notAfter.IsZero(), "notAfter should be non-zero")
		// PKI leaf NotAfter is now+24h. Inside the synctest bubble the
		// synthetic clock makes the remaining duration exact.
		assert(days == 1, "expected daysRemaining == 1, got %d", days)
	})
}

func TestCertExpiry_LeafPopulated(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)

	tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
	assert(err == nil, "X509KeyPair: %v", err)

	// Explicitly populate Leaf; CertExpiry must use it directly without
	// reparsing. We verify by swapping in a sentinel NotAfter that does
	// not match the DER-encoded cert.
	sentinel := time.Date(2099, 6, 15, 0, 0, 0, 0, time.UTC)
	leafCopy := *pki.LeafCert
	leafCopy.NotAfter = sentinel
	tlsCert.Leaf = &leafCopy

	notAfter, days, err := CertExpiry(tlsCert)
	assert(err == nil, "CertExpiry: %v", err)
	assert(notAfter.Equal(sentinel), "expected sentinel NotAfter from cert.Leaf, got %v", notAfter)
	assert(days > 0, "expected positive days, got %d", days)
}

func TestCertExpiry_NoLeaf(t *testing.T) {
	assert := newAsserter(t)

	_, _, err := CertExpiry(tls.Certificate{})
	assert(err != nil, "expected error for empty tls.Certificate")
	assert(err.Error() == "cert: tls certificate has no leaf",
		"unexpected error message: %q", err.Error())
}

func TestCertExpiry_Expired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		// Build an expired leaf cert signed by the PKI intermediate.
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(999),
			Subject:      pkix.Name{CommonName: "expired.example.com"},
			NotBefore:    time.Now().Add(-72 * time.Hour),
			NotAfter:     time.Now().Add(-48 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"expired.example.com"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.IntermCert, &pki.LeafKey.PublicKey, pki.IntermKey)
		assert(err == nil, "CreateCertificate: %v", err)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{der},
		}

		notAfter, days, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(!notAfter.IsZero(), "notAfter should be non-zero")
		assert(days == -2, "expected daysRemaining == -2 for cert expired 48h ago, got %d", days)
	})
}

func TestCertExpiry_ExpiredLessThanOneDay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		// Build a leaf cert that expired 2 hours ago. The pre-fix arithmetic
		// (int(Hours()/24) on a negative float) would truncate toward zero
		// and report 0 days, hiding the expiry from `if days < 7` checks.
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1000),
			Subject:      pkix.Name{CommonName: "expired-recent.example.com"},
			NotBefore:    time.Now().Add(-26 * time.Hour),
			NotAfter:     time.Now().Add(-2 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"expired-recent.example.com"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.IntermCert, &pki.LeafKey.PublicKey, pki.IntermKey)
		assert(err == nil, "CreateCertificate: %v", err)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{der},
		}

		_, days, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(days == -1, "expected daysRemaining == -1 for cert expired 2h ago, got %d", days)
	})
}

func TestCertExpiry_InFutureLessThanOneDay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1001),
			Subject:      pkix.Name{CommonName: "soon.example.com"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(2 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"soon.example.com"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.IntermCert, &pki.LeafKey.PublicKey, pki.IntermKey)
		assert(err == nil, "CreateCertificate: %v", err)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{der},
		}

		_, days, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(days == 0, "expected daysRemaining == 0 for cert expiring in 2h, got %d", days)
	})
}

func TestCertExpiry_ParsesFromCertificate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		tlsCert, err := tls.X509KeyPair(pki.LeafPEM, pki.LeafKeyPEM)
		assert(err == nil, "X509KeyPair: %v", err)

		// Force parse path: Leaf nil, Certificate[0] must be parsed.
		tlsCert.Leaf = nil
		assert(len(tlsCert.Certificate) > 0, "expected Certificate[0] to be populated")

		notAfter, days, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(notAfter.Equal(pki.LeafCert.NotAfter),
			"expected parsed NotAfter %v, got %v", pki.LeafCert.NotAfter, notAfter)
		assert(days == 1, "expected daysRemaining == 1, got %d", days)
	})
}

func TestCertExpiry_ExactlyOneDayRemaining(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1002),
			Subject:      pkix.Name{CommonName: "oneday.example.com"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"oneday.example.com"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.IntermCert, &pki.LeafKey.PublicKey, pki.IntermKey)
		assert(err == nil, "CreateCertificate: %v", err)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{der},
		}

		_, days, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(days == 1, "expected daysRemaining == 1 at exactly 24h, got %d", days)
	})
}

func TestCertExpiry_ExactlyAtExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1003),
			Subject:      pkix.Name{CommonName: "now.example.com"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now(),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"now.example.com"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.IntermCert, &pki.LeafKey.PublicKey, pki.IntermKey)
		assert(err == nil, "CreateCertificate: %v", err)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{der},
		}

		_, days, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(days == 0, "expected daysRemaining == 0 at exact expiry, got %d", days)
	})
}

func TestCertExpiry_JustOverOneDayExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1004),
			Subject:      pkix.Name{CommonName: "justover.example.com"},
			NotBefore:    time.Now().Add(-48 * time.Hour),
			NotAfter:     time.Now().Add(-24*time.Hour - time.Nanosecond),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"justover.example.com"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pki.IntermCert, &pki.LeafKey.PublicKey, pki.IntermKey)
		assert(err == nil, "CreateCertificate: %v", err)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{der},
		}

		_, days, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(days == -2, "expected daysRemaining == -2 for cert expired 24h+1ns ago, got %d", days)
	})
}
