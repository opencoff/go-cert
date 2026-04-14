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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
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

		c, remaining, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(c != nil, "expected non-nil cert")
		assert(c.Subject.CommonName == "test.example.com",
			"expected CN test.example.com, got %q", c.Subject.CommonName)
		// PKI leaf NotAfter is now+24h. Inside the synctest bubble the
		// synthetic clock makes the remaining duration exact.
		assert(remaining == 24*time.Hour,
			"expected remaining == 24h, got %v", remaining)
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

	c, remaining, err := CertExpiry(tlsCert)
	assert(err == nil, "CertExpiry: %v", err)
	assert(c == &leafCopy, "expected pointer equality to tc.Leaf")
	assert(c.NotAfter.Equal(sentinel),
		"expected sentinel NotAfter from cert.Leaf, got %v", c.NotAfter)
	assert(remaining > 0, "expected positive remaining, got %v", remaining)
}

func TestCertExpiry_NoLeaf(t *testing.T) {
	assert := newAsserter(t)

	c, remaining, err := CertExpiry(tls.Certificate{})
	assert(err != nil, "expected error for empty tls.Certificate")
	assert(strings.Contains(err.Error(), "no leaf"),
		"expected error to contain %q, got %q", "no leaf", err.Error())
	assert(c == nil, "expected nil cert, got %v", c)
	assert(remaining == 0, "expected remaining == 0, got %v", remaining)
}

func TestCertExpiry_Expired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(999),
			Subject:      pkix.Name{CommonName: "expired.example.com"},
			NotBefore:    now.Add(-72 * time.Hour),
			NotAfter:     now.Add(-48 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"expired.example.com"},
		}
		_, der := signCert(t, pki.IntermCert, pki.IntermKey, tmpl, &pki.LeafKey.PublicKey)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{der},
		}

		c, remaining, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(c != nil, "expected non-nil cert")
		assert(remaining == -48*time.Hour,
			"expected remaining == -48h, got %v", remaining)
		assert(c.NotAfter.Equal(now.Add(-48*time.Hour)),
			"expected NotAfter == now-48h, got %v", c.NotAfter)
	})
}

func TestCertExpiry_ExpiredLessThanOneDay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1000),
			Subject:      pkix.Name{CommonName: "expired-recent.example.com"},
			NotBefore:    time.Now().Add(-26 * time.Hour),
			NotAfter:     time.Now().Add(-2 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"expired-recent.example.com"},
		}
		_, der := signCert(t, pki.IntermCert, pki.IntermKey, tmpl, &pki.LeafKey.PublicKey)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{der},
		}

		_, remaining, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(remaining == -2*time.Hour,
			"expected remaining == -2h, got %v", remaining)
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
		_, der := signCert(t, pki.IntermCert, pki.IntermKey, tmpl, &pki.LeafKey.PublicKey)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{der},
		}

		_, remaining, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(remaining == 2*time.Hour,
			"expected remaining == 2h, got %v", remaining)
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

		c, remaining, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(c.NotAfter.Equal(pki.LeafCert.NotAfter),
			"expected parsed NotAfter %v, got %v", pki.LeafCert.NotAfter, c.NotAfter)
		assert(remaining == 24*time.Hour,
			"expected remaining == 24h, got %v", remaining)
	})
}

func TestCertExpiry_IntermediateExpiresFirst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		// Intermediate that expires in 1 day, signed by the root.
		intermTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(2001),
			Subject:               pkix.Name{CommonName: "short-interm.example.com"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            0,
		}
		intermKey := genRSAKey(t)
		intermCert, intermDER := signCert(t, pki.RootCert, pki.RootKey, intermTmpl, &intermKey.PublicKey)

		// Leaf that expires in 365 days, signed by the short intermediate.
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2002),
			Subject:      pkix.Name{CommonName: "longlived.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"longlived.example.com"},
		}
		_, leafDER := signCert(t, intermCert, intermKey, leafTmpl, &pki.LeafKey.PublicKey)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{leafDER, intermDER},
		}

		c, remaining, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(c != nil, "expected non-nil cert")
		assert(c.SerialNumber.Cmp(intermCert.SerialNumber) == 0,
			"expected intermediate serial %v, got %v", intermCert.SerialNumber, c.SerialNumber)
		assert(remaining == 24*time.Hour,
			"expected remaining == 24h (intermediate), got %v", remaining)
	})
}

func TestCertExpiry_TieBreakPrefersEarlierIndex(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assert := newAsserter(t)
		pki := newTestPKI(t)

		sharedNotAfter := time.Now().Add(12 * time.Hour)

		intermTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(3001),
			Subject:               pkix.Name{CommonName: "tie-interm.example.com"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              sharedNotAfter,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            0,
		}
		intermKey := genRSAKey(t)
		intermCert, intermDER := signCert(t, pki.RootCert, pki.RootKey, intermTmpl, &intermKey.PublicKey)

		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3002),
			Subject:      pkix.Name{CommonName: "tie-leaf.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     sharedNotAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"tie-leaf.example.com"},
		}
		leafCert, leafDER := signCert(t, intermCert, intermKey, leafTmpl, &pki.LeafKey.PublicKey)

		tlsCert := tls.Certificate{
			Certificate: [][]byte{leafDER, intermDER},
		}

		c, _, err := CertExpiry(tlsCert)
		assert(err == nil, "CertExpiry: %v", err)
		assert(c.SerialNumber.Cmp(leafCert.SerialNumber) == 0,
			"expected leaf serial %v (index 0 wins on tie), got %v",
			leafCert.SerialNumber, c.SerialNumber)
	})
}

func TestCertExpiry_ChainParseFailure(t *testing.T) {
	assert := newAsserter(t)
	pki := newTestPKI(t)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{pki.LeafCert.Raw, []byte("garbage")},
	}

	_, _, err := CertExpiry(tlsCert)
	assert(err != nil, "expected parse error")
	assert(strings.Contains(err.Error(), "chain[1]"),
		"expected error to contain %q, got %q", "chain[1]", err.Error())
}

// signCert creates an x509 certificate signed by parent/parentKey from
// the provided template and returns the parsed cert plus its DER bytes.
func signCert(t *testing.T, parent *x509.Certificate, parentKey *rsa.PrivateKey, tmpl *x509.Certificate, pub any) (*x509.Certificate, []byte) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return c, der
}
