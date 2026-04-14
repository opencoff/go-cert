// testhelper_test.go - shared test utilities and PKI generation
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// newAsserter returns a fatal assertion function bound to t.
func newAsserter(t *testing.T) func(bool, string, ...any) {
	return func(cond bool, format string, args ...any) {
		t.Helper()
		if !cond {
			t.Fatalf(format, args...)
		}
	}
}

// skipIfRoot skips the test when running as root or on Windows,
// since permission checks are bypassed or unavailable.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("permission checks not available on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, permission checks are bypassed")
	}
}

// writeFileChmod creates a file and then sets its mode precisely,
// bypassing the umask that os.WriteFile applies.
func writeFileChmod(t *testing.T, path string, data []byte, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// mkdirChmod creates a directory and then sets its mode precisely.
func mkdirChmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// testPKI holds a complete test PKI hierarchy generated in memory.
type testPKI struct {
	RootCert *x509.Certificate
	RootKey  *rsa.PrivateKey
	RootPEM  []byte

	IntermCert *x509.Certificate
	IntermKey  *rsa.PrivateKey
	IntermPEM  []byte

	LeafCert   *x509.Certificate
	LeafKey    *rsa.PrivateKey
	LeafPEM    []byte
	LeafKeyPEM []byte

	ECLeafCert   *x509.Certificate
	ECLeafKey    *ecdsa.PrivateKey
	ECLeafPEM    []byte
	ECLeafKeyPEM []byte

	// leaf + intermediate chain
	ChainPEM []byte

	// root + intermediate bundle
	CABundlePEM []byte

	// PKCS#8 encoded leaf key
	LeafKeyPKCS8PEM []byte
}

// newTestPKI generates a complete test PKI hierarchy.
func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	pki := &testPKI{}

	// root CA
	pki.RootKey = genRSAKey(t)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &pki.RootKey.PublicKey, pki.RootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	pki.RootCert, _ = x509.ParseCertificate(rootDER)
	pki.RootPEM = pemEncode("CERTIFICATE", rootDER)

	// intermediate CA
	pki.IntermKey = genRSAKey(t)
	intermTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
	}
	intermDER, err := x509.CreateCertificate(rand.Reader, intermTmpl, pki.RootCert, &pki.IntermKey.PublicKey, pki.RootKey)
	if err != nil {
		t.Fatalf("create intermediate cert: %v", err)
	}
	pki.IntermCert, _ = x509.ParseCertificate(intermDER)
	pki.IntermPEM = pemEncode("CERTIFICATE", intermDER)

	// RSA leaf
	pki.LeafKey = genRSAKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com", "localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, pki.IntermCert, &pki.LeafKey.PublicKey, pki.IntermKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	pki.LeafCert, _ = x509.ParseCertificate(leafDER)
	pki.LeafPEM = pemEncode("CERTIFICATE", leafDER)
	pki.LeafKeyPEM = pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(pki.LeafKey))

	// PKCS#8 key
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(pki.LeafKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	pki.LeafKeyPKCS8PEM = pemEncode("PRIVATE KEY", pkcs8DER)

	// EC leaf
	pki.ECLeafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	ecLeafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "ec.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"ec.example.com"},
	}
	ecLeafDER, err := x509.CreateCertificate(rand.Reader, ecLeafTmpl, pki.IntermCert, &pki.ECLeafKey.PublicKey, pki.IntermKey)
	if err != nil {
		t.Fatalf("create EC leaf cert: %v", err)
	}
	pki.ECLeafCert, _ = x509.ParseCertificate(ecLeafDER)
	pki.ECLeafPEM = pemEncode("CERTIFICATE", ecLeafDER)
	ecKeyDER, err := x509.MarshalECPrivateKey(pki.ECLeafKey)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	pki.ECLeafKeyPEM = pemEncode("EC PRIVATE KEY", ecKeyDER)

	// chain: leaf + intermediate
	pki.ChainPEM = append(append([]byte{}, pki.LeafPEM...), pki.IntermPEM...)

	// CA bundle: root + intermediate
	pki.CABundlePEM = append(append([]byte{}, pki.RootPEM...), pki.IntermPEM...)

	return pki
}

func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	// 2048 is the minimum for security; smaller keys are faster
	// but some Go versions reject them.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func pemEncode(blockType string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: data,
	})
}

// safeTempDir returns a t.TempDir() with permissions fixed to 0755.
// On macOS, t.TempDir() creates directories with mode 0775 which
// triggers the group-writable check. This helper also fixes the
// parent test root directory.
func safeTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writePEM writes PEM data to a file with the given permissions.
func writePEM(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	writeFileChmod(t, path, data, mode)
	return path
}
