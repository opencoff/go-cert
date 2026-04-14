// loadcert_test.go - tests for standalone LoadCertKey function
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
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCertKey_RSA_PKCS1(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)
	keyPath := writePEM(t, dir, "leaf.key", pki.LeafKeyPEM, 0o600)

	tlsCert, err := LoadCertKey(certPath, keyPath, nil)
	assert(err == nil, "LoadCertKey: %v", err)
	assert(len(tlsCert.Certificate) > 0, "no certificates in TLS cert")
}

func TestLoadCertKey_RSA_PKCS8(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)
	keyPath := writePEM(t, dir, "leaf-pkcs8.key", pki.LeafKeyPKCS8PEM, 0o600)

	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err == nil, "LoadCertKey with PKCS#8 key: %v", err)
}

func TestLoadCertKey_EC(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	certPath := writePEM(t, dir, "ec-leaf.pem", pki.ECLeafPEM, 0o600)
	keyPath := writePEM(t, dir, "ec-leaf.key", pki.ECLeafKeyPEM, 0o600)

	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err == nil, "LoadCertKey with EC key: %v", err)
}

func TestLoadCertKey_FullChain(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	certPath := writePEM(t, dir, "chain.pem", pki.ChainPEM, 0o600)
	keyPath := writePEM(t, dir, "leaf.key", pki.LeafKeyPEM, 0o600)

	tlsCert, err := LoadCertKey(certPath, keyPath, nil)
	assert(err == nil, "LoadCertKey with chain: %v", err)
	// chain should have leaf + intermediate
	assert(len(tlsCert.Certificate) == 2, "chain has %d certs, want 2", len(tlsCert.Certificate))
}

func TestLoadCertKey_MismatchedKeyReject(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	// RSA cert with EC key — mismatch
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)
	keyPath := writePEM(t, dir, "ec.key", pki.ECLeafKeyPEM, 0o600)

	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err != nil, "expected error for mismatched cert/key")
}

func TestLoadCertKey_EncryptedPKCS8Reject(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)

	// simulate encrypted PKCS#8 key
	encPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("fake encrypted data"),
	})
	keyPath := writePEM(t, dir, "encrypted.key", encPEM, 0o600)

	pki := newTestPKI(t)
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)

	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err != nil, "expected error for encrypted PKCS#8 key")
	assert(strings.Contains(err.Error(), "encrypted PKCS#8"),
		"error should mention encrypted PKCS#8: %v", err)
	assert(strings.Contains(err.Error(), "openssl"),
		"error should include remediation command: %v", err)
}

func TestLoadCertKey_LegacyEncryptedReject(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)

	// simulate legacy DEK-Info encrypted key
	legacyPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,fake"},
		Bytes:   []byte("fake encrypted data"),
	})
	keyPath := writePEM(t, dir, "legacy.key", legacyPEM, 0o600)

	pki := newTestPKI(t)
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)

	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err != nil, "expected error for legacy encrypted key")
	assert(strings.Contains(err.Error(), "legacy encrypted"),
		"error should mention legacy encrypted: %v", err)
	assert(strings.Contains(err.Error(), "openssl"),
		"error should include remediation command: %v", err)
}

func TestLoadCertKey_EncryptedPKCS8_NotFirstBlock(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	// key file: leading CERTIFICATE block + ENCRYPTED PRIVATE KEY block
	certBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("fake cert bytes"),
	})
	encBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("fake encrypted data"),
	})
	keyPEM := append([]byte{}, certBlock...)
	keyPEM = append(keyPEM, encBlock...)
	keyPath := writePEM(t, dir, "encrypted-second.key", keyPEM, 0o600)

	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)

	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err != nil, "expected error for encrypted PKCS#8 key after leading block")
	assert(strings.Contains(err.Error(), "encrypted PKCS#8"),
		"error should mention encrypted PKCS#8: %v", err)
	assert(strings.Contains(err.Error(), "openssl"),
		"error should include remediation command: %v", err)
}

func TestLoadCertKey_LegacyEncrypted_NotFirstBlock(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	// key file: leading CERTIFICATE block + legacy-encrypted RSA PRIVATE KEY
	certBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("fake cert bytes"),
	})
	legacyBlock := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,fake"},
		Bytes:   []byte("fake encrypted data"),
	})
	keyPEM := append([]byte{}, certBlock...)
	keyPEM = append(keyPEM, legacyBlock...)
	keyPath := writePEM(t, dir, "legacy-second.key", keyPEM, 0o600)

	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)

	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err != nil, "expected error for legacy encrypted key after leading block")
	assert(strings.Contains(err.Error(), "legacy encrypted"),
		"error should mention legacy encrypted: %v", err)
	assert(strings.Contains(err.Error(), "openssl"),
		"error should include remediation command: %v", err)
}

func TestLoadCertKey_NoPrivateKeyBlock(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	// key file with only CERTIFICATE blocks — no private key
	onlyCerts := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("fake cert bytes"),
	})
	keyPath := writePEM(t, dir, "no-key.key", onlyCerts, 0o600)

	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)

	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err != nil, "expected error for file with no private key block")
	assert(strings.Contains(err.Error(), "no private key PEM block"),
		"error should mention missing private key block: %v", err)
}

func TestLoadCertKey_KeyBadPermissions(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)
	keyPath := writePEM(t, dir, "leaf.key", pki.LeafKeyPEM, 0o644)

	// Key.Perm=0o600 (default) rejects key files with group/world read
	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err != nil, "expected permission error for key with mode 0644")

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "expected PermissionError, got %T: %v", err, err)
}

func TestLoadCertKey_CertBadPermissions(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o666)
	keyPath := writePEM(t, dir, "leaf.key", pki.LeafKeyPEM, 0o600)

	// 0666 has world-write bit, rejected by the hardcoded floor
	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err != nil, "expected permission error for cert with mode 0666")

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "expected PermissionError, got %T: %v", err, err)
}

func TestLoadCertKey_NonexistentCert(t *testing.T) {
	assert := newAsserter(t)

	dir := safeTempDir(t)
	pki := newTestPKI(t)
	keyPath := writePEM(t, dir, "leaf.key", pki.LeafKeyPEM, 0o600)

	_, err := LoadCertKey("/nonexistent/cert.pem", keyPath, nil)
	assert(err != nil, "expected error for nonexistent cert file")
}

func TestLoadCertKey_NonexistentKey(t *testing.T) {
	assert := newAsserter(t)

	dir := safeTempDir(t)
	pki := newTestPKI(t)
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)

	_, err := LoadCertKey(certPath, "/nonexistent/key.pem", nil)
	assert(err != nil, "expected error for nonexistent key file")
}

func TestLoadCertKey_EmptyKeyFile(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)
	keyPath := filepath.Join(dir, "empty.key")
	if err := os.WriteFile(keyPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err != nil, "expected error for empty key file")
}

func TestLoadCertKey_NilOptsUsesDefaults(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	// nil opts defaults to Perm=0o600, so both files must be 0o600
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o600)
	keyPath := writePEM(t, dir, "leaf.key", pki.LeafKeyPEM, 0o600)

	// nil opts should use strict defaults and succeed
	_, err := LoadCertKey(certPath, keyPath, nil)
	assert(err == nil, "LoadCertKey with nil opts: %v", err)
}

func TestLoadCertKey_ExplicitPermAllowsCertAt644(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o644)
	keyPath := writePEM(t, dir, "leaf.key", pki.LeafKeyPEM, 0o600)

	// Cert.Perm=0o644 allows the cert file to be group/world readable;
	// Key.Perm=0o600 still enforces owner-only on the key.
	opts := &SecurityOpts{
		Cert: FilePerm{Perm: 0o644, Uid: -1, Gid: -1},
		Key:  FilePerm{Perm: 0o600, Uid: -1, Gid: -1},
	}
	tlsCert, err := LoadCertKey(certPath, keyPath, opts)
	assert(err == nil, "LoadCertKey with Cert.Perm=0644: %v", err)
	assert(len(tlsCert.Certificate) > 0, "no certificates in TLS cert")
}

func TestLoadCertKey_SplitPerms(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	// cert at 0o644, key at 0o600; nil opts uses role defaults.
	certPath := writePEM(t, dir, "leaf.pem", pki.LeafPEM, 0o644)
	keyPath := writePEM(t, dir, "leaf.key", pki.LeafKeyPEM, 0o600)

	tlsCert, err := LoadCertKey(certPath, keyPath, nil)
	assert(err == nil, "LoadCertKey with split default perms: %v", err)
	assert(len(tlsCert.Certificate) > 0, "no certificates in TLS cert")
}
