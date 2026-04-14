// store_test.go - tests for Store API and lifecycle
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
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// --- LoadCAFile ---

func TestStore_LoadCAFile_ValidBundle(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	writePEM(t, dir, "bundle.pem", pki.CABundlePEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	n, err := s.LoadCAFile(filepath.Join(dir, "bundle.pem"))
	assert(err == nil, "LoadCAFile: %v", err)
	assert(n == 2, "loaded %d certs, want 2", n)

	count, err := s.Count()
	assert(err == nil, "Count: %v", err)
	assert(count == 2, "Count = %d, want 2", count)
}

func TestStore_LoadCAFile_SingleCert(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	n, err := s.LoadCAFile(filepath.Join(dir, "root.pem"))
	assert(err == nil, "LoadCAFile: %v", err)
	assert(n == 1, "loaded %d certs, want 1", n)
}

func TestStore_LoadCAFile_NoCerts(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writePEM(t, dir, "empty.pem", []byte("not a PEM file"), 0o644)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile(filepath.Join(dir, "empty.pem"))
	assert(err != nil, "expected error for file with no certs")
}

func TestStore_LoadCAFile_BadPermissions(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	writePEM(t, dir, "ca.pem", pki.RootPEM, 0o666)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile(filepath.Join(dir, "ca.pem"))
	assert(err != nil, "expected permission error")

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "expected PermissionError, got %T: %v", err, err)
}

func TestStore_LoadCAFile_NonexistentFile(t *testing.T) {
	assert := newAsserter(t)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile("/nonexistent/file.pem")
	assert(err != nil, "expected error for nonexistent file")
}

// --- LoadCADir ---

func TestStore_LoadCADir_ValidFiles(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)
	writePEM(t, dir, "intermediate.crt", pki.IntermPEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	n, err := s.LoadCADir(dir, false)
	assert(err == nil, "LoadCADir: %v", err)
	assert(n == 2, "loaded %d certs, want 2", n)
}

func TestStore_LoadCADir_MixedFiles(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	writePEM(t, dir, "valid.pem", pki.RootPEM, 0o644)
	writePEM(t, dir, "not-a-cert.txt", []byte("hello"), 0o644)
	writePEM(t, dir, "readme.md", []byte("# readme"), 0o644)

	s := NewStore(nil)
	defer s.Close()

	n, err := s.LoadCADir(dir, false)
	assert(err == nil, "LoadCADir: %v", err)
	assert(n == 1, "loaded %d certs, want 1", n)
}

func TestStore_LoadCADir_EmptyDir(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)

	s := NewStore(nil)
	defer s.Close()

	n, err := s.LoadCADir(dir, false)
	assert(err == nil, "LoadCADir: %v", err)
	assert(n == 0, "loaded %d certs, want 0", n)
}

func TestStore_LoadCADir_BadPermissionFile(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	writePEM(t, dir, "good.pem", pki.RootPEM, 0o644)
	writePEM(t, dir, "bad.pem", pki.IntermPEM, 0o666)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCADir(dir, false)
	assert(err != nil, "expected permission error for bad file in directory")

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "expected PermissionError, got %T: %v", err, err)
}

func TestStore_LoadCADir_Recursive(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)

	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writePEM(t, sub, "intermediate.pem", pki.IntermPEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	n, err := s.LoadCADir(dir, true)
	assert(err == nil, "LoadCADir recursive: %v", err)
	assert(n == 2, "loaded %d certs, want 2", n)
}

func TestStore_LoadCADir_NonRecursiveSkipsSubdir(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)

	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writePEM(t, sub, "nested.pem", pki.IntermPEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	n, err := s.LoadCADir(dir, false)
	assert(err == nil, "LoadCADir: %v", err)
	assert(n == 1, "loaded %d certs, want 1 (subdir should be skipped)", n)
}

func TestStore_LoadCADir_WorldWritableDir(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	mkdirChmod(t, bad, 0o777)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCADir(bad, false)
	assert(err != nil, "expected error for world-writable directory")
}

func TestStore_LoadCADir_UppercaseExt(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	writePEM(t, dir, "ROOT.PEM", pki.RootPEM, 0o644)
	writePEM(t, dir, "INTERM.CRT", pki.IntermPEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	n, err := s.LoadCADir(dir, false)
	assert(err == nil, "LoadCADir: %v", err)
	assert(n == 2, "loaded %d certs, want 2 (uppercase extensions)", n)
}

// TestStore_LoadCAFile_EmptyCertBlock verifies that a PEM file whose
// CERTIFICATE block has zero DER bytes is rejected with a parse error
// (x509.ParseCertificate fails on empty input).
func TestStore_LoadCAFile_EmptyCertBlock(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	empty := pemEncode("CERTIFICATE", nil)
	writePEM(t, dir, "empty-cert.pem", empty, 0o644)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile(filepath.Join(dir, "empty-cert.pem"))
	assert(err != nil, "expected error for empty CERTIFICATE block")
}

// TestStore_LoadCAFile_MalformedInBundle verifies fail-fast behavior:
// a bundle containing a valid CERTIFICATE followed by a malformed one
// returns an error with no partial load.
func TestStore_LoadCAFile_MalformedInBundle(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	bad := pemEncode("CERTIFICATE", []byte("not a real DER encoding"))
	bundle := append([]byte{}, pki.RootPEM...)
	bundle = append(bundle, bad...)
	writePEM(t, dir, "bad-bundle.pem", bundle, 0o644)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile(filepath.Join(dir, "bad-bundle.pem"))
	assert(err != nil, "expected error for bundle with malformed block")

	count, cerr := s.Count()
	assert(cerr == nil, "Count: %v", cerr)
	assert(count == 0, "Count = %d, want 0 (fail-fast, no partial load)", count)
}

func TestStore_LoadCADir_SkipsNonPEMContent(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)

	keyPEM := pemEncode("RSA PRIVATE KEY", []byte("fake key data"))
	writePEM(t, dir, "key.pem", keyPEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	n, err := s.LoadCADir(dir, false)
	assert(err == nil, "LoadCADir: %v", err)
	assert(n == 0, "loaded %d certs, want 0 (no CERTIFICATE blocks)", n)
}

// --- Finalize ---

func TestStore_Finalize(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)

	s := NewStore(nil)

	_, err := s.LoadCAFile(filepath.Join(dir, "root.pem"))
	assert(err == nil, "LoadCAFile: %v", err)

	p1, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)
	assert(p1 != nil, "Finalize returned nil Pool")
	assert(p1.Pool() != nil, "Pool.Pool() is nil")

	// CA loading is now rejected.
	_, err = s.LoadCAFile(filepath.Join(dir, "root.pem"))
	assert(err != nil, "expected error after Finalize, LoadCAFile succeeded")

	// Count and Sources still work after Finalize.
	count, err := s.Count()
	assert(err == nil, "Count after Finalize: %v", err)
	assert(count == 1, "Count = %d, want 1", count)

	srcs, err := s.Sources()
	assert(err == nil, "Sources after Finalize: %v", err)
	assert(len(srcs) == 1, "Sources length = %d, want 1", len(srcs))

	// Second Finalize returns the same *Pool (idempotent).
	p2, err := s.Finalize()
	assert(err == nil, "second Finalize: %v", err)
	assert(p2 == p1, "second Finalize returned a different *Pool")
}

func TestStore_Finalize_Empty(t *testing.T) {
	assert := newAsserter(t)

	s := NewStore(nil)

	p, err := s.Finalize()
	assert(err == nil, "Finalize on empty store: %v", err)
	assert(p != nil, "expected non-nil *Pool")
	assert(p.Pool() != nil, "expected non-nil *x509.CertPool")
	assert(p.Count() == 0, "Count = %d, want 0", p.Count())
}

func TestStore_Finalize_AfterClose(t *testing.T) {
	assert := newAsserter(t)

	s := NewStore(nil)
	s.Close()

	_, err := s.Finalize()
	assert(err != nil, "Finalize should fail after Close")
}

// --- Sources / Count ---

func TestStore_Sources(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)
	writePEM(t, dir, "bundle.pem", pki.CABundlePEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile(filepath.Join(dir, "root.pem"))
	assert(err == nil, "LoadCAFile root: %v", err)
	_, err = s.LoadCAFile(filepath.Join(dir, "bundle.pem"))
	assert(err == nil, "LoadCAFile bundle: %v", err)

	srcs, err := s.Sources()
	assert(err == nil, "Sources: %v", err)
	assert(len(srcs) == 2, "Sources returned %d entries, want 2", len(srcs))
}

func TestStore_Count_Accumulates(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)
	writePEM(t, dir, "bundle.pem", pki.CABundlePEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile(filepath.Join(dir, "root.pem"))
	assert(err == nil, "LoadCAFile root: %v", err)
	c1, err := s.Count()
	assert(err == nil, "Count: %v", err)
	assert(c1 == 1, "Count after first load = %d, want 1", c1)

	_, err = s.LoadCAFile(filepath.Join(dir, "bundle.pem"))
	assert(err == nil, "LoadCAFile bundle: %v", err)
	c2, err := s.Count()
	assert(err == nil, "Count: %v", err)
	// bundle.pem contains root + intermediate; root is a duplicate
	// of the first load so dedup yields 2 unique certs total.
	assert(c2 == 2, "Count after second load = %d, want 2 (deduped)", c2)
}

// --- NewSystemStore ---

func TestNewSystemStore(t *testing.T) {
	assert := newAsserter(t)

	s, err := NewSystemStore(nil)
	assert(err == nil, "NewSystemStore: %v", err)

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)
	assert(p != nil, "expected non-nil *Pool from system store")
	assert(p.Pool() != nil, "expected non-nil *x509.CertPool")
}

// --- Close ---

func TestStore_Close_InvalidatesAll(t *testing.T) {
	assert := newAsserter(t)

	s := NewStore(nil)
	s.Close()

	_, err := s.LoadCAFile("/tmp/test.pem")
	assert(err != nil, "LoadCAFile should fail after Close")
	_, err = s.LoadCADir("/tmp", false)
	assert(err != nil, "LoadCADir should fail after Close")
	_, err = s.Finalize()
	assert(err != nil, "Finalize should fail after Close")
	_, err = s.Count()
	assert(err != nil, "Count should fail after Close")
	_, err = s.Sources()
	assert(err != nil, "Sources should fail after Close")
}

func TestStore_Close_Idempotent(t *testing.T) {
	assert := newAsserter(t)

	s := NewStore(nil)
	err := s.Close()
	assert(err == nil, "first Close: %v", err)
	err = s.Close()
	assert(err == nil, "second Close should return nil, got: %v", err)
}

func TestStore_Close_AfterFinalize(t *testing.T) {
	assert := newAsserter(t)

	s := NewStore(nil)

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)
	assert(p != nil, "Finalize returned nil *Pool")

	// Close after Finalize is idempotent (root already nil).
	err = s.Close()
	assert(err == nil, "Close after Finalize: %v", err)

	// The *Pool returned earlier is still usable — it holds no fds.
	assert(p.Pool() != nil, "*Pool.Pool() should remain valid after Store.Close")
}

// --- Finalize-finalized store prevents further CA loading ---

func TestStore_LoadCADir_AfterFinalize(t *testing.T) {
	assert := newAsserter(t)

	s := NewStore(nil)

	_, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)

	_, err = s.LoadCADir("/tmp", false)
	assert(err != nil, "expected error for LoadCADir on finalized pool")
}

// --- Pool ---

func TestPool_Source_ReturnsFilePath(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	caPath := writePEM(t, dir, "ca.pem", pki.RootPEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile(caPath)
	assert(err == nil, "LoadCAFile: %v", err)

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)

	// pki.RootCert has the same Raw bytes as the cert loaded from
	// disk, so Source should return the path recorded during
	// addCerts (the caller-facing path passed to LoadCAFile).
	got := p.Source(pki.RootCert)
	assert(got == caPath, "Source = %q, want %q", got, caPath)
}

func TestPool_Source_UnknownCert(t *testing.T) {
	assert := newAsserter(t)

	pki := newTestPKI(t)

	s := NewStore(nil)
	defer s.Close()

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)

	// A cert that was never loaded must return "".
	got := p.Source(pki.LeafCert)
	assert(got == "", "Source(unknown) = %q, want \"\"", got)
}

func TestPool_Source_NilCert(t *testing.T) {
	assert := newAsserter(t)

	s := NewStore(nil)
	defer s.Close()

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)

	got := p.Source(nil)
	assert(got == "", "Source(nil) = %q, want \"\"", got)
}

func TestPool_Sources_Populated(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)
	writePEM(t, dir, "bundle.pem", pki.CABundlePEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile(filepath.Join(dir, "root.pem"))
	assert(err == nil, "LoadCAFile root: %v", err)
	_, err = s.LoadCAFile(filepath.Join(dir, "bundle.pem"))
	assert(err == nil, "LoadCAFile bundle: %v", err)

	preSrcs, err := s.Sources()
	assert(err == nil, "Sources pre-finalize: %v", err)

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)

	postSrcs := p.Sources()
	assert(len(postSrcs) == len(preSrcs), "Pool.Sources length = %d, want %d",
		len(postSrcs), len(preSrcs))
	for i, v := range preSrcs {
		assert(postSrcs[i] == v, "Pool.Sources[%d] = %q, want %q", i, postSrcs[i], v)
	}

	// Returned slice is a copy — mutation must not leak into the Pool.
	if len(postSrcs) > 0 {
		postSrcs[0] = "tampered"
		again := p.Sources()
		assert(again[0] != "tampered", "Pool.Sources returned a shared slice")
	}
}

func TestPool_Count(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	writePEM(t, dir, "bundle.pem", pki.CABundlePEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile(filepath.Join(dir, "bundle.pem"))
	assert(err == nil, "LoadCAFile: %v", err)

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)

	// bundle has 2 certs (root + intermediate).
	assert(p.Count() == 2, "Pool.Count = %d, want 2", p.Count())
}

func TestPool_Count_SystemStoreExcludesSystem(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)

	s, err := NewSystemStore(nil)
	assert(err == nil, "NewSystemStore: %v", err)
	defer s.Close()

	_, err = s.LoadCAFile(filepath.Join(dir, "root.pem"))
	assert(err == nil, "LoadCAFile: %v", err)

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)

	// System certs are not counted — only the one we explicitly loaded.
	assert(p.Count() == 1, "Pool.Count = %d, want 1 (system certs not counted)", p.Count())
}

func TestPool_ConcurrentReaders(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	caPath := writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)

	s := NewStore(nil)
	_, err := s.LoadCAFile(caPath)
	assert(err == nil, "LoadCAFile: %v", err)
	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)
	s.Close()

	const goroutines = 16
	const iters = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if cp := p.Pool(); cp == nil {
					t.Errorf("Pool() returned nil")
					return
				}
				_ = p.Source(pki.RootCert)
				_ = p.Source(pki.LeafCert)
				_ = p.Source(nil)
				_ = p.Sources()
				_ = p.Count()
			}
		}()
	}
	wg.Wait()
}

func TestPool_Pool_ReturnsUsablePool(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	writePEM(t, dir, "root.pem", pki.RootPEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	_, err := s.LoadCAFile(filepath.Join(dir, "root.pem"))
	assert(err == nil, "LoadCAFile: %v", err)

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)

	cp := p.Pool()
	assert(cp != nil, "Pool.Pool() returned nil")

	// Ensure the returned *x509.CertPool is the stdlib type.
	var _ *x509.CertPool = cp
}

// TestStore_ConcurrentLoadCAFile verifies the Store-level mutex by
// loading the same two CA files into one Store from many goroutines
// and asserting the deduped count is exactly 2. Run under -race.
//
// Because of dedup, only the first goroutine to win the mutex for a
// given path will report a successful load; the rest will see "all
// duplicates" errors. Both outcomes are acceptable here — the test's
// purpose is to exercise concurrent access to the Store's internal
// state under -race.
func TestStore_ConcurrentLoadCAFile(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	// Two single-cert files; each goroutine races to load one of them.
	const N = 50
	paths := make([]string, N)
	for i := 0; i < N; i++ {
		var pemBytes []byte
		if i%2 == 0 {
			pemBytes = pki.RootPEM
		} else {
			pemBytes = pki.IntermPEM
		}
		paths[i] = writePEM(t, dir, "ca-"+itoa(i)+".pem", pemBytes, 0o644)
	}

	s := NewStore(nil)
	defer s.Close()

	var wg sync.WaitGroup
	for _, p := range paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			// Errors from "all duplicates" are expected once one
			// goroutine wins; ignore them.
			_, _ = s.LoadCAFile(path)
		}(p)
	}
	wg.Wait()

	n, err := s.Count()
	assert(err == nil, "Count: %v", err)
	assert(n == 2, "Count = %d, want 2 (deduped root+interm)", n)
}

// --- Dedup ---

// TestStore_LoadCAFile_DeduplicatesSameBundle loads the same bundle
// twice and asserts the second load is a no-op (returns 0 plus an
// error) and that Count reflects only the unique certs.
func TestStore_LoadCAFile_DeduplicatesSameBundle(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)
	path := writePEM(t, dir, "bundle.pem", pki.CABundlePEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	n, err := s.LoadCAFile(path)
	assert(err == nil, "LoadCAFile #1: %v", err)
	assert(n == 2, "first load added %d, want 2", n)

	n2, err := s.LoadCAFile(path)
	assert(err != nil, "expected error on all-duplicate reload")
	assert(n2 == 0, "second load added %d, want 0", n2)

	count, err := s.Count()
	assert(err == nil, "Count: %v", err)
	assert(count == 2, "Count = %d, want 2 (deduped)", count)

	// Sources should record only the first (productive) load.
	srcs, err := s.Sources()
	assert(err == nil, "Sources: %v", err)
	assert(len(srcs) == 1, "Sources length = %d, want 1", len(srcs))
}

// TestStore_LoadCADir_DeduplicatesAcrossFiles writes the same root
// cert into two distinct files and asserts the directory walk reports
// only one unique cert, attributing the source to the first-seen file.
func TestStore_LoadCADir_DeduplicatesAcrossFiles(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	aPath := writePEM(t, dir, "a.pem", pki.RootPEM, 0o644)
	bPath := writePEM(t, dir, "b.pem", pki.RootPEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	total, err := s.LoadCADir(dir, false)
	assert(err == nil, "LoadCADir: %v", err)
	assert(total == 1, "LoadCADir total = %d, want 1 (deduped)", total)

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)

	got := p.Source(pki.RootCert)
	// fs.WalkDir / fs.ReadDir emit entries in lexical order, so a.pem
	// is observed before b.pem.
	assert(got == aPath || got == bPath, "Source = %q, want one of %q/%q", got, aPath, bPath)
	assert(got == aPath, "Source = %q, want first-seen %q", got, aPath)
}

// TestStore_Finalize_Deduped verifies that after a deduped load the
// resulting *Pool's count matches the unique-cert count and that the
// underlying *x509.CertPool's Subjects list matches.
func TestStore_Finalize_Deduped(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	pki := newTestPKI(t)
	dir := safeTempDir(t)

	// Two files that both contain the same bundle (root + interm).
	writePEM(t, dir, "a.pem", pki.CABundlePEM, 0o644)
	writePEM(t, dir, "b.pem", pki.CABundlePEM, 0o644)

	s := NewStore(nil)
	defer s.Close()

	total, err := s.LoadCADir(dir, false)
	assert(err == nil, "LoadCADir: %v", err)
	assert(total == 2, "total = %d, want 2 (root+interm, deduped)", total)

	p, err := s.Finalize()
	assert(err == nil, "Finalize: %v", err)
	assert(p.Count() == 2, "Pool.Count = %d, want 2", p.Count())

	cp := p.Pool()
	subs := cp.Subjects() //nolint:staticcheck // simplest portable count
	assert(len(subs) == 2, "CertPool subjects = %d, want 2", len(subs))
}

// itoa is a tiny base-10 helper so the test does not pull strconv
// just for filename construction.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
