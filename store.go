// store.go - Store type, CA loading, Finalize management
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
	"encoding/pem"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/opencoff/go-cert/internal/safeio"
)

// Store provides secure loading and accumulation of CA certificates
// into a *Pool. It wraps a safeio.Root with a permission
// policy appropriate for CA files (default Perm=0644).
//
// For loading cert+key pairs, use the standalone LoadCertKey function
// which applies its own stricter permission policy (default Perm=0600).
//
// On Windows, permission and ownership checks are no-ops; query
// SecurityEnforced to detect this at runtime.
//
// Store is safe for concurrent use; a single mutex serializes
// LoadCAFile, LoadCADir, Finalize, Close, Count, and Sources. The
// *Pool it produces via Finalize is safe for concurrent readers.
//
// Store inherits the directory-handle caching of safeio.Root:
// permission changes to a directory after its first access are not
// observed by subsequent loads on the same Store. Use a fresh Store
// per startup cycle if you need to re-evaluate directory permissions.
type Store struct {
	mu      sync.Mutex
	root    *safeio.Root
	certs   []*x509.Certificate
	sources []string
	// origin tracks provenance for each loaded cert, keyed by
	// sha256(cert.Raw). It is forwarded to *Pool at Finalize.
	origin  map[[32]byte]string
	sysPool *x509.CertPool
	pool    *Pool // non-nil after Finalize
}

// NewStore creates a Store with the given security policy.
// If opts is nil, strict defaults are used (Cert: Perm=0644, Uid=-1, Gid=-1).
// Store uses only opts.Cert; opts.Key is ignored.
//
// The Store's safeio.Root filters directory walks by certificate
// extension (.pem, .crt, .cer) automatically.
func NewStore(opts *SecurityOpts) *Store {

	return newStore(opts, nil)
}

// NewSystemStore creates a Store initialized with the system trust
// store (x509.SystemCertPool). System CA files are NOT subject to
// permission checks (they are managed by the OS). Only subsequently
// loaded files are checked. If opts is nil, strict defaults are used.
func NewSystemStore(opts *SecurityOpts) (*Store, error) {
	sys, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("cert: cannot load system CA pool: %w", err)
	}

	return newStore(opts, sys), nil
}

// SecurityEnforced reports whether permission and ownership checks
// are actually performed on this platform. Returns true on Unix and
// false on Windows.
//
// Unguarded: reads only the immutable build-time platform constant.
func (s *Store) SecurityEnforced() bool {
	return SecurityEnforced()
}

// newStore creates a new cert store root with an optional system pool
func newStore(opts *SecurityOpts, sys *x509.CertPool) *Store {
	o := resolveOpts(opts)

	role := o.Role
	if role == "" {
		role = "ca"
	}

	filter := o.Filter
	if filter == nil {
		filter = filterNonCerts
	}

	return &Store{
		root:    safeio.NewRoot(toSafeIO(o.Cert, role, filter)),
		origin:  make(map[[32]byte]string),
		sysPool: sys,
	}
}

// LoadCAFile loads one or more PEM-encoded CA certificates from a
// single file (which may be a bundle containing multiple certs).
// Returns the number of certificates added and any error.
//
// Returns an error if the file contains no CERTIFICATE blocks OR if
// every certificate is already present in the Store (duplicates are
// detected by sha256 of the DER bytes; the first-seen source is kept).
func (s *Store) LoadCAFile(path string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkActiveForLoad(); err != nil {
		return 0, err
	}

	data, err := readAll(s.root, path)
	if err != nil {
		return 0, fmt.Errorf("cert: %w", err)
	}

	n, err := s.addCerts(data, path)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("cert: no certificates found in %q", path)
	}

	s.sources = append(s.sources, fmt.Sprintf("%d certs from %s", n, path))
	return n, nil
}

// LoadCADir loads PEM-encoded CA certificates from all files in the
// given directory. If recurse is true, subdirectories are walked.
// Files are filtered by extension (.pem, .crt, .cer) before opening.
// Files that are not valid PEM are silently skipped. Files that fail
// permission checks stop the walk on the first error. Duplicate
// certificates (same DER bytes) are counted once; the first-seen file
// path is recorded as the source.
//
// On error, previously loaded certificates remain in the Store and
// will be included if Finalize is subsequently called. Callers who
// require all-or-nothing semantics should call Close() on the Store
// after a LoadCADir error.
//
// Returns the total number of certificates added and any error.
//
// LoadCADir holds the Store's internal mutex for the duration of the
// directory walk. Concurrent calls to any Store method (including
// Count and Sources) on the same Store will block until the walk
// completes. Since LoadCADir is typically called at startup, this is
// usually fine; callers loading from directories with many large files
// or across slow filesystems should be aware.
func (s *Store) LoadCADir(dir string, recurse bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkActiveForLoad(); err != nil {
		return 0, err
	}

	var total int
	err := s.root.ReadDir(dir, recurse, func(name string, rd io.Reader) error {
		data, err := io.ReadAll(rd)
		if err != nil {
			return err
		}

		n, err := s.addCerts(data, name)
		if err != nil {
			return err
		}
		total += n
		return nil
	})
	if err != nil {
		return total, fmt.Errorf("cert: %w", err)
	}

	if total > 0 {
		s.sources = append(s.sources, fmt.Sprintf("%d certs from %s", total, dir))
	}
	return total, nil
}

// Finalize assembles the accumulated CA certificates into an
// *x509.CertPool, wraps it in a *Pool with provenance metadata,
// caches the result, and releases all internal directory handles.
// Subsequent calls return the same cached *Pool.
//
// Callers that previously used the returned *x509.CertPool directly
// should call Pool.Pool() on the returned value.
//
// After Finalize, LoadCAFile and LoadCADir return errors. Count and
// Sources continue to work (they read from the preserved state).
func (s *Store) Finalize() (*Pool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pool != nil {
		return s.pool, nil
	}
	if s.root == nil {
		return nil, fmt.Errorf("cert: store is closed")
	}

	var certPool *x509.CertPool
	if s.sysPool != nil {
		certPool = s.sysPool
	} else {
		certPool = x509.NewCertPool()
	}

	for _, c := range s.certs {
		certPool.AddCert(c)
	}

	// Build the immutable Pool. sources/origin/count are copied
	// (or handed over) so the Pool remains valid after the Store
	// is closed.
	p := &Pool{
		pool:    certPool,
		sources: append([]string(nil), s.sources...),
		origin:  s.origin,
		count:   len(s.certs),
	}
	s.pool = p

	// release the certs slice (Pool holds the x509 pool and origin
	// map it needs) and close the safeio root handles.
	s.certs = nil
	s.sysPool = nil
	s.origin = nil
	s.root.Close()
	s.root = nil

	return p, nil
}

// Count returns the number of CA certificates loaded so far
// (not counting system CAs if NewSystemStore was used).
//
// Count continues to work after Finalize; it returns an error only
// after the Store has been Close'd without being finalized.
func (s *Store) Count() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkActiveForRead(); err != nil {
		return 0, err
	}
	if s.pool != nil {
		return s.pool.Count(), nil
	}
	return len(s.certs), nil
}

// Sources returns a human-readable summary of where certs were loaded
// from, suitable for startup logging.
//
// Sources continues to work after Finalize; it returns an error only
// after the Store has been Close'd without being finalized.
func (s *Store) Sources() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkActiveForRead(); err != nil {
		return nil, err
	}
	if s.pool != nil {
		return s.pool.Sources(), nil
	}
	out := make([]string, len(s.sources))
	copy(out, s.sources)
	return out, nil
}

// Close closes all cached directory handles and invalidates the
// store. After Close, load and read methods on the Store return
// errors. Any *Pool previously returned by Finalize remains valid
// (a Pool holds no file descriptors).
//
// Close is idempotent and safe to call after Finalize.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.root == nil {
		// Already finalized or closed. Invalidate any cached
		// Pool reference on the Store so post-Close reads fail.
		s.pool = nil
		return nil
	}

	err := s.root.Close()
	s.root = nil
	s.certs = nil
	s.sysPool = nil
	s.origin = nil
	s.pool = nil
	return err
}

// checkActiveForLoad returns an error if the store can no longer
// accept CA loads (either closed or already finalized).
func (s *Store) checkActiveForLoad() error {
	if s.root == nil && s.pool == nil {
		return fmt.Errorf("cert: store is closed")
	}
	if s.pool != nil {
		return fmt.Errorf("cert: CA pool is finalized")
	}
	return nil
}

// checkActiveForRead returns an error only if the store has been
// closed. Finalized stores are still readable via Count/Sources.
func (s *Store) checkActiveForRead() error {
	if s.root == nil && s.pool == nil {
		return fmt.Errorf("cert: store is closed")
	}
	return nil
}

// addCerts parses PEM certificates from data and appends new ones to
// the store. Duplicates (same sha256 of DER bytes) are dropped to
// keep s.certs and the resulting CertPool free of double entries; the
// first-seen origin is preserved. Returns the count of newly added
// (non-duplicate) certificates.
func (s *Store) addCerts(data []byte, path string) (int, error) {
	certs, err := parsePEMCerts(data)
	if err != nil {
		return 0, fmt.Errorf("cert: %s: %w", path, err)
	}
	added := 0
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		if _, ok := s.origin[sum]; ok {
			// duplicate — keep first-seen origin, don't re-append
			continue
		}
		s.origin[sum] = path
		s.certs = append(s.certs, c)
		added++
	}
	return added, nil
}

// readAll opens a file via a safeio.Root, reads all bytes, and closes it.
func readAll(root *safeio.Root, path string) ([]byte, error) {
	rc, err := root.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// parsePEMCerts parses all CERTIFICATE PEM blocks from data.
// Returns an error if a CERTIFICATE block is present but malformed.
// Returns (nil, nil) if no CERTIFICATE blocks are found at all.
//
// Only CERTIFICATE PEM blocks are recognized; TRUSTED CERTIFICATE
// blocks (OpenSSL trust-metadata format) are silently skipped. This
// matches crypto/x509.CertPool.AppendCertsFromPEM.
func parsePEMCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// filterNonCerts returns true for all non-cert files. The extension
// comparison is Unicode-correct case-insensitive (via strings.EqualFold)
// so that files named ROOT.PEM, INTERM.CRT, etc. are picked up on
// case-insensitive filesystems.
func filterNonCerts(name string) bool {
	ext := filepath.Ext(name)
	for _, want := range []string{".pem", ".crt", ".cer"} {
		if strings.EqualFold(ext, want) {
			return false
		}
	}
	return true
}
