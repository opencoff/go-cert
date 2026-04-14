// safeio.go - Root, SecurityOpts, ReadFile, ReadDir, Close
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

// Package safeio provides secure, openat-backed file reading with
// permission and ownership validation. It walks directory hierarchies
// from "/" using chained os.Root.OpenRoot calls, checking each
// directory for unsafe write permissions, then opens files via the
// secured root and validates permissions on the open file descriptor.
//
// Group-writable and world-writable bits on directories and files are
// always rejected (hardcoded security floor, not configurable).
// File permission limits and ownership requirements are configurable
// via SecurityOpts at Root construction time.
//
// Root caches directory handles to amortize the cost of secure walks
// across multiple operations in the same directory hierarchy.
package safeio

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// SecurityOpts controls file permission and ownership policy.
// Group-writable and world-writable bits on directories and files
// are always rejected regardless of Perm.
type SecurityOpts struct {
	// Perm is the maximum acceptable permission bits for files.
	// Any bits set beyond this mask cause rejection.
	Perm fs.FileMode

	// Uid is the expected file owner UID. Set to -1 to skip UID check.
	Uid int

	// Gid is the expected file owner GID. Set to -1 to skip GID check.
	Gid int

	// Role is a label included in error messages (e.g., "ca", "key").
	Role string

	// Filter, if non-nil, is called by ReadDir for each file name.
	// Files where Filter returns true are skipped (not opened, not
	// permission-checked). ReadFile ignores the filter.
	Filter func(name string) bool
}

// Root caches openat-backed directory handles and provides secure
// file reading with permission and ownership validation. Security
// policy is fixed at construction time.
//
// Directory paths from "/" to the target are walked via chained
// os.Root.OpenRoot calls. Each unique directory is walked only once;
// subsequent operations in the same directory reuse the cached root.
//
// Files are opened via the cached root (openat), then fstat'd on the
// open fd — no TOCTOU gap between permission check and read.
//
// On Windows, permission and ownership validation is a no-op; see
// SecurityEnforced.
//
// Caching and staleness: each unique directory (after Abs +
// EvalSymlinks) is walked from "/" once and its handle is cached for
// the lifetime of the Root. Permission changes to a directory after
// its first access are not observed by subsequent operations on this
// Root. To re-evaluate directory permissions, construct a fresh Root.
// This is intentional: it bounds file-descriptor use and keeps reads
// within a Root's lifetime consistent with the audit performed at
// first access.
//
// Safe for concurrent use; a single mutex serializes ReadFile,
// ReadDir, and Close.
type Root struct {
	SecurityOpts

	mu     sync.Mutex
	dirs   map[string]*os.Root
	closed bool

	// statOwner extracts UID/GID from FileInfo. Defaults to the
	// platform-specific defaultStatOwner; tests may override for
	// mocking without real filesystem ownership.
	statOwner func(fi fs.FileInfo) (uid, gid int, err error)
}

// NewRoot creates a new Root with the given security policy.
// On Windows, permission and ownership checks are no-ops; see
// SecurityEnforced for the runtime capability query.
func NewRoot(opts *SecurityOpts) *Root {
	r := &Root{
		dirs:      make(map[string]*os.Root),
		statOwner: defaultStatOwner,
	}

	if opts != nil {
		r.SecurityOpts = *opts
	}

	if r.Filter == nil {
		r.Filter = func(_ string) bool {

			// don't filter anything
			return false
		}
	}

	return r
}

// SecurityEnforced reports whether permission and ownership checks
// are actually performed on this platform. Returns true on Unix and
// false on Windows.
//
// Unguarded: reads only the immutable securityEnforced build constant.
func (r *Root) SecurityEnforced() bool {
	return securityEnforced
}

// SecurityEnforced reports whether permission and ownership checks
// are actually performed on this platform. Returns true on Unix and
// false on Windows.
func SecurityEnforced() bool {
	return securityEnforced
}

// ReadFile resolves path (Abs + EvalSymlinks), obtains or creates a
// cached root for the parent directory, opens the file via the root
// (openat), fstats the open fd, checks permissions and ownership,
// and returns the open file as an io.ReadCloser.
//
// The caller must close the returned reader.
//
// ReadFile ignores the Filter in SecurityOpts.
func (r *Root) ReadFile(path string) (io.ReadCloser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil, fmt.Errorf("safeio: root is closed")
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return nil, err
	}

	dir := filepath.Dir(abs)
	name := filepath.Base(abs)

	root, err := r.getRoot(dir)
	if err != nil {
		return nil, err
	}

	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	if err := r.checkFilePerm(fi, path); err != nil {
		f.Close()
		return nil, err
	}

	return f, nil
}

// ReadDir walks a directory (recursively if recurse is true), opens
// every regular file that passes the SecurityOpts.Filter (if set),
// permission-checks it via fstat on the open fd, and calls fn with
// the file path and an io.Reader. The file is closed automatically
// after fn returns; fn must not retain the Reader.
//
// fn returning a non-nil error stops the walk. ReadDir returns the
// first error encountered (directory permission, file permission,
// or callback error).
func (r *Root) ReadDir(dir string, recurse bool, fn func(path string, rd io.Reader) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("safeio: root is closed")
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}

	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return err
	}

	root, err := r.getRoot(abs)
	if err != nil {
		return err
	}

	rfs := root.FS()

	// open opens a file relative to root, permission-checks it, and
	// calls fn with the full path. The file is closed after fn returns.
	open := func(relPath string) error {
		path := filepath.Join(dir, relPath)
		f, err := root.Open(relPath)
		if err != nil {
			return err
		}
		defer f.Close()

		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if err := r.checkFilePerm(fi, path); err != nil {
			return err
		}
		return fn(path, f)
	}

	if recurse {
		return fs.WalkDir(rfs, ".", func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			m := d.Type()
			switch {
			case m.IsDir():
				if path == "." {
					return nil
				}
				fi, err := root.Stat(path)
				if err != nil {
					return err
				}
				return checkDirPerm(fi, filepath.Join(dir, path))
			case m.IsRegular():
				if r.Filter(d.Name()) {
					return nil
				}
				return open(path)
			}
			return nil
		})
	}

	entries, err := fs.ReadDir(rfs, ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		nm := entry.Name()
		if !entry.Type().IsRegular() || r.Filter(nm) {
			continue
		}
		if err := open(nm); err != nil {
			return err
		}
	}
	return nil
}

// Close closes all cached directory handles. Idempotent; subsequent
// calls return nil.
func (r *Root) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	var errs []error
	for _, root := range r.dirs {
		if err := root.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	clear(r.dirs)
	r.dirs = nil
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
