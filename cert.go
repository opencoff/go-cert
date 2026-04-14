// cert.go - SecurityOpts, FilePerm, DefaultSecurityOpts, resolveOpts
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

// Package cert provides secure TLS certificate and CA pool loading
// with file permission and ownership validation for Go.
//
// The package enforces strict Unix file permissions by default. A nil
// SecurityOpts always means strict defaults — the zero-effort path
// is the secure path. On Windows, permission and ownership checks
// are unavailable; use SecurityEnforced at runtime to detect the
// platform capability.
//
// Policy is split by file role via the nested FilePerm type:
// SecurityOpts.Cert applies to CA files and to the cert file in
// LoadCertKey; SecurityOpts.Key applies only to the key file in
// LoadCertKey.
//
// Store.Finalize returns a *Pool: an immutable, concurrency-safe
// value that wraps the assembled *x509.CertPool along with per-cert
// provenance metadata. Use Pool.Pool() to obtain the *x509.CertPool
// for use with tls.Config.
//
// Caching and reload: a Store caches directory handles for its
// lifetime (inherited from the underlying safeio.Root). Permission
// changes to a directory after its first access are not observed by
// subsequent loads on the same Store. Use a fresh Store per startup
// cycle if you need to re-evaluate directory permissions.
package cert

import (
	"io/fs"

	"github.com/opencoff/go-cert/internal/safeio"
)

// SecurityOpts controls per-file permission and ownership policy.
// A nil value means DefaultSecurityOpts().
//
// Cert applies to CA files (LoadCAFile, LoadCADir) and to the cert
// file in LoadCertKey. Key applies only to the key file in LoadCertKey
// and is ignored by Store operations.
//
// Group-writable and world-writable bits on files and directories are
// always rejected regardless of Perm (hardcoded security floor).
type SecurityOpts struct {
	// Cert is the policy for cert/CA files.
	Cert FilePerm

	// Key is the policy for private key files (LoadCertKey only).
	Key FilePerm

	// Role is an optional label included in error messages. When empty,
	// the package supplies a role-appropriate label ("ca", "cert", "key")
	// based on which file is being checked.
	Role string

	// Filter, if non-nil, is applied to directory walks in Store
	// operations. The Store sets its own default when this is nil.
	Filter func(name string) bool
}

// FilePerm is a permission and ownership policy for a single file role.
// Use -1 for Uid or Gid to skip that ownership check.
//
// Each field has its own zero-value fallback: Perm=0 becomes the
// role-appropriate default, and Uid=0/Gid=0 become -1 (skip). Because
// 0 is also the legitimate UID/GID of root, this package does not
// support "require root ownership" via FilePerm; callers who need that
// must perform their own out-of-band check. Use -1 explicitly to skip
// an ownership check.
type FilePerm struct {
	// Perm is the maximum acceptable permission bits.
	// Any bits set beyond this mask cause rejection.
	Perm fs.FileMode

	// Uid is the expected file owner UID. Set to -1 to skip UID check.
	Uid int

	// Gid is the expected file owner GID. Set to -1 to skip GID check.
	Gid int
}

// DefaultSecurityOpts returns a SecurityOpts with strict role-appropriate
// defaults:
//
//   - Cert: Perm=0o644, Uid=-1, Gid=-1
//   - Key:  Perm=0o600, Uid=-1, Gid=-1
//
// Ownership is not checked by default because the common deployment
// pattern is a non-root service loading root-owned cert files. Callers
// that want ownership enforcement must set Uid/Gid explicitly.
// Permission-bit checks (and the hardcoded group/world-writable floor)
// still apply and provide the security floor.
func DefaultSecurityOpts() *SecurityOpts {
	return &SecurityOpts{
		Cert: FilePerm{Perm: 0o644, Uid: -1, Gid: -1},
		Key:  FilePerm{Perm: 0o600, Uid: -1, Gid: -1},
	}
}

// SecurityEnforced reports whether permission and ownership checks
// are actually performed on this platform. Returns true on Unix and
// false on Windows. Callers that rely on the security guarantee should
// query this at startup and refuse to run (or log a clear warning)
// when it returns false.
func SecurityEnforced() bool {
	return safeio.SecurityEnforced()
}

// resolveOpts returns a fully-populated SecurityOpts. If opts is nil,
// role defaults are returned. Otherwise each FilePerm field is
// independently checked: Perm=0 becomes the role default (cert: 0o644,
// key: 0o600); Uid=0 and Gid=0 become -1 (skip).
func resolveOpts(opts *SecurityOpts) *SecurityOpts {
	if opts == nil {
		return DefaultSecurityOpts()
	}

	resolved := *opts
	fillFilePerm(&resolved.Cert, 0o644)
	fillFilePerm(&resolved.Key, 0o600)
	return &resolved
}

// fillFilePerm replaces zero-valued fields in fp with safe defaults.
// Perm=0 => defaultPerm. Uid=0 => -1 (skip). Gid=0 => -1 (skip).
// The Uid/Gid replacement is deliberate: 0 collides with the legitimate
// root UID/GID, and the safer interpretation is "skip the check".
func fillFilePerm(fp *FilePerm, defaultPerm fs.FileMode) {
	if fp.Perm == 0 {
		fp.Perm = defaultPerm
	}
	if fp.Uid == 0 {
		fp.Uid = -1
	}
	if fp.Gid == 0 {
		fp.Gid = -1
	}
}

// toSafeIO builds a safeio.SecurityOpts from a FilePerm plus role label
// and optional filter. The safeio layer holds one Perm/Uid/Gid per Root;
// role-split policy is implemented at the cert layer by constructing one
// safeio.Root per role.
func toSafeIO(fp FilePerm, role string, filter func(string) bool) *safeio.SecurityOpts {
	return &safeio.SecurityOpts{
		Perm:   fp.Perm,
		Uid:    fp.Uid,
		Gid:    fp.Gid,
		Role:   role,
		Filter: filter,
	}
}
