// cert_test.go - tests for SecurityOpts, resolveOpts, error types
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
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"testing"
)

func TestSecurityEnforced(t *testing.T) {
	assert := newAsserter(t)

	want := runtime.GOOS != "windows"
	got := SecurityEnforced()
	assert(got == want, "SecurityEnforced() = %v, want %v on %s", got, want, runtime.GOOS)

	// Store.SecurityEnforced must match the package-level function.
	s := NewStore(nil)
	defer s.Close()
	assert(s.SecurityEnforced() == want,
		"Store.SecurityEnforced() = %v, want %v", s.SecurityEnforced(), want)
}

func TestDefaultSecurityOpts_Values(t *testing.T) {
	assert := newAsserter(t)
	opts := DefaultSecurityOpts()

	assert(opts.Cert.Perm == 0o644, "Cert.Perm = %04o, want 0644", opts.Cert.Perm)
	assert(opts.Cert.Uid == -1, "Cert.Uid = %d, want -1", opts.Cert.Uid)
	assert(opts.Cert.Gid == -1, "Cert.Gid = %d, want -1", opts.Cert.Gid)

	assert(opts.Key.Perm == 0o600, "Key.Perm = %04o, want 0600", opts.Key.Perm)
	assert(opts.Key.Uid == -1, "Key.Uid = %d, want -1", opts.Key.Uid)
	assert(opts.Key.Gid == -1, "Key.Gid = %d, want -1", opts.Key.Gid)
}

func TestResolveOpts_NilMeansDefaults(t *testing.T) {
	assert := newAsserter(t)
	opts := resolveOpts(nil)
	def := DefaultSecurityOpts()

	assert(opts.Cert == def.Cert, "Cert = %+v, want %+v", opts.Cert, def.Cert)
	assert(opts.Key == def.Key, "Key = %+v, want %+v", opts.Key, def.Key)
}

func TestResolveOpts_ZeroCertFilledWithRoleDefault(t *testing.T) {
	assert := newAsserter(t)
	opts := resolveOpts(&SecurityOpts{
		Key: FilePerm{Perm: 0o400, Uid: -1, Gid: -1},
	})

	// Cert was zero-valued; role default (0o644, -1, -1) applies.
	assert(opts.Cert.Perm == 0o644, "Cert.Perm = %04o, want 0644", opts.Cert.Perm)
	assert(opts.Cert.Uid == -1, "Cert.Uid = %d, want -1", opts.Cert.Uid)
	assert(opts.Cert.Gid == -1, "Cert.Gid = %d, want -1", opts.Cert.Gid)

	// Key was explicitly set; taken as-is.
	assert(opts.Key.Perm == 0o400, "Key.Perm = %04o, want 0400", opts.Key.Perm)
}

func TestResolveOpts_ZeroKeyFilledWithRoleDefault(t *testing.T) {
	assert := newAsserter(t)
	opts := resolveOpts(&SecurityOpts{
		Cert: FilePerm{Perm: 0o400, Uid: -1, Gid: -1},
	})

	// Key was zero-valued; role default (0o600, -1, -1) applies.
	assert(opts.Key.Perm == 0o600, "Key.Perm = %04o, want 0600", opts.Key.Perm)
	assert(opts.Key.Uid == -1, "Key.Uid = %d, want -1", opts.Key.Uid)
	assert(opts.Key.Gid == -1, "Key.Gid = %d, want -1", opts.Key.Gid)

	assert(opts.Cert.Perm == 0o400, "Cert.Perm = %04o, want 0400", opts.Cert.Perm)
}

func TestResolveOpts_ExplicitValuesPreserved(t *testing.T) {
	assert := newAsserter(t)
	opts := resolveOpts(&SecurityOpts{
		Cert: FilePerm{Perm: 0o644, Uid: 1000, Gid: 1000},
		Key:  FilePerm{Perm: 0o600, Uid: 1000, Gid: 1000},
	})

	assert(opts.Cert.Perm == 0o644, "Cert.Perm = %04o, want 0644", opts.Cert.Perm)
	assert(opts.Cert.Uid == 1000, "Cert.Uid = %d, want 1000", opts.Cert.Uid)
	assert(opts.Cert.Gid == 1000, "Cert.Gid = %d, want 1000", opts.Cert.Gid)
	assert(opts.Key.Perm == 0o600, "Key.Perm = %04o, want 0600", opts.Key.Perm)
	assert(opts.Key.Uid == 1000, "Key.Uid = %d, want 1000", opts.Key.Uid)
	assert(opts.Key.Gid == 1000, "Key.Gid = %d, want 1000", opts.Key.Gid)
}

func TestResolveOpts_PerFieldDefaults(t *testing.T) {
	assert := newAsserter(t)
	opts := resolveOpts(&SecurityOpts{
		Cert: FilePerm{Perm: 0o600},
	})

	// Perm was set explicitly; Uid/Gid are zero so they fall back to
	// -1 (skip) rather than literal "must be root".
	assert(opts.Cert.Perm == 0o600, "Cert.Perm = %04o, want 0600", opts.Cert.Perm)
	assert(opts.Cert.Uid == -1, "Cert.Uid = %d, want -1", opts.Cert.Uid)
	assert(opts.Cert.Gid == -1, "Cert.Gid = %d, want -1", opts.Cert.Gid)
}

func TestResolveOpts_ZeroUidBecomesSkip(t *testing.T) {
	assert := newAsserter(t)
	opts := resolveOpts(&SecurityOpts{
		Cert: FilePerm{Perm: 0o600, Uid: 0, Gid: 1000},
	})

	assert(opts.Cert.Uid == -1, "Cert.Uid = %d, want -1", opts.Cert.Uid)
	assert(opts.Cert.Gid == 1000, "Cert.Gid = %d, want 1000", opts.Cert.Gid)
}

func TestResolveOpts_DoesNotMutateInput(t *testing.T) {
	assert := newAsserter(t)
	original := &SecurityOpts{
		Cert: FilePerm{Perm: 0o400, Uid: -1, Gid: -1},
		Key:  FilePerm{Perm: 0o400, Uid: -1, Gid: -1},
	}
	_ = resolveOpts(original)

	// The original should not be modified.
	assert(original.Cert.Perm == 0o400, "resolveOpts mutated the input struct (Cert)")
	assert(original.Key.Perm == 0o400, "resolveOpts mutated the input struct (Key)")
}

func TestPermissionError_Format(t *testing.T) {
	assert := newAsserter(t)
	err := &PermissionError{
		Path:        "/etc/ssl/server.key",
		Mode:        fs.FileMode(0o640),
		AllowedMode: fs.FileMode(0o600),
		Role:        "key",
	}

	msg := err.Error()

	// Must be lowercase, no trailing punctuation.
	assert(!strings.HasSuffix(msg, ".") && !strings.HasSuffix(msg, "!"),
		"error has trailing punctuation: %s", msg)
	assert(strings.Contains(msg, "0640"), "error missing actual mode: %s", msg)
	assert(strings.Contains(msg, "0600"), "error missing allowed mode: %s", msg)
	assert(strings.Contains(msg, "key"), "error missing role: %s", msg)
	assert(strings.Contains(msg, "/etc/ssl/server.key"), "error missing path: %s", msg)
}

func TestPermissionError_ErrorsAs(t *testing.T) {
	assert := newAsserter(t)
	var err error = &PermissionError{
		Path:        "/tmp/test.key",
		Mode:        0o644,
		AllowedMode: 0o600,
		Role:        "key",
	}

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "errors.As failed for PermissionError")
	assert(permErr.Path == "/tmp/test.key", "Path = %q, want %q", permErr.Path, "/tmp/test.key")
}

func TestOwnershipError_FormatUID(t *testing.T) {
	assert := newAsserter(t)
	err := &OwnershipError{
		Path:      "/etc/ssl/ca.pem",
		ActualUID: 0,
		ActualGID: 0,
		ExpectUID: 1001,
		ExpectGID: 0,
	}

	msg := err.Error()

	assert(strings.Contains(msg, "uid"), "error should mention uid mismatch: %s", msg)
	assert(strings.Contains(msg, "1001"), "error missing expected uid: %s", msg)
}

func TestOwnershipError_FormatGID(t *testing.T) {
	assert := newAsserter(t)
	err := &OwnershipError{
		Path:      "/etc/ssl/ca.pem",
		ActualUID: 1001,
		ActualGID: 100,
		ExpectUID: 1001,
		ExpectGID: 1001,
	}

	msg := err.Error()

	assert(strings.Contains(msg, "gid"), "error should mention gid mismatch: %s", msg)
	assert(strings.Contains(msg, "100"), "error missing actual gid: %s", msg)
}

func TestOwnershipError_ErrorsAs(t *testing.T) {
	assert := newAsserter(t)
	var err error = &OwnershipError{
		Path:      "/tmp/test.pem",
		ActualUID: 0,
		ExpectUID: 1000,
	}

	var ownerErr *OwnershipError
	assert(errors.As(err, &ownerErr), "errors.As failed for OwnershipError")
	assert(ownerErr.Path == "/tmp/test.pem", "Path = %q, want %q", ownerErr.Path, "/tmp/test.pem")
}
