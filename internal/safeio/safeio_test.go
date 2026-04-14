// safeio_test.go - tests for secure file I/O layer
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

package safeio

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
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

// safeTempDir returns a t.TempDir() with permissions fixed to 0755.
// On macOS, t.TempDir() creates directories with mode 0775 which
// triggers the group-writable check.
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

// --- Permission Matrix ---

func TestCheckFilePerm_PermissionMatrix(t *testing.T) {
	skipIfRoot(t)

	tests := []struct {
		name    string
		mode    fs.FileMode
		perm    fs.FileMode
		wantErr bool
	}{
		// key file checks (max 0600)
		{"key 0600 OK", 0o600, 0o600, false},
		{"key 0400 OK", 0o400, 0o600, false},
		{"key 0640 reject", 0o640, 0o600, true},
		{"key 0644 reject", 0o644, 0o600, true},
		{"key 0660 reject", 0o660, 0o600, true},

		// CA file checks (max 0644)
		{"ca 0644 OK", 0o644, 0o644, false},
		{"ca 0444 OK", 0o444, 0o644, false},
		{"ca 0600 OK", 0o600, 0o644, false},
		{"ca 0646 reject", 0o646, 0o644, true},
		{"ca 0664 reject", 0o664, 0o644, true},
		{"ca 0666 reject", 0o666, 0o644, true},

		// hardcoded floor: group/world-write always rejected
		{"grp-write 0620 reject", 0o620, 0o644, true},
		{"world-write 0602 reject", 0o602, 0o644, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := newAsserter(t)
			dir := safeTempDir(t)
			path := filepath.Join(dir, "testfile")
			writeFileChmod(t, path, []byte("test"), tt.mode)

			fi, err := os.Stat(path)
			assert(err == nil, "Stat: %v", err)

			r := NewRoot(&SecurityOpts{Perm: tt.perm, Uid: -1, Gid: -1})
			defer r.Close()

			err = r.checkFilePerm(fi, path)
			if tt.wantErr {
				assert(err != nil, "checkFilePerm() expected error for mode %04o", tt.mode)
				var permErr *PermissionError
				assert(errors.As(err, &permErr), "expected PermissionError, got %T: %v", err, err)
			} else {
				assert(err == nil, "checkFilePerm() unexpected error: %v", err)
			}
		})
	}
}

// --- Ownership ---

func TestCheckFilePerm_OwnershipMismatch(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	path := filepath.Join(dir, "testfile")
	writeFileChmod(t, path, []byte("test"), 0o600)

	fi, err := os.Stat(path)
	assert(err == nil, "Stat: %v", err)

	// file is owned by euid; expect UID 9999 → mismatch
	r := NewRoot(&SecurityOpts{Perm: 0o600, Uid: 9999, Gid: -1})
	defer r.Close()

	err = r.checkFilePerm(fi, path)
	assert(err != nil, "expected ownership error, got nil")

	var ownerErr *OwnershipError
	assert(errors.As(err, &ownerErr), "expected OwnershipError, got %T: %v", err, err)
	assert(ownerErr.ActualUID == os.Geteuid(), "ActualUID = %d, want %d", ownerErr.ActualUID, os.Geteuid())
}

func TestCheckFilePerm_OwnershipSkipUID(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	path := filepath.Join(dir, "testfile")
	writeFileChmod(t, path, []byte("test"), 0o600)

	fi, err := os.Stat(path)
	assert(err == nil, "Stat: %v", err)

	// get actual file GID (may differ from egid on macOS /tmp)
	_, fileGid, err := defaultStatOwner(fi)
	assert(err == nil, "statOwner: %v", err)

	// UID=-1 skips UID check; GID matches real file owner
	r := NewRoot(&SecurityOpts{Perm: 0o600, Uid: -1, Gid: fileGid})
	defer r.Close()

	err = r.checkFilePerm(fi, path)
	assert(err == nil, "expected nil (UID skip), got: %v", err)
}

func TestCheckFilePerm_OwnershipSkipGID(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	path := filepath.Join(dir, "testfile")
	writeFileChmod(t, path, []byte("test"), 0o600)

	fi, err := os.Stat(path)
	assert(err == nil, "Stat: %v", err)

	// GID=-1 skips GID check; UID matches real file owner
	r := NewRoot(&SecurityOpts{Perm: 0o600, Uid: os.Geteuid(), Gid: -1})
	defer r.Close()

	err = r.checkFilePerm(fi, path)
	assert(err == nil, "expected nil (GID skip), got: %v", err)
}

func TestCheckFilePerm_MockedOwnership(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	path := filepath.Join(dir, "testfile")
	writeFileChmod(t, path, []byte("test"), 0o600)

	fi, err := os.Stat(path)
	assert(err == nil, "Stat: %v", err)

	// inject a mock statOwner that returns arbitrary UID/GID without
	// relying on real filesystem ownership.
	r := NewRoot(&SecurityOpts{Perm: 0o600, Uid: 4242, Gid: 4242})
	r.statOwner = func(_ fs.FileInfo) (int, int, error) {
		return 4242, 4242, nil
	}
	defer r.Close()

	err = r.checkFilePerm(fi, path)
	assert(err == nil, "expected nil with matching mocked ownership, got: %v", err)

	// now mock a mismatch on UID.
	r.statOwner = func(_ fs.FileInfo) (int, int, error) {
		return 1, 4242, nil
	}
	err = r.checkFilePerm(fi, path)
	assert(err != nil, "expected ownership error with mocked UID mismatch")

	var ownerErr *OwnershipError
	assert(errors.As(err, &ownerErr), "expected OwnershipError, got %T: %v", err, err)
	assert(ownerErr.ActualUID == 1, "ActualUID = %d, want 1", ownerErr.ActualUID)
	assert(ownerErr.ExpectUID == 4242, "ExpectUID = %d, want 4242", ownerErr.ExpectUID)
}

func TestCheckFilePerm_OwnershipMatch(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	path := filepath.Join(dir, "testfile")
	writeFileChmod(t, path, []byte("test"), 0o600)

	fi, err := os.Stat(path)
	assert(err == nil, "Stat: %v", err)

	// get actual file UID/GID (may differ from euid/egid on macOS /tmp)
	fileUid, fileGid, err := defaultStatOwner(fi)
	assert(err == nil, "statOwner: %v", err)

	// both UID and GID match real file owner
	r := NewRoot(&SecurityOpts{Perm: 0o600, Uid: fileUid, Gid: fileGid})
	defer r.Close()

	err = r.checkFilePerm(fi, path)
	assert(err == nil, "expected nil, got: %v", err)
}

// --- getRoot ---

func TestGetRoot_WorldWritable(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	parent := t.TempDir()
	bad := filepath.Join(parent, "writable")
	mkdirChmod(t, bad, 0o777)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	_, err := r.getRoot(bad)
	assert(err != nil, "expected error for world-writable directory")

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "expected PermissionError, got %T: %v", err, err)
	assert(permErr.Role == "directory", "Role = %q, want %q", permErr.Role, "directory")
}

func TestGetRoot_GroupWritable(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	parent := t.TempDir()
	bad := filepath.Join(parent, "groupwr")
	mkdirChmod(t, bad, 0o770)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	_, err := r.getRoot(bad)
	assert(err != nil, "expected error for group-writable directory")
}

func TestGetRoot_StickyWorldWritable(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	parent := safeTempDir(t)
	sticky := filepath.Join(parent, "sticky")
	mkdirChmod(t, sticky, 0o1777)

	fi, err := os.Stat(sticky)
	assert(err == nil, "Stat: %v", err)
	if fi.Mode().Perm()&0o002 == 0 {
		t.Skip("chmod did not set world-writable bit")
	}
	if fi.Mode()&fs.ModeSticky == 0 {
		t.Skip("chmod did not set sticky bit")
	}

	child := filepath.Join(sticky, "child")
	mkdirChmod(t, child, 0o755)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	_, err = r.getRoot(child)
	assert(err == nil, "sticky+world-writable parent should be accepted, got: %v", err)
}

func TestGetRoot_SafeDir(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	safe := safeTempDir(t)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	_, err := r.getRoot(safe)
	assert(err == nil, "expected nil for safe directory, got: %v", err)
}

func TestGetRoot_NestedBadParent(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	top := t.TempDir()
	bad := filepath.Join(top, "bad")
	mkdirChmod(t, bad, 0o777)

	child := filepath.Join(bad, "child")
	mkdirChmod(t, child, 0o755)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	_, err := r.getRoot(child)
	assert(err != nil, "expected error due to world-writable parent")
}

func TestGetRoot_Symlink(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	top := safeTempDir(t)
	real := filepath.Join(top, "real")
	mkdirChmod(t, real, 0o755)
	link := filepath.Join(top, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	resolved, err := filepath.EvalSymlinks(link)
	assert(err == nil, "EvalSymlinks: %v", err)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	_, err = r.getRoot(resolved)
	assert(err == nil, "expected nil for resolved symlink to safe dir, got: %v", err)
}

func TestGetRoot_CachesIntermediates(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	top := safeTempDir(t)
	a := filepath.Join(top, "a")
	mkdirChmod(t, a, 0o755)
	b := filepath.Join(a, "b")
	mkdirChmod(t, b, 0o755)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	_, err := r.getRoot(b)
	assert(err == nil, "getRoot: %v", err)

	// every component from "/" down to b should be cached
	_, ok := r.dirs["/"]
	assert(ok, "expected / to be cached")
	_, ok = r.dirs[top]
	assert(ok, "expected %s to be cached", top)
	_, ok = r.dirs[a]
	assert(ok, "expected %s to be cached", a)
	_, ok = r.dirs[b]
	assert(ok, "expected %s to be cached", b)
}

func TestGetRoot_ReusesPrefix(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	top := safeTempDir(t)
	a := filepath.Join(top, "a")
	mkdirChmod(t, a, 0o755)
	b := filepath.Join(top, "b")
	mkdirChmod(t, b, 0o755)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	_, err := r.getRoot(a)
	assert(err == nil, "getRoot(a): %v", err)
	countAfterFirst := len(r.dirs)

	// second sibling shares the entire prefix up to top
	_, err = r.getRoot(b)
	assert(err == nil, "getRoot(b): %v", err)

	// only one new entry (b itself) should be added
	assert(len(r.dirs) == countAfterFirst+1,
		"expected %d cached roots, got %d", countAfterFirst+1, len(r.dirs))
}

// --- ReadFile ---

func TestReadFile_OK(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	path := filepath.Join(dir, "test.pem")
	writeFileChmod(t, path, []byte("hello"), 0o644)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile(path)
	assert(err == nil, "ReadFile: %v", err)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	assert(err == nil, "ReadAll: %v", err)
	assert(string(data) == "hello", "got %q, want %q", data, "hello")
}

func TestReadFile_BadPerms(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	path := filepath.Join(dir, "test.key")
	writeFileChmod(t, path, []byte("secret"), 0o644)

	r := NewRoot(&SecurityOpts{Perm: 0o600, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile(path)
	if rc != nil {
		rc.Close()
	}
	assert(err != nil, "expected permission error")

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "expected PermissionError, got %T: %v", err, err)
}

func TestReadFile_FollowsSymlinks(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	real := filepath.Join(dir, "real.pem")
	writeFileChmod(t, real, []byte("symlinked"), 0o644)
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile(link)
	assert(err == nil, "ReadFile via symlink: %v", err)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	assert(err == nil, "ReadAll: %v", err)
	assert(string(data) == "symlinked", "got %q, want %q", data, "symlinked")
}

func TestReadFile_SymlinkBadPerms(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	real := filepath.Join(dir, "real.key")
	writeFileChmod(t, real, []byte("secret"), 0o644)
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	r := NewRoot(&SecurityOpts{Perm: 0o600, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile(link)
	if rc != nil {
		rc.Close()
	}
	assert(err != nil, "expected error for symlink to file with bad perms")
}

func TestReadFile_Nonexistent(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile("/nonexistent/file.pem")
	if rc != nil {
		rc.Close()
	}
	assert(err != nil, "expected error for nonexistent file")
}

func TestReadFile_CachesRoot(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writeFileChmod(t, filepath.Join(dir, "a.pem"), []byte("a"), 0o644)
	writeFileChmod(t, filepath.Join(dir, "b.pem"), []byte("b"), 0o644)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile(filepath.Join(dir, "a.pem"))
	assert(err == nil, "ReadFile a.pem: %v", err)
	rc.Close()

	countAfterFirst := len(r.dirs)

	rc, err = r.ReadFile(filepath.Join(dir, "b.pem"))
	assert(err == nil, "ReadFile b.pem: %v", err)
	rc.Close()

	// white-box: second file in same dir should reuse the cache entirely
	assert(len(r.dirs) == countAfterFirst,
		"expected %d cached roots (unchanged), got %d", countAfterFirst, len(r.dirs))
}

// --- ReadDir ---

func TestReadDir_OK(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writeFileChmod(t, filepath.Join(dir, "a.pem"), []byte("aaa"), 0o644)
	writeFileChmod(t, filepath.Join(dir, "b.pem"), []byte("bbb"), 0o644)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	var names []string
	err := r.ReadDir(dir, false, func(name string, rd io.Reader) error {
		data, err := io.ReadAll(rd)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			t.Errorf("empty data for %s", name)
		}
		names = append(names, name)
		return nil
	})
	assert(err == nil, "ReadDir: %v", err)
	assert(len(names) == 2, "expected 2 files, got %d: %v", len(names), names)
}

func TestReadDir_WithFilter(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writeFileChmod(t, filepath.Join(dir, "cert.pem"), []byte("cert"), 0o644)
	writeFileChmod(t, filepath.Join(dir, "readme.txt"), []byte("text"), 0o644)
	writeFileChmod(t, filepath.Join(dir, "data.json"), []byte("{}"), 0o644)

	filter := func(name string) bool {
		return filepath.Ext(name) != ".pem"
	}

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1, Filter: filter})
	defer r.Close()

	var names []string
	err := r.ReadDir(dir, false, func(name string, rd io.Reader) error {
		names = append(names, name)
		return nil
	})
	assert(err == nil, "ReadDir: %v", err)
	assert(len(names) == 1 && names[0] == filepath.Join(dir, "cert.pem"),
		"expected [%s], got %v", filepath.Join(dir, "cert.pem"), names)
}

func TestReadDir_Recursive(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writeFileChmod(t, filepath.Join(dir, "top.pem"), []byte("top"), 0o644)
	sub := filepath.Join(dir, "sub")
	mkdirChmod(t, sub, 0o755)
	writeFileChmod(t, filepath.Join(sub, "nested.pem"), []byte("nested"), 0o644)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	var names []string
	err := r.ReadDir(dir, true, func(name string, rd io.Reader) error {
		names = append(names, name)
		return nil
	})
	assert(err == nil, "ReadDir recursive: %v", err)
	assert(len(names) == 2, "expected 2 files, got %d: %v", len(names), names)
}

func TestReadDir_RecursiveBadSubdirPerm(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writeFileChmod(t, filepath.Join(dir, "top.pem"), []byte("top"), 0o644)

	// subdirectory with world-writable permissions — must be rejected
	bad := filepath.Join(dir, "bad")
	mkdirChmod(t, bad, 0o777)
	writeFileChmod(t, filepath.Join(bad, "nested.pem"), []byte("nested"), 0o644)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	err := r.ReadDir(dir, true, func(name string, rd io.Reader) error {
		return nil
	})
	assert(err != nil, "expected error for world-writable subdirectory in recursive walk")

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "expected PermissionError, got %T: %v", err, err)
}

func TestReadDir_NonRecursiveSkipsSubdir(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writeFileChmod(t, filepath.Join(dir, "top.pem"), []byte("top"), 0o644)
	sub := filepath.Join(dir, "sub")
	mkdirChmod(t, sub, 0o755)
	writeFileChmod(t, filepath.Join(sub, "nested.pem"), []byte("nested"), 0o644)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	var names []string
	err := r.ReadDir(dir, false, func(name string, rd io.Reader) error {
		names = append(names, name)
		return nil
	})
	assert(err == nil, "ReadDir: %v", err)
	assert(len(names) == 1 && names[0] == filepath.Join(dir, "top.pem"),
		"expected [%s], got %v", filepath.Join(dir, "top.pem"), names)
}

func TestReadDir_BadPermFile(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writeFileChmod(t, filepath.Join(dir, "good.pem"), []byte("good"), 0o644)
	writeFileChmod(t, filepath.Join(dir, "bad.pem"), []byte("bad"), 0o666)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	err := r.ReadDir(dir, false, func(name string, rd io.Reader) error {
		return nil
	})
	assert(err != nil, "expected permission error for bad.pem")

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "expected PermissionError, got %T: %v", err, err)
}

func TestReadDir_Empty(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	var count int
	err := r.ReadDir(dir, false, func(name string, rd io.Reader) error {
		count++
		return nil
	})
	assert(err == nil, "ReadDir: %v", err)
	assert(count == 0, "expected 0 callbacks, got %d", count)
}

func TestReadDir_WorldWritableDir(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	parent := t.TempDir()
	bad := filepath.Join(parent, "unsafe")
	mkdirChmod(t, bad, 0o777)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	err := r.ReadDir(bad, false, func(name string, rd io.Reader) error {
		return nil
	})
	assert(err != nil, "expected error for world-writable directory")
}

// --- Close ---

func TestClose_Idempotent(t *testing.T) {
	assert := newAsserter(t)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	err := r.Close()
	assert(err == nil, "first Close: %v", err)
	err = r.Close()
	assert(err == nil, "second Close should return nil, got: %v", err)
}

func TestClose_InvalidatesReadFile(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	path := filepath.Join(dir, "test.pem")
	writeFileChmod(t, path, []byte("data"), 0o644)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	r.Close()

	rc, err := r.ReadFile(path)
	if rc != nil {
		rc.Close()
	}
	assert(err != nil, "expected error after Close")
}

func TestClose_InvalidatesReadDir(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	r.Close()

	err := r.ReadDir(dir, false, func(name string, rd io.Reader) error {
		return nil
	})
	assert(err != nil, "expected error after Close")
}

// --- Symlink / path-resolution edge cases ---

// TestReadFile_SymlinkTargetParentWorldWritable verifies that when a
// symlink in a safe directory resolves to a target whose own parent
// chain contains a world-writable directory, the hierarchy audit on
// the resolved path rejects the read with a PermissionError whose
// Role is "directory".
func TestReadFile_SymlinkTargetParentWorldWritable(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	safe := safeTempDir(t)
	unsafeParent := filepath.Join(safe, "unsafe")
	mkdirChmod(t, unsafeParent, 0o777)

	real := filepath.Join(unsafeParent, "real.pem")
	writeFileChmod(t, real, []byte("secret"), 0o600)

	link := filepath.Join(safe, "link.pem")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile(link)
	if rc != nil {
		rc.Close()
	}
	assert(err != nil, "expected error for symlink target with unsafe parent")

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "expected PermissionError, got %T: %v", err, err)
	assert(permErr.Role == "directory", "Role = %q, want %q", permErr.Role, "directory")
}

// TestReadFile_SymlinkChain_UnsafeLeaf verifies a multi-hop symlink
// chain that eventually resolves inside a world-writable directory is
// rejected.
func TestReadFile_SymlinkChain_UnsafeLeaf(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	safe := safeTempDir(t)
	unsafeParent := filepath.Join(safe, "unsafe")
	mkdirChmod(t, unsafeParent, 0o777)

	final := filepath.Join(unsafeParent, "final.pem")
	writeFileChmod(t, final, []byte("secret"), 0o600)

	link2 := filepath.Join(safe, "link2.pem")
	if err := os.Symlink(final, link2); err != nil {
		t.Fatal(err)
	}
	link1 := filepath.Join(safe, "link1.pem")
	if err := os.Symlink(link2, link1); err != nil {
		t.Fatal(err)
	}

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile(link1)
	if rc != nil {
		rc.Close()
	}
	assert(err != nil, "expected error for chained symlink to unsafe target")
}

// TestReadFile_SymlinkLoop verifies that a symlink cycle does not
// cause an infinite loop; filepath.EvalSymlinks should return ELOOP.
func TestReadFile_SymlinkLoop(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile(a)
	if rc != nil {
		rc.Close()
	}
	assert(err != nil, "expected error for symlink loop")
}

// TestReadDir_EscapingSymlink_NotFollowed verifies that a symlink
// inside a directory whose target escapes the root is NOT followed by
// the ReadDir walk. Directory entries that are not regular files are
// skipped — symlinks are neither opened nor passed to the callback,
// so an escaping symlink cannot leak data from outside the root.
func TestReadDir_EscapingSymlink_NotFollowed(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writeFileChmod(t, filepath.Join(dir, "good.pem"), []byte("ok"), 0o644)

	// symlink that escapes the directory: target is /etc/hosts (absolute,
	// outside the root).
	escape := filepath.Join(dir, "evil.pem")
	if err := os.Symlink("/etc/hosts", escape); err != nil {
		t.Fatal(err)
	}

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	var seen []string
	err := r.ReadDir(dir, false, func(name string, rd io.Reader) error {
		seen = append(seen, filepath.Base(name))
		return nil
	})
	assert(err == nil, "ReadDir returned unexpected error: %v", err)
	assert(len(seen) == 1 && seen[0] == "good.pem",
		"expected only good.pem, got %v", seen)
}

// TestReadDir_SymlinkCycle_NoInfiniteLoop verifies the recursive walk
// terminates (with or without an error) when it encounters a symlink
// cycle. We wrap the call in a goroutine + time.AfterFunc guard so the
// test fails cleanly instead of hanging the suite.
func TestReadDir_SymlinkCycle_NoInfiniteLoop(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writeFileChmod(t, filepath.Join(dir, "a.pem"), []byte("a"), 0o644)
	// self-referencing symlink: link -> dir
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink(dir, loop); err != nil {
		t.Fatal(err)
	}

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.ReadDir(dir, true, func(name string, rd io.Reader) error {
			return nil
		})
	}()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		// terminated — success whether err was nil or not.
	case <-timer.C:
		assert(false, "ReadDir did not terminate within 5s (symlink cycle)")
	}
}

// TestReadFile_PathWithDotDot verifies that a path containing ".."
// components is canonicalized before permission checks, and a file
// reachable via "./sub/../ca.pem" is read exactly like "./ca.pem".
func TestReadFile_PathWithDotDot(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	sub := filepath.Join(dir, "sub")
	mkdirChmod(t, sub, 0o755)
	writeFileChmod(t, filepath.Join(dir, "ca.pem"), []byte("root"), 0o644)

	// path with "sub/.." that should cleanly resolve to dir/ca.pem
	messy := filepath.Join(dir, "sub", "..", "ca.pem")

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile(messy)
	assert(err == nil, "ReadFile with .. path: %v", err)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	assert(err == nil, "ReadAll: %v", err)
	assert(string(data) == "root", "got %q, want %q", data, "root")
}

// TestReadFile_RelativePath verifies ReadFile resolves a relative path
// against the current working directory. The test chdirs to a safe
// temp dir for the duration and restores the previous cwd after.
func TestReadFile_RelativePath(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	writeFileChmod(t, filepath.Join(dir, "ca.pem"), []byte("abs"), 0o644)

	prev, err := os.Getwd()
	assert(err == nil, "Getwd: %v", err)
	defer func() {
		_ = os.Chdir(prev)
	}()
	assert(os.Chdir(dir) == nil, "Chdir: dir=%s", dir)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	rc, err := r.ReadFile("ca.pem")
	assert(err == nil, "ReadFile relative path: %v", err)
	defer rc.Close()

	data, err := io.ReadAll(rc)
	assert(err == nil, "ReadAll: %v", err)
	assert(string(data) == "abs", "got %q, want %q", data, "abs")
}

// TestRoot_ConcurrentReadFile verifies that ReadFile is safe under
// concurrent use. It launches many goroutines reading the same file
// through one Root and asserts every result is correct. Run under
// -race to catch missing locks around shared state (the dirs cache,
// in particular).
func TestRoot_ConcurrentReadFile(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	want := []byte("concurrent-read-bytes")
	path := filepath.Join(dir, "ca.pem")
	writeFileChmod(t, path, want, 0o644)

	r := NewRoot(&SecurityOpts{Perm: 0o644, Uid: -1, Gid: -1})
	defer r.Close()

	const N = 50
	var wg sync.WaitGroup
	errs := make(chan error, N)
	bufs := make(chan []byte, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, err := r.ReadFile(path)
			if err != nil {
				errs <- err
				return
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				errs <- err
				return
			}
			bufs <- data
		}()
	}
	wg.Wait()
	close(errs)
	close(bufs)

	for err := range errs {
		assert(err == nil, "concurrent ReadFile: %v", err)
	}
	count := 0
	for got := range bufs {
		assert(bytes.Equal(got, want), "got %q, want %q", got, want)
		count++
	}
	assert(count == N, "got %d successful reads, want %d", count, N)
}
