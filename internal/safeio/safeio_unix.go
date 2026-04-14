// safeio_unix.go - Unix permission and ownership validation
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

//go:build unix

package safeio

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// securityEnforced is true on Unix: permission and ownership checks
// are real.
const securityEnforced = true

// defaultStatOwner extracts UID and GID from file info using syscall.
func defaultStatOwner(fi fs.FileInfo) (uid, gid int, err error) {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("safeio: unexpected stat type %T", fi.Sys())
	}
	return int(stat.Uid), int(stat.Gid), nil
}

// checkFilePerm checks permission bits and ownership on a FileInfo.
// It rejects non-regular files, then rejects group-writable and
// world-writable files, then checks against the configured Perm mask,
// then checks ownership. path is used only for error messages.
func (r *Root) checkFilePerm(fi fs.FileInfo, path string) error {
	// reject non-regular files (devices, sockets, FIFOs, etc.).
	// symlinks have already been resolved at this point.
	if !fi.Mode().IsRegular() {
		return &PermissionError{
			Path:        path,
			Mode:        fi.Mode(),
			AllowedMode: r.Perm,
			Role:        r.Role,
		}
	}

	perm := fi.Mode().Perm()
	allowed := r.Perm.Perm()

	// hardcoded floor: always reject group-writable and world-writable (0o022).
	// configurable mask: reject bits outside the allowed mask.
	if perm&0o022 != 0 || perm & ^allowed != 0 {
		return &PermissionError{
			Path:        path,
			Mode:        fi.Mode(),
			AllowedMode: r.Perm,
			Role:        r.Role,
		}
	}

	// check ownership
	if r.Uid != -1 || r.Gid != -1 {
		uid, gid, err := r.statOwner(fi)
		if err != nil {
			return fmt.Errorf("safeio: cannot determine ownership of %q: %w", path, err)
		}
		if r.Uid != -1 && uid != r.Uid {
			return &OwnershipError{
				Path:      path,
				ActualUID: uid,
				ActualGID: gid,
				ExpectUID: r.Uid,
				ExpectGID: r.Gid,
			}
		}
		if r.Gid != -1 && gid != r.Gid {
			return &OwnershipError{
				Path:      path,
				ActualUID: uid,
				ActualGID: gid,
				ExpectUID: r.Uid,
				ExpectGID: r.Gid,
			}
		}
	}

	return nil
}

// getRoot returns a cached *os.Root for dir, or walks from the
// deepest cached ancestor to dir, permission-checking and caching
// each intermediate directory along the way.
//
// dir must be an absolute, symlink-resolved path. The caller must
// hold r.mu — getRoot mutates r.dirs and is called only from the
// already-locked exported methods (ReadFile, ReadDir).
func (r *Root) getRoot(dir string) (*os.Root, error) {
	if root, ok := r.dirs[dir]; ok {
		return root, nil
	}

	var parts []string

	abs := filepath.Clean(dir)
	if abs != "/" {
		parts = strings.Split(abs[1:], string(filepath.Separator))
	}

	// find the deepest cached ancestor
	j := 0
	var current *os.Root
	for i := len(parts); i > 0; i-- {
		prefix := "/" + filepath.Join(parts[:i]...)
		if root, ok := r.dirs[prefix]; ok {
			current = root
			j = i
			break
		}
	}

	if current == nil {
		abs := "/"
		root, err := os.OpenRoot(abs)
		if err != nil {
			return nil, err
		}
		if err := checkRootDirPerm(root, abs); err != nil {
			root.Close()
			return nil, err
		}
		r.dirs[abs] = root
		current = root
	}

	// walk remaining components, caching each one
	for i := j; i < len(parts); i++ {
		next, err := current.OpenRoot(parts[i])
		if err != nil {
			return nil, err
		}

		path := "/" + filepath.Join(parts[:i+1]...)
		if err := checkRootDirPerm(next, path); err != nil {
			next.Close()
			return nil, err
		}

		r.dirs[path] = next
		current = next
	}

	return current, nil
}

// checkRootDirPerm stats "." on the open Root and checks for unsafe
// write permissions. Directories with the sticky bit (e.g., /tmp mode
// 1777) are exempt from group-writable and world-writable checks.
func checkRootDirPerm(root *os.Root, path string) error {
	fi, err := root.Stat(".")
	if err != nil {
		return err
	}
	return checkDirPerm(fi, path)
}

// checkDirPerm checks a single directory's permissions for unsafe
// write bits. Directories with the sticky bit are exempt.
func checkDirPerm(fi fs.FileInfo, path string) error {
	perm := fi.Mode().Perm()
	sticky := fi.Mode()&fs.ModeSticky != 0
	groupWritable := perm&0o020 != 0 && !sticky
	worldWritable := perm&0o002 != 0 && !sticky

	if groupWritable || worldWritable {
		return &PermissionError{
			Path:        path,
			Mode:        fi.Mode(),
			AllowedMode: 0o755,
			Role:        "directory",
		}
	}
	return nil
}
