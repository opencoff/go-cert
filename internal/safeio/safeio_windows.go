// safeio_windows.go - no-op permission and ownership stubs for Windows
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

//go:build windows

// On Windows, Unix-style file permission and ownership checks are not
// available. Permission and ownership validation functions are no-ops.
// secureRoot opens the directory directly without a permission audit.

package safeio

import (
	"io/fs"
	"os"
)

// securityEnforced is false on Windows: permission and ownership
// checks are no-ops.
const securityEnforced = false

// defaultStatOwner is a no-op on Windows.
func defaultStatOwner(fi fs.FileInfo) (uid, gid int, err error) {
	return 0, 0, nil
}

// checkFilePerm is a no-op on Windows.
func (r *Root) checkFilePerm(fi fs.FileInfo, path string) error {
	return nil
}

// checkDirPerm is a no-op on Windows.
func checkDirPerm(fi fs.FileInfo, path string) error {
	return nil
}

// getRoot returns a cached *os.Root for dir, or opens it directly.
// On Windows, no directory permission audit is performed.
//
// The caller must hold r.mu — getRoot mutates r.dirs and is called
// only from the already-locked exported methods (ReadFile, ReadDir).
func (r *Root) getRoot(dir string) (*os.Root, error) {
	if root, ok := r.dirs[dir]; ok {
		return root, nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	r.dirs[dir] = root
	return root, nil
}
