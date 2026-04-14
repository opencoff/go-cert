// safeio_unix_test.go - unix-only tests (FIFO/non-regular rejection)
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
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestReadFile_NonRegularFile_Rejected verifies that a FIFO (or any
// other non-regular file) is rejected by checkFilePerm. This mirrors
// the IsRegular() guard in safeio_unix.go's checkFilePerm.
//
// Opening a FIFO with os.Open blocks until a writer appears, so we
// stat it directly and invoke checkFilePerm — the guard we care about.
func TestReadFile_NonRegularFile_Rejected(t *testing.T) {
	skipIfRoot(t)
	assert := newAsserter(t)

	dir := safeTempDir(t)
	fifo := filepath.Join(dir, "fifo.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("syscall.Mkfifo unavailable: %v", err)
	}

	fi, err := os.Lstat(fifo)
	assert(err == nil, "Lstat fifo: %v", err)

	r := NewRoot(&SecurityOpts{Perm: 0o600, Uid: -1, Gid: -1})
	defer r.Close()

	err = r.checkFilePerm(fi, fifo)
	assert(err != nil, "expected checkFilePerm to reject non-regular file")

	var permErr *PermissionError
	assert(errors.As(err, &permErr), "expected *PermissionError, got %T: %v", err, err)
}
