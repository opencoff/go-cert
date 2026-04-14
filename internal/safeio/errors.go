// errors.go - PermissionError and OwnershipError types
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
	"fmt"
	"io/fs"
)

// PermissionError is returned when a file or directory fails
// permission validation.
type PermissionError struct {
	Path        string
	Mode        fs.FileMode
	AllowedMode fs.FileMode
	Role        string // caller-supplied label: "ca", "cert", "key", "directory"
}

// Error implements the error interface.
func (e *PermissionError) Error() string {
	return fmt.Sprintf("%s file %q has mode %04o, maximum allowed is %04o",
		e.Role, e.Path, e.Mode.Perm(), e.AllowedMode.Perm())
}

// OwnershipError is returned when a file fails ownership validation.
type OwnershipError struct {
	Path      string
	ActualUID int
	ActualGID int
	ExpectUID int
	ExpectGID int
}

// Error implements the error interface.
func (e *OwnershipError) Error() string {
	if e.ActualUID != e.ExpectUID {
		return fmt.Sprintf("file %q owned by uid %d, expected uid %d",
			e.Path, e.ActualUID, e.ExpectUID)
	}
	return fmt.Sprintf("file %q owned by gid %d, expected gid %d",
		e.Path, e.ActualGID, e.ExpectGID)
}
