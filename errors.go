// errors.go - PermissionError and OwnershipError type aliases
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
	"github.com/opencoff/go-cert/internal/safeio"
)

// PermissionError is returned when a file fails permission validation.
// Callers can use errors.As to distinguish permission failures from
// I/O or parse errors.
type PermissionError = safeio.PermissionError

// OwnershipError is returned when a file fails ownership validation.
// Callers can use errors.As to distinguish ownership failures from
// I/O or parse errors.
type OwnershipError = safeio.OwnershipError
