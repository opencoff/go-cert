// loadcert.go - standalone LoadCertKey function, encrypted key detection
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
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/opencoff/go-cert/internal/safeio"
)

// LoadCertKey loads a TLS certificate and private key from the given
// files with permission validation. The cert file is checked against
// opts.Cert (default Perm=0o644); the key file is checked against
// opts.Key (default Perm=0o600). The cert file may contain a full
// chain (leaf + intermediates). Encrypted keys are rejected with
// actionable error messages.
//
// On Windows, permission and ownership checks are no-ops; query
// SecurityEnforced to detect this at runtime.
//
// If opts is nil, strict defaults are used (Cert: Perm=0o644, Uid=-1,
// Gid=-1; Key: Perm=0o600, Uid=-1, Gid=-1).
func LoadCertKey(certFile, keyFile string, opts *SecurityOpts) (tls.Certificate, error) {
	o := resolveOpts(opts)

	certRole := o.Role
	if certRole == "" {
		certRole = "cert"
	}
	keyRole := o.Role
	if keyRole == "" {
		keyRole = "key"
	}

	certRoot := safeio.NewRoot(toSafeIO(o.Cert, certRole, nil))
	certPEM, err := readAll(certRoot, certFile)
	certRoot.Close()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: %w", err)
	}

	keyRoot := safeio.NewRoot(toSafeIO(o.Key, keyRole, nil))
	keyPEM, err := readAll(keyRoot, keyFile)
	keyRoot.Close()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: %w", err)
	}

	if err := checkEncryptedKey(keyPEM, keyFile); err != nil {
		return tls.Certificate{}, err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: %w", err)
	}

	return tlsCert, nil
}

// checkEncryptedKey inspects PEM data for encrypted key indicators
// and returns an actionable error if the key is encrypted. It scans
// every PEM block in the file and applies the encryption checks to
// the first block whose Type identifies a private key. Non-private-key
// blocks (e.g., CERTIFICATE) are skipped so that files with leading
// junk or a bundled chain are still audited correctly.
func checkEncryptedKey(keyPEM []byte, path string) error {
	rest := keyPEM
	sawAnyBlock := false

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawAnyBlock = true

		if !strings.Contains(strings.ToUpper(block.Type), "PRIVATE KEY") {
			continue
		}

		if block.Type == "ENCRYPTED PRIVATE KEY" {
			return fmt.Errorf("cert: encrypted PKCS#8 keys not supported; convert with: openssl pkcs8 -topk8 -nocrypt -in %s -out plain.key", path)
		}

		if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
			return fmt.Errorf("cert: legacy encrypted PEM keys not supported; convert with: openssl pkcs8 -topk8 -nocrypt -in %s -out plain.key", path)
		}

		// First private-key-class block is unencrypted: accept.
		return nil
	}

	if !sawAnyBlock {
		return fmt.Errorf("cert: no PEM data found in key file %q", path)
	}

	return fmt.Errorf("cert: no private key PEM block found in %q", path)
}
