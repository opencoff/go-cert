# go-cert

[![GoDoc](https://pkg.go.dev/badge/github.com/opencoff/go-cert.svg)](https://pkg.go.dev/github.com/opencoff/go-cert)
[![Go Report Card](https://goreportcard.com/badge/github.com/opencoff/go-cert)](https://goreportcard.com/report/github.com/opencoff/go-cert)

Secure TLS certificate and CA pool loading with file permission and
ownership validation for Go. Zero external dependencies — stdlib only.

## Motivation

Loading TLS certificates from disk is straightforward in Go, but
production deployments need more than just parsing PEM. Key files left
group-readable, CA directories that are world-writable, or encrypted
keys that silently fail at runtime are all common misconfiguration
classes that surface as outages rather than clear errors.

`go-cert` adds a security-checked loading layer on top of the standard
library. Every file is opened via `openat(2)` through a secured
directory handle, then permission-checked via `fstat` on the open file
descriptor — no TOCTOU gap between check and read. The entire directory
hierarchy from `/` is audited for unsafe write bits. The default policy
is strict — a nil `SecurityOpts` gives you secure defaults — so the
zero-effort path is the secure path.

## Features

- **Permission-checked file I/O** — opens files via `openat(2)` through
  a cached `os.Root`, then validates permissions via `fstat` on the open
  fd. Group-writable and world-writable bits are always rejected
  (hardcoded security floor). Configurable permission mask and optional
  UID/GID ownership checks.
- **Directory hierarchy auditing** — walks from `/` to the target
  directory via chained `os.Root.OpenRoot` calls, rejecting
  group-writable or world-writable path components (sticky-bit
  directories like `/tmp` are exempt). Directory handles are cached
  across operations.
- **CA pool accumulation** — `Store` accumulates CA certificates from
  individual files, directories (with optional recursion), and the
  system trust store. `Finalize` produces the `*x509.CertPool` and
  releases directory handles. All operations share a single cached
  security context with CA-appropriate defaults (`Cert.Perm=0644`).
- **Cert+key pair loading** — the standalone `LoadCertKey` function
  handles full chains (leaf + intermediates), rejects encrypted keys
  with actionable `openssl` commands in the error message, and supports
  PKCS#1, PKCS#8, and EC key formats. Cert and key files are checked
  under independent policies (`Cert.Perm=0644`, `Key.Perm=0600` by
  default), so a shared, world-readable cert is fine while the key
  stays owner-only.
- **Opinionated TLS configs** — `ServerConfig` and `ClientConfig`
  return `*tls.Config` values with TLS 1.2 minimum and stdlib-managed
  cipher suites. mTLS is a one-argument toggle.
- **Structured errors** — `PermissionError` and `OwnershipError`
  types work with `errors.As` for programmatic handling.
- **Cross-platform** — full checks on Unix; graceful no-op on Windows.

## API Overview

### Security Policy

`SecurityOpts` controls file permission and ownership policy, split
by file role via the nested `FilePerm` type:

```go
type SecurityOpts struct {
    Cert   FilePerm               // policy for cert/CA files
    Key    FilePerm               // policy for private-key files (LoadCertKey only)
    Role   string                 // optional label for error messages
    Filter func(name string) bool // optional ReadDir filter
}

type FilePerm struct {
    Perm fs.FileMode
    Uid  int // -1 to skip ownership check
    Gid  int // -1 to skip ownership check
}
```

`Store` uses `Cert` (default `Perm=0644`) and ignores `Key`.
`LoadCertKey` uses `Cert` for the cert file (default `Perm=0644`) and
`Key` for the key file (default `Perm=0600`), each via its own
ephemeral security context.

Passing `nil` applies strict role-appropriate defaults. Ownership is
not checked by default (the common deployment pattern is a non-root
service loading root-owned files) — callers that want ownership
enforcement must set `Uid`/`Gid` explicitly (`Uid=0` means "must be
root"; use `-1` to skip). `DefaultSecurityOpts()` returns an explicit
copy. Group-writable and world-writable bits on files and directories
are always rejected regardless of `Perm`.

```go
// CA loading — Store uses Cert (default Perm=0644)
caStore := cert.NewStore(nil)

// Cert+key loading — cert@0644, key@0600 by default
tlsCert, err := cert.LoadCertKey("server.crt", "server.key", nil)

// Custom per-role policy
opts := &cert.SecurityOpts{
    Cert: cert.FilePerm{Perm: 0o644, Uid: 0, Gid: -1}, // must be root-owned
    Key:  cert.FilePerm{Perm: 0o400, Uid: 0, Gid: -1}, // read-only, root
}
tlsCert, err = cert.LoadCertKey("server.crt", "server.key", opts)
```

### CA Pool

`NewStore` and `NewSystemStore` create a `Store`.
`Store.LoadCAFile` and `Store.LoadCADir` accumulate certificates with
permission validation. `Store.Finalize` returns a `*Pool`: an
immutable, concurrency-safe value that wraps the assembled
`*x509.CertPool` together with per-cert provenance metadata.
`Pool.Pool()` exposes the `*x509.CertPool` for use with `tls.Config`,
`Pool.Source(cert)` returns the file path a cert was loaded from, and
`Pool.Sources()` / `Pool.Count()` mirror the `Store` introspection
methods for post-`Finalize` use.

`Finalize` is idempotent and releases all internal directory handles;
the returned `*Pool` remains valid after `Store.Close`.

```go
store := cert.NewStore(nil)
if _, err := store.LoadCADir("/etc/ssl/certs", false); err != nil {
    return err
}
pool, err := store.Finalize()
if err != nil {
    return err
}
store.Close()

cfg := &tls.Config{RootCAs: pool.Pool()}
```

`NewSystemStore` seeds the store from the OS trust store; system CAs
bypass permission checks since they are OS-managed.

### Caching and Reload

A `Store` caches directory handles for its lifetime — each unique
directory walked from `/` is opened once and reused for subsequent
operations in the same hierarchy. Permission changes to a directory
*after* its first access are not observed by later loads on the same
`Store`. This is intentional: it bounds file-descriptor use and keeps
reads consistent with the audit performed at first access. Operators
who want permission changes to take effect should use a fresh `Store`
per startup cycle (or per reload event) rather than expecting a
long-lived `Store` to pick them up.

### Certificate and Key Loading

`LoadCertKey(certFile, keyFile, opts)` loads a TLS certificate and
private key pair. It checks the cert file under `opts.Cert` (default
`Perm=0644`) and the key file under `opts.Key` (default `Perm=0600`)
via two independent ephemeral security contexts. The cert file may
contain a full chain. Encrypted keys are rejected with an error
message containing the exact `openssl` command to decrypt them.

### TLS Configuration

`ServerConfig` and `ClientConfig` return ready-to-use `*tls.Config`
values. Both set `MinVersion` to TLS 1.2 and leave `CipherSuites` nil
so Go's stdlib defaults (updated each release) govern cipher
selection. Passing a non-nil `clientCA` to `ServerConfig` enables
mutual TLS; passing a non-nil `clientCert` to `ClientConfig` does the
same on the client side.

#### TLS Config Options

Both `ServerConfig` and `ClientConfig` accept a variadic list of
`TLSOption` values applied after the opinionated defaults, so callers
can override them without writing new constructors:

```go
cfg := cert.ServerConfig(tlsCert, clientCA,
    cert.WithNextProtos("h2", "http/1.1"),
    cert.WithMinVersion(tls.VersionTLS13),
)
```

Available options:

- `WithMinVersion(v uint16)` — override the TLS 1.2 floor.
- `WithNextProtos(protos ...string)` — set ALPN protocols.
- `WithServerName(name string)` — set SNI / verification name (client-side).
- `WithClientAuth(mode tls.ClientAuthType)` — downgrade or change the
  server-side client-cert policy.
- `WithSPKIPins(pins ...[]byte)` — pin peer certificates by raw SHA-256
  SubjectPublicKeyInfo digests; fail-closed if no pin matches.
- `WithSessionTicketKeys(keys ...[32]byte)` — rotate ticket keys across
  server instances.

### Cert Expiry

`CertExpiry(cert)` returns the certificate in `tls.Certificate` with
the earliest `NotAfter` along with the duration remaining until that
cert expires (negative if already expired). Scans the leaf and all
shipped intermediates; returns whichever expires first. Root CAs are
not inspected because they live in the peer's trust store, not in
`tls.Certificate.Certificate`.

```go
c, remaining, err := cert.CertExpiry(tlsCert)
if err != nil {
    log.Fatal(err)
}
switch {
case remaining <= 0:
    log.Printf("EXPIRED: %s (expired %s ago)", c.Subject.CommonName, -remaining)
case remaining < 7*24*time.Hour:
    log.Printf("expiring soon: %s in %s", c.Subject.CommonName, remaining)
}
```

## Requirements

- Go 1.25 or later (for `os.Root` / `openat`-backed file access)
- No external dependencies

## License

See [LICENSE](LICENSE) for details.
