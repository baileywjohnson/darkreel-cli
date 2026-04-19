# Security

## Threat model

darkreel-cli is a client for a [Darkreel](https://github.com/baileywjohnson/darkreel) server. All encryption and decryption happens locally; the server never sees plaintext.

### In scope

- **Hostile or compromised Darkreel server**: the CLI must not corrupt local state, exhaust memory, write outside its output directory, or leak the user's password given malicious responses.
- **MITM on the wire**: HTTPS is enforced by default for non-localhost URLs. All HTTP clients disable redirect following (so a malicious server cannot redirect auth requests to an unrelated host and harvest the bearer token). TLS 1.2 minimum is pinned on every client.
- **Local filesystem attackers with a different UID**: encrypted blobs and downloaded plaintext files are written with `0600` permissions. Temp directories are `0700`.
- **Terminal-injection attacks**: filenames and server error bodies are sanitized of control characters before display.

### Out of scope

- **Same-UID processes on the host.** While the CLI is running, `DRK_PASS` is recoverable from `/proc/<pid>/environ` by anyone who can read that file (same UID, root, a compromised sidecar). `os.Unsetenv` clears the Go runtime's environment map — useful for preventing subprocesses from inheriting the value — but it does not scrub kernel-visible environ. See the README "Security" section for detail. For hardened deployments, pass credentials via a secret manager or run the CLI on a dedicated host.
- **Kernel and Go-runtime side channels**: swap, core dumps, GC heap residue, memory compression. Sensitive `[]byte` buffers are zeroed on best-effort basis; this does not defend against a root attacker.
- **Attackers with write access to the binary** (e.g., tampered build artifacts). Use the signed release checksums.

## Cryptographic notes

- AES-256-GCM with 12-byte random nonce; AAD binding identical to the server (`UTF8(mediaID) || BigEndian(uint64(chunkIndex))` for chunks, `UTF8(mediaID)` for file-key wrapping, `UTF8(userID)` for master-key unwrap).
- Master-key derivation: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output. Parameters must match the server; any divergence breaks compatibility and is caught by the test suite.
- Recovery codes are never held by the CLI — they are server-issued artifacts from account creation flows.

## Network hardening

- TLS `MinVersion` pinned to 1.2 on every HTTP client via `newHTTPTransport()`. Go's default CA store is used for verification; `InsecureSkipVerify` is never set.
- Redirect following is disabled on all clients (`CheckRedirect` returns `http.ErrUseLastResponse`), so a compromised or MITM'd server cannot bounce an authenticated request to a different origin and capture the `Authorization` header.
- Response-body size limits: 1 MB for login responses, 5 MB for media list JSON, 20 MB per downloaded chunk, 1 MB for encrypted metadata.
- URL schemes other than `http` and `https` are rejected before any request is sent. `-insecure` is required to use `http://` for non-localhost URLs.

## Subprocess hardening

- All `ffmpeg` / `ffprobe` invocations use `exec.Command` with argument arrays — no shell.
- File paths passed to subprocesses are resolved to absolute form so a leading `-` cannot be interpreted as a flag.
- All subprocesses have a 10-minute context-enforced timeout.
- `ffprobe` stdout is capped at 1 MB via a `limitWriter`; output beyond the cap is silently discarded and treated as probe failure.
- The CLI does not inherit its parent's environment to subprocesses beyond what Go's default `exec.Command` does. It does *not* explicitly scrub `DRK_PASS` before spawning `ffmpeg`/`ffprobe`, because `os.Unsetenv("DRK_PASS")` has already run by that point — but note the `/proc/environ` caveat above if the subprocess itself is a threat.

## Reporting a vulnerability

Email **baileywjohnson@gmail.com** with details. Please do not open a public issue for unfixed vulnerabilities. Include version, reproduction steps, and threat-model assumptions.

## Supported versions

Only the latest tagged release receives security updates. Binaries are built and signed via GitHub Actions; verify the `SHA256SUMS` file before running.

## Dependency hygiene

`govulncheck` runs on every push, PR, and weekly in CI (see `.github/workflows/security.yml`).
