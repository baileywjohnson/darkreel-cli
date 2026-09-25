# Security

## Threat model

darkreel-cli is a client for a [Darkreel](https://github.com/baileywjohnson/darkreel) server. All encryption and decryption happens locally; the server never sees plaintext.

### In scope

- **Hostile or compromised Darkreel server's responses**: whatever the server returns, the CLI must not exhaust memory, write outside its output directory, overwrite existing files, inject terminal escape sequences, or seal file keys to a key other than the account's own (the login response's public key is checked against the decrypted private key). Item IDs must be canonical UUIDs; anything else is dropped.
- **MITM on the wire**: HTTPS is enforced by default for non-localhost URLs. All HTTP clients disable redirect following (so a malicious server cannot redirect auth requests to an unrelated host and harvest the bearer token). TLS 1.2 minimum is pinned on every client.
- **Local filesystem attackers with a different UID**: encrypted blobs and downloaded plaintext files are written with `0600` permissions. Temp directories are `0700`.
- **Terminal-injection attacks**: filenames and server error bodies are sanitized of control characters before display.

### Out of scope

- **A malicious server at login time.** Darkreel's login sends the password to the server (over TLS), which runs Argon2id and briefly holds the master key and private key while answering. A server that is compromised while you log in can capture them; Darkreel's zero-knowledge property is about data at rest. The CLI can't change that without a protocol change on the Darkreel side.
- **Items you didn't upload.** Anyone who can seal to your public key — a connected app such as PPVDA, the server, or someone with write access to its database — can add items to your library. Owner tags let `list` mark them `[not your upload]`, but `download` still fetches them (names sanitized, written only inside the output directory, never over an existing file).

- **Same-UID processes on the host *when using `DRK_PASS`*.** The env var path leaves the password briefly readable from `/proc/<pid>/environ` between exec and the first `os.Unsetenv` call. `os.Unsetenv` clears the Go runtime's environment map — useful for preventing subprocesses from inheriting the value — but it does not scrub kernel-visible environ. **Use `-pw-stdin` (v0.3.1+) to close this window entirely**: stdin bytes never enter the process environment, so `/proc/<pid>/environ` never contains the password at any point. The `DRK_PASS` path is retained for backwards compatibility.
- **Kernel and Go-runtime side channels**: swap, core dumps, GC heap residue, memory compression. Sensitive `[]byte` buffers are zeroed on best-effort basis; this does not defend against a root attacker.
- **Attackers with write access to the binary** (e.g., tampered build artifacts). Release binaries come with a `SHA256SUMS` file; it detects corrupted downloads but is not signed, so it does not authenticate a release on its own.

## Cryptographic notes

All formats must match the Darkreel web client and server exactly. The tests pin the AAD layout, chunk-frame bucket sizes and owner-tag inputs; they don't carry known-answer vectors from the web client, so drift in the sealed-box or PBKDF2 parameters would show up as failures against a real server rather than in `go test`.

- **Content encryption**: AES-256-GCM with 12-byte random nonces. AAD for chunks is `UTF8(mediaID) || BigEndian(uint64(chunkIndex))`; AAD for metadata is `UTF8(mediaID)`. Binding prevents cross-file and cross-chunk confused-deputy substitution.
- **Per-file key sealing (schema v2, v0.3.0+)**: each upload generates three random 32-byte symmetric keys (`fileKey`, `thumbKey`, `metadataKey`) and seals each to the account's X25519 public key via X25519-ECDH + HKDF-SHA256 + AES-256-GCM (HKDF info `"darkreel-seal-v1"`; 92 bytes per sealed key). On download, sealed keys are opened with the account private key (itself AES-256-GCM-encrypted under the master key with `UTF8(userID)` as AAD, delivered in the login response and unwrapped client-side).
- **Chunk format 2**: each chunk's plaintext is a frame `version(1)=2 | flags(1, bit 0 = last chunk) | u32be length | data | zero padding`, padded so the ciphertext is exactly 1, 2, 4, 8 or 16 MiB (then whole MiB); thumbnails are exactly 256 KiB. The server and network see bucket sizes only, and the authenticated last-chunk flag lets downloads detect a dropped tail. Items without `chunk_format: 2` in their metadata are read as plain chunks.
- **Owner tags**: HMAC-SHA256 under `HKDF-SHA256(masterKey, info "darkreel-owner-v1")` over the label, media ID and the three sealed keys, stored in the encrypted metadata. Only the master-key holder can compute one.
- **Metadata padding**: the metadata JSON is padded with spaces to a power-of-2 size (minimum 512 bytes) before encryption.
- **Master-key session key**: the server returns the master key encrypted under PBKDF2-HMAC-SHA256(password, `kdf_salt`), 600,000 iterations, 32-byte output, with `UTF8(userID)` as AAD. Parameters must match the server.
- **fMP4 scanner safety**: `largesize` box headers are range-checked so a crafted `.mp4` can't drive the box walk into an infinite backward loop. Accumulated moof-offset slice growth is capped at 100k entries.
- **Recovery codes are never stored by the CLI.** `-register` prints the recovery code the server returns (to stderr, once) and keeps no copy; store it yourself.

## Network hardening

- TLS `MinVersion` pinned to 1.2 on every HTTP client via `newHTTPTransport()`. Go's default CA store is used for verification; `InsecureSkipVerify` is never set.
- Redirect following is disabled on all clients (`CheckRedirect` returns `http.ErrUseLastResponse`), so a compromised or MITM'd server cannot bounce an authenticated request to a different origin and capture the `Authorization` header.
- Response-body size limits: 1 MB for login responses, 5 MB for media list JSON, 20 MB per downloaded chunk, 1 MB for encrypted metadata. **Per-item total cap of 50 GB** on downloads — without it, the 20 MB × 50k-chunk ceilings could be combined into a TB-scale bandwidth/disk attack by a compromised server.
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

Only the latest tagged release receives security updates. Binaries are built via GitHub Actions; `SHA256SUMS` detects corrupted downloads but is not signed, so building from source is the way to avoid trusting the release pipeline.

## Dependency hygiene

`govulncheck` runs on every push, PR, and weekly in CI (see `.github/workflows/security.yml`).
