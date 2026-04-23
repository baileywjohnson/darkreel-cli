# darkreel-cli

Command-line client for [Darkreel](https://github.com/baileywjohnson/darkreel) — upload, list, and download encrypted media. All encryption and decryption happens locally. The server never sees your plaintext files.

> ## Server compatibility
>
> - **v0.3.0+** speaks Darkreel **schema v2** (sealed-box uploads, X25519 per-file keys). Required for any Darkreel server released alongside delegated-upload support.
> - **v0.2.x and earlier** speak **schema v1** only (legacy `file_key_enc` / master-key-wrapped metadata) and will be rejected by v2 servers with `sealed key has wrong length`.
>
> The CLI still authenticates with username + `DRK_PASS` (no copy-paste delegation flow — it's your own machine, so full-account access is simpler). What changed in v0.3.0 is the on-wire crypto: per-file `fileKey` / `thumbKey` / `metadataKey` are now generated locally and sealed to the account's X25519 public key, matching what Darkreel's web SPA and PPVDA produce.

## Features

- **Upload** -- Encrypt and upload files with Darkreel's schema v2 wire format: per-file `fileKey` / `thumbKey` / `metadataKey` generated locally, sealed to the account's X25519 public key (X25519-ECDH + HKDF-SHA256 + AES-256-GCM), chunks AEAD-encrypted under `fileKey` with media ID + chunk index as AAD
- **List** -- List all media items with decrypted filenames, types, and sizes (opens sealed metadata keys with the account private key)
- **Download** -- Download and decrypt media items (parallel chunk fetching, 4 workers, sealed-key opening)
- **Streaming uploads** -- Chunks are read from disk, encrypted, and streamed to the server one at a time. Only one chunk (~1 MB) is in memory at any time, regardless of file size
- **Thumbnail generation** -- Automatic thumbnails for images (native) and videos (requires ffmpeg)
- **Hash modification** -- Random metadata injected into file headers before encryption, streaming from disk (only reads a small header, not the full file)
- **Batch operations** -- Upload or download multiple files in a single command
- **Account registration** -- Create accounts via CLI with `-register`
- **Credential hygiene** -- Password accepted via `DRK_PASS` env var or `-pw-stdin` flag (never as a CLI flag value). `-pw-stdin` (v0.3.1+) is preferred in scripts — stdin bytes never enter the process environment, so they're not observable via `/proc/<pid>/environ`. `DRK_PASS` is cleared from the process environment immediately after reading and zeroed in memory after master-key derivation

## Minimum requirements

- Go 1.26.2+ (to build from source — pinned for stdlib CVE coverage)
- ffmpeg (optional, for video thumbnails and fMP4 remuxing — placeholders used if unavailable)
- ffprobe (optional, for video codec detection — defaults used if unavailable)

## Install

### From GitHub releases

Download the latest binary for your platform from [Releases](https://github.com/baileywjohnson/darkreel-cli/releases):

```bash
# Linux (amd64)
curl -fSL -o darkreel-cli https://github.com/baileywjohnson/darkreel-cli/releases/latest/download/darkreel-cli-linux-amd64
chmod +x darkreel-cli
sudo mv darkreel-cli /usr/local/bin/

# Linux (arm64)
curl -fSL -o darkreel-cli https://github.com/baileywjohnson/darkreel-cli/releases/latest/download/darkreel-cli-linux-arm64
chmod +x darkreel-cli
sudo mv darkreel-cli /usr/local/bin/

# macOS (Apple Silicon)
curl -fSL -o darkreel-cli https://github.com/baileywjohnson/darkreel-cli/releases/latest/download/darkreel-cli-darwin-arm64
chmod +x darkreel-cli
sudo mv darkreel-cli /usr/local/bin/

# macOS (Intel)
curl -fSL -o darkreel-cli https://github.com/baileywjohnson/darkreel-cli/releases/latest/download/darkreel-cli-darwin-amd64
chmod +x darkreel-cli
sudo mv darkreel-cli /usr/local/bin/

# Verify checksum (recommended)
curl -fSL -o SHA256SUMS https://github.com/baileywjohnson/darkreel-cli/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

### From source

```bash
git clone https://github.com/baileywjohnson/darkreel-cli.git
cd darkreel-cli
go build -o darkreel-cli .
```

## Usage

```
darkreel-cli upload [flags] FILE [FILE...]
darkreel-cli list [flags]
darkreel-cli download [flags] [-o DIR] [ID...]
```

### Common flags

| Flag | Description |
|------|-------------|
| `-server` | Darkreel server URL (e.g., `https://media.example.com`) |
| `-user` | Username |
| `-insecure` | Allow plaintext HTTP for non-localhost URLs (blocked by default) |
| `-pw-stdin` | Read password from stdin (one line, trailing CR/LF stripped). Preferred over `DRK_PASS` in scripts — stdin bytes never enter the process environment, closing the `/proc/<pid>/environ` window the env var briefly exposes. Available in v0.3.1+ |

### Upload flags

| Flag | Description |
|------|-------------|
| `-register` | Register a new account before uploading (requires `ALLOW_REGISTRATION=true` on the server) |

### Download flags

| Flag | Description |
|------|-------------|
| `-o` | Output directory (default: current directory) |

If no IDs are specified, all items are downloaded. Downloaded files are created with `0600` permissions (owner-only).

### Environment variables

Non-password credentials can be passed via env vars instead of CLI flags — useful for automation and keeps them out of shell history / `ps aux`:

| Variable | Description |
|----------|-------------|
| `DRK_SERVER` | Darkreel server URL |
| `DRK_USER` | Username |
| `DRK_PASS` | Password. Cleared from the process environment immediately after reading. **In scripted deployments, prefer `-pw-stdin`** — `DRK_PASS` is briefly visible in `/proc/<pid>/environ` between exec and unset, while stdin bytes never enter the environment at all. |

Server URL and username can also be set via `-server` and `-user` flags, which take precedence over their env var equivalents. The password must come from exactly one of `DRK_PASS` or `-pw-stdin`.

## Examples

```bash
# Set credentials (interactive use)
export DRK_SERVER=https://media.example.com
export DRK_USER=alice
export DRK_PASS=secret

# Upload files
darkreel-cli upload photo.jpg video.mp4

# Upload all images in a directory
darkreel-cli upload ~/Photos/*.jpg

# Scripted upload with password from a secret file (no env var exposure)
cat ~/.secrets/drk-pw | darkreel-cli upload -pw-stdin \
  -server https://media.example.com -user alice vacation.mp4

# Scripted upload with password from a secret manager
vault kv get -field=pw secret/drk | darkreel-cli upload -pw-stdin \
  -server https://media.example.com -user alice vacation.mp4

# Register a new account and upload
DRK_PASS=mypassword darkreel-cli upload -server https://media.example.com -user newuser -register vacation.mp4

# List all media items (shows decrypted filenames)
darkreel-cli list

# Download all items to a directory
darkreel-cli download -o ~/Downloads/darkreel/

# Download specific items by ID
darkreel-cli download -o ~/Downloads/ a3d9c8e2-7b14-... f47ac10b-58cc-...

# Override server and user via flags
DRK_PASS=secret darkreel-cli upload -server https://media.example.com -user alice photo.jpg
```

## How it works

### Upload pipeline

1. Authenticates with the Darkreel server (registers first if `-register` is set)
2. Receives the master key encrypted with a PBKDF2-derived session key, decrypts it client-side
3. Unwraps the account's X25519 private key (AES-256-GCM-encrypted under the master key with user ID as AAD) — needed to open sealed keys during download/list, and carried alongside the master key for the life of the session
4. For each file:
   - **Videos:** Remuxes to fragmented MP4 via ffmpeg (`-c copy`, no re-encoding, written to temp file)
   - **Hash modification:** Reads a small header (64 KB) from disk to determine the insertion point, streams the modified file to a temp file — the full file is never loaded into memory
   - Generates a 320px JPEG thumbnail from the file path (images: native decode, videos: ffmpeg)
   - Generates three per-file random 256-bit keys — `fileKey`, `thumbKey`, `metadataKey` — and seals each to the account's X25519 public key (X25519-ECDH + HKDF-SHA256 + AES-256-GCM, 92 bytes per sealed key). This matches Darkreel's schema v2 sealed-box protocol, bytes-identical to what the web SPA and PPVDA produce.
   - Encrypts metadata (name, type, MIME, size, chunk count, codec info) under the dedicated `metadataKey` (not the master key) — keeps metadata-rotation / rename scope-limited to a delegated client that only holds metadata access. Padded to a power-of-2 bucket (minimum 512 bytes) before encryption, preventing blob size from leaking filename length or field presence
   - Computes segment boundaries — videos at fMP4 moof boundaries (scanned from file headers), other files at 1 MB
   - Streams the multipart upload via `io.Pipe`: each segment is read from disk, encrypted with AES-256-GCM under `fileKey` (media ID + chunk index as AAD), and written directly to the HTTP request — only one chunk is in memory at a time

The server only ever receives ciphertext blobs and three sealed keys. File names, types, sizes, dimensions, codecs, and all symmetric key material remain opaque to the server.

Videos uploaded via the CLI are flagged as `fragmented` in the encrypted metadata, enabling instant streaming playback in the Darkreel web UI via MediaSource Extensions.

### Download pipeline

1. Authenticates, unwraps the X25519 private key, fetches the media list
2. For each item: opens the sealed `metadataKey` with the private key and decrypts the metadata blob to get the filename, chunk count, etc.; opens the sealed `fileKey` the same way for chunk decryption
3. Fetches chunks in parallel (4 workers, connection-pooled) via the padded chunk endpoint
4. Each chunk: strips server-side padding → decrypts with AES-256-GCM under `fileKey` → writes to disk in order
5. Downloaded filenames are sanitized (`filepath.Base`) to prevent path traversal
6. Per-item total-bytes cap of 50 GB guards against a compromised server padding `chunk_count` × 20 MB per chunk into a TB-scale download

### List

Fetches all media items (paginated), opens each sealed `metadataKey` with the private key, decrypts the metadata blob, and prints a table with ID, type, size, and filename.

## Hash modification

When a file is encrypted, a random 32-byte nonce is injected into the file's metadata before encryption. This means the decrypted file will have a different hash from the original, without affecting playback or display:

| Format | Method |
|--------|--------|
| JPEG | Inserts a COM (comment) marker after SOI |
| PNG | Inserts a tEXt chunk before IDAT |
| MP4 | Appends a "free" box at the end of the file |

Unsupported formats (WebM, MKV, AVI, generic files, etc.) skip hash modification and are uploaded as-is. Hash modification is also skipped for fMP4-remuxed videos since it would break the container structure. A hash nonce is always generated and sent to the server regardless of format, so the server cannot distinguish modified from unmodified files by the presence or absence of the field.

## Supported formats

**Images:** JPEG, PNG, GIF, WebP — with thumbnail generation and `IMG` badge in the gallery

**Videos:** MP4, MKV, WebM, AVI, MOV, M4V — with thumbnail generation (requires ffmpeg) and streaming playback for remuxed formats

**Any file:** PDFs, documents, archives, code, and any other file type — uploaded with full encryption and displayed with a `FILE` badge in the gallery

Video thumbnails and fMP4 remuxing require ffmpeg. If ffmpeg is not available, a 1x1 placeholder thumbnail is used and videos are uploaded without remuxing (no streaming playback, full download required).

## Development

```bash
# Run the test suite (crypto round-trips, AAD binding, hash modification,
# padding buckets, filename sanitization, server response sanitization)
go test ./...

# With verbose output
go test -v ./...
```

The crypto tests verify compatibility with the Darkreel server's protocol — changes to AAD construction, key wrapping, or hash modification that diverge from the server's scheme will be caught here.

## Releasing

Binaries are automatically built and published when a version tag is pushed:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions builds binaries for Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64). Each release includes a `SHA256SUMS` file for verifying binary integrity.

## Security

- **Password never on CLI argv** — never accepted as a flag value (invisible to `ps aux` / `/proc/<pid>/cmdline`)
- **Two password input paths:**
  - **`-pw-stdin` (preferred for scripts, v0.3.1+)** — stdin bytes never enter the process environment, so they're not observable via `/proc/<pid>/environ` at any point. Closes the exec-time leak window that the env var path inherently has
  - **`DRK_PASS` env var** — read and cleared via `os.Unsetenv("DRK_PASS")` immediately after reading so any subprocess the CLI spawns (ffmpeg, ffprobe) does not inherit it. **Caveat:** on Linux, `os.Unsetenv` only modifies the Go runtime's environment map; the kernel-visible `/proc/<pid>/environ` still contains the original value briefly between exec and the unset call — and potentially longer depending on how the runtime reconciles the two. Prefer `-pw-stdin` on shared hosts or anywhere else other same-UID processes could observe `/proc/<pid>/environ`
- **Password zeroed in memory** — stored as `[]byte` (not Go `string`) and zeroed after master key derivation. Auth JSON bodies are constructed directly from `[]byte` without converting the password to an immutable Go `string`, preventing un-zeroable copies from lingering on the heap
- **File keys zeroed** — all per-file encryption keys are zeroed after use via `defer`
- **JWT tokens zeroed** — auth tokens are stored as `[]byte` (not Go `string`) and passed through the upload/list/download call stack as byte slices. The token is zeroed after the last API call, and the original JSON-decoded string field is released so the GC can reclaim it
- **Plaintext buffers zeroed** — decrypted chunk plaintext is zeroed immediately after being written to disk during download. Upload-side read buffers are zeroed when the upload goroutine exits. Encrypted metadata's plaintext (containing the original filename and file info) is zeroed after encryption
- **Server responses sanitized** — error bodies stripped of non-printable characters (ANSI escapes, control codes) before display, truncated to 512 chars
- **Path traversal protection** — downloaded filenames sanitized via `filepath.Base()` to prevent writes outside the output directory. Dotfile names (e.g., `.bashrc`) are prefixed with the media ID to prevent overwriting shell configs when downloading to a home directory
- **Restrictive file permissions** — downloaded files created with `0600` (owner read/write only)
- **No shell execution** — all subprocesses (ffmpeg, ffprobe) spawned via `exec.Command` with argument arrays, never through a shell
- **Absolute paths for subprocesses** — file paths resolved to absolute before passing to ffmpeg/ffprobe, preventing `-` prefix filenames from being interpreted as flags
- **Chunk download limits** — response bodies capped at 20 MB per chunk, and server-side padding drained with a 20 MB cap, to prevent memory exhaustion from a malicious server
- **Per-item download size cap** — total decrypted bytes per item are capped at 50 GB, preventing a compromised server from combining the 20 MB per-chunk × 50k chunk-count ceilings into a TB-scale bandwidth/disk attack
- **fMP4 scanner bounds checking** — 64-bit `largesize` box headers that don't fit in int64 are rejected (prevents pathological files driving the box walk into an infinite backward loop); accumulated moof-offset slice growth is capped at 100 k entries
- **Response body limits** — login responses capped at 1 MB, media list responses at 5 MB, preventing memory exhaustion from a malicious server on success paths
- **HTTPS enforced by default** — plaintext HTTP is blocked for non-localhost URLs unless `-insecure` is explicitly passed. Localhost (`127.0.0.1`, `::1`, `localhost`) is exempt. Prevents accidental credential transmission in the clear
- **URL scheme validation** — server URLs are validated to use only `http://` or `https://` schemes, rejecting `file://`, `ftp://`, and other exotic schemes that could be used to exfiltrate credentials
- **HTTP redirect protection** — all HTTP clients disable redirect following, preventing a compromised or MITM'd server from redirecting API requests to leak the Authorization header
- **Subprocess timeouts** — all ffmpeg and ffprobe invocations have a 10-minute timeout via `exec.CommandContext`, preventing indefinite hangs on malformed or adversarially crafted files
- **HTTP status validation** — all API responses checked for expected status codes before processing
- **Temp file isolation** — each upload creates a private temp directory (0700 permissions), cleaned up atomically via `defer`. Temp files use non-identifying names, preventing other users or processes from observing upload activity or file types
- **PNG parsing overflow protection** — hash modification for PNG files uses 64-bit arithmetic for chunk length calculations, preventing integer overflow on 32-bit systems and guarding against chunks extending beyond the 64 KB header buffer
- **Chunk count validation** — downloaded media with invalid chunk counts (outside 1–50,000, matching the server limit) is rejected before allocating memory or spawning workers
- **Media list pagination bounded** — the total number of items fetched from the server is capped at 50,000, preventing memory exhaustion from a malicious server returning unbounded pagination
- **Server-provided IDs validated** — media item IDs from the server are validated as UUIDs before use in URL construction and decryption AAD
- **Filename display sanitization** — filenames from decrypted metadata are stripped of control characters and ANSI escape sequences before terminal output, preventing terminal injection
- **Metadata blob padding** — encrypted metadata blobs are padded to power-of-2 buckets (minimum 512 bytes) before encryption, preventing the encrypted blob size from revealing filename length or which optional fields are present
- **Hash nonce always sent** — a random 32-byte hash nonce is always generated and sent to the server, even for formats that don't support hash modification. This prevents the server from inferring file format category by the presence or absence of the field
- **Connection pool tuning** — download HTTP client's `MaxIdleConnsPerHost` matches the worker count (4), ensuring all parallel chunk fetches reuse connections instead of creating new ones

## Related projects

- [Darkreel](https://github.com/baileywjohnson/darkreel) -- E2E encrypted media server
- [PPVDA](https://github.com/baileywjohnson/ppvda) -- Privacy-focused video downloader with Darkreel integration

## License

MIT
