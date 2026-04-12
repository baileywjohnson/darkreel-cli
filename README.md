# darkreel-cli

Command-line client for [Darkreel](https://github.com/baileywjohnson/darkreel) — upload, list, and download encrypted media. All encryption and decryption happens locally. The server never sees your plaintext files.

## Features

- **Upload** -- Encrypt and upload files with AES-256-GCM chunk encryption matching Darkreel's protocol
- **List** -- List all media items with decrypted filenames, types, and sizes
- **Download** -- Download and decrypt media items (parallel chunk fetching, 4 workers)
- **Streaming uploads** -- Chunks are read from disk, encrypted, and streamed to the server one at a time. Only one chunk (~1 MB) is in memory at any time, regardless of file size
- **Thumbnail generation** -- Automatic thumbnails for images (native) and videos (requires ffmpeg)
- **Hash modification** -- Random metadata injected into file headers before encryption, streaming from disk (only reads a small header, not the full file)
- **Batch operations** -- Upload or download multiple files in a single command
- **Account registration** -- Create accounts via CLI with `-register`
- **Credential hygiene** -- Password accepted only via `DRK_PASS` env var (never a CLI flag), cleared from process environment immediately after reading, zeroed in memory after use

## Minimum requirements

- Go 1.22+ (to build from source)
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

Credentials can be passed via environment variables instead of CLI flags. This is recommended for automation and prevents credentials from appearing in shell history or `ps aux`:

| Variable | Description |
|----------|-------------|
| `DRK_SERVER` | Darkreel server URL |
| `DRK_USER` | Username |
| `DRK_PASS` | Password (**required**, env var only — never accepted as a CLI flag) |

The password must be set via `DRK_PASS`. It is cleared from the process environment immediately after reading. Server URL and username can also be set via `-server` and `-user` flags, which take precedence over their env var equivalents.

## Examples

```bash
# Set credentials (recommended)
export DRK_SERVER=https://media.example.com
export DRK_USER=alice
export DRK_PASS=secret

# Upload files
darkreel-cli upload photo.jpg video.mp4

# Upload all images in a directory
darkreel-cli upload ~/Photos/*.jpg

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
3. For each file:
   - **Videos:** Remuxes to fragmented MP4 via ffmpeg (`-c copy`, no re-encoding, written to temp file)
   - **Hash modification:** Reads a small header (64 KB) from disk to determine the insertion point, streams the modified file to a temp file — the full file is never loaded into memory
   - Generates a 320px JPEG thumbnail from the file path (images: native decode, videos: ffmpeg)
   - Generates random 256-bit encryption keys for file and thumbnail
   - Encrypts metadata (name, type, MIME, size, chunk count, codec info) into a single blob with the master key
   - Computes segment boundaries — videos at fMP4 moof boundaries (scanned from file headers), other files at 1 MB
   - Streams the multipart upload via `io.Pipe`: each segment is read from disk, encrypted with AES-256-GCM (media ID + chunk index as AAD), and written directly to the HTTP request — only one chunk is in memory at a time

The server only ever receives encrypted data and an encrypted metadata blob. File names, types, sizes, dimensions, and codecs are never visible to the server.

Videos uploaded via the CLI are flagged as `fragmented` in the encrypted metadata, enabling instant streaming playback in the Darkreel web UI via MediaSource Extensions.

### Download pipeline

1. Authenticates and fetches the media list
2. Decrypts metadata blobs to get filenames, chunk counts, and file keys
3. For each item, fetches chunks in parallel (4 workers) via the padded chunk endpoint
4. Each chunk: strips server-side padding → decrypts with AES-256-GCM → writes to disk in order
5. Downloaded filenames are sanitized (`filepath.Base`) to prevent path traversal

### List

Fetches all media items (paginated), decrypts each metadata blob, and prints a table with ID, type, size, and filename.

## Hash modification

When a file is encrypted, a random 32-byte nonce is injected into the file's metadata before encryption. This means the decrypted file will have a different hash from the original, without affecting playback or display:

| Format | Method |
|--------|--------|
| JPEG | Inserts a COM (comment) marker after SOI |
| PNG | Inserts a tEXt chunk before IDAT |
| MP4 | Inserts a "free" box after ftyp |

Unsupported formats (WebM, MKV, AVI, generic files, etc.) skip hash modification and are uploaded as-is. Hash modification is also skipped for fMP4-remuxed videos since it would break the container structure.

## Supported formats

**Images:** JPEG, PNG, GIF, WebP — with thumbnail generation and `IMG` badge in the gallery

**Videos:** MP4, MKV, WebM, AVI, MOV, M4V — with thumbnail generation (requires ffmpeg) and streaming playback for remuxed formats

**Any file:** PDFs, documents, archives, code, and any other file type — uploaded with full encryption and displayed with a `FILE` badge in the gallery

Video thumbnails and fMP4 remuxing require ffmpeg. If ffmpeg is not available, a 1x1 placeholder thumbnail is used and videos are uploaded without remuxing (no streaming playback, full download required).

## Releasing

Binaries are automatically built and published when a version tag is pushed:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions builds binaries for Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64).

## Security

- **Password never on CLI** — accepted only via `DRK_PASS` environment variable (invisible to `ps aux` / `/proc/pid/cmdline`)
- **Password cleared from environment** — `os.Unsetenv("DRK_PASS")` called immediately after reading, invisible to child processes and `/proc/pid/environ`
- **Password zeroed in memory** — stored as `[]byte` (not Go `string`) and zeroed after master key derivation
- **File keys zeroed** — all per-file encryption keys are zeroed after use via `defer`
- **Server responses sanitized** — error bodies stripped of non-printable characters (ANSI escapes, control codes) before display, truncated to 512 chars
- **Path traversal protection** — downloaded filenames sanitized via `filepath.Base()` to prevent writes outside the output directory
- **Restrictive file permissions** — downloaded files created with `0600` (owner read/write only)
- **No shell execution** — all subprocesses (ffmpeg, ffprobe) spawned via `exec.Command` with argument arrays, never through a shell
- **Absolute paths for subprocesses** — file paths resolved to absolute before passing to ffmpeg/ffprobe, preventing `-` prefix filenames from being interpreted as flags
- **Chunk download limits** — response bodies capped at 20 MB per chunk to prevent memory exhaustion from a malicious server
- **HTTP status validation** — all API responses checked for expected status codes before processing
- **Temp file cleanup** — all temporary files (fMP4 remux, hash modification) cleaned up via `defer`, even on error paths

## Related projects

- [Darkreel](https://github.com/baileywjohnson/darkreel) -- E2E encrypted media server
- [PPVDA](https://github.com/baileywjohnson/ppvda) -- Privacy-focused video downloader with Darkreel integration

## License

MIT
