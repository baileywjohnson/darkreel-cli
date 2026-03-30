# darkreel-cli

Command-line tool for encrypting and uploading media to a [Darkreel](https://github.com/baileywjohnson/darkreel) server. All encryption happens locally before upload -- the server never sees your plaintext files.

## Features

- **Client-side encryption** -- AES-256-GCM chunk encryption matching Darkreel's protocol
- **Thumbnail generation** -- Automatic thumbnails for images (native) and videos (requires ffmpeg)
- **Hash modification** -- Decrypted files have a different hash from originals via metadata injection
- **Batch uploads** -- Upload multiple files in a single command
- **Account registration** -- Create accounts via CLI with `-register`
- **Env var credentials** -- Pass credentials via environment variables to avoid shell history exposure

## Minimum requirements

- Go 1.22+ (to build from source)
- ffmpeg (optional, for video thumbnails -- a placeholder is used if unavailable)

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

Flags:
  -server    Darkreel server URL (e.g., https://media.example.com)
  -user      Username
  -pass      Password
  -register  Register a new account before uploading
```

### Environment variables

Credentials can be passed via environment variables instead of CLI flags. This is recommended for automation and prevents credentials from appearing in shell history or `ps aux`:

| Variable | Description |
|----------|-------------|
| `DRK_SERVER` | Darkreel server URL |
| `DRK_USER` | Username |
| `DRK_PASS` | Password |

CLI flags take precedence over environment variables.

## Examples

```bash
# Upload using CLI flags
darkreel-cli upload -server https://media.example.com -user alice -pass secret photo.jpg video.mp4

# Upload using environment variables (recommended)
export DRK_SERVER=https://media.example.com
export DRK_USER=alice
export DRK_PASS=secret
darkreel-cli upload photo.jpg video.mp4

# Register a new account and upload
darkreel-cli upload -server https://media.example.com -user newuser -pass mypassword -register vacation.mp4

# Upload all images in a directory
darkreel-cli upload ~/Photos/*.jpg
```

## What happens during upload

1. Authenticates with the Darkreel server (registers first if `-register` is set)
2. Derives master key from your password using PBKDF2-SHA256 (100k iterations)
3. For each file:
   - Reads the file
   - Injects random metadata to modify the file hash (without affecting playback)
   - Generates a 320px JPEG thumbnail
   - Generates random 256-bit encryption keys for file and thumbnail
   - Encrypts metadata (name, type, MIME, size, dimensions, duration) into a single blob with the master key
   - Splits the file into 1 MB chunks
   - Encrypts each chunk with AES-256-GCM (chunk index as AAD)
   - Encrypts the thumbnail
   - Encrypts the file/thumbnail keys with your master key
   - Uploads everything via multipart POST

The server only ever receives encrypted data and an encrypted metadata blob.

## Hash modification

When a file is encrypted, a random 32-byte nonce is injected into the file's metadata before encryption. This means the decrypted file will have a different hash from the original, without affecting playback or display:

| Format | Method |
|--------|--------|
| JPEG | Inserts a COM (comment) marker after SOI |
| PNG | Inserts a tEXt chunk before IDAT |
| MP4 | Inserts a "free" box after ftyp |
| WebM | Appends marker bytes |
| Other | Appends marker bytes |

If hash modification fails for a given format, the file is uploaded unmodified.

## Supported formats

**Images:** JPEG, PNG, GIF, WebP

**Videos:** MP4, MKV, WebM, AVI, MOV, M4V

Video thumbnails require ffmpeg. If ffmpeg is not available, a 1x1 placeholder thumbnail is used.

## Releasing

Binaries are automatically built and published when a version tag is pushed:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions builds binaries for Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64).

## Related projects

- [Darkreel](https://github.com/baileywjohnson/darkreel) -- E2E encrypted media server
- [PPVDA](https://github.com/baileywjohnson/ppvda) -- Privacy-focused video downloader with Darkreel integration

## License

MIT
