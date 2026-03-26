# darkreel-cli

Command-line tool for encrypting and uploading media to a [Darkreel](https://github.com/baileywjohnson/darkreel) server. All encryption happens locally before upload -- the server never sees your plaintext files.

## Features

- **Client-side encryption** -- AES-256-GCM chunk encryption matching Darkreel's protocol
- **Thumbnail generation** -- Automatic thumbnails for images (native) and videos (requires ffmpeg)
- **Hash modification** -- Decrypted files have a different hash from originals (metadata injection)
- **Batch uploads** -- Upload multiple files in a single command
- **Account registration** -- Create accounts via CLI with `-register`

## Requirements

- Go 1.22+ (to build from source)
- ffmpeg (optional, for video thumbnails)

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

## Examples

```bash
# Upload photos and videos
darkreel-cli upload -server https://media.example.com -user alice -pass secret photo.jpg video.mp4

# Register a new account and upload
darkreel-cli upload -server https://media.example.com -user newuser -pass mypassword -register vacation.mp4

# Upload all images in a directory
darkreel-cli upload -server https://media.example.com -user alice -pass secret ~/Photos/*.jpg
```

## What happens during upload

1. Authenticates with the Darkreel server (registers first if `-register` is set)
2. Derives master key from your password using PBKDF2
3. For each file:
   - Reads the file
   - Injects random metadata to modify the file hash (without affecting playback)
   - Generates a thumbnail (320px, JPEG)
   - Generates random encryption keys for the file and thumbnail
   - Splits the file into 1 MB chunks
   - Encrypts each chunk with AES-256-GCM (chunk index as AAD)
   - Encrypts the thumbnail
   - Encrypts the file/thumbnail keys with your master key
   - Uploads everything via multipart POST

The server only ever receives encrypted data.

## Supported formats

**Images:** JPEG, PNG, GIF, WebP

**Videos:** MP4, MKV, WebM, AVI, MOV, M4V (ffmpeg required for video thumbnails; a placeholder is used if ffmpeg is not available)

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
