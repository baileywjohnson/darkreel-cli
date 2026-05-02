package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/gif"
	_ "image/png"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/baileywjohnson/darkreel-cli/internal/crypto"
	"github.com/google/uuid"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
	"golang.org/x/crypto/pbkdf2"
)

const chunkSize = 1 << 20       // 1 MB — used for non-fragmented files only
const subprocessTimeout = 10 * time.Minute // ffmpeg/ffprobe timeout
const maxMetadataBytes = 1 << 20 // 1 MB — hard cap on encrypted metadata size

// newHTTPTransport returns a transport with an explicit TLS minimum version so
// a refactor can't silently weaken the default or enable InsecureSkipVerify.
func newHTTPTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// limitWriter wraps an io.Writer and silently discards bytes past limit.
// Used to cap subprocess stdout so a pathological child cannot exhaust memory.
type limitWriter struct {
	w       io.Writer
	limit   int
	written int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.written >= l.limit {
		return len(p), nil // pretend to accept; discard
	}
	remaining := l.limit - l.written
	if len(p) <= remaining {
		n, err := l.w.Write(p)
		l.written += n
		return n, err
	}
	n, err := l.w.Write(p[:remaining])
	l.written += n
	return len(p), err // report full len so the child doesn't see short writes
}

// segment describes a byte range in a source file.
type segment struct {
	offset int64
	length int64
}

type loginResponse struct {
	Token              string `json:"token"`
	KDFSalt            string `json:"kdf_salt"`
	UserID             string `json:"user_id"`
	EncryptedMasterKey string `json:"encrypted_master_key"`
	// Shape-2 additions. PublicKey is the user's X25519 public key (32 bytes),
	// needed to seal per-file keys during upload. EncryptedPrivKey is the
	// matching private key encrypted with AES-256-GCM under the master key,
	// with userID as AAD — CLI unwraps it after decrypting the master key.
	PublicKey        string `json:"public_key"`
	EncryptedPrivKey string `json:"encrypted_priv_key"`
}

// userSession holds the credentials derived from a successful login. All byte
// slices are sensitive and must be zeroed before the process exits; callers
// use sess.zero() in a defer immediately after login.
type userSession struct {
	token     []byte
	masterKey []byte
	publicKey []byte
	privKey   []byte
	userID    string
}

func (s *userSession) zero() {
	zeroBytes(s.token)
	zeroBytes(s.masterKey)
	// publicKey is public, no need to wipe, but cheap and consistent
	zeroBytes(s.publicKey)
	zeroBytes(s.privKey)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "upload":
		cmdUpload()
	case "list":
		cmdList()
	case "download":
		cmdDownload()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`drk — Darkreel CLI

Usage:
  drk upload -server URL -user USERNAME FILE [FILE...]
  drk list -server URL -user USERNAME
  drk download -server URL -user USERNAME [-o DIR] [ID...]

Environment variables:
  DRK_PASS    Password (alternative to -pw-stdin; cleared from env immediately
              after read, but visible in /proc/<pid>/environ for a brief
              window between exec and unset — prefer -pw-stdin in scripts)
  DRK_SERVER  Server URL (fallback if -server not provided)
  DRK_USER    Username (fallback if -user not provided)

Commands:
  upload    Encrypt and upload files to a Darkreel server
  list      List all media items (decrypts filenames)
  download  Download and decrypt media items by ID (or all if no IDs given)

Common flags:
  -server   Server URL (e.g., https://media.example.com)
  -user     Username
  -insecure Allow plaintext HTTP for non-localhost URLs
  -pw-stdin Read the password from stdin (one line, trailing newline stripped)
            — stdin bytes never enter the process environment, so this closes
            the exec-time /proc/<pid>/environ leak DRK_PASS opens.

Upload flags:
  -register Register a new account before uploading

Download flags:
  -o        Output directory (default: current directory)`)
}

func cmdUpload() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: drk upload -server URL -user USERNAME FILE [FILE...]")
		os.Exit(1)
	}

	var serverURL, username string
	var register, insecure, pwStdin bool
	var files []string

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-server":
			i++
			if i >= len(args) {
				fatal("-server requires a value")
			}
			serverURL = strings.TrimRight(args[i], "/")
		case "-user":
			i++
			if i >= len(args) {
				fatal("-user requires a value")
			}
			username = args[i]
		case "-register":
			register = true
		case "-insecure":
			insecure = true
		case "-pw-stdin":
			pwStdin = true
		default:
			files = append(files, args[i])
		}
	}

	// Fall back to environment variables
	if serverURL == "" {
		serverURL = strings.TrimRight(os.Getenv("DRK_SERVER"), "/")
	}
	if username == "" {
		username = os.Getenv("DRK_USER")
	}
	// Password from stdin (preferred — never enters the process environment)
	// or DRK_PASS env var (legacy — unset immediately after read).
	password := readPasswordSource(pwStdin)

	if serverURL == "" || username == "" || len(password) == 0 {
		fmt.Fprintln(os.Stderr, "Error: -server, -user, and a password (via DRK_PASS or -pw-stdin) are required")
		os.Exit(1)
	}
	validateServerURL(serverURL)
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no files specified")
		os.Exit(1)
	}

	requireHTTPS(serverURL, insecure)

	noRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	authClient := &http.Client{Timeout: 30 * time.Second, CheckRedirect: noRedirect, Transport: newHTTPTransport()}
	uploadClient := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: noRedirect, Transport: newHTTPTransport()}

	// Register if requested
	if register {
		fmt.Printf("Registering user %q...\n", username)
		regBody := buildAuthJSON(username, password)
		resp, err := authClient.Post(serverURL+"/api/auth/register", "application/json", bytes.NewReader(regBody))
		zeroBytes(regBody)
		if err != nil {
			fatal("register request failed: %v", err)
		}
		if resp.StatusCode != 201 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			fatal("register failed (%d): %s", resp.StatusCode, sanitizeServerResponse(b))
		}
		resp.Body.Close()
		fmt.Println("Registered successfully.")
	}

	// Login
	fmt.Printf("Logging in as %q...\n", username)
	sess := login(connFlags{serverURL: serverURL, username: username, password: password})
	// login() zeroes password internally as soon as it's done with it.
	defer sess.zero()

	fmt.Fprintf(os.Stderr, "Authenticated. Uploading %d file(s)...\n\n", len(files))

	success, fail := 0, 0
	for _, f := range files {
		fmt.Fprintf(os.Stderr, "  file %d/%d ", success+fail+1, len(files))
		if err := uploadFile(uploadClient, serverURL, sess, f); err != nil {
			// Error details intentionally omitted — server responses may contain
			// information useful for fingerprinting or probing the API.
			fmt.Fprintf(os.Stderr, "FAILED\n")
			fail++
		} else {
			fmt.Fprintf(os.Stderr, "OK\n")
			success++
		}
	}

	fmt.Fprintf(os.Stderr, "\nDone: %d uploaded, %d failed\n", success, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func decryptMasterKey(encB64 string, password []byte, kdfSaltB64, userID string) ([]byte, error) {
	encData, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, err
	}
	kdfSalt, err := base64.StdEncoding.DecodeString(kdfSaltB64)
	if err != nil {
		return nil, fmt.Errorf("invalid kdf_salt: %w", err)
	}
	sessionKey := pbkdf2.Key(password, kdfSalt, 600000, 32, sha256.New)
	defer zeroBytes(sessionKey)

	return crypto.DecryptBlock(encData, sessionKey, []byte(userID))
}

func uploadFile(client *http.Client, serverURL string, sess *userSession, filePath string) error {
	// Resolve to absolute path so filenames starting with "-" aren't
	// interpreted as flags by ffmpeg/ffprobe.
	absPath, err := filepath.Abs(filePath)
	if err == nil {
		filePath = absPath
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	mediaType := "file"
	if isImage(ext) {
		mediaType = "image"
	} else if isVideo(ext) {
		mediaType = "video"
	}

	// srcPath is the file we'll read chunks from. It may be the original,
	// a hash-modified temp file, or an fMP4-remuxed temp file.
	srcPath := filePath
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return fmt.Errorf("create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	fragmented := false
	codecString := ""
	var videoWidth, videoHeight int
	var videoDuration float64

	// Start thumbnail generation concurrently (reads original file, not remuxed)
	var thumbData []byte
	var thumbWg sync.WaitGroup
	if mediaType == "video" {
		thumbWg.Add(1)
		go func() {
			defer thumbWg.Done()
			thumbData = generateThumbnail(filePath, tmpDir)
		}()
	}

	if mediaType == "video" {
		fmp4Path, ok := remuxToFMP4File(filePath, tmpDir)
		if ok {
			srcPath = fmp4Path
			fragmented = true
			mimeType = "video/mp4"
		}
		codecString, videoWidth, videoHeight, videoDuration = probeVideoInfo(filePath)
	}

	// Always generate a hash nonce so the server cannot distinguish
	// modified from unmodified files by presence/absence of the field.
	hashNonce, err := crypto.GenerateHashNonce()
	if err != nil {
		return fmt.Errorf("generate hash nonce: %w", err)
	}
	// Hash modification — skip for fMP4 remuxed videos (would break container)
	if !fragmented {
		tmpHash, nonce, hashErr := modifyHashToFile(srcPath, mimeType, tmpDir)
		if hashErr == nil {
			srcPath = tmpHash
			hashNonce = nonce
		}
		// Non-fatal if unsupported format — continue with unmodified file
	}

	// Wait for thumbnail if running concurrently, or generate synchronously
	if mediaType == "video" {
		thumbWg.Wait()
	} else {
		thumbData = generateThumbnail(filePath, tmpDir)
	}

	// Get file size from source
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	fileSize := srcInfo.Size()

	// Compute segment boundaries from the source file.
	// For fMP4: scan moof box boundaries.
	// For non-fMP4: fixed 1 MB chunks.
	var segments []segment
	if fragmented {
		segments = scanFMP4Segments(srcPath)
	} else {
		for start := int64(0); start < fileSize; start += int64(chunkSize) {
			length := int64(chunkSize)
			if start+length > fileSize {
				length = fileSize - start
			}
			segments = append(segments, segment{start, length})
		}
	}
	if len(segments) == 0 {
		segments = []segment{{0, fileSize}}
	}
	chunkCount := len(segments)

	// Three per-file symmetric keys, each sealed to the user's X25519 public
	// key. Using separate keys for file/thumbnail/metadata means no one key
	// unlocks everything, and the metadata key in particular can be given to
	// a delegated client for renaming without granting chunk-read access.
	fileKey, err := crypto.GenerateFileKey()
	if err != nil {
		return err
	}
	defer zeroBytes(fileKey)

	thumbKey, err := crypto.GenerateFileKey()
	if err != nil {
		return err
	}
	defer zeroBytes(thumbKey)

	metadataKey, err := crypto.GenerateFileKey()
	if err != nil {
		return err
	}
	defer zeroBytes(metadataKey)

	mediaID := uuid.New().String()
	mediaIDBytes := []byte(mediaID)

	encThumb, err := crypto.EncryptChunk(thumbData, thumbKey, 0, mediaID)
	if err != nil {
		return fmt.Errorf("encrypt thumbnail: %w", err)
	}

	// Seal each symmetric key to the user's X25519 public key. The server
	// validates exactly 92 bytes (SealBoxOverhead + 32) — anything else
	// is rejected at the upload handler.
	fileKeySealed, err := crypto.SealBox(fileKey, sess.publicKey)
	if err != nil {
		return fmt.Errorf("seal file key: %w", err)
	}
	thumbKeySealed, err := crypto.SealBox(thumbKey, sess.publicKey)
	if err != nil {
		return fmt.Errorf("seal thumb key: %w", err)
	}
	metadataKeySealed, err := crypto.SealBox(metadataKey, sess.publicKey)
	if err != nil {
		return fmt.Errorf("seal metadata key: %w", err)
	}

	metaMap := map[string]any{
		"name":        filepath.Base(filePath),
		"media_type":  mediaType,
		"mime_type":   mimeType,
		"size":        fileSize,
		"chunk_count": chunkCount,
	}
	if fragmented {
		metaMap["fragmented"] = true
	}
	if codecString != "" {
		metaMap["codecs"] = codecString
	}
	if videoWidth > 0 && videoHeight > 0 {
		metaMap["width"] = videoWidth
		metaMap["height"] = videoHeight
	}
	if videoDuration > 0 {
		metaMap["duration"] = videoDuration
	}
	metadataPlain, err := json.Marshal(metaMap)
	if err != nil {
		return err
	}
	// Pad metadata to a power-of-2 bucket (min 512 bytes) so the encrypted
	// blob size does not reveal filename length or metadata field presence.
	metadataPlain = padToBucket(metadataPlain, 512)
	defer zeroBytes(metadataPlain) // wipe filename and other metadata from memory
	// Encrypt metadata with its OWN key, not the master key — the browser and
	// PPVDA upload paths do this so a delegated client can rotate metadata
	// without holding the master key.
	metadataEnc, err := crypto.EncryptBlock(metadataPlain, metadataKey, mediaIDBytes)
	if err != nil {
		return err
	}
	metadataNonce := metadataEnc[:12]
	metadataCiphertext := metadataEnc[12:]

	uploadMeta := map[string]any{
		"media_id":            mediaID,
		"chunk_count":         chunkCount,
		"file_key_sealed":     base64.StdEncoding.EncodeToString(fileKeySealed),
		"thumb_key_sealed":    base64.StdEncoding.EncodeToString(thumbKeySealed),
		"metadata_key_sealed": base64.StdEncoding.EncodeToString(metadataKeySealed),
		"metadata_enc":        base64.StdEncoding.EncodeToString(metadataCiphertext),
		"metadata_nonce":      base64.StdEncoding.EncodeToString(metadataNonce),
	}
	uploadMeta["hash_nonce"] = base64.StdEncoding.EncodeToString(hashNonce)

	// Stream the multipart body via io.Pipe. Each segment is read from the
	// source file, encrypted, and written directly to the pipe — only one
	// chunk is in memory at a time.
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	// WaitGroup ensures the goroutine has finished before uploadFile returns,
	// preventing a race where deferred zeroBytes(fileKey) runs while the
	// goroutine is still using fileKey to initialize the cipher.
	var uploadWg sync.WaitGroup
	uploadWg.Add(1)
	go func() {
		defer uploadWg.Done()
		defer srcFile.Close()
		var writeErr error
		defer func() { pw.CloseWithError(writeErr) }()

		metaPart, err := writer.CreateFormField("metadata")
		if err != nil {
			writeErr = err
			return
		}
		if writeErr = json.NewEncoder(metaPart).Encode(uploadMeta); writeErr != nil {
			return
		}

		thumbPart, err := writer.CreateFormField("thumbnail")
		if err != nil {
			writeErr = err
			return
		}
		if _, writeErr = thumbPart.Write(encThumb); writeErr != nil {
			return
		}

		// Read each segment from disk, encrypt, write to pipe
		gcm, err := crypto.NewChunkCipher(fileKey)
		if err != nil {
			writeErr = fmt.Errorf("init cipher: %w", err)
			return
		}
		buf := make([]byte, 0, chunkSize+chunkSize/2) // reusable read buffer
		defer func() {
			// Wipe plaintext from the read buffer (last chunk's content lingers otherwise)
			if cap(buf) > 0 {
				b := buf[:cap(buf)]
				for i := range b {
					b[i] = 0
				}
			}
		}()
		for i, seg := range segments {
			if cap(buf) < int(seg.length) {
				buf = make([]byte, seg.length)
			}
			buf = buf[:seg.length]
			if _, err := srcFile.ReadAt(buf, seg.offset); err != nil {
				writeErr = fmt.Errorf("read chunk %d: %w", i, err)
				return
			}
			enc, err := crypto.EncryptChunkWith(gcm, buf, i, mediaID)
			if err != nil {
				writeErr = fmt.Errorf("encrypt chunk %d: %w", i, err)
				return
			}
			chunkPart, err := writer.CreateFormField(fmt.Sprintf("chunk_%d", i))
			if err != nil {
				writeErr = err
				return
			}
			if _, writeErr = chunkPart.Write(enc); writeErr != nil {
				return
			}
		}
		writeErr = writer.Close()
	}()

	req, err := http.NewRequest("POST", serverURL+"/api/media/upload", pr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+string(sess.token))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	// Wait for the upload goroutine to finish before returning, so deferred
	// key zeroing doesn't race with the goroutine's reads.
	uploadWg.Wait()
	if err != nil {
		return fmt.Errorf("upload request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, sanitizeServerResponse(b))
	}

	return nil
}

// remuxToFMP4File remuxes the video at filePath to fragmented MP4 using ffmpeg.
// Returns the temp file path and true on success. Caller must remove the temp file.
func remuxToFMP4File(filePath, tmpDir string) (string, bool) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n    (ffmpeg not found — skipping fMP4 remux)\n    ")
		return "", false
	}

	tmpFile, err := os.CreateTemp(tmpDir, "*.mp4")
	if err != nil {
		return "", false
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), subprocessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffmpeg,
		"-y",
		"-i", filePath,
		"-c", "copy",
		"-movflags", "frag_keyframe+empty_moov+default_base_moof",
		"-f", "mp4",
		tmpPath,
	)
	cmd.Stderr = nil
	cmd.Stdout = nil

	if err := cmd.Run(); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "\n    (fMP4 remux failed — using original file)\n    ")
		return "", false
	}

	return tmpPath, true
}

// scanFMP4Segments scans an fMP4 file for moof boundaries and returns
// segment offsets. The first segment is the init segment (everything before
// the first moof), subsequent segments are moof+mdat pairs.
func scanFMP4Segments(filePath string) []segment {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil
	}
	fileSize := info.Size()

	var header [16]byte
	var segments []segment
	var moofOffsets []int64
	pos := int64(0)

	// Cap on moof offsets — a crafted mp4 with millions of empty moofs would
	// otherwise grow this slice without bound. 50k matches the server's
	// chunk-count limit, so anything past that would fail upload anyway.
	const maxMoofOffsets = 100_000

	for pos < fileSize {
		if _, err := f.ReadAt(header[:8], pos); err != nil {
			break
		}
		rawSize := binary.BigEndian.Uint32(header[:4])
		boxType := string(header[4:8])
		var boxSize int64
		if rawSize == 1 {
			// 64-bit extended size. Read as uint64, reject values that don't
			// fit in int64 — a negative int64 would make pos+boxSize wrap
			// backwards or satisfy the later bounds check, causing an
			// infinite loop or OOB read on a malicious file.
			if pos+16 > fileSize {
				break
			}
			if _, err := f.ReadAt(header[:16], pos); err != nil {
				break
			}
			largeSize := binary.BigEndian.Uint64(header[8:16])
			if largeSize > math.MaxInt64 {
				break
			}
			boxSize = int64(largeSize)
			if boxSize < 16 {
				break
			}
		} else if rawSize == 0 {
			boxSize = fileSize - pos
		} else {
			boxSize = int64(rawSize)
		}
		if boxSize < 8 || pos > fileSize-boxSize {
			break
		}

		if boxType == "moof" {
			moofOffsets = append(moofOffsets, pos)
			if len(moofOffsets) > maxMoofOffsets {
				return nil
			}
		}
		pos += boxSize
	}

	if len(moofOffsets) == 0 {
		return []segment{{0, fileSize}}
	}

	// Init segment: everything before first moof
	segments = append(segments, segment{0, moofOffsets[0]})

	// Media segments: each moof to the next moof (or EOF)
	for i, off := range moofOffsets {
		var end int64
		if i+1 < len(moofOffsets) {
			end = moofOffsets[i+1]
		} else {
			end = fileSize
		}
		segments = append(segments, segment{off, end - off})
	}

	return segments
}

// probeVideoInfo uses a single ffprobe call to get video codec, audio codec,
// dimensions, and duration. Returns (codecString, width, height, duration).
func probeVideoInfo(filePath string) (string, int, int, float64) {
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		return "avc1.64001f,mp4a.40.2", 0, 0, 0
	}

	type streamInfo struct {
		CodecName string `json:"codec_name"`
		CodecType string `json:"codec_type"`
		Width     int    `json:"width"`
		Height    int    `json:"height"`
	}
	type ffprobeResult struct {
		Streams []streamInfo `json:"streams"`
		Format  struct {
			Duration string `json:"duration"`
		} `json:"format"`
	}

	ctx, cancel := context.WithTimeout(context.Background(), subprocessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffprobe,
		"-v", "quiet",
		"-show_entries", "stream=codec_name,codec_type,width,height:format=duration",
		"-of", "json",
		filePath,
	)
	// Cap ffprobe stdout at 1 MB — real JSON output is <10 KB. A crafted input
	// could cause ffprobe to emit unbounded output; we treat that as a probe
	// failure and fall back to defaults.
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, limit: 1 << 20}
	if err := cmd.Run(); err != nil {
		return "avc1.64001f,mp4a.40.2", 0, 0, 0
	}

	var result ffprobeResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		return "avc1.64001f,mp4a.40.2", 0, 0, 0
	}

	var videoCodec, audioCodec string
	var w, h int
	for _, s := range result.Streams {
		switch s.CodecType {
		case "video":
			if videoCodec == "" {
				videoCodec = s.CodecName
				w = s.Width
				h = s.Height
			}
		case "audio":
			if audioCodec == "" {
				audioCodec = s.CodecName
			}
		}
	}

	videoMSE := mapVideoCodec(videoCodec)
	audioMSE := mapAudioCodec(audioCodec)
	codecString := videoMSE
	if audioMSE != "" {
		codecString += "," + audioMSE
	}

	var dur float64
	if result.Format.Duration != "" {
		fmt.Sscanf(result.Format.Duration, "%f", &dur)
	}

	return codecString, w, h, dur
}

func mapVideoCodec(codec string) string {
	switch codec {
	case "h264":
		return "avc1.64001f"
	case "hevc", "h265":
		return "hev1.1.6.L93.B0"
	case "vp9":
		return "vp09.00.10.08"
	case "av1":
		return "av01.0.01M.08"
	default:
		return "avc1.64001f"
	}
}

func mapAudioCodec(codec string) string {
	switch codec {
	case "aac":
		return "mp4a.40.2"
	case "opus":
		return "opus"
	case "mp3":
		return "mp4a.40.34"
	default:
		if codec != "" {
			return "mp4a.40.2"
		}
		return ""
	}
}

func generateThumbnail(filePath, tmpDir string) []byte {
	if isVideo(strings.ToLower(filepath.Ext(filePath))) {
		return generateVideoThumbnail(filePath, tmpDir)
	}
	return generateImageThumbnailFromFile(filePath)
}

func generateImageThumbnailFromFile(filePath string) []byte {
	f, err := os.Open(filePath)
	if err != nil {
		return placeholderThumb()
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		return placeholderThumb()
	}

	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	const maxDim = 320

	tw, th := maxDim, maxDim
	if w > h {
		th = h * maxDim / w
	} else {
		tw = w * maxDim / h
	}
	if tw < 1 {
		tw = 1
	}
	if th < 1 {
		th = 1
	}

	thumb := image.NewRGBA(image.Rect(0, 0, tw, th))
	draw.ApproxBiLinear.Scale(thumb, thumb.Bounds(), img, bounds, draw.Over, nil)

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, thumb, &jpeg.Options{Quality: 70}); err != nil {
		return placeholderThumb()
	}
	return buf.Bytes()
}

func generateVideoThumbnail(filePath, tmpDir string) []byte {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n    (ffmpeg not found — using placeholder thumbnail for video)\n    ")
		return placeholderThumb()
	}

	tmpFile, err := os.CreateTemp(tmpDir, "*.jpg")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n    (failed to create temp file — using placeholder thumbnail)\n    ")
		return placeholderThumb()
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	ctx, cancel := context.WithTimeout(context.Background(), subprocessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffmpeg,
		"-i", filePath,
		"-ss", "00:00:01",
		"-vframes", "1",
		"-vf", "scale=320:-1",
		"-q:v", "5",
		"-y",
		tmpPath,
	)
	cmd.Stderr = nil
	cmd.Stdout = nil

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n    (ffmpeg failed — using placeholder thumbnail)\n    ")
		return placeholderThumb()
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return placeholderThumb()
	}
	return data
}

func placeholderThumb() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	var buf bytes.Buffer
	jpeg.Encode(&buf, img, &jpeg.Options{Quality: 50})
	return buf.Bytes()
}

// modifyHashToFile applies hash modification by streaming: reads a small header
// to compute the insertion point and blob, then writes [prefix][blob][rest] to
// a temp file. Returns the temp file path (caller must remove) and the nonce.
// Returns ("", nil, nil) if hash modification is not supported for the format.
func modifyHashToFile(srcPath, mimeType, tmpDir string) (tmpPath string, nonce []byte, err error) {
	lower := strings.ToLower(mimeType)

	// Read a small header to determine the insertion point
	src, err := os.Open(srcPath)
	if err != nil {
		return "", nil, err
	}
	defer src.Close()

	header := make([]byte, 64*1024)
	n, _ := io.ReadFull(src, header)
	header = header[:n]
	if n < 8 {
		return "", nil, fmt.Errorf("file too small")
	}

	nonce, err = crypto.GenerateHashNonce()
	if err != nil {
		return "", nil, err
	}

	// Determine the insertion point and the blob to insert, based on format.
	// This reuses the same logic as the in-memory functions but only on the header.
	var insertPos int
	var blob []byte
	var endBlob []byte // appended after file content (MP4 free box)

	switch {
	case (strings.Contains(lower, "jpeg") || strings.Contains(lower, "jpg")) && header[0] == 0xFF && header[1] == 0xD8:
		// JPEG: insert COM marker after SOI (2 bytes)
		insertPos = 2
		comLen := uint16(len(nonce) + 2)
		blob = make([]byte, 4+len(nonce))
		blob[0] = 0xFF
		blob[1] = 0xFE
		binary.BigEndian.PutUint16(blob[2:4], comLen)
		copy(blob[4:], nonce)

	case strings.Contains(lower, "png") && bytes.Equal(header[:8], []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}):
		// PNG: insert tEXt chunk before first IDAT
		pos := 8
		for pos+8 <= n {
			chunkLen := binary.BigEndian.Uint32(header[pos : pos+4])
			chunkType := string(header[pos+4 : pos+8])
			if chunkType == "IDAT" {
				break
			}
			next := int64(pos) + 12 + int64(chunkLen)
			if next > int64(n) {
				// Chunk extends beyond header buffer; insert at current position
				break
			}
			pos = int(next)
		}
		insertPos = pos
		keyword := "Comment"
		textData := append([]byte(keyword), 0)
		textData = append(textData, nonce...)
		blob = crypto.BuildPNGChunkExported("tEXt", textData)

	case (strings.Contains(lower, "mp4") || strings.Contains(lower, "quicktime")) && n >= 8:
		// MP4: append 'free' box at the END of the file.
		// Inserting before moov would corrupt stco/co64 byte offsets.
		insertPos = n // write full header as prefix; blob appended after streaming
		boxSize := uint32(8 + len(nonce))
		endBlob = make([]byte, boxSize)
		binary.BigEndian.PutUint32(endBlob[0:4], boxSize)
		copy(endBlob[4:8], "free")
		copy(endBlob[8:], nonce)

	default:
		return "", nil, fmt.Errorf("unsupported format: %s", mimeType)
	}

	// Write to temp file: [prefix][blob][rest streamed from original]
	tmp, err := os.CreateTemp(tmpDir, "*")
	if err != nil {
		return "", nil, err
	}
	tmpPath = tmp.Name()

	// Write prefix (bytes before insertion point)
	if _, err := tmp.Write(header[:insertPos]); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", nil, err
	}
	// Write the injection blob
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", nil, err
	}
	// Write the rest: first from header buffer, then stream from file
	if _, err := tmp.Write(header[insertPos:]); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", nil, err
	}
	// Stream remaining file content (beyond what we read into header)
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", nil, err
	}
	// Append blob at end of file (e.g. MP4 free box)
	if endBlob != nil {
		if _, err := tmp.Write(endBlob); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return "", nil, err
		}
	}
	tmp.Close()
	return tmpPath, nonce, nil
}

func isImage(ext string) bool {
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp":
		return true
	}
	return false
}

func isVideo(ext string) bool {
	switch ext {
	case ".mp4", ".mkv", ".webm", ".avi", ".mov", ".m4v":
		return true
	}
	return false
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// padToBucket pads data with spaces to the nearest power-of-2 bucket
// (minimum minSize). JSON parsers ignore trailing whitespace, so the
// padded data can be decrypted and unmarshalled without stripping.
func padToBucket(data []byte, minSize int) []byte {
	target := minSize
	for target < len(data) {
		target *= 2
	}
	if len(data) == target {
		return data
	}
	padded := make([]byte, target)
	copy(padded, data)
	for i := len(data); i < target; i++ {
		padded[i] = ' '
	}
	return padded
}

// buildAuthJSON constructs a JSON body like {"username":"...","password":"..."}
// without converting the password to a Go string (which would be immutable and
// impossible to zero from memory). The returned []byte should be zeroed after use.
func buildAuthJSON(username string, password []byte) []byte {
	// JSON-escape the password bytes in case they contain characters that need escaping.
	var escaped []byte
	for _, b := range password {
		switch b {
		case '"':
			escaped = append(escaped, '\\', '"')
		case '\\':
			escaped = append(escaped, '\\', '\\')
		case '\n':
			escaped = append(escaped, '\\', 'n')
		case '\r':
			escaped = append(escaped, '\\', 'r')
		case '\t':
			escaped = append(escaped, '\\', 't')
		default:
			if b < 0x20 {
				escaped = append(escaped, []byte(fmt.Sprintf("\\u%04x", b))...)
			} else {
				escaped = append(escaped, b)
			}
		}
	}
	// JSON-escape the username too (it's already a string, but be safe).
	usernameJSON, _ := json.Marshal(username)
	buf := make([]byte, 0, len(`{"username":,"password":""}`)+len(usernameJSON)+len(escaped))
	buf = append(buf, `{"username":`...)
	buf = append(buf, usernameJSON...)
	buf = append(buf, `,"password":"`...)
	buf = append(buf, escaped...)
	buf = append(buf, `"}`...)
	zeroBytes(escaped)
	return buf
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}

// connFlags holds parsed connection flags shared across commands.
type connFlags struct {
	serverURL string
	username  string
	password  []byte // []byte so it can be zeroed after use
	insecure  bool   // allow plaintext HTTP for non-localhost
}

// readPasswordFromStdin reads one line from stdin as the password, stripping
// a trailing newline. Unlike DRK_PASS, which briefly appears in os.Environ()
// between exec and Unsetenv and can be observed via /proc/<pid>/environ or a
// core dump during that window, stdin bytes never enter the process
// environment. Prefer this when calling the CLI from a script that already
// has the password in memory (e.g. via `printf %s "$pw" | drk ... -pw-stdin`).
func readPasswordFromStdin() ([]byte, error) {
	// Cap at 64 KiB — enforcement matches the server's register/login
	// body limit; anything larger is a script bug, not a real password.
	const maxPw = 64 << 10
	buf, err := io.ReadAll(io.LimitReader(os.Stdin, maxPw+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > maxPw {
		return nil, fmt.Errorf("password from stdin exceeds %d bytes", maxPw)
	}
	// Strip a single trailing \r?\n so `echo pw | drk` works.
	for len(buf) > 0 && (buf[len(buf)-1] == '\n' || buf[len(buf)-1] == '\r') {
		buf = buf[:len(buf)-1]
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("stdin provided an empty password")
	}
	return buf, nil
}

func parseConnFlags(args []string) (connFlags, []string) {
	var cf connFlags
	var rest []string
	pwStdin := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-server":
			i++
			if i >= len(args) {
				fatal("-server requires a value")
			}
			cf.serverURL = strings.TrimRight(args[i], "/")
		case "-user":
			i++
			if i >= len(args) {
				fatal("-user requires a value")
			}
			cf.username = args[i]
		case "-insecure":
			cf.insecure = true
		case "-pw-stdin":
			pwStdin = true
		default:
			rest = append(rest, args[i])
		}
	}
	// Re-shift the loop counter state (the outer for used `i := 0`, already
	// done above by the case bodies — this helper is just a no-op marker).
	if cf.serverURL == "" {
		cf.serverURL = strings.TrimRight(os.Getenv("DRK_SERVER"), "/")
	}
	if cf.username == "" {
		cf.username = os.Getenv("DRK_USER")
	}
	cf.password = readPasswordSource(pwStdin)
	if cf.serverURL == "" || cf.username == "" || len(cf.password) == 0 {
		fmt.Fprintln(os.Stderr, "Error: -server, -user, and a password (via DRK_PASS or -pw-stdin) are required")
		os.Exit(1)
	}
	validateServerURL(cf.serverURL)
	requireHTTPS(cf.serverURL, cf.insecure)
	return cf, rest
}

// readPasswordSource returns the password from stdin (preferred — never
// enters the process environment) or DRK_PASS. Callers that hit either path
// end up with cf.password as a []byte that zeroBytes can wipe after use.
func readPasswordSource(pwStdin bool) []byte {
	if pwStdin {
		pw, err := readPasswordFromStdin()
		if err != nil {
			fatal("failed to read password from stdin: %v", err)
		}
		return pw
	}
	pw := []byte(os.Getenv("DRK_PASS"))
	os.Unsetenv("DRK_PASS") // remove from process environment immediately
	return pw
}

// requireHTTPS blocks plaintext HTTP for non-localhost URLs unless -insecure is set.
func requireHTTPS(serverURL string, insecure bool) {
	if !strings.HasPrefix(serverURL, "http://") {
		return // HTTPS or other — already validated by validateServerURL
	}
	u, err := url.Parse(serverURL)
	if err == nil {
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return // localhost is exempt
		}
	}
	if insecure {
		fmt.Fprintln(os.Stderr, "WARNING: Using plaintext HTTP. Credentials and encryption keys will be sent unencrypted.")
		return
	}
	fatal("Refusing plaintext HTTP for non-localhost URL.\n  Use HTTPS, or pass -insecure to override.")
}

// validateServerURL ensures the server URL uses http or https scheme.
func validateServerURL(serverURL string) {
	u, err := url.Parse(serverURL)
	if err != nil {
		fatal("invalid server URL: %v", err)
	}
	switch u.Scheme {
	case "http", "https":
		// ok
	default:
		fatal("server URL must use http:// or https:// scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		fatal("server URL must include a host")
	}
}

// login authenticates and returns (token, masterKey). Caller must zeroBytes both.
// Zeroes the password in cf after use. Token is returned as []byte (not string)
// so the caller can wipe it from memory after the last API call.
func login(cf connFlags) *userSession {
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: newHTTPTransport()}
	jsonBody := buildAuthJSON(cf.username, cf.password)
	resp, err := client.Post(cf.serverURL+"/api/auth/login", "application/json", bytes.NewReader(jsonBody))
	zeroBytes(jsonBody)
	if err != nil {
		fatal("login request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		fatal("login failed (%d): %s", resp.StatusCode, sanitizeServerResponse(b))
	}
	var lr loginResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&lr); err != nil {
		fatal("failed to parse login response: %v", err)
	}
	resp.Body.Close()

	masterKey, err := decryptMasterKey(lr.EncryptedMasterKey, cf.password, lr.KDFSalt, lr.UserID)
	zeroBytes(cf.password)
	if err != nil {
		fatal("failed to decrypt master key: %v", err)
	}

	// Unwrap the X25519 private key. The server stores it as AES-256-GCM
	// ciphertext under the master key, with userID as AAD. Required for
	// opening file/thumb/metadata keys returned by /api/media, which are
	// sealed to the user's public key rather than wrapped with master key.
	publicKey, err := base64.StdEncoding.DecodeString(lr.PublicKey)
	if err != nil || len(publicKey) != crypto.X25519PublicKeySize {
		fatal("login response has malformed public_key")
	}
	encPriv, err := base64.StdEncoding.DecodeString(lr.EncryptedPrivKey)
	if err != nil {
		fatal("login response has malformed encrypted_priv_key")
	}
	privKey, err := crypto.DecryptBlock(encPriv, masterKey, []byte(lr.UserID))
	if err != nil {
		fatal("failed to decrypt private key: %v", err)
	}
	if len(privKey) != crypto.X25519PrivateKeySize {
		fatal("decrypted private key has wrong length: %d", len(privKey))
	}

	// Verify that the server-supplied public key actually matches the
	// private key we just decrypted. Without this check, a hostile server
	// could pair a valid wrapped private key with an attacker-controlled
	// public key, causing every subsequent SealBox call (file/thumb/metadata
	// keys) to seal to the attacker rather than to us.
	derivedPub, err := crypto.DerivePublicKey(privKey)
	if err != nil {
		fatal("failed to derive public key from decrypted private key: %v", err)
	}
	if subtle.ConstantTimeCompare(derivedPub, publicKey) != 1 {
		fatal("login response public_key does not match decrypted private key — server may be malicious")
	}

	token := []byte(lr.Token)
	lr.Token = "" // release the string reference so GC can reclaim the original
	return &userSession{
		token:     token,
		masterKey: masterKey,
		publicKey: publicKey,
		privKey:   privKey,
		userID:    lr.UserID,
	}
}

// sanitizeServerResponse strips non-printable characters and truncates for safe display.
func sanitizeServerResponse(b []byte) string {
	const maxLen = 512
	s := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7F { // printable ASCII only
			s = append(s, c)
		}
	}
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return string(s)
}

// apiMediaItem matches the JSON returned by GET /api/media. The *KeySealed
// fields are X25519 sealed boxes (92 bytes each) wrapping a 32-byte AES key;
// open with the user's private key via crypto.OpenSealedBox. Each key is used
// to decrypt a specific blob: fileKey for chunks, thumbKey for thumbnail,
// metadataKey for the metadata JSON.
type apiMediaItem struct {
	ID                string `json:"id"`
	FileKeySealed     string `json:"file_key_sealed"`
	ThumbKeySealed    string `json:"thumb_key_sealed"`
	MetadataKeySealed string `json:"metadata_key_sealed"`
	HashNonce         string `json:"hash_nonce"`
	MetadataEnc       string `json:"metadata_enc"`
	MetadataNonce     string `json:"metadata_nonce"`
	CreatedAt         string `json:"created_at"`
}

type mediaMetadata struct {
	Name       string  `json:"name"`
	MediaType  string  `json:"media_type"`
	MimeType   string  `json:"mime_type"`
	Size       int64   `json:"size"`
	ChunkCount int     `json:"chunk_count"`
	Width      int     `json:"width,omitempty"`
	Height     int     `json:"height,omitempty"`
	Duration   float64 `json:"duration,omitempty"`
}

func decryptMetadata(item apiMediaItem, publicKey, privKey []byte) (*mediaMetadata, error) {
	// Hard cap on metadata size. Real metadata is <1 KB (filename, mime, dims,
	// duration); anything beyond this is a hostile/compromised server trying to
	// exhaust client memory before AES-GCM authentication fails.
	if len(item.MetadataEnc) > maxMetadataBytes {
		return nil, fmt.Errorf("metadata too large: %d bytes", len(item.MetadataEnc))
	}
	sealed, err := base64.StdEncoding.DecodeString(item.MetadataKeySealed)
	if err != nil {
		return nil, fmt.Errorf("metadata_key_sealed: %w", err)
	}
	metadataKey, err := crypto.OpenSealedBox(sealed, publicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("open metadata key: %w", err)
	}
	defer zeroBytes(metadataKey)

	encData, err := base64.StdEncoding.DecodeString(item.MetadataEnc)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(item.MetadataNonce)
	if err != nil {
		return nil, err
	}
	// Reconstruct nonce||ciphertext for DecryptBlock
	combined := make([]byte, len(nonce)+len(encData))
	copy(combined, nonce)
	copy(combined[len(nonce):], encData)
	aad := []byte(item.ID)

	plaintext, err := crypto.DecryptBlock(combined, metadataKey, aad)
	if err != nil {
		return nil, err
	}
	var meta mediaMetadata
	if err := json.Unmarshal(plaintext, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func fetchAllMedia(serverURL string, token []byte) ([]apiMediaItem, error) {
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: newHTTPTransport()}
	var all []apiMediaItem
	page := 1
	const maxPages = 1000
	for page <= maxPages {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/media?page=%d&limit=200", serverURL, page), nil)
		req.Header.Set("Authorization", "Bearer "+string(token))
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, sanitizeServerResponse(b))
		}
		var result struct {
			Items []apiMediaItem `json:"items"`
			Total int            `json:"total"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 5<<20)).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("invalid response on page %d: %w", page, err)
		}
		resp.Body.Close()
		all = append(all, result.Items...)
		if len(all) > 50000 {
			break
		}
		if len(all) >= result.Total || len(result.Items) == 0 {
			break
		}
		page++
	}
	return all, nil
}

func cmdList() {
	cf, _ := parseConnFlags(os.Args[2:])
	sess := login(cf)
	defer sess.zero()

	items, err := fetchAllMedia(cf.serverURL, sess.token)
	if err != nil {
		fatal("failed to list media: %v", err)
	}

	if len(items) == 0 {
		fmt.Println("No media items found.")
		return
	}

	fmt.Printf("%-36s  %-8s  %-10s  %s\n", "ID", "TYPE", "SIZE", "NAME")
	for _, item := range items {
		meta, err := decryptMetadata(item, sess.publicKey, sess.privKey)
		if err != nil {
			fmt.Printf("%-36s  %-8s  %-10s  %s\n", item.ID, "?", "?", "(decryption failed)")
			continue
		}
		fmt.Printf("%-36s  %-8s  %-10s  %s\n", item.ID, meta.MediaType, formatSize(meta.Size), meta.Name)
	}
	fmt.Printf("\n%d items total\n", len(items))
}

// stripPadding extracts the real data from a padded chunk/thumbnail.
// On-disk format: [4 bytes big-endian real length][data][random padding]
func stripPadding(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, fmt.Errorf("padded data too short")
	}
	realLen := int(binary.BigEndian.Uint32(padded[:4]))
	if realLen > len(padded)-4 {
		return nil, fmt.Errorf("invalid padding length")
	}
	return padded[4 : 4+realLen], nil
}

func cmdDownload() {
	args := os.Args[2:]
	var outDir string
	var filteredArgs []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-o" {
			i++
			if i >= len(args) {
				fatal("-o requires a value")
			}
			outDir = args[i]
		} else {
			filteredArgs = append(filteredArgs, args[i])
		}
	}
	cf, ids := parseConnFlags(filteredArgs)

	if outDir == "" {
		outDir = "."
	}

	sess := login(cf)
	defer sess.zero()

	items, err := fetchAllMedia(cf.serverURL, sess.token)
	if err != nil {
		fatal("failed to list media: %v", err)
	}

	// Build a map for lookup
	itemMap := make(map[string]apiMediaItem, len(items))
	for _, item := range items {
		if _, err := uuid.Parse(item.ID); err != nil {
			continue
		}
		itemMap[item.ID] = item
	}

	// If specific IDs given, download those; otherwise download all
	var toDownload []apiMediaItem
	if len(ids) > 0 {
		for _, id := range ids {
			item, ok := itemMap[id]
			if !ok {
				fmt.Fprintf(os.Stderr, "Warning: item %s not found, skipping\n", id)
				continue
			}
			toDownload = append(toDownload, item)
		}
	} else {
		toDownload = items
	}

	if len(toDownload) == 0 {
		fmt.Println("No items to download.")
		return
	}

	client := &http.Client{
		Timeout:       10 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 4, // match dlWorkers to reuse connections
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	success, fail := 0, 0

	for i, item := range toDownload {
		meta, err := decryptMetadata(item, sess.publicKey, sess.privKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%d/%d] %s — decryption failed, skipping\n", i+1, len(toDownload), item.ID)
			fail++
			continue
		}

		displayName := sanitizeServerResponse([]byte(meta.Name))
		fmt.Fprintf(os.Stderr, "  [%d/%d] %s ", i+1, len(toDownload), displayName)

		// Open the sealed file key with the user's X25519 private key.
		fileKeySealed, err := base64.StdEncoding.DecodeString(item.FileKeySealed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAILED\n")
			fail++
			continue
		}
		fileKey, err := crypto.OpenSealedBox(fileKeySealed, sess.publicKey, sess.privKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAILED\n")
			fail++
			continue
		}

		// Fetch and decrypt each chunk via the padded endpoint
		// Sanitize filename to prevent path traversal from crafted metadata.
		// filepath.Base strips directory components (e.g., "../../evil" → "evil").
		safeName := filepath.Base(meta.Name)
		if safeName == "." || safeName == ".." || safeName == "" {
			safeName = item.ID // fallback to media ID
		}
		// Reject dotfiles — a crafted server could set meta.Name to ".bashrc"
		// or similar, which filepath.Base would pass through unchanged, overwriting
		// shell configs if the user downloads to their home directory.
		if strings.HasPrefix(safeName, ".") {
			safeName = item.ID + "_" + strings.TrimLeft(safeName, ".")
		}
		outPath := filepath.Join(outDir, safeName)
		outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAILED\n")
			fail++
			zeroBytes(fileKey)
			continue
		}

		// Fetch, decrypt, and write chunks. Uses a pipeline of concurrent
		// fetchers feeding an ordered channel so writes stay sequential.
		const dlWorkers = 4
		type chunkResult struct {
			index int
			data  []byte
			err   error
		}

		gcm, gcmErr := crypto.NewChunkCipher(fileKey)
		if gcmErr != nil {
			fmt.Fprintf(os.Stderr, "FAILED\n")
			fail++
			zeroBytes(fileKey)
			outFile.Close()
			os.Remove(outPath)
			continue
		}

		if meta.ChunkCount <= 0 || meta.ChunkCount > 50000 {
			fmt.Fprintf(os.Stderr, "FAILED (invalid chunk count %d)\n", meta.ChunkCount)
			fail++
			zeroBytes(fileKey)
			outFile.Close()
			os.Remove(outPath)
			continue
		}

		// Sliding window of result channels — bounds memory to windowSize
		// chunks ahead of the writer instead of buffering all chunks.
		const windowSize = 2 * dlWorkers
		window := make([]chan chunkResult, windowSize)
		for i := range window {
			window[i] = make(chan chunkResult, 1)
		}

		sem := make(chan struct{}, dlWorkers)
		nextLaunch := 0

		// Per-item cancellation + WaitGroup so the deferred token-zero at the
		// end of cmdDownload never runs while goroutines still hold a token
		// reference. On early error break below, cancel() unblocks any pending
		// sends on the result channels and fetchWg.Wait() ensures every fetch
		// goroutine has released its reference before we move on.
		fetchCtx, fetchCancel := context.WithCancel(context.Background())
		var fetchWg sync.WaitGroup

		fetchChunk := func(ci int) {
			slot := ci % windowSize
			sem <- struct{}{}
			fetchWg.Add(1)
			go func() {
				defer fetchWg.Done()
				defer func() { <-sem }()
				res := chunkResult{index: ci}
				send := func(r chunkResult) {
					select {
					case window[slot] <- r:
					case <-fetchCtx.Done():
					}
				}
				req, _ := http.NewRequestWithContext(fetchCtx, "GET", fmt.Sprintf("%s/api/media/%s/chunk/%d", cf.serverURL, item.ID, ci), nil)
				req.Header.Set("Authorization", "Bearer "+string(sess.token))
				resp, err := client.Do(req)
				if err != nil {
					res.err = err
					send(res)
					return
				}
				if resp.StatusCode != 200 {
					resp.Body.Close()
					res.err = fmt.Errorf("status %d", resp.StatusCode)
					send(res)
					return
				}
				// Read length prefix, then only the real data (skip padding)
				var lenBuf [4]byte
				if _, err := io.ReadFull(resp.Body, lenBuf[:]); err != nil {
					resp.Body.Close()
					res.err = fmt.Errorf("read length prefix: %w", err)
					send(res)
					return
				}
				realLen := binary.BigEndian.Uint32(lenBuf[:])
				if realLen > 20<<20 {
					resp.Body.Close()
					res.err = fmt.Errorf("chunk too large: %d", realLen)
					send(res)
					return
				}
				encrypted := make([]byte, realLen)
				if _, err := io.ReadFull(resp.Body, encrypted); err != nil {
					resp.Body.Close()
					res.err = fmt.Errorf("read chunk data: %w", err)
					send(res)
					return
				}
				io.Copy(io.Discard, io.LimitReader(resp.Body, 20<<20)) // drain padding
				resp.Body.Close()
				plaintext, err := crypto.DecryptChunkWith(gcm, encrypted, ci, item.ID)
				if err != nil {
					res.err = err
					send(res)
					return
				}
				res.data = plaintext
				send(res)
			}()
		}

		// Seed the window with initial fetches
		for nextLaunch < meta.ChunkCount && nextLaunch < windowSize {
			fetchChunk(nextLaunch)
			nextLaunch++
		}

		// Cap on total decrypted bytes per item. Without this, a compromised
		// server could feed us 20 MB × 50k chunks = 1 TB before the per-chunk
		// limits alone would stop it. 50 GB is generous for real media and
		// ~2 orders of magnitude below the pathological worst case.
		const maxItemBytes int64 = 50 << 30

		// Write chunks in order, launching new fetches as slots free up
		ok := true
		var totalBytes int64
		for ci := 0; ci < meta.ChunkCount; ci++ {
			res := <-window[ci%windowSize]
			if res.err != nil {
				ok = false
				break
			}
			totalBytes += int64(len(res.data))
			if totalBytes > maxItemBytes {
				zeroBytes(res.data)
				fmt.Fprintf(os.Stderr, "FAILED (item exceeds %d bytes)\n", maxItemBytes)
				ok = false
				break
			}
			if _, err := outFile.Write(res.data); err != nil {
				zeroBytes(res.data)
				ok = false
				break
			}
			zeroBytes(res.data) // wipe decrypted plaintext from memory
			if nextLaunch < meta.ChunkCount {
				fetchChunk(nextLaunch)
				nextLaunch++
			}
		}
		// Cancel any in-flight fetches (their sends unblock via fetchCtx.Done)
		// and wait for them to return before we touch token/masterKey on the
		// next iteration or via the deferred zeroBytes at function exit.
		fetchCancel()
		fetchWg.Wait()
		outFile.Close()
		zeroBytes(fileKey)

		if ok {
			fmt.Fprintf(os.Stderr, "OK\n")
			success++
		} else {
			os.Remove(outPath) // clean up partial file
			fmt.Fprintf(os.Stderr, "FAILED\n")
			fail++
		}
	}

	fmt.Fprintf(os.Stderr, "\nDone: %d downloaded, %d failed\n", success, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}
