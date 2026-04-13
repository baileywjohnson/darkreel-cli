package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/gif"
	_ "image/png"
	"io"
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
  DRK_PASS    Password (required; not accepted as a CLI flag for security)
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
	var register, insecure bool
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
	// Password must come from environment variable only (never a CLI flag)
	password := []byte(os.Getenv("DRK_PASS"))
	os.Unsetenv("DRK_PASS") // remove from process environment immediately

	if serverURL == "" || username == "" || len(password) == 0 {
		fmt.Fprintln(os.Stderr, "Error: -server, -user, and DRK_PASS environment variable are required")
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
	authClient := &http.Client{Timeout: 30 * time.Second, CheckRedirect: noRedirect}
	uploadClient := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: noRedirect}

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
	loginBody := buildAuthJSON(username, password)
	resp, err := authClient.Post(serverURL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	zeroBytes(loginBody)
	if err != nil {
		fatal("login request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		fatal("login failed (%d): %s", resp.StatusCode, sanitizeServerResponse(b))
	}

	var loginResp loginResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&loginResp); err != nil {
		fatal("failed to parse login response: %v", err)
	}
	resp.Body.Close()

	// Derive master key: decrypt the encrypted master key from server
	masterKey, err := decryptMasterKey(loginResp.EncryptedMasterKey, password, loginResp.KDFSalt, loginResp.UserID)
	zeroBytes(password)
	if err != nil {
		fatal("failed to decrypt master key: %v", err)
	}
	defer zeroBytes(masterKey)

	fmt.Fprintf(os.Stderr, "Authenticated. Uploading %d file(s)...\n\n", len(files))

	success, fail := 0, 0
	for _, f := range files {
		fmt.Fprintf(os.Stderr, "  file %d/%d ", success+fail+1, len(files))
		if err := uploadFile(uploadClient, serverURL, loginResp.Token, masterKey, f); err != nil {
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

func uploadFile(client *http.Client, serverURL, token string, masterKey []byte, filePath string) error {
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

	// Generate keys
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

	mediaID := uuid.New().String()
	mediaIDBytes := []byte(mediaID)

	encThumb, err := crypto.EncryptChunk(thumbData, thumbKey, 0, mediaID)
	if err != nil {
		return fmt.Errorf("encrypt thumbnail: %w", err)
	}

	encFileKey, err := crypto.EncryptKey(fileKey, masterKey, mediaIDBytes)
	if err != nil {
		return err
	}
	encThumbKey, err := crypto.EncryptKey(thumbKey, masterKey, mediaIDBytes)
	if err != nil {
		return err
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
	metadataEnc, err := crypto.EncryptBlock(metadataPlain, masterKey, mediaIDBytes)
	if err != nil {
		return err
	}
	metadataNonce := metadataEnc[:12]
	metadataCiphertext := metadataEnc[12:]

	uploadMeta := map[string]any{
		"media_id":       mediaID,
		"chunk_count":    chunkCount,
		"file_key_enc":   base64.StdEncoding.EncodeToString(encFileKey),
		"thumb_key_enc":  base64.StdEncoding.EncodeToString(encThumbKey),
		"metadata_enc":   base64.StdEncoding.EncodeToString(metadataCiphertext),
		"metadata_nonce": base64.StdEncoding.EncodeToString(metadataNonce),
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
	req.Header.Set("Authorization", "Bearer "+token)
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

	for pos < fileSize {
		if _, err := f.ReadAt(header[:8], pos); err != nil {
			break
		}
		boxSize := int64(binary.BigEndian.Uint32(header[:4]))
		boxType := string(header[4:8])
		if boxSize == 1 && pos+16 <= fileSize {
			if _, err := f.ReadAt(header[:16], pos); err != nil {
				break
			}
			boxSize = int64(binary.BigEndian.Uint64(header[8:16]))
		}
		if boxSize == 0 {
			boxSize = fileSize - pos
		}
		if boxSize < 8 || pos+boxSize > fileSize {
			break
		}

		if boxType == "moof" {
			moofOffsets = append(moofOffsets, pos)
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
	out, err := cmd.Output()
	if err != nil {
		return "avc1.64001f,mp4a.40.2", 0, 0, 0
	}

	var result ffprobeResult
	if err := json.Unmarshal(out, &result); err != nil {
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

func parseConnFlags(args []string) (connFlags, []string) {
	var cf connFlags
	var rest []string
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
		default:
			rest = append(rest, args[i])
		}
	}
	if cf.serverURL == "" {
		cf.serverURL = strings.TrimRight(os.Getenv("DRK_SERVER"), "/")
	}
	if cf.username == "" {
		cf.username = os.Getenv("DRK_USER")
	}
	cf.password = []byte(os.Getenv("DRK_PASS"))
	os.Unsetenv("DRK_PASS") // remove from process environment immediately
	if cf.serverURL == "" || cf.username == "" || len(cf.password) == 0 {
		fmt.Fprintln(os.Stderr, "Error: -server, -user, and DRK_PASS environment variable are required")
		os.Exit(1)
	}
	validateServerURL(cf.serverURL)
	requireHTTPS(cf.serverURL, cf.insecure)
	return cf, rest
}

// requireHTTPS blocks plaintext HTTP for non-localhost URLs unless -insecure is set.
func requireHTTPS(serverURL string, insecure bool) {
	if !strings.HasPrefix(serverURL, "http://") {
		return // HTTPS or other — already validated by validateServerURL
	}
	if strings.HasPrefix(serverURL, "http://localhost") ||
		strings.HasPrefix(serverURL, "http://127.0.0.1") ||
		strings.HasPrefix(serverURL, "http://[::1]") {
		return // localhost is exempt
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

// login authenticates and returns (token, masterKey). Caller must zeroBytes(masterKey).
// Zeroes the password in cf after use.
func login(cf connFlags) (string, []byte) {
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
	return lr.Token, masterKey
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

// apiMediaItem matches the JSON returned by GET /api/media.
type apiMediaItem struct {
	ID            string `json:"id"`
	FileKeyEnc    string `json:"file_key_enc"`
	ThumbKeyEnc   string `json:"thumb_key_enc"`
	HashNonce     string `json:"hash_nonce"`
	MetadataEnc   string `json:"metadata_enc"`
	MetadataNonce string `json:"metadata_nonce"`
	CreatedAt     string `json:"created_at"`
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

func decryptMetadata(item apiMediaItem, masterKey []byte) (*mediaMetadata, error) {
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

	plaintext, err := crypto.DecryptBlock(combined, masterKey, aad)
	if err != nil {
		return nil, err
	}
	var meta mediaMetadata
	if err := json.Unmarshal(plaintext, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func fetchAllMedia(serverURL, token string) ([]apiMediaItem, error) {
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var all []apiMediaItem
	page := 1
	const maxPages = 1000
	for page <= maxPages {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/media?page=%d&limit=200", serverURL, page), nil)
		req.Header.Set("Authorization", "Bearer "+token)
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
	token, masterKey := login(cf)
	defer zeroBytes(masterKey)

	items, err := fetchAllMedia(cf.serverURL, token)
	if err != nil {
		fatal("failed to list media: %v", err)
	}

	if len(items) == 0 {
		fmt.Println("No media items found.")
		return
	}

	fmt.Printf("%-36s  %-8s  %-10s  %s\n", "ID", "TYPE", "SIZE", "NAME")
	for _, item := range items {
		meta, err := decryptMetadata(item, masterKey)
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

	token, masterKey := login(cf)
	defer zeroBytes(masterKey)

	items, err := fetchAllMedia(cf.serverURL, token)
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
		Transport:     &http.Transport{MaxIdleConnsPerHost: 4}, // match dlWorkers to reuse connections
	}
	success, fail := 0, 0

	for i, item := range toDownload {
		meta, err := decryptMetadata(item, masterKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [%d/%d] %s — decryption failed, skipping\n", i+1, len(toDownload), item.ID)
			fail++
			continue
		}

		displayName := sanitizeServerResponse([]byte(meta.Name))
		fmt.Fprintf(os.Stderr, "  [%d/%d] %s ", i+1, len(toDownload), displayName)

		// Decrypt file key
		fileKeyEnc, err := base64.StdEncoding.DecodeString(item.FileKeyEnc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAILED\n")
			fail++
			continue
		}
		fileKey, err := crypto.DecryptKey(fileKeyEnc, masterKey, []byte(item.ID))
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

		results := make([]chan chunkResult, meta.ChunkCount)
		for ci := range results {
			results[ci] = make(chan chunkResult, 1)
		}

		// Bounded worker pool: fetch + decrypt chunks concurrently
		sem := make(chan struct{}, dlWorkers)
		for ci := 0; ci < meta.ChunkCount; ci++ {
			ci := ci
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				res := chunkResult{index: ci}
				req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/media/%s/chunk/%d", cf.serverURL, item.ID, ci), nil)
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := client.Do(req)
				if err != nil {
					res.err = err
					results[ci] <- res
					return
				}
				if resp.StatusCode != 200 {
					resp.Body.Close()
					res.err = fmt.Errorf("status %d", resp.StatusCode)
					results[ci] <- res
					return
				}
				// Read length prefix, then only the real data (skip padding)
				var lenBuf [4]byte
				if _, err := io.ReadFull(resp.Body, lenBuf[:]); err != nil {
					resp.Body.Close()
					res.err = fmt.Errorf("read length prefix: %w", err)
					results[ci] <- res
					return
				}
				realLen := binary.BigEndian.Uint32(lenBuf[:])
				if realLen > 20<<20 {
					resp.Body.Close()
					res.err = fmt.Errorf("chunk too large: %d", realLen)
					results[ci] <- res
					return
				}
				encrypted := make([]byte, realLen)
				if _, err := io.ReadFull(resp.Body, encrypted); err != nil {
					resp.Body.Close()
					res.err = fmt.Errorf("read chunk data: %w", err)
					results[ci] <- res
					return
				}
				io.Copy(io.Discard, io.LimitReader(resp.Body, 20<<20)) // drain padding
				resp.Body.Close()
				plaintext, err := crypto.DecryptChunkWith(gcm, encrypted, ci, item.ID)
				if err != nil {
					res.err = err
					results[ci] <- res
					return
				}
				res.data = plaintext
				results[ci] <- res
			}()
		}

		// Write chunks in order
		ok := true
		for ci := 0; ci < meta.ChunkCount; ci++ {
			res := <-results[ci]
			if res.err != nil {
				ok = false
				break
			}
			if _, err := outFile.Write(res.data); err != nil {
				ok = false
				break
			}
		}
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
