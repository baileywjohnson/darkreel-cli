package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/baileywjohnson/darkreel-cli/internal/crypto"
	_ "golang.org/x/image/webp"
	"golang.org/x/crypto/pbkdf2"
)

const chunkSize = 1 << 20 // 1 MB — must match server

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

Environment variables:
  DRK_PASS    Password (required; not accepted as a CLI flag for security)
  DRK_SERVER  Server URL (fallback if -server not provided)
  DRK_USER    Username (fallback if -user not provided)

Commands:
  upload    Encrypt and upload files to a Darkreel server

Upload flags:
  -server   Server URL (e.g., http://localhost:8080)
  -user     Username
  -register Register a new account before uploading`)
}

func cmdUpload() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: drk upload -server URL -user USERNAME FILE [FILE...]")
		os.Exit(1)
	}

	var serverURL, username string
	var register bool
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
	password := os.Getenv("DRK_PASS")

	if serverURL == "" || username == "" || password == "" {
		fmt.Fprintln(os.Stderr, "Error: -server, -user, and DRK_PASS environment variable are required")
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no files specified")
		os.Exit(1)
	}

	// Warn when using plaintext HTTP for non-localhost URLs
	if strings.HasPrefix(serverURL, "http://") &&
		!strings.HasPrefix(serverURL, "http://localhost") &&
		!strings.HasPrefix(serverURL, "http://127.0.0.1") &&
		!strings.HasPrefix(serverURL, "http://[::1]") {
		fmt.Fprintln(os.Stderr, "WARNING: Using plaintext HTTP. Credentials and encryption keys will be sent unencrypted.")
		fmt.Fprintln(os.Stderr, "         Use HTTPS for production deployments.")
	}

	authClient := &http.Client{Timeout: 30 * time.Second}
	uploadClient := &http.Client{Timeout: 10 * time.Minute}

	// Register if requested
	if register {
		fmt.Printf("Registering user %q...\n", username)
		body, _ := json.Marshal(map[string]string{"username": username, "password": password})
		resp, err := authClient.Post(serverURL+"/api/auth/register", "application/json", bytes.NewReader(body))
		if err != nil {
			fatal("register request failed: %v", err)
		}
		if resp.StatusCode != 201 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			fatal("register failed (%d): %s", resp.StatusCode, string(b))
		}
		resp.Body.Close()
		fmt.Println("Registered successfully.")
	}

	// Login
	fmt.Printf("Logging in as %q...\n", username)
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := authClient.Post(serverURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		fatal("login request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		fatal("login failed (%d): %s", resp.StatusCode, string(b))
	}

	var loginResp loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		fatal("failed to parse login response: %v", err)
	}
	resp.Body.Close()

	// Derive master key: decrypt the encrypted master key from server
	masterKey, err := decryptMasterKey(loginResp.EncryptedMasterKey, password, loginResp.KDFSalt)
	if err != nil {
		fatal("failed to decrypt master key: %v", err)
	}
	defer zeroBytes(masterKey)

	fmt.Fprintf(os.Stderr, "Authenticated. Uploading %d file(s)...\n\n", len(files))

	success, fail := 0, 0
	for _, f := range files {
		fmt.Fprintf(os.Stderr, "  file %d/%d ", success+fail+1, len(files))
		if err := uploadFile(uploadClient, serverURL, loginResp.Token, masterKey, f); err != nil {
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

func decryptMasterKey(encB64, password, kdfSaltB64 string) ([]byte, error) {
	encData, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, err
	}
	kdfSalt, err := base64.StdEncoding.DecodeString(kdfSaltB64)
	if err != nil {
		return nil, fmt.Errorf("invalid kdf_salt: %w", err)
	}
	sessionKey := pbkdf2.Key([]byte(password), kdfSalt, 600000, 32, sha256.New)
	defer zeroBytes(sessionKey)

	return crypto.DecryptBlock(encData, sessionKey)
}

func uploadFile(client *http.Client, serverURL, token string, masterKey []byte, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	mediaType := "image"
	if isVideo(ext) {
		mediaType = "video"
	}

	// For videos, attempt fMP4 remux and codec probing
	fragmented := false
	codecString := ""
	var videoWidth, videoHeight int
	var videoDuration float64

	if mediaType == "video" {
		fmp4Data, ok := remuxToFMP4(filePath)
		if ok {
			data = fmp4Data
			fragmented = true
			mimeType = "video/mp4"
		}
		codecString = probeCodecs(filePath)
		videoWidth, videoHeight, videoDuration = probeVideoDimensions(filePath)
	}

	// Hash modification — skip for fMP4 remuxed videos (would break container)
	var hashNonce []byte
	if fragmented {
		hashNonce = nil
	} else {
		hashNonce, err = crypto.GenerateHashNonce()
		if err != nil {
			return err
		}
		data, err = crypto.ModifyHash(data, mimeType, hashNonce)
		if err != nil {
			// Non-fatal; continue with unmodified data
			data, _ = os.ReadFile(filePath)
			hashNonce = nil
		}
	}

	// Generate thumbnail
	thumbData := generateThumbnail(data, mimeType, filePath)

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

	// Encrypt thumbnail
	encThumb, err := crypto.EncryptChunk(thumbData, thumbKey, 0)
	if err != nil {
		return fmt.Errorf("encrypt thumbnail: %w", err)
	}

	// Encrypt file in chunks
	chunkCount := (len(data) + chunkSize - 1) / chunkSize
	encChunks := make([][]byte, chunkCount)
	for i := 0; i < chunkCount; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		enc, err := crypto.EncryptChunk(data[start:end], fileKey, i)
		if err != nil {
			return fmt.Errorf("encrypt chunk %d: %w", i, err)
		}
		encChunks[i] = enc
	}

	// Encrypt keys with master key
	encFileKey, err := crypto.EncryptKey(fileKey, masterKey)
	if err != nil {
		return err
	}
	encThumbKey, err := crypto.EncryptKey(thumbKey, masterKey)
	if err != nil {
		return err
	}

	// Build and encrypt the metadata blob (name, type, mime, size, etc.)
	metaMap := map[string]any{
		"name":        filepath.Base(filePath),
		"media_type":  mediaType,
		"mime_type":   mimeType,
		"size":        len(data),
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
	metadataEnc, err := crypto.EncryptBlock(metadataPlain, masterKey)
	if err != nil {
		return err
	}
	// EncryptBlock returns nonce || ciphertext || tag. Split nonce (first 12 bytes) from rest.
	metadataNonce := metadataEnc[:12]
	metadataCiphertext := metadataEnc[12:]

	// Build upload metadata
	meta := map[string]any{
		"chunk_count":    chunkCount,
		"file_key_enc":   base64.StdEncoding.EncodeToString(encFileKey),
		"thumb_key_enc":  base64.StdEncoding.EncodeToString(encThumbKey),
		"metadata_enc":   base64.StdEncoding.EncodeToString(metadataCiphertext),
		"metadata_nonce": base64.StdEncoding.EncodeToString(metadataNonce),
	}
	if len(hashNonce) > 0 {
		meta["hash_nonce"] = base64.StdEncoding.EncodeToString(hashNonce)
	}

	// Build multipart body
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	metaPart, err := writer.CreateFormField("metadata")
	if err != nil {
		return err
	}
	json.NewEncoder(metaPart).Encode(meta)

	thumbPart, err := writer.CreateFormField("thumbnail")
	if err != nil {
		return err
	}
	thumbPart.Write(encThumb)

	for i, chunk := range encChunks {
		chunkPart, err := writer.CreateFormField(fmt.Sprintf("chunk_%d", i))
		if err != nil {
			return err
		}
		chunkPart.Write(chunk)
	}
	writer.Close()

	req, err := http.NewRequest("POST", serverURL+"/api/media/upload", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(b))
	}

	return nil
}

// remuxToFMP4 remuxes the video at filePath to fragmented MP4 using ffmpeg.
// Returns the fMP4 data and true on success, or nil and false if ffmpeg is
// unavailable or the remux fails.
func remuxToFMP4(filePath string) ([]byte, bool) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n    (ffmpeg not found — skipping fMP4 remux)\n    ")
		return nil, false
	}

	tmpFile, err := os.CreateTemp("", "drk-fmp4-*.mp4")
	if err != nil {
		return nil, false
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	cmd := exec.Command(ffmpeg,
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
		fmt.Fprintf(os.Stderr, "\n    (fMP4 remux failed — using original file)\n    ")
		return nil, false
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, false
	}
	return data, true
}

// probeCodecs uses ffprobe to determine video and audio codecs, returning a
// codec string suitable for MSE (e.g. "avc1.64001f,mp4a.40.2"). Returns a
// reasonable default if ffprobe is unavailable.
func probeCodecs(filePath string) string {
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		return "avc1.64001f,mp4a.40.2"
	}

	// Probe video codec
	videoCodec := probeStreamCodec(ffprobe, filePath, "v:0")
	audioCodec := probeStreamCodec(ffprobe, filePath, "a:0")

	videoMSE := mapVideoCodec(videoCodec)
	audioMSE := mapAudioCodec(audioCodec)

	if videoMSE != "" && audioMSE != "" {
		return videoMSE + "," + audioMSE
	}
	if videoMSE != "" {
		return videoMSE
	}
	return "avc1.64001f,mp4a.40.2"
}

func probeStreamCodec(ffprobe, filePath, stream string) string {
	type ffprobeResult struct {
		Streams []struct {
			CodecName string `json:"codec_name"`
		} `json:"streams"`
	}

	cmd := exec.Command(ffprobe,
		"-v", "quiet",
		"-select_streams", stream,
		"-show_entries", "stream=codec_name",
		"-of", "json",
		filePath,
	)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	var result ffprobeResult
	if err := json.Unmarshal(out, &result); err != nil || len(result.Streams) == 0 {
		return ""
	}
	return result.Streams[0].CodecName
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

// probeVideoDimensions uses ffprobe to get video width, height, and duration.
func probeVideoDimensions(filePath string) (int, int, float64) {
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		return 0, 0, 0
	}

	type ffprobeResult struct {
		Streams []struct {
			Width  int `json:"width"`
			Height int `json:"height"`
		} `json:"streams"`
		Format struct {
			Duration string `json:"duration"`
		} `json:"format"`
	}

	cmd := exec.Command(ffprobe,
		"-v", "quiet",
		"-select_streams", "v:0",
		"-show_entries", "stream=width,height:format=duration",
		"-of", "json",
		filePath,
	)
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, 0
	}

	var result ffprobeResult
	if err := json.Unmarshal(out, &result); err != nil {
		return 0, 0, 0
	}

	var w, h int
	if len(result.Streams) > 0 {
		w = result.Streams[0].Width
		h = result.Streams[0].Height
	}

	var dur float64
	if result.Format.Duration != "" {
		fmt.Sscanf(result.Format.Duration, "%f", &dur)
	}

	return w, h, dur
}

func generateThumbnail(data []byte, mimeType, filePath string) []byte {
	if isVideo(strings.ToLower(filepath.Ext(filePath))) {
		return generateVideoThumbnail(filePath)
	}
	return generateImageThumbnail(data)
}

func generateImageThumbnail(data []byte) []byte {
	img, _, err := image.Decode(bytes.NewReader(data))
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
	for y := 0; y < th; y++ {
		for x := 0; x < tw; x++ {
			srcX := x * w / tw + bounds.Min.X
			srcY := y * h / th + bounds.Min.Y
			thumb.Set(x, y, img.At(srcX, srcY))
		}
	}

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, thumb, &jpeg.Options{Quality: 70}); err != nil {
		return placeholderThumb()
	}
	return buf.Bytes()
}

func generateVideoThumbnail(filePath string) []byte {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n    (ffmpeg not found — using placeholder thumbnail for video)\n    ")
		return placeholderThumb()
	}

	tmpFile, err := os.CreateTemp("", "drk-thumb-*.jpg")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n    (failed to create temp file — using placeholder thumbnail)\n    ")
		return placeholderThumb()
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	cmd := exec.Command(ffmpeg,
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

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
