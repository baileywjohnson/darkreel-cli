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
  drk upload -server URL -user USERNAME -pass PASSWORD FILE [FILE...]

Commands:
  upload    Encrypt and upload files to a Darkreel server

Upload flags:
  -server   Server URL (e.g., http://localhost:8080)
  -user     Username
  -pass     Password
  -register Register a new account before uploading`)
}

func cmdUpload() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: drk upload -server URL -user USERNAME -pass PASSWORD FILE [FILE...]")
		os.Exit(1)
	}

	var serverURL, username, password string
	var register bool
	var files []string

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-server":
			i++
			serverURL = strings.TrimRight(args[i], "/")
		case "-user":
			i++
			username = args[i]
		case "-pass":
			i++
			password = args[i]
		case "-register":
			register = true
		default:
			files = append(files, args[i])
		}
	}

	// Fall back to environment variables for credentials (avoids exposure in ps aux)
	if serverURL == "" {
		serverURL = strings.TrimRight(os.Getenv("DRK_SERVER"), "/")
	}
	if username == "" {
		username = os.Getenv("DRK_USER")
	}
	if password == "" {
		password = os.Getenv("DRK_PASS")
	}

	if serverURL == "" || username == "" || password == "" {
		fmt.Fprintln(os.Stderr, "Error: -server, -user, and -pass are required")
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no files specified")
		os.Exit(1)
	}

	client := &http.Client{}

	// Register if requested
	if register {
		fmt.Printf("Registering user %q...\n", username)
		body, _ := json.Marshal(map[string]string{"username": username, "password": password})
		resp, err := client.Post(serverURL+"/api/auth/register", "application/json", bytes.NewReader(body))
		if err != nil {
			fatal("register request failed: %v", err)
		}
		if resp.StatusCode != 201 {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fatal("register failed (%d): %s", resp.StatusCode, string(b))
		}
		resp.Body.Close()
		fmt.Println("Registered successfully.")
	}

	// Login
	fmt.Printf("Logging in as %q...\n", username)
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := client.Post(serverURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		fatal("login request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fatal("login failed (%d): %s", resp.StatusCode, string(b))
	}

	var loginResp loginResponse
	json.NewDecoder(resp.Body).Decode(&loginResp)
	resp.Body.Close()

	// Derive master key: decrypt the encrypted master key from server
	masterKey, err := decryptMasterKey(loginResp.EncryptedMasterKey, password)
	if err != nil {
		fatal("failed to decrypt master key: %v", err)
	}
	defer zeroBytes(masterKey)

	fmt.Printf("Authenticated. Uploading %d file(s)...\n\n", len(files))

	success, fail := 0, 0
	for _, f := range files {
		fmt.Printf("  %s ", filepath.Base(f))
		if err := uploadFile(client, serverURL, loginResp.Token, masterKey, f); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			fail++
		} else {
			fmt.Println("OK")
			success++
		}
	}

	fmt.Printf("\nDone: %d uploaded, %d failed\n", success, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func decryptMasterKey(encB64, password string) ([]byte, error) {
	encData, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, err
	}
	sessionKey := pbkdf2.Key([]byte(password), []byte("darkreel-session-key"), 100000, 32, sha256.New)
	defer zeroBytes(sessionKey)

	return crypto.DecryptBlock(encData, sessionKey)
}

func uploadFile(client *http.Client, serverURL, token string, masterKey []byte, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
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

	// Hash modification
	hashNonce, err := crypto.GenerateHashNonce()
	if err != nil {
		return err
	}
	data, err = crypto.ModifyHash(data, mimeType, hashNonce)
	if err != nil {
		// Non-fatal; continue with unmodified data
		data, _ = os.ReadFile(filePath)
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

	// Encrypt filename
	encName, err := crypto.EncryptBlock([]byte(filepath.Base(filePath)), masterKey)
	if err != nil {
		return err
	}

	// Build metadata
	meta := map[string]any{
		"name":          base64.StdEncoding.EncodeToString(encName),
		"media_type":    mediaType,
		"mime_type":     mimeType,
		"size":          info.Size(),
		"chunk_count":   chunkCount,
		"file_key_enc":  base64.StdEncoding.EncodeToString(encFileKey),
		"thumb_key_enc": base64.StdEncoding.EncodeToString(encThumbKey),
		"hash_nonce":    base64.StdEncoding.EncodeToString(hashNonce),
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
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(b))
	}

	return nil
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

	tmpFile := filepath.Join(os.TempDir(), "drk-thumb.jpg")
	defer os.Remove(tmpFile)

	cmd := exec.Command(ffmpeg,
		"-i", filePath,
		"-ss", "00:00:01",
		"-vframes", "1",
		"-vf", "scale=320:-1",
		"-q:v", "5",
		"-y",
		tmpFile,
	)
	cmd.Stderr = nil
	cmd.Stdout = nil

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n    (ffmpeg failed — using placeholder thumbnail)\n    ")
		return placeholderThumb()
	}

	data, err := os.ReadFile(tmpFile)
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
