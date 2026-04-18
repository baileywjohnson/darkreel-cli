package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"image"
	"image/jpeg"
	"image/png"
	"testing"
)

// ---- Test helpers ----

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// ---- AES-256-GCM round-trip ----

func TestEncryptBlock_RoundTrip(t *testing.T) {
	key := randBytes(t, 32)
	aad := []byte("test-media-id")
	plaintext := []byte("the decrypted plaintext must match")

	ct, err := EncryptBlock(plaintext, key, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	pt, err := DecryptBlock(ct, key, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestEncryptBlock_WrongAADFails(t *testing.T) {
	key := randBytes(t, 32)
	plaintext := []byte("secret")

	ct, err := EncryptBlock(plaintext, key, []byte("aad-A"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptBlock(ct, key, []byte("aad-B")); err == nil {
		t.Fatal("decrypt with wrong AAD should fail")
	}
}

func TestEncryptBlock_WrongKeyFails(t *testing.T) {
	key1 := randBytes(t, 32)
	key2 := randBytes(t, 32)
	aad := []byte("same-aad")

	ct, err := EncryptBlock([]byte("secret"), key1, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptBlock(ct, key2, aad); err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestEncryptBlock_TamperedCiphertextFails(t *testing.T) {
	key := randBytes(t, 32)
	aad := []byte("aad")

	ct, err := EncryptBlock([]byte("secret"), key, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip a bit in the ciphertext body
	ct[len(ct)/2] ^= 0x01
	if _, err := DecryptBlock(ct, key, aad); err == nil {
		t.Fatal("decrypt of tampered ciphertext should fail")
	}
}

func TestDecryptBlock_ShortCiphertextFails(t *testing.T) {
	key := randBytes(t, 32)
	if _, err := DecryptBlock([]byte{0, 1, 2}, key, nil); err == nil {
		t.Fatal("decrypt of ciphertext shorter than nonce should fail")
	}
}

// ---- Chunk encryption / AAD ----

func TestEncryptChunk_RoundTrip(t *testing.T) {
	key := randBytes(t, 32)
	mediaID := "a3d9c8e2-7b14-4f5e-8c1a-0fa1b9d2e3c4"
	plaintext := []byte("chunk data...")

	ct, err := EncryptChunk(plaintext, key, 42, mediaID)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := DecryptChunk(ct, key, 42, mediaID)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatal("round-trip mismatch")
	}
}

func TestChunkAAD_DifferentIndexFails(t *testing.T) {
	key := randBytes(t, 32)
	mediaID := "media"
	ct, err := EncryptChunk([]byte("x"), key, 1, mediaID)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptChunk(ct, key, 2, mediaID); err == nil {
		t.Fatal("chunk with wrong index must not decrypt (prevents reordering)")
	}
}

func TestChunkAAD_DifferentMediaIDFails(t *testing.T) {
	key := randBytes(t, 32)
	ct, err := EncryptChunk([]byte("x"), key, 1, "media-A")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptChunk(ct, key, 1, "media-B"); err == nil {
		t.Fatal("chunk with wrong mediaID must not decrypt (prevents cross-file substitution)")
	}
}

func TestChunkAAD_Deterministic(t *testing.T) {
	a := ChunkAAD("media-id", 42)
	b := ChunkAAD("media-id", 42)
	if !bytes.Equal(a, b) {
		t.Fatal("ChunkAAD must be deterministic")
	}
}

func TestChunkAAD_Format(t *testing.T) {
	// AAD = UTF8(mediaID) || BigEndian(uint64(chunkIndex))
	mediaID := "xyz"
	aad := ChunkAAD(mediaID, 0x0102030405060708)
	want := append([]byte(mediaID), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
	if !bytes.Equal(aad, want) {
		t.Fatalf("AAD mismatch: got %x, want %x", aad, want)
	}
}

func TestChunkCipher_Reusable(t *testing.T) {
	key := randBytes(t, 32)
	mediaID := "m"
	gcm, err := NewChunkCipher(key)
	if err != nil {
		t.Fatalf("NewChunkCipher: %v", err)
	}
	// Encrypt several chunks with the same GCM, decrypt with the same.
	for i := 0; i < 5; i++ {
		pt := []byte{byte(i), byte(i + 1)}
		ct, err := EncryptChunkWith(gcm, pt, i, mediaID)
		if err != nil {
			t.Fatalf("EncryptChunkWith[%d]: %v", i, err)
		}
		got, err := DecryptChunkWith(gcm, ct, i, mediaID)
		if err != nil {
			t.Fatalf("DecryptChunkWith[%d]: %v", i, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("chunk %d: mismatch", i)
		}
	}
}

// ---- Key wrapping ----

func TestKeyWrap_RoundTrip(t *testing.T) {
	masterKey, err := GenerateFileKey()
	if err != nil {
		t.Fatalf("GenerateFileKey: %v", err)
	}
	fileKey, err := GenerateFileKey()
	if err != nil {
		t.Fatalf("GenerateFileKey: %v", err)
	}
	mediaID := []byte("m1")

	wrapped, err := EncryptKey(fileKey, masterKey, mediaID)
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	unwrapped, err := DecryptKey(wrapped, masterKey, mediaID)
	if err != nil {
		t.Fatalf("DecryptKey: %v", err)
	}
	if !bytes.Equal(unwrapped, fileKey) {
		t.Fatal("unwrapped key doesn't match original")
	}
}

func TestKeyWrap_WrongMediaIDFails(t *testing.T) {
	master, _ := GenerateFileKey()
	file, _ := GenerateFileKey()
	wrapped, err := EncryptKey(file, master, []byte("media-A"))
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}
	if _, err := DecryptKey(wrapped, master, []byte("media-B")); err == nil {
		t.Fatal("wrapped key with wrong mediaID must not decrypt")
	}
}

func TestGenerateFileKey_Length(t *testing.T) {
	k, err := GenerateFileKey()
	if err != nil {
		t.Fatalf("GenerateFileKey: %v", err)
	}
	if len(k) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(k))
	}
}

// ---- Hash modification ----

func TestGenerateHashNonce_Length(t *testing.T) {
	n, err := GenerateHashNonce()
	if err != nil {
		t.Fatalf("GenerateHashNonce: %v", err)
	}
	if len(n) != hashNonceLen {
		t.Fatalf("expected %d bytes, got %d", hashNonceLen, len(n))
	}
}

func TestModifyJPEG_DecodesAfterModification(t *testing.T) {
	// Build a minimal JPEG
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 70}); err != nil {
		t.Fatalf("jpeg.Encode: %v", err)
	}
	original := buf.Bytes()

	nonce := randBytes(t, hashNonceLen)
	modified, err := ModifyHash(original, "image/jpeg", nonce)
	if err != nil {
		t.Fatalf("ModifyHash: %v", err)
	}
	if bytes.Equal(modified, original) {
		t.Fatal("modified JPEG is identical to original")
	}
	// Modified JPEG must still decode as a valid image.
	if _, err := jpeg.Decode(bytes.NewReader(modified)); err != nil {
		t.Fatalf("modified JPEG failed to decode: %v", err)
	}
}

func TestModifyPNG_DecodesAfterModification(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	original := buf.Bytes()

	nonce := randBytes(t, hashNonceLen)
	modified, err := ModifyHash(original, "image/png", nonce)
	if err != nil {
		t.Fatalf("ModifyHash: %v", err)
	}
	if bytes.Equal(modified, original) {
		t.Fatal("modified PNG is identical to original")
	}
	if _, err := png.Decode(bytes.NewReader(modified)); err != nil {
		t.Fatalf("modified PNG failed to decode: %v", err)
	}
}

func TestModifyMP4_PreservesOriginalBytes(t *testing.T) {
	// Minimal ftyp box so the detector sees a valid MP4-looking file.
	ftyp := make([]byte, 16)
	binary.BigEndian.PutUint32(ftyp[0:4], 16)
	copy(ftyp[4:8], "ftyp")
	copy(ftyp[8:12], "isom")
	// remainder is zeros — fine for this structural test.

	nonce := randBytes(t, hashNonceLen)
	modified, err := ModifyHash(ftyp, "video/mp4", nonce)
	if err != nil {
		t.Fatalf("ModifyHash: %v", err)
	}
	// Original must be a prefix (we append a free box at the end).
	if !bytes.HasPrefix(modified, ftyp) {
		t.Fatal("modified MP4 must preserve the original bytes as a prefix")
	}
	// The appended box must be [size(4)]['free'(4)][nonce(32)].
	appended := modified[len(ftyp):]
	if len(appended) != 8+len(nonce) {
		t.Fatalf("appended length: got %d, want %d", len(appended), 8+len(nonce))
	}
	if size := binary.BigEndian.Uint32(appended[0:4]); size != uint32(8+len(nonce)) {
		t.Fatalf("free box size: got %d, want %d", size, 8+len(nonce))
	}
	if string(appended[4:8]) != "free" {
		t.Fatalf("appended box type: got %q, want %q", appended[4:8], "free")
	}
	if !bytes.Equal(appended[8:], nonce) {
		t.Fatal("appended box payload != nonce")
	}
}

func TestModifyHash_UnsupportedFormatFails(t *testing.T) {
	nonce := randBytes(t, hashNonceLen)
	if _, err := ModifyHash([]byte("x"), "video/webm", nonce); err == nil {
		t.Fatal("webm should be unsupported")
	}
	if _, err := ModifyHash([]byte("x"), "application/pdf", nonce); err == nil {
		t.Fatal("pdf should be unsupported")
	}
}

func TestModifyJPEG_RejectsInvalidInput(t *testing.T) {
	nonce := randBytes(t, hashNonceLen)
	if _, err := ModifyHash([]byte{0x00, 0x00, 0x00}, "image/jpeg", nonce); err == nil {
		t.Fatal("non-JPEG input should fail")
	}
}

func TestModifyPNG_RejectsInvalidInput(t *testing.T) {
	nonce := randBytes(t, hashNonceLen)
	if _, err := ModifyHash([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "image/png", nonce); err == nil {
		t.Fatal("non-PNG input should fail")
	}
}
