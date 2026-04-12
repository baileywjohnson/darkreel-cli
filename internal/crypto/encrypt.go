package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
)

// EncryptBlock encrypts a small block (e.g., a file key) with AES-256-GCM.
// The aad parameter provides additional authenticated data that binds the
// ciphertext to its context (e.g., user ID for master key wrapping, media ID
// for file key wrapping), preventing ciphertext substitution attacks.
// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
func EncryptBlock(plaintext, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// EncryptChunk encrypts a single chunk with AES-256-GCM.
// The mediaID and chunk index are used as additional authenticated data to
// bind each chunk to its specific file and position, preventing both reordering
// and cross-file chunk substitution.
// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
func EncryptChunk(plaintext, key []byte, chunkIndex int, mediaID string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return EncryptChunkWith(gcm, plaintext, chunkIndex, mediaID)
}

// NewChunkCipher creates a reusable GCM cipher for encrypting/decrypting
// multiple chunks with the same key, avoiding re-computing the AES key schedule.
func NewChunkCipher(key []byte) (cipher.AEAD, error) {
	return newGCM(key)
}

// EncryptChunkWith encrypts a chunk using a pre-initialized GCM cipher.
func EncryptChunkWith(gcm cipher.AEAD, plaintext []byte, chunkIndex int, mediaID string) ([]byte, error) {
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := ChunkAAD(mediaID, chunkIndex)
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ChunkAAD builds the additional authenticated data for chunk encryption:
// UTF-8(mediaID) || BigEndian(uint64(chunkIndex))
func ChunkAAD(mediaID string, chunkIndex int) []byte {
	idBytes := []byte(mediaID)
	aad := make([]byte, len(idBytes)+8)
	copy(aad, idBytes)
	binary.BigEndian.PutUint64(aad[len(idBytes):], uint64(chunkIndex))
	return aad
}
