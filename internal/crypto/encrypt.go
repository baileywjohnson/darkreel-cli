package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
)

// EncryptBlock encrypts a small block (e.g., a file key) with AES-256-GCM.
// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
func EncryptBlock(plaintext, key []byte) ([]byte, error) {
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
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// EncryptChunk encrypts a single chunk with AES-256-GCM.
// The chunk index is used as additional authenticated data to prevent reordering.
// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
func EncryptChunk(plaintext, key []byte, chunkIndex int) ([]byte, error) {
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

	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, uint64(chunkIndex))

	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}
