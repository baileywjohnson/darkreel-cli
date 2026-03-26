package crypto

import (
	"crypto/rand"
	"fmt"
)

// GenerateFileKey generates a random 256-bit file encryption key.
func GenerateFileKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate file key: %w", err)
	}
	return key, nil
}

// EncryptKey encrypts a file key with the user's master key using AES-256-GCM.
func EncryptKey(fileKey, masterKey []byte) ([]byte, error) {
	return EncryptBlock(fileKey, masterKey)
}
