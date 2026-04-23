package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// X25519 sealed-box, bytes-identical to Darkreel server's implementation so
// the CLI can seal file/thumb/metadata keys directly to a user's public key
// and open sealed keys returned by /api/media.
//
// Wire format:
//
//	ephemeral_pk (32) || nonce (12) || AES-256-GCM(derived_key, nonce, msg)
//
// where derived_key = HKDF-SHA256(ECDH(ephemeral_sk, recipient_pk),
//
//	salt=empty, info="darkreel-seal-v1")
//
// Overhead for a 32-byte payload: 32 + 12 + 32 + 16 = 92 bytes.
const (
	X25519PublicKeySize  = 32
	X25519PrivateKeySize = 32
	sealEphPubKeySize    = 32
	sealNonceSize        = 12
	sealGCMTagSize       = 16
	// SealBoxOverhead is the non-payload byte count: eph pubkey + nonce + tag.
	SealBoxOverhead = sealEphPubKeySize + sealNonceSize + sealGCMTagSize
)

var sealInfo = []byte("darkreel-seal-v1")

// GenerateKeypair returns a new X25519 keypair. The private key is clamped
// per RFC 7748 §5 so it's safe to use directly with curve25519.
func GenerateKeypair() ([]byte, []byte, error) {
	priv := make([]byte, X25519PrivateKeySize)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, fmt.Errorf("generate x25519 private key: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive x25519 public key: %w", err)
	}
	return pub, priv, nil
}

// SealBox encrypts msg to recipientPub using X25519-ECDH + HKDF-SHA256 +
// AES-256-GCM. The sender is anonymous — only the recipient can decrypt.
func SealBox(msg, recipientPub []byte) ([]byte, error) {
	if len(recipientPub) != X25519PublicKeySize {
		return nil, fmt.Errorf("sealbox: recipient public key must be %d bytes, got %d", X25519PublicKeySize, len(recipientPub))
	}

	ephPub, ephPriv, err := GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("sealbox: ephemeral keypair: %w", err)
	}
	defer clear(ephPriv)

	gcm, err := deriveSealCipher(ephPriv, recipientPub)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, sealNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("sealbox: nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, msg, nil)

	out := make([]byte, 0, SealBoxOverhead+len(msg))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// OpenSealedBox reverses SealBox using the recipient's keypair.
func OpenSealedBox(sealed, recipientPub, recipientPriv []byte) ([]byte, error) {
	if len(sealed) < SealBoxOverhead {
		return nil, fmt.Errorf("sealbox: input too short (%d bytes, minimum %d)", len(sealed), SealBoxOverhead)
	}
	if len(recipientPub) != X25519PublicKeySize {
		return nil, fmt.Errorf("sealbox: recipient public key must be %d bytes", X25519PublicKeySize)
	}
	if len(recipientPriv) != X25519PrivateKeySize {
		return nil, fmt.Errorf("sealbox: recipient private key must be %d bytes", X25519PrivateKeySize)
	}

	ephPub := sealed[:sealEphPubKeySize]
	nonce := sealed[sealEphPubKeySize : sealEphPubKeySize+sealNonceSize]
	ciphertext := sealed[sealEphPubKeySize+sealNonceSize:]

	gcm, err := deriveSealCipher(recipientPriv, ephPub)
	if err != nil {
		return nil, err
	}

	msg, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("sealbox: authentication failed: %w", err)
	}
	return msg, nil
}

// deriveSealCipher performs X25519 ECDH + HKDF-SHA256 and returns a ready
// AES-256-GCM AEAD. Symmetric in priv/peerPub: works for both Seal (priv=
// ephemeral, peerPub=recipient) and Open (priv=recipient, peerPub=ephemeral).
func deriveSealCipher(priv, peerPub []byte) (cipher.AEAD, error) {
	shared, err := curve25519.X25519(priv, peerPub)
	if err != nil {
		return nil, fmt.Errorf("sealbox: ecdh: %w", err)
	}
	defer clear(shared)

	// curve25519.X25519 rejects the all-zero shared secret (low-order points),
	// so a maliciously chosen ephemeral pubkey cannot coerce the derived key
	// into a known value.

	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, sealInfo), key); err != nil {
		return nil, fmt.Errorf("sealbox: hkdf: %w", err)
	}
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sealbox: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sealbox: gcm: %w", err)
	}
	return gcm, nil
}
