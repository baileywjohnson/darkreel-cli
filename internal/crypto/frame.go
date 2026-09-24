package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Chunk format 2 — mirrors web/js/crypto.js in the Darkreel repo exactly.
//
// The plaintext of every chunk (and thumbnail) is a frame:
//
//	version(1) = 2 | flags(1, bit0 = last chunk) | u32be data length | data | zero padding
//
// padded so the ciphertext (nonce + frame + tag) is exactly one of a few
// bucket sizes. The server and the network only ever see bucket sizes, not
// exact chunk lengths, and the authenticated last-chunk flag lets a reader
// detect a dropped tail. Items opt in with `chunk_format: 2` in their
// encrypted metadata.
const (
	ChunkFormat  = 2
	frameHeader  = 6
	gcmOverhead  = 28 // 12-byte nonce + 16-byte tag
	mib          = 1 << 20
	thumbCTSize  = 256 * 1024
	lastChunkBit = 1
)

// ChunkDataSize is the largest chunk payload that fits the smallest (1 MiB)
// ciphertext bucket.
const ChunkDataSize = mib - gcmOverhead - frameHeader

// chunkCiphertextSize returns the ciphertext size for a chunk carrying
// dataLen bytes: 1, 2, 4, 8 or 16 MiB, then whole MiB.
func chunkCiphertextSize(dataLen int) int {
	need := dataLen + frameHeader + gcmOverhead
	for _, b := range []int{1, 2, 4, 8, 16} {
		if need <= b*mib {
			return b * mib
		}
	}
	return (need + mib - 1) / mib * mib
}

func frame(data []byte, isLast bool, ciphertextSize int) ([]byte, error) {
	frameLen := ciphertextSize - gcmOverhead
	if len(data)+frameHeader > frameLen {
		return nil, errors.New("chunk too large for its frame")
	}
	out := make([]byte, frameLen)
	out[0] = ChunkFormat
	if isLast {
		out[1] = lastChunkBit
	}
	binary.BigEndian.PutUint32(out[2:6], uint32(len(data)))
	copy(out[frameHeader:], data)
	return out, nil
}

// FrameChunk wraps a chunk payload in a padded format-2 frame.
func FrameChunk(data []byte, isLast bool) ([]byte, error) {
	return frame(data, isLast, chunkCiphertextSize(len(data)))
}

// FrameThumbnail wraps a thumbnail in a format-2 frame whose ciphertext is
// always exactly 256 KiB.
func FrameThumbnail(data []byte) ([]byte, error) {
	return frame(data, true, thumbCTSize)
}

// UnframeChunk extracts the payload from a decrypted format-2 frame.
// expectLast must say whether this is the item's final chunk; a mismatch
// means chunks were dropped or the chunk count was altered.
func UnframeChunk(plain []byte, expectLast bool) ([]byte, error) {
	if len(plain) < frameHeader || plain[0] != ChunkFormat {
		return nil, errors.New("invalid chunk frame")
	}
	isLast := plain[1]&lastChunkBit != 0
	if isLast != expectLast {
		if expectLast {
			return nil, errors.New("chunk stream truncated")
		}
		return nil, errors.New("unexpected final chunk")
	}
	n := binary.BigEndian.Uint32(plain[2:6])
	if uint64(n) > uint64(len(plain)-frameHeader) {
		return nil, errors.New("invalid chunk frame length")
	}
	return plain[frameHeader : frameHeader+int(n)], nil
}

var ownerInfo = []byte("darkreel-owner-v1")

// OwnerTag computes an item's owner tag — HMAC-SHA256 under
// HKDF-SHA256(masterKey, info "darkreel-owner-v1") over the label, the media
// ID and the three sealed keys. Only the master-key holder can produce it, so
// it distinguishes the owner's own uploads from items created by anyone else
// who can seal to the public key (delegated apps, the server, a DB writer).
func OwnerTag(masterKey []byte, mediaID string, fileKeySealed, thumbKeySealed, metadataKeySealed []byte) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, masterKey, nil, ownerInfo), key); err != nil {
		return nil, err
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write(ownerInfo)
	mac.Write([]byte(mediaID))
	mac.Write(fileKeySealed)
	mac.Write(thumbKeySealed)
	mac.Write(metadataKeySealed)
	return mac.Sum(nil), nil
}

// VerifyOwnerTag reports whether tag is the valid owner tag for the item.
func VerifyOwnerTag(tag, masterKey []byte, mediaID string, fileKeySealed, thumbKeySealed, metadataKeySealed []byte) bool {
	want, err := OwnerTag(masterKey, mediaID, fileKeySealed, thumbKeySealed, metadataKeySealed)
	if err != nil {
		return false
	}
	return hmac.Equal(tag, want)
}
