package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
)

const hashNonceLen = 32

// GenerateHashNonce creates a random nonce for hash modification.
func GenerateHashNonce() ([]byte, error) {
	nonce := make([]byte, hashNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// ModifyHash injects a random nonce into file metadata to change the file hash
// without affecting playback/display. Returns the modified file data.
func ModifyHash(data []byte, mimeType string, nonce []byte) ([]byte, error) {
	lower := strings.ToLower(mimeType)
	switch {
	case strings.Contains(lower, "jpeg") || strings.Contains(lower, "jpg"):
		return modifyJPEG(data, nonce)
	case strings.Contains(lower, "png"):
		return modifyPNG(data, nonce)
	case strings.Contains(lower, "mp4") || strings.Contains(lower, "quicktime"):
		return modifyMP4(data, nonce)
	case strings.Contains(lower, "webm") || strings.Contains(lower, "matroska"):
		return nil, fmt.Errorf("unsupported format for hash modification: %s", mimeType)
	default:
		return nil, fmt.Errorf("unsupported format for hash modification: %s", mimeType)
	}
}

func modifyJPEG(data []byte, nonce []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, fmt.Errorf("not a valid JPEG")
	}
	comLen := uint16(len(nonce) + 2)
	com := make([]byte, 4+len(nonce))
	com[0] = 0xFF
	com[1] = 0xFE
	binary.BigEndian.PutUint16(com[2:4], comLen)
	copy(com[4:], nonce)

	result := make([]byte, 0, len(data)+len(com))
	result = append(result, data[:2]...)
	result = append(result, com...)
	result = append(result, data[2:]...)
	return result, nil
}

func modifyPNG(data []byte, nonce []byte) ([]byte, error) {
	sig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(data) < 8 || !bytes.Equal(data[:8], sig) {
		return nil, fmt.Errorf("not a valid PNG")
	}

	pos := 8
	for pos+8 <= len(data) {
		chunkLen := binary.BigEndian.Uint32(data[pos : pos+4])
		chunkType := string(data[pos+4 : pos+8])
		if chunkType == "IDAT" {
			break
		}
		pos += 12 + int(chunkLen)
	}

	keyword := "darkreel"
	textData := append([]byte(keyword), 0)
	textData = append(textData, nonce...)
	chunk := buildPNGChunk("tEXt", textData)

	result := make([]byte, 0, len(data)+len(chunk))
	result = append(result, data[:pos]...)
	result = append(result, chunk...)
	result = append(result, data[pos:]...)
	return result, nil
}

func buildPNGChunk(chunkType string, chunkData []byte) []byte {
	buf := make([]byte, 12+len(chunkData))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(chunkData)))
	copy(buf[4:8], chunkType)
	copy(buf[8:], chunkData)
	crc := crc32PNG(buf[4 : 8+len(chunkData)])
	binary.BigEndian.PutUint32(buf[8+len(chunkData):], crc)
	return buf
}

func crc32PNG(data []byte) uint32 {
	var table [256]uint32
	for i := 0; i < 256; i++ {
		c := uint32(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = 0xEDB88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		table[i] = c
	}
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc = table[byte(crc)^b] ^ (crc >> 8)
	}
	return crc ^ 0xFFFFFFFF
}

func modifyMP4(data []byte, nonce []byte) ([]byte, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("not a valid MP4")
	}

	// Append a 'free' box at the END of the file.
	// Inserting before moov would corrupt stco/co64 byte offsets.
	boxSize := uint32(8 + len(nonce))
	freeBox := make([]byte, boxSize)
	binary.BigEndian.PutUint32(freeBox[0:4], boxSize)
	copy(freeBox[4:8], "free")
	copy(freeBox[8:], nonce)

	result := make([]byte, 0, len(data)+len(freeBox))
	result = append(result, data...)
	result = append(result, freeBox...)
	return result, nil
}

