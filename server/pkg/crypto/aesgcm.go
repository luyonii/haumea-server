package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// SealResult carries the wire fields the client expects: ciphertext and tag separated.
type SealResult struct {
	IV, Ciphertext, Tag []byte
}

// SealGCM encrypts plaintext with AES-256-GCM. IV is 12 B random; tag is 16 B.
func SealGCM(key, plaintext []byte) (*SealResult, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, iv, plaintext, nil)
	ct := sealed[:len(sealed)-16]
	tag := sealed[len(sealed)-16:]
	return &SealResult{IV: iv, Ciphertext: ct, Tag: tag}, nil
}

// OpenGCM is the inverse, used by tests.
func OpenGCM(key, iv, ciphertext, tag []byte) ([]byte, error) {
	if len(key) != 32 || len(iv) != 12 || len(tag) != 16 {
		return nil, errors.New("bad input sizes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	combined := make([]byte, 0, len(ciphertext)+len(tag))
	combined = append(combined, ciphertext...)
	combined = append(combined, tag...)
	return aead.Open(nil, iv, combined, nil)
}

// RandBytes returns n cryptographically random bytes.
func RandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
