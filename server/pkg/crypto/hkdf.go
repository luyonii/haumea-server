// Package crypto wraps the primitives the C++ client expects.
// HKDF-SHA256 (RFC 5869), HMAC-SHA256, AES-256-GCM.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDFSalt is the 16-byte ASCII constant both sides use for the fixed-salt case.
var HKDFSalt = []byte("SecBlind_HKDF_v1")

// HKDF derives `n` bytes from ikm using HMAC-SHA256.
func HKDF(ikm, salt, info []byte, n int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// HMAC256 returns HMAC-SHA256(key, data).
func HMAC256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// Equal is a constant-time byte comparison.
func Equal(a, b []byte) bool { return hmac.Equal(a, b) }
