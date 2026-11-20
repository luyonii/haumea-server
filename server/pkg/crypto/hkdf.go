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

// Per-context HKDF info tags (RFC 5869 §3.1). ASCII, no null terminator.
// Both server and C++ loader must use these byte-for-byte or key separation
// (closes TODO 9).
var (
	InfoSession   = []byte("secblind/session/v1")
	InfoPayload   = []byte("secblind/payload/v1")
	InfoHeartbeat = []byte("secblind/heartbeat/v1")
)

// HKDF derives `n` bytes from ikm using HMAC-SHA256.
func HKDF(ikm, salt, info []byte, n int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// HKDFExpand derives `outLen` bytes from an existing PRK via HKDF-Expand
// (RFC 5869 §2.3), HMAC-SHA256. Used for session_key -> per-use sub-keys.
// Returns an error only when outLen exceeds the RFC limit of 255*HashLen bytes.
func HKDFExpand(prk, info []byte, outLen int) ([]byte, error) {
	r := hkdf.Expand(sha256.New, prk, info)
	out := make([]byte, outLen)
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
