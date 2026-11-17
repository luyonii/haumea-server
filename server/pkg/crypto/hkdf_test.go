package crypto

import (
	"encoding/hex"
	"testing"
)

// RFC 5869 Appendix A.1 — basic SHA-256 vector.
// We only compare the first 32 bytes (L=42 expected, 32 is one block).
func TestHKDF_RFC5869_A1_FirstBlock(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	// Expected L=42 OKM: 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
	want, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")

	got, err := HKDF(ikm, salt, info, 32)
	if err != nil {
		t.Fatalf("HKDF: %v", err)
	}
	if !Equal(got, want) {
		t.Fatalf("mismatch\n got=%x\nwant=%x", got, want)
	}
}

// HMAC-SHA256 NIST test vector (RFC 4231 test case 1).
func TestHMAC256_RFC4231_Case1(t *testing.T) {
	key, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	data := []byte("Hi There")
	want, _ := hex.DecodeString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

	got := HMAC256(key, data)
	if !Equal(got, want) {
		t.Fatalf("mismatch\n got=%x\nwant=%x", got, want)
	}
}

func TestHKDFSalt_Literal(t *testing.T) {
	if len(HKDFSalt) != 16 || string(HKDFSalt) != "SecBlind_HKDF_v1" {
		t.Fatalf("bad salt literal: %q (%d B)", HKDFSalt, len(HKDFSalt))
	}
}
