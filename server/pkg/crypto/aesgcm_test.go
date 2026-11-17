package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// NIST GCM test vector (gcmEncryptExtIV256.rsp, 256/104/0/408/128 case 0, abridged):
// Key: 31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22
// IV:  0d18e06c7c725ac9e362e1ce
// PT:  2db5168e932556f8089a0622981d017d
// AAD: (empty)
// CT:  fa4362189661d163fcd6a56d8bf0405a
// Tag: d636ac1bbedd5cc3ee727dc2ab4a9489
func TestAESGCM_NISTVector(t *testing.T) {
	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	iv, _ := hex.DecodeString("0d18e06c7c725ac9e362e1ce")
	pt, _ := hex.DecodeString("2db5168e932556f8089a0622981d017d")
	wantCT, _ := hex.DecodeString("fa4362189661d163fcd6a56d8bf0405a")
	wantTag, _ := hex.DecodeString("d636ac1bbedd5cc3ee727dc2ab4a9489")

	// Decrypt path (deterministic, no random IV).
	got, err := OpenGCM(key, iv, wantCT, wantTag)
	if err != nil {
		t.Fatalf("OpenGCM: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("plaintext mismatch\n got=%x\nwant=%x", got, pt)
	}
}

func TestAESGCM_RoundTrip(t *testing.T) {
	key, _ := RandBytes(32)
	msg := []byte("secblind watermark || PE body")
	s, err := SealGCM(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.IV) != 12 || len(s.Tag) != 16 {
		t.Fatalf("bad sizes iv=%d tag=%d", len(s.IV), len(s.Tag))
	}
	got, err := OpenGCM(key, s.IV, s.Ciphertext, s.Tag)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch")
	}
}
