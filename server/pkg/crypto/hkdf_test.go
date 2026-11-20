package crypto

import (
	"encoding/hex"
	"testing"
)

// Fixed PRK (session_key) = bytes 0x00..0x1f. Expected sub-keys computed
// independently (HMAC-SHA256(prk, info||0x01), single HKDF-Expand block).
// The C++ client must derive these exact bytes for the same inputs.
func TestHKDFExpandSubKeys(t *testing.T) {
	prk := make([]byte, 32)
	for i := range prk {
		prk[i] = byte(i)
	}

	cases := []struct {
		name string
		info string
		want string
	}{
		{"k_payload_aes", "secblind/payload/v1", "983f87a4de6cf8b2cd24323cb9806f7bd8ad716796d1212fc54a70d0f102773c"},
		{"k_heartbeat", "secblind/heartbeat/v1", "472b6c85079efe3d07954d7eea7b8ec6de8dd2cd72a9c300e919f5a7a8459400"},
		{"k_watermark", "sb.v1.watermark.hmac", "903e0bd2d1769e6a165fb042c1e19ff315c43801fedf3e4009503aba6f23e4a5"},
		{"k_rpc", "sb.v1.rpc.hmac", "8ea36ae7b6b9bb5034f6445b723b83a0710f2f1b781127a3ee7bf0dfb5cf4793"},
	}
	for _, c := range cases {
		b, err := HKDFExpand(prk, []byte(c.info), 32)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := hex.EncodeToString(b)
		if got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

// TestHKDFContextSeparation: changing only the info tag yields a different
// key, i.e. key separation per RFC 5869 §3.1 actually holds.
func TestHKDFContextSeparation(t *testing.T) {
	prk := make([]byte, 32)
	for i := range prk {
		prk[i] = byte(i)
	}
	a, _ := HKDFExpand(prk, InfoPayload, 32)
	b, _ := HKDFExpand(prk, InfoHeartbeat, 32)
	c, _ := HKDFExpand(prk, InfoSession, 32)
	if hex.EncodeToString(a) == hex.EncodeToString(b) ||
		hex.EncodeToString(a) == hex.EncodeToString(c) ||
		hex.EncodeToString(b) == hex.EncodeToString(c) {
		t.Fatalf("context tags collide: payload=%x heartbeat=%x session=%x", a, b, c)
	}
}
