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
		{"k_payload_aes", "sb.v1.payload.aes256gcm", "4e8a23816873957d1c4a074b1a1371a1044cb791bea972df12e198beaaff61a3"},
		{"k_heartbeat", "sb.v1.heartbeat.hmac", "265deb22d853f0a7cd0d793236944d653bbaa3cd92ba5591804d4eeecb6dfbc0"},
		{"k_watermark", "sb.v1.watermark.hmac", "903e0bd2d1769e6a165fb042c1e19ff315c43801fedf3e4009503aba6f23e4a5"},
		{"k_rpc", "sb.v1.rpc.hmac", "8ea36ae7b6b9bb5034f6445b723b83a0710f2f1b781127a3ee7bf0dfb5cf4793"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(HKDFExpand(prk, []byte(c.info), 32))
		if got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}
