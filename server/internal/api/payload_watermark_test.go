package api

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestBuildWatermark_TTL_OneHour pins the watermark TTL field (wm[72:80],
// little-endian uint64 seconds) to 3600. Shrinking it from 86400 is the point
// of this change; a regression back to a day would silently re-widen the
// post-revoke replay window.
func TestBuildWatermark_TTL_OneHour(t *testing.T) {
	hwid := strings.Repeat("ab", 32) // 64 hex chars -> 32 bytes
	wm, err := buildWatermark(hwid, "any-license-key", make([]byte, 32))
	if err != nil {
		t.Fatalf("buildWatermark: %v", err)
	}
	ttl := binary.LittleEndian.Uint64(wm[72:80])
	if ttl != 3600 {
		t.Fatalf("watermark TTL=%d want 3600", ttl)
	}
}
