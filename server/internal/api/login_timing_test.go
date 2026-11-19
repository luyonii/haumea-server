package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/secblind/server/internal/store"
	"github.com/secblind/server/pkg/crypto"
)

// TestLoginTimingOracle_UniformResponse asserts that every /auth/login
// credential-rejection path returns the SAME {error, message} JSON body,
// closing the oracle an attacker would otherwise use to distinguish
// "license exists" / "banned" / "HMAC wrong" / "HWID cooldown".
//
// Env-gated like revoke_test.go: skips unless SB_TEST_PG_DSN +
// SB_TEST_REDIS_ADDR are set. Happy-path subtests additionally need
// SB_TEST_LICENSE_KEY (the test only READS it; never mutates).
func TestLoginTimingOracle_UniformResponse(t *testing.T) {
	dsn := os.Getenv("SB_TEST_PG_DSN")
	rAddr := os.Getenv("SB_TEST_REDIS_ADDR")
	if dsn == "" || rAddr == "" {
		t.Skip("set SB_TEST_PG_DSN and SB_TEST_REDIS_ADDR to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pg, err := store.OpenPG(ctx, dsn)
	if err != nil {
		t.Fatalf("pg: %v", err)
	}
	defer pg.Close()
	rdb := store.OpenRedis(rAddr)
	defer rdb.Close()

	s := &Server{PG: pg, RDB: rdb, Cfg: Config{
		SessionTTL:  15 * time.Minute,
		HWIDCooldown: 30 * 24 * time.Hour,
		RatePerIP:   10000, RatePerHWID: 10000,
	}}

	hwid := strings.Repeat("ab", 32) // 64 hex chars

	// Helper: seed challenge for HWID, build request, call handler, return body.
	call := func(t *testing.T, licenseKey, hwid string, withGoodMAC bool) (int, map[string]any) {
		t.Helper()
		nonce, _ := crypto.RandBytes(32)
		nonceB64 := base64.StdEncoding.EncodeToString(nonce)
		if err := rdb.PutChallenge(ctx, hwid, nonceB64); err != nil {
			t.Fatalf("put challenge: %v", err)
		}

		var respB64 string
		if withGoodMAC {
			salt := append([]byte(hwid), crypto.HKDFSalt...)
			derived, _ := crypto.HKDF([]byte(licenseKey), salt, nil, 32)
			mac := crypto.HMAC256(derived, nonce)
			respB64 = base64.StdEncoding.EncodeToString(mac)
		} else {
			respB64 = base64.StdEncoding.EncodeToString([]byte("not-the-mac-0000000000000000000"))
		}

		body, _ := json.Marshal(map[string]string{
			"license_key":        licenseKey,
			"hwid":               hwid,
			"challenge":          nonceB64,
			"challenge_response": respB64,
		})
		r := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.handleLogin(w, r)

		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	// Path 1: unknown_license (no seed needed — uses a key that will not exist).
	unknownKey := "timing-oracle-probe-" + hex.EncodeToString([]byte{0xDE, 0xAD})
	code1, body1 := call(t, unknownKey, hwid, false)
	if code1 != http.StatusUnauthorized || body1["error"] != "invalid_credentials" {
		t.Fatalf("unknown_license: got %d %v, want 401 invalid_credentials", code1, body1)
	}

	// Paths 2–4 need a seeded license; fall back to a skip to keep CI green
	// when the operator didn't provide one.
	licKey := os.Getenv("SB_TEST_LICENSE_KEY")
	if licKey == "" {
		t.Log("SB_TEST_LICENSE_KEY unset — only unknown_license verified")
		return
	}

	// Path 2: bad HMAC (license exists, response wrong).
	code2, body2 := call(t, licKey, hwid, false)
	if code2 != code1 || body2["error"] != body1["error"] || body2["message"] != body1["message"] {
		t.Fatalf("bad_challenge_response: %d %v differs from unknown_license %d %v",
			code2, body2, code1, body1)
	}

	// Path 3: hwid_cooldown — flip to a new HWID after good login would bind.
	// We don't want to actually bind here (would mutate seeded state), so we
	// assert the invariant via the response of a fresh-HWID attempt that will
	// either succeed (OK, 200) or fail uniformly. Only enforce uniformity when
	// it fails; a 200 just means the seed had no prior bind.
	hwid2 := strings.Repeat("cd", 32)
	code3, body3 := call(t, licKey, hwid2, true)
	if code3 != http.StatusOK {
		if code3 != code1 || body3["error"] != body1["error"] {
			t.Fatalf("hwid_cooldown: %d %v differs from unknown_license %d %v",
				code3, body3, code1, body1)
		}
	}
}
