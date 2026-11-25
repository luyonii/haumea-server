package api

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/secblind/server/internal/store"
	"github.com/secblind/server/pkg/crypto"
)

// bindSalt48 builds the
//   running_digest(32)||LE32(anti_debug)||LE32(anti_hook)||LE32(tool_detect)||LE32(anti_vm)
// suffix the client appends to the /auth/login HKDF salt. Mirrors
// buildBinaryBindSalt in cmd/server/main.go and the C++ client (auth.cpp).
func bindSalt48(digest []byte, ad, ah, td, av uint32) []byte {
	b := make([]byte, 48)
	copy(b[0:32], digest)
	binary.LittleEndian.PutUint32(b[32:36], ad)
	binary.LittleEndian.PutUint32(b[36:40], ah)
	binary.LittleEndian.PutUint32(b[40:44], td)
	binary.LittleEndian.PutUint32(b[44:48], av)
	return b
}

// digest32 returns a deterministic 32-byte test digest seeded by base.
func digest32(base byte) []byte {
	d := make([]byte, 32)
	for i := range d {
		d[i] = base + byte(i)
	}
	return d
}

// loginMAC reproduces the client's challenge_response: HMAC(derived, nonce)
// with derived = HKDF(license_key, hwid||HKDFSalt||bind).
func loginMAC(licenseKey, hwid string, nonce, bind []byte) []byte {
	salt := append([]byte(hwid), crypto.HKDFSalt...)
	salt = append(salt, bind...)
	derived, _ := crypto.HKDF([]byte(licenseKey), salt, nil, 32)
	return crypto.HMAC256(derived, nonce)
}

// TestBinaryBind_WrongDigestDivergesKey is a pure unit test (no PG/Redis): it
// proves that a one-bit change in ANY of the 32 running-digest bytes — or in any
// of the four anti-analysis detection masks — makes the derived key, and
// therefore the challenge_response the server verifies, diverge. So a mismatched
// binary (a runtime .text patch that perturbs any code-integrity sample) OR a
// client running in a detected environment (non-zero mask) cannot produce an
// accepted MAC (audit #1/#10, Fix B).
func TestBinaryBind_WrongDigestDivergesKey(t *testing.T) {
	hwid := strings.Repeat("ab", 32)
	nonce, _ := crypto.RandBytes(32)

	// Baseline reference machine: clean binary digest, all four masks zero.
	digest := digest32(0x10)
	good := bindSalt48(digest, 0, 0, 0, 0)
	expected := loginMAC("LICENSE-KEY-TEST", hwid, nonce, good)

	// A single flipped bit in EACH of the 32 digest bytes must diverge the MAC.
	for i := 0; i < 32; i++ {
		bad := make([]byte, 32)
		copy(bad, digest)
		bad[i] ^= 0x01
		if crypto.Equal(loginMAC("LICENSE-KEY-TEST", hwid, nonce, bindSalt48(bad, 0, 0, 0, 0)), expected) {
			t.Fatalf("flipped digest byte %d produced an accepted MAC", i)
		}
	}

	// Each of the four detection masks still diverges exactly as before.
	masks := []struct {
		name           string
		ad, ah, td, av uint32
	}{
		{"anti_debug_mask", 1, 0, 0, 0},
		{"anti_hook_mask", 0, 1, 0, 0},
		{"tool_detect_mask", 0, 0, 1, 0},
		{"anti_vm_mask", 0, 0, 0, 1},
	}
	for _, m := range masks {
		if crypto.Equal(loginMAC("LICENSE-KEY-TEST", hwid, nonce, bindSalt48(digest, m.ad, m.ah, m.td, m.av)), expected) {
			t.Fatalf("divergent %s produced an accepted MAC", m.name)
		}
	}

	// Sanity: identical bind reproduces the same MAC.
	if !crypto.Equal(loginMAC("LICENSE-KEY-TEST", hwid, nonce, good), expected) {
		t.Fatal("identical bind did not reproduce the MAC")
	}
}

// TestLogin_WrongBinaryBindRejected is the full-handler path, env-gated like
// the other integration tests (needs SB_TEST_PG_DSN + SB_TEST_REDIS_ADDR). It
// seeds a fresh license, then shows the SAME request is accepted (200) with the
// matching bind and rejected (401) with a wrong CRC.
func TestLogin_WrongBinaryBindRejected(t *testing.T) {
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

	digest := digest32(0x20)
	s := &Server{PG: pg, RDB: rdb, Cfg: Config{
		SessionTTL:     15 * time.Minute,
		HWIDCooldown:   30 * 24 * time.Hour,
		RatePerIP:      100000, RatePerHWID: 100000,
		BinaryBindSalt: bindSalt48(digest, 0, 0, 0, 0),
	}}

	key := "bind-test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, _, err := pg.InsertLicense(ctx, key, nil); err != nil {
		t.Fatalf("insert license: %v", err)
	}

	// call seeds a fresh challenge and posts a login whose challenge_response is
	// computed with the given bind salt. Fresh HWID per sub-case avoids cooldown.
	call := func(hwid string, bind []byte) int {
		nonce, _ := crypto.RandBytes(32)
		nonceB64 := base64.StdEncoding.EncodeToString(nonce)
		if err := rdb.PutChallenge(ctx, hwid, nonceB64); err != nil {
			t.Fatalf("put challenge: %v", err)
		}
		body, _ := json.Marshal(map[string]string{
			"license_key":        key,
			"hwid":               hwid,
			"challenge":          nonceB64,
			"challenge_response": base64.StdEncoding.EncodeToString(loginMAC(key, hwid, nonce, bind)),
		})
		r := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.handleLogin(w, r)
		return w.Code
	}

	if code := call(strings.Repeat("ab", 32), bindSalt48(digest, 0, 0, 0, 0)); code != http.StatusOK {
		t.Fatalf("matching bind: status=%d want 200", code)
	}
	badDigest := make([]byte, 32)
	copy(badDigest, digest)
	badDigest[0] ^= 0x01 // one flipped bit = a perturbed code-integrity sample
	if code := call(strings.Repeat("cd", 32), bindSalt48(badDigest, 0, 0, 0, 0)); code != http.StatusUnauthorized {
		t.Fatalf("wrong digest: status=%d want 401", code)
	}
	// A detected environment (non-zero anti_debug mask) must also be rejected.
	if code := call(strings.Repeat("ef", 32), bindSalt48(digest, 1, 0, 0, 0)); code != http.StatusUnauthorized {
		t.Fatalf("detected env (anti_debug mask): status=%d want 401", code)
	}
}
