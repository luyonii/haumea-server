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

// bindSalt28 builds the
//   LE32(crc)||LE64(fp)||LE32(anti_debug)||LE32(anti_hook)||LE32(tool_detect)||LE32(anti_vm)
// suffix the client appends to the /auth/login HKDF salt. Mirrors
// buildBinaryBindSalt in cmd/server/main.go and the C++ client (auth.cpp).
func bindSalt28(crc uint32, fp uint64, ad, ah, td, av uint32) []byte {
	b := make([]byte, 28)
	binary.LittleEndian.PutUint32(b[0:4], crc)
	binary.LittleEndian.PutUint64(b[4:12], fp)
	binary.LittleEndian.PutUint32(b[12:16], ad)
	binary.LittleEndian.PutUint32(b[16:20], ah)
	binary.LittleEndian.PutUint32(b[20:24], td)
	binary.LittleEndian.PutUint32(b[24:28], av)
	return b
}

// loginMAC reproduces the client's challenge_response: HMAC(derived, nonce)
// with derived = HKDF(license_key, hwid||HKDFSalt||bind).
func loginMAC(licenseKey, hwid string, nonce, bind []byte) []byte {
	salt := append([]byte(hwid), crypto.HKDFSalt...)
	salt = append(salt, bind...)
	derived, _ := crypto.HKDF([]byte(licenseKey), salt, nil, 32)
	return crypto.HMAC256(derived, nonce)
}

// TestBinaryBind_WrongCRCDivergesKey is a pure unit test (no PG/Redis): it
// proves that a one-bit change in ANY bound field — the .text CRC32, the code
// fingerprint, or any of the four anti-analysis detection masks — makes the
// derived key, and therefore the challenge_response the server verifies,
// diverge. So a mismatched binary OR a client running in a detected environment
// (non-zero mask) cannot produce an accepted MAC (audit #1/#10).
func TestBinaryBind_WrongCRCDivergesKey(t *testing.T) {
	hwid := strings.Repeat("ab", 32)
	nonce, _ := crypto.RandBytes(32)

	// Baseline reference machine: clean binary, all four masks zero.
	good := bindSalt28(0x11223344, 0xAABBCCDD, 0, 0, 0, 0)
	expected := loginMAC("LICENSE-KEY-TEST", hwid, nonce, good)

	cases := []struct {
		name string
		bind []byte
	}{
		{"text_crc32", bindSalt28(0x11223345, 0xAABBCCDD, 0, 0, 0, 0)},
		{"code_fingerprint", bindSalt28(0x11223344, 0xAABBCCDE, 0, 0, 0, 0)},
		{"anti_debug_mask", bindSalt28(0x11223344, 0xAABBCCDD, 1, 0, 0, 0)},
		{"anti_hook_mask", bindSalt28(0x11223344, 0xAABBCCDD, 0, 1, 0, 0)},
		{"tool_detect_mask", bindSalt28(0x11223344, 0xAABBCCDD, 0, 0, 1, 0)},
		{"anti_vm_mask", bindSalt28(0x11223344, 0xAABBCCDD, 0, 0, 0, 1)},
	}
	for _, c := range cases {
		if crypto.Equal(loginMAC("LICENSE-KEY-TEST", hwid, nonce, c.bind), expected) {
			t.Fatalf("divergent %s produced an accepted MAC", c.name)
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

	const crc uint32 = 0x11223344
	const fp uint64 = 0xAABBCCDD
	s := &Server{PG: pg, RDB: rdb, Cfg: Config{
		SessionTTL:     15 * time.Minute,
		HWIDCooldown:   30 * 24 * time.Hour,
		RatePerIP:      100000, RatePerHWID: 100000,
		BinaryBindSalt: bindSalt28(crc, fp, 0, 0, 0, 0),
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

	if code := call(strings.Repeat("ab", 32), bindSalt28(crc, fp, 0, 0, 0, 0)); code != http.StatusOK {
		t.Fatalf("matching bind: status=%d want 200", code)
	}
	if code := call(strings.Repeat("cd", 32), bindSalt28(crc+1, fp, 0, 0, 0, 0)); code != http.StatusUnauthorized {
		t.Fatalf("wrong crc: status=%d want 401", code)
	}
	// A detected environment (non-zero anti_debug mask) must also be rejected.
	if code := call(strings.Repeat("ef", 32), bindSalt28(crc, fp, 1, 0, 0, 0)); code != http.StatusUnauthorized {
		t.Fatalf("detected env (anti_debug mask): status=%d want 401", code)
	}
}
