package api

import (
	"context"
	"encoding/base64"
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

// --- Pure validation tests (no PG/Redis): mask presence + range are checked
// before any store access, so these run everywhere. They cover Review Focus
// #1 (missing field -> 400, no silent default-to-zero) and #2 (out-of-range
// -> 400 before the HMAC canonical ever sees a mutated value). ---

// hbBody builds a /session/heartbeat JSON body. Mask fields are injected as
// raw JSON tokens so a test can send "-1", "4294967296", or omit a field.
func hbBody(sentinelTok, toolTok string) string {
	var sb strings.Builder
	sb.WriteString(`{"session_token":"t","hmac":"aGk=","timestamp":"`)
	sb.WriteString(strconv.FormatInt(time.Now().Unix(), 10))
	sb.WriteString(`","next_nonce":"n"`)
	if sentinelTok != "" {
		sb.WriteString(`,"sentinel_mask":`)
		sb.WriteString(sentinelTok)
	}
	if toolTok != "" {
		sb.WriteString(`,"tool_mask":`)
		sb.WriteString(toolTok)
	}
	sb.WriteString("}")
	return sb.String()
}

func postHeartbeat(s *Server, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/session/heartbeat", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleHeartbeat(w, r)
	return w
}

func TestHeartbeat_RejectsMissingMaskFields(t *testing.T) {
	s := &Server{Cfg: Config{TimestampSkew: 5 * time.Minute}}

	cases := []struct {
		name         string
		sentinel     string
		tool         string
	}{
		{"missing_sentinel", "", "0"},
		{"missing_tool", "0", ""},
		{"missing_both", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := postHeartbeat(s, hbBody(c.sentinel, c.tool))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
			}
			var out map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			if out["error"] != "bad_request" {
				t.Fatalf("error=%v want bad_request", out["error"])
			}
		})
	}
}

func TestHeartbeat_RejectsOutOfRangeMask(t *testing.T) {
	s := &Server{Cfg: Config{TimestampSkew: 5 * time.Minute}}

	cases := []struct {
		name     string
		sentinel string
		tool     string
	}{
		{"negative", "-1", "0"},
		{"too_big", "4294967296", "0"}, // 2^32, one past uint32 max
		{"tool_negative", "0", "-5"},
		{"non_integer", "1.5", "0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := postHeartbeat(s, hbBody(c.sentinel, c.tool))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want 400; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// --- Integration tests (env-gated like revoke_test.go / login_timing_test.go).
// Need a real Postgres + Redis: SB_TEST_PG_DSN + SB_TEST_REDIS_ADDR. They seed
// a session directly into Redis and a license into Postgres. ---

type hbEnv struct {
	s          *Server
	rdb        *store.Redis
	pg         *store.PG
	ctx        context.Context
	token      string
	sessionKey []byte
	licenseID  int64
	nonce      string
}

func setupHeartbeatEnv(t *testing.T) *hbEnv {
	t.Helper()
	dsn := os.Getenv("SB_TEST_PG_DSN")
	rAddr := os.Getenv("SB_TEST_REDIS_ADDR")
	if dsn == "" || rAddr == "" {
		t.Skip("set SB_TEST_PG_DSN and SB_TEST_REDIS_ADDR to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	pg, err := store.OpenPG(ctx, dsn)
	if err != nil {
		t.Fatalf("pg: %v", err)
	}
	t.Cleanup(pg.Close)
	rdb := store.OpenRedis(rAddr)
	t.Cleanup(func() { _ = rdb.Close() })

	s := &Server{PG: pg, RDB: rdb, Cfg: Config{
		SessionTTL:    15 * time.Minute,
		TimestampSkew: 5 * time.Minute,
		RatePerIP:     100000, RatePerHWID: 100000,
	}}

	// Fresh unbanned license.
	key := "hb-telemetry-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	id, _, err := pg.InsertLicense(ctx, key, nil)
	if err != nil {
		t.Fatalf("insert license: %v", err)
	}

	// Seed a session directly.
	sessionKey, _ := crypto.RandBytes(32)
	tokenRaw, _ := crypto.RandBytes(16)
	token := base64.RawURLEncoding.EncodeToString(tokenRaw)
	nonceRaw, _ := crypto.RandBytes(32)
	nonce := base64.StdEncoding.EncodeToString(nonceRaw)
	sess := &store.Session{
		LicenseID:  id,
		HWID:       strings.Repeat("ab", 32),
		SessionKey: base64.StdEncoding.EncodeToString(sessionKey),
		NextNonce:  nonce,
		ExpiresAt:  time.Now().Add(15 * time.Minute),
	}
	if err := rdb.PutSession(ctx, token, sess, 15*time.Minute); err != nil {
		t.Fatalf("put session: %v", err)
	}

	return &hbEnv{s: s, rdb: rdb, pg: pg, ctx: ctx,
		token: token, sessionKey: sessionKey, licenseID: id, nonce: nonce}
}

// sendTrip builds a correctly-signed heartbeat with the given masks over the
// NEW canonical and posts it. Refreshes the stored nonce for the next call.
func (e *hbEnv) sendTrip(t *testing.T, sMask, tMask uint32) *httptest.ResponseRecorder {
	t.Helper()
	// Re-read current nonce from the session (rotates each successful beat).
	sess, err := e.rdb.GetSession(e.ctx, e.token)
	if err != nil || sess == nil {
		t.Fatalf("get session: %v", err)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	kHB, _ := crypto.HKDFExpand(e.sessionKey, infoHeartbeat, 32)
	canon := ts + "|" + strconv.FormatUint(uint64(sMask), 10) + "|" + strconv.FormatUint(uint64(tMask), 10)
	mac := base64.StdEncoding.EncodeToString(crypto.HMAC256(kHB, []byte(canon)))
	body, _ := json.Marshal(map[string]any{
		"session_token": e.token,
		"hmac":          mac,
		"timestamp":     ts,
		"next_nonce":    sess.NextNonce,
		"sentinel_mask": sMask,
		"tool_mask":     tMask,
	})
	r := httptest.NewRequest("POST", "/api/v1/session/heartbeat", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	e.s.handleHeartbeat(w, r)
	return w
}

func TestHeartbeat_CanonicalIncludesMasks(t *testing.T) {
	e := setupHeartbeatEnv(t)
	// HMAC computed over the OLD canonical (timestamp only), masks zero.
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	kHB, _ := crypto.HKDFExpand(e.sessionKey, infoHeartbeat, 32)
	mac := base64.StdEncoding.EncodeToString(crypto.HMAC256(kHB, []byte(ts)))
	body, _ := json.Marshal(map[string]any{
		"session_token": e.token,
		"hmac":          mac,
		"timestamp":     ts,
		"next_nonce":    e.nonce,
		"sentinel_mask": 0,
		"tool_mask":     0,
	})
	r := httptest.NewRequest("POST", "/api/v1/session/heartbeat", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	e.s.handleHeartbeat(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", w.Code, w.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["error"] != "invalid_hmac" {
		t.Fatalf("error=%v want invalid_hmac", out["error"])
	}
}

func TestHeartbeat_TripLogsAbuse(t *testing.T) {
	e := setupHeartbeatEnv(t)
	w := e.sendTrip(t, 1, 0)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var n int
	err := e.pg.Pool.QueryRow(e.ctx,
		`SELECT count(*) FROM abuse_log WHERE license_id = $1 AND reason = $2`,
		e.licenseID, "sentinel_trip:s=1,t=0").Scan(&n)
	if err != nil {
		t.Fatalf("count abuse_log: %v", err)
	}
	if n != 1 {
		t.Fatalf("abuse_log rows=%d want 1", n)
	}
}

func TestHeartbeat_AutoBanOnSecondTrip(t *testing.T) {
	e := setupHeartbeatEnv(t)
	if w := e.sendTrip(t, 1, 0); w.Code != http.StatusOK {
		t.Fatalf("first trip status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	w := e.sendTrip(t, 4, 0)
	if w.Code != http.StatusOK {
		t.Fatalf("second trip status=%d want 200; body=%s", w.Code, w.Body.String())
	}
	var out struct {
		Kill    bool `json:"kill"`
		Revoked bool `json:"revoked"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Kill || !out.Revoked {
		t.Fatalf("second trip body=%s want kill+revoked true", w.Body.String())
	}
	var banned bool
	if err := e.pg.Pool.QueryRow(e.ctx,
		`SELECT banned FROM licenses WHERE id = $1`, e.licenseID).Scan(&banned); err != nil {
		t.Fatalf("read banned: %v", err)
	}
	if !banned {
		t.Fatalf("licenses.banned=false want true")
	}
}

func TestAutoBanIfSentinelThreshold_Idempotent(t *testing.T) {
	e := setupHeartbeatEnv(t)
	// Two sentinel trips already in the window.
	e.pg.LogAbuse(e.ctx, &e.licenseID, "203.0.113.1", "sentinel_trip:s=1,t=0")
	e.pg.LogAbuse(e.ctx, &e.licenseID, "203.0.113.1", "sentinel_trip:s=4,t=0")
	// LogAbuse is fire-and-forget on a detached ctx; give it a beat to land.
	time.Sleep(200 * time.Millisecond)

	banned, err := e.pg.AutoBanIfSentinelThreshold(e.ctx, e.licenseID, 2, 24*time.Hour)
	if err != nil {
		t.Fatalf("first autoban: %v", err)
	}
	if !banned {
		t.Fatalf("first autoban banned=false want true")
	}
	banned2, err := e.pg.AutoBanIfSentinelThreshold(e.ctx, e.licenseID, 2, 24*time.Hour)
	if err != nil {
		t.Fatalf("second autoban: %v", err)
	}
	if banned2 {
		t.Fatalf("second autoban banned=true want false (idempotent)")
	}
}
