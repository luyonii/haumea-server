// Package api holds the 5 HTTP handlers.
// All crypto parameters here are forced by the shipped C++ client — see PLAN.md.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/secblind/server/internal/store"
	"github.com/secblind/server/pkg/crypto"
)

// --- Config passed in from main ---

type Config struct {
	MasterSecret      []byte // 32+ bytes
	SessionTTL        time.Duration
	HeartbeatInterval int
	HWIDCooldown      time.Duration
	TimestampSkew     time.Duration // ±window
	RatePerIP         int
	RatePerHWID       int
}

type Server struct {
	PG  *store.PG
	RDB *store.Redis
	Cfg Config
}

func New(pg *store.PG, rdb *store.Redis, cfg Config) *Server {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 900 * time.Second
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 60
	}
	if cfg.HWIDCooldown == 0 {
		cfg.HWIDCooldown = 30 * 24 * time.Hour
	}
	if cfg.TimestampSkew == 0 {
		cfg.TimestampSkew = 5 * time.Minute
	}
	if cfg.RatePerIP == 0 {
		cfg.RatePerIP = 30
	}
	if cfg.RatePerHWID == 0 {
		cfg.RatePerHWID = 10
	}
	return &Server{PG: pg, RDB: rdb, Cfg: cfg}
}

// Register wires the 5 endpoints to a mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/auth/challenge", s.handleChallenge)
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/session/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/api/v1/payload/fetch", s.handleFetch)
	mux.HandleFunc("/api/v1/rpc/call", s.handleRPC)
}

// ---- Helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": code, "message": msg})
}

func readJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 2<<20) // 2 MiB cap
	return json.NewDecoder(r.Body).Decode(v)
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if i := strings.IndexByte(xf, ','); i >= 0 {
			return strings.TrimSpace(xf[:i])
		}
		return strings.TrimSpace(xf)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) rateLimit(ctx context.Context, ip, hwid string) bool {
	ok, _ := s.RDB.Allow(ctx, "rate:ip:"+ip, s.Cfg.RatePerIP)
	if !ok {
		return false
	}
	if hwid != "" {
		ok, _ = s.RDB.Allow(ctx, "rate:hwid:"+hwid, s.Cfg.RatePerHWID)
	}
	return ok
}

// isValidHWID accepts exactly 64 lowercase hex characters.
func isValidHWID(h string) bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ---- 1. /auth/challenge ----

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	var req struct {
		HWID string `json:"hwid"`
	}
	if err := readJSON(r, &req); err != nil || !isValidHWID(req.HWID) {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid hwid")
		return
	}
	ctx := r.Context()
	if !s.rateLimit(ctx, clientIP(r), req.HWID) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "rate_limited", "retry_after": 30,
		})
		return
	}

	nonce, err := crypto.RandBytes(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "rand failed")
		return
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	if err := s.RDB.PutChallenge(ctx, req.HWID, nonceB64); err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "redis write")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":  nonceB64,
		"expires_at": time.Now().Add(60 * time.Second).Unix(),
	})
}

// ---- 2. /auth/login ----

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	var req struct {
		LicenseKey        string `json:"license_key"`
		HWID              string `json:"hwid"`
		Challenge         string `json:"challenge"`
		ChallengeResponse string `json:"challenge_response"`
	}
	if err := readJSON(r, &req); err != nil || req.LicenseKey == "" ||
		len(req.LicenseKey) > 64 ||
		!isValidHWID(req.HWID) || req.Challenge == "" || req.ChallengeResponse == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "missing fields")
		return
	}
	ctx := r.Context()
	ip := clientIP(r)
	if !s.rateLimit(ctx, ip, req.HWID) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "rate_limited", "retry_after": 30,
		})
		return
	}

	// 1) license exists and not banned
	lic, err := s.PG.LicenseByKey(ctx, req.LicenseKey)
	if errors.Is(err, store.ErrNotFound) {
		s.PG.LogAbuse(ctx, nil, ip, "unknown_license")
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "db")
		return
	}
	if lic.Banned {
		writeErr(w, http.StatusUnauthorized, "banned", "license banned")
		return
	}
	if killed, _ := s.PG.KillStatus(ctx, lic.ID); killed {
		writeErr(w, http.StatusUnauthorized, "banned", "license killed")
		return
	}

	// 2) consume challenge (one-shot)
	stored, err := s.RDB.TakeChallenge(ctx, req.HWID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "redis")
		return
	}
	if stored == "" || stored != req.Challenge {
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "challenge missing or mismatch")
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "challenge decode")
		return
	}

	// 3) derive key EXACTLY like the client (auth.cpp):
	//    salt = hwid_bytes || "SecBlind_HKDF_v1" ; info = empty
	salt := make([]byte, 0, len(req.HWID)+len(crypto.HKDFSalt))
	salt = append(salt, []byte(req.HWID)...)
	salt = append(salt, crypto.HKDFSalt...)
	derived, err := crypto.HKDF([]byte(req.LicenseKey), salt, nil, 32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "hkdf")
		return
	}

	// 4) expected = HMAC-SHA256(derived, nonce)
	expected := crypto.HMAC256(derived, nonce)
	gotMAC, err := base64.StdEncoding.DecodeString(req.ChallengeResponse)
	if err != nil || !crypto.Equal(gotMAC, expected) {
		s.PG.LogAbuse(ctx, &lic.ID, ip, "bad_challenge_response")
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "challenge response mismatch")
		return
	}

	// 5) HWID bind + cooldown
	curBind, err := s.PG.HWIDBind(ctx, lic.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if err := s.PG.HWIDUpsertBind(ctx, lic.ID, req.HWID); err != nil {
			writeErr(w, http.StatusInternalServerError, "server_error", "bind")
			return
		}
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "server_error", "bind read")
		return
	case curBind != req.HWID:
		last, err := s.PG.HWIDLastChange(ctx, lic.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "server_error", "cooldown read")
			return
		}
		if !last.IsZero() && time.Since(last) < s.Cfg.HWIDCooldown {
			s.PG.LogAbuse(ctx, &lic.ID, ip, "hwid_cooldown")
			writeErr(w, http.StatusUnauthorized, "hwid_cooldown", "hwid change within cooldown")
			return
		}
		if err := s.PG.HWIDUpsertBind(ctx, lic.ID, req.HWID); err != nil {
			writeErr(w, http.StatusInternalServerError, "server_error", "rebind")
			return
		}
	}

	// 6) Kill previous session for this license.
	if prev, _ := s.RDB.LatestToken(ctx, lic.ID); prev != "" {
		s.RDB.DeleteSession(ctx, prev)
	}

	// 7) Build session.
	sessionIDRaw, _ := crypto.RandBytes(16)
	tokenRaw, _ := crypto.RandBytes(32)
	token := hex.EncodeToString(tokenRaw)

	// hwid_hash_bytes for session-key info: raw bytes of the HWID hex-decoded
	// (same 32 B the watermark uses at [0..32]).
	hwidHashBytes, err := hex.DecodeString(req.HWID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "hwid decode")
		return
	}
	info := append(append([]byte{}, sessionIDRaw...), hwidHashBytes...)
	sessionKey, err := crypto.HKDF(s.Cfg.MasterSecret, crypto.HKDFSalt, info, 32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "sess hkdf")
		return
	}

	nextNonce, _ := crypto.RandBytes(32)
	nextNonceB64 := base64.StdEncoding.EncodeToString(nextNonce)

	sess := &store.Session{
		LicenseID:  lic.ID,
		HWID:       req.HWID,
		SessionKey: base64.StdEncoding.EncodeToString(sessionKey),
		NextNonce:  nextNonceB64,
		ExpiresAt:  time.Now().Add(s.Cfg.SessionTTL),
	}
	if err := s.RDB.PutSession(ctx, token, sess, s.Cfg.SessionTTL); err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "session put")
		return
	}
	_ = s.RDB.RememberLatestToken(ctx, lic.ID, token, s.Cfg.SessionTTL)

	writeJSON(w, http.StatusOK, map[string]any{
		"session_token":      token,
		"session_key":        sess.SessionKey,
		"ttl":                int(s.Cfg.SessionTTL.Seconds()),
		"heartbeat_interval": s.Cfg.HeartbeatInterval,
		"next_nonce":         nextNonceB64,
	})
}

// ---- 3. /session/heartbeat ----

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	var req struct {
		Token     string `json:"session_token"`
		HMAC      string `json:"hmac"`
		Timestamp string `json:"timestamp"`
		NextNonce string `json:"next_nonce"`
	}
	if err := readJSON(r, &req); err != nil ||
		req.Token == "" || req.HMAC == "" || req.Timestamp == "" || req.NextNonce == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "missing fields")
		return
	}
	ctx := r.Context()

	sess, err := s.RDB.GetSession(ctx, req.Token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "redis")
		return
	}
	if sess == nil {
		writeErr(w, http.StatusUnauthorized, "session_expired", "")
		return
	}

	// Anti-replay: supplied nonce must match stored.
	if !crypto.Equal([]byte(req.NextNonce), []byte(sess.NextNonce)) {
		writeErr(w, http.StatusUnauthorized, "invalid_token", "nonce mismatch")
		return
	}

	// Timestamp window (±skew).
	ts, err := strconv.ParseInt(req.Timestamp, 10, 64)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_hmac", "bad timestamp")
		return
	}
	skew := time.Since(time.Unix(ts, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > s.Cfg.TimestampSkew {
		writeErr(w, http.StatusUnauthorized, "invalid_hmac", "timestamp out of window")
		return
	}

	// HMAC over ASCII timestamp bytes (match heartbeat.cpp).
	sessionKey, err := base64.StdEncoding.DecodeString(sess.SessionKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "key decode")
		return
	}
	expected := crypto.HMAC256(sessionKey, []byte(req.Timestamp))
	got, err := base64.StdEncoding.DecodeString(req.HMAC)
	if err != nil || !crypto.Equal(got, expected) {
		writeErr(w, http.StatusUnauthorized, "invalid_hmac", "")
		return
	}

	// Rotate nonce, renew TTL. Check kill flag.
	killed, _ := s.PG.KillStatus(ctx, sess.LicenseID)

	newNonce, _ := crypto.RandBytes(32)
	newNonceB64 := base64.StdEncoding.EncodeToString(newNonce)
	sess.NextNonce = newNonceB64
	sess.ExpiresAt = time.Now().Add(s.Cfg.SessionTTL)
	if err := s.RDB.RefreshSession(ctx, req.Token, sess, s.Cfg.SessionTTL); err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "refresh")
		return
	}
	_ = s.RDB.RememberLatestToken(ctx, sess.LicenseID, req.Token, s.Cfg.SessionTTL)

	writeJSON(w, http.StatusOK, map[string]any{
		"next_nonce": newNonceB64,
		"kill":       killed,
		"revoked":    false,
	})
}

// ---- 4. /payload/fetch ----

func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	var req struct {
		Token string `json:"session_token"`
	}
	if err := readJSON(r, &req); err != nil || req.Token == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "missing session_token")
		return
	}
	ctx := r.Context()

	sess, err := s.RDB.GetSession(ctx, req.Token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "redis")
		return
	}
	if sess == nil {
		writeErr(w, http.StatusUnauthorized, "session_expired", "")
		return
	}

	lic, err := licenseByID(ctx, s.PG, sess.LicenseID)
	if err != nil {
		writeErr(w, http.StatusForbidden, "not_authorized", "")
		return
	}
	if killed, _ := s.PG.KillStatus(ctx, sess.LicenseID); killed {
		writeErr(w, http.StatusForbidden, "not_authorized", "killed")
		return
	}

	pe, err := s.PG.LatestPayload(ctx, sess.LicenseID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusForbidden, "not_authorized", "no payload")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "payload")
		return
	}

	sessionKey, err := base64.StdEncoding.DecodeString(sess.SessionKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "key")
		return
	}

	wm, err := buildWatermark(sess.HWID, lic.Key, sessionKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "watermark")
		return
	}

	plaintext := make([]byte, 0, len(wm)+len(pe))
	plaintext = append(plaintext, wm...)
	plaintext = append(plaintext, pe...)

	sealed, err := crypto.SealGCM(sessionKey, plaintext)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "seal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"iv":         base64.StdEncoding.EncodeToString(sealed.IV),
		"tag":        base64.StdEncoding.EncodeToString(sealed.Tag),
		"ciphertext": base64.StdEncoding.EncodeToString(sealed.Ciphertext),
	})
}

// buildWatermark assembles the 128-byte block the client expects.
// Layout matches watermark.cpp; see PLAN.md for the hwid-field deviation from SERVER_PLAN.
func buildWatermark(hwidHex, licenseKey string, sessionKey []byte) ([]byte, error) {
	wm := make([]byte, 128)

	hwidBytes, err := hex.DecodeString(hwidHex)
	if err != nil || len(hwidBytes) != 32 {
		return nil, errors.New("hwid decode")
	}
	copy(wm[0:32], hwidBytes)

	lh := sha256sum([]byte(licenseKey))
	copy(wm[32:64], lh)

	binary.LittleEndian.PutUint64(wm[64:72], uint64(time.Now().Unix()))
	binary.LittleEndian.PutUint64(wm[72:80], 86400) // 24 h, never 0

	nonce, err := crypto.RandBytes(16)
	if err != nil {
		return nil, err
	}
	copy(wm[80:96], nonce)

	sig := crypto.HMAC256(sessionKey, wm[0:96])
	copy(wm[96:128], sig)
	return wm, nil
}

func sha256sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// ---- 5. /rpc/call ----

func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	// Capture `payload` as the exact wire span — json.RawMessage preserves it.
	var req struct {
		Method    string          `json:"method"`
		Token     string          `json:"session_token"`
		Payload   json.RawMessage `json:"payload"`
		Timestamp string          `json:"timestamp"`
		HMAC      string          `json:"hmac"`
	}
	if err := readJSON(r, &req); err != nil ||
		req.Method == "" || req.Token == "" || req.Timestamp == "" || req.HMAC == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "missing fields")
		return
	}
	ctx := r.Context()
	sess, err := s.RDB.GetSession(ctx, req.Token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "redis")
		return
	}
	if sess == nil {
		writeErr(w, http.StatusUnauthorized, "session_expired", "")
		return
	}

	ts, err := strconv.ParseInt(req.Timestamp, 10, 64)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_hmac", "bad timestamp")
		return
	}
	skew := time.Since(time.Unix(ts, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > s.Cfg.TimestampSkew {
		writeErr(w, http.StatusUnauthorized, "invalid_hmac", "timestamp out of window")
		return
	}

	// Canonical: method|token|timestamp|payload_json_raw
	payload := req.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	canon := make([]byte, 0, len(req.Method)+len(req.Token)+len(req.Timestamp)+len(payload)+3)
	canon = append(canon, req.Method...)
	canon = append(canon, '|')
	canon = append(canon, req.Token...)
	canon = append(canon, '|')
	canon = append(canon, req.Timestamp...)
	canon = append(canon, '|')
	canon = append(canon, payload...)

	sessionKey, err := base64.StdEncoding.DecodeString(sess.SessionKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "key")
		return
	}
	expected := crypto.HMAC256(sessionKey, canon)
	got, err := base64.StdEncoding.DecodeString(req.HMAC)
	if err != nil || !crypto.Equal(got, expected) {
		writeErr(w, http.StatusUnauthorized, "invalid_hmac", "")
		return
	}

	// Dispatch.
	switch req.Method {
	case "ping":
		writeJSON(w, http.StatusOK, map[string]any{"pong": true})
	default:
		writeErr(w, http.StatusNotFound, "unknown_method", req.Method)
	}
}

// ---- small wrappers ----

func licenseByID(ctx context.Context, pg *store.PG, id int64) (*store.License, error) {
	var l store.License
	err := pg.Pool.QueryRow(ctx,
		`SELECT id, license_key, banned FROM licenses WHERE id = $1`, id,
	).Scan(&l.ID, &l.Key, &l.Banned)
	if err != nil {
		return nil, err
	}
	if l.Banned {
		return nil, errors.New("banned")
	}
	return &l, nil
}

// LogStartup prints a small sign-of-life line.
func (s *Server) LogStartup(addr string) {
	log.Printf("sec-blind listening on %s (TTL=%s, HB=%ds)",
		addr, s.Cfg.SessionTTL, s.Cfg.HeartbeatInterval)
}
