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
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/secblind/server/internal/store"
	"github.com/secblind/server/pkg/crypto"
)

// HKDF-Expand info tags for session_key key-separation (RFC 5869 §3.3).
// The client derives the same four sub-keys from the same PRK (session_key).
var (
	infoPayloadAES = []byte("sb.v1.payload.aes256gcm")
	infoHeartbeat  = []byte("sb.v1.heartbeat.hmac")
	infoWatermark  = []byte("sb.v1.watermark.hmac")
	infoRPC        = []byte("sb.v1.rpc.hmac")
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
	RatePerHWIDFetch  int // per-HWID limit for /payload/fetch (heavier)
	// TrustedProxies: CIDRs or single IPs allowed to set X-Forwarded-For.
	// Empty = never trust XFF (clientIP returns RemoteAddr always).
	TrustedProxies []string

	// EnableDebug gates /debug/metrics registration. Default false.
	EnableDebug bool
	// DebugToken, when EnableDebug=true, is required in X-Debug-Token
	// (constant-time compare). Empty + EnableDebug=true fails safe:
	// route is NOT registered, startup logs a warning.
	DebugToken string
}

// authSink absorbs discarded HMAC results so the compiler cannot elide the
// HKDF+HMAC that /auth/login performs before the license lookup (timing
// side-channel defense). Package-level, never read.
var authSink atomic.Pointer[[]byte]

// trustedProxyNets is the parsed TrustedProxies list. Set once by New(); read
// only by clientIP. Package-level so middleware.go's observe() can call clientIP
// without threading the Server through.
var trustedProxyNets []*net.IPNet

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
	if cfg.RatePerHWIDFetch == 0 {
		cfg.RatePerHWIDFetch = 6
	}
	nets, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		panic(fmt.Sprintf("api: trusted_proxies: %v", err))
	}
	trustedProxyNets = nets
	return &Server{PG: pg, RDB: rdb, Cfg: cfg}
}

// parseTrustedProxies accepts CIDR notation ("10.0.0.0/8") or single IPs
// ("127.0.0.1"); single IPs are promoted to /32 or /128.
func parseTrustedProxies(entries []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			out = append(out, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return nil, fmt.Errorf("bad entry %q", e)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

func isTrustedProxy(ip net.IP) bool {
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Register wires the 5 endpoints to a mux.
func (s *Server) Register(mux *http.ServeMux) {
	reg := func(path string, h http.HandlerFunc) {
		mux.Handle(path, observe(path, h))
	}
	reg("/api/v1/auth/challenge", s.handleChallenge)
	reg("/api/v1/auth/login", s.handleLogin)
	reg("/api/v1/session/heartbeat", s.handleHeartbeat)
	reg("/api/v1/payload/fetch", s.handleFetch)
	reg("/api/v1/rpc/call", s.handleRPC)
	if s.Cfg.EnableDebug {
		if s.Cfg.DebugToken == "" {
			L().Warnw("enable_debug=true but debug_token empty; /debug/metrics NOT registered (fail-safe)")
		} else {
			// Debug port exposes the same Prometheus registry as the dedicated
			// metrics bind, gated by X-Debug-Token. Prefer metrics_addr; this is
			// a legacy convenience.
			reg("/debug/metrics", debugAuth(s.Cfg.DebugToken, MetricsHandler().ServeHTTP))
		}
	}
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

func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // 2 MiB cap; writes 413 on overflow
	return json.NewDecoder(r.Body).Decode(v)
}

// clientIP returns the caller IP as a string. X-Forwarded-For is honored only
// when RemoteAddr is itself in the trusted-proxy list; the last XFF entry (the
// hop closest to the trusted proxy, not spoofable by the external client) is
// used. On any mismatch or parse failure, falls back to RemoteAddr.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(host)
	if remote != nil && isTrustedProxy(remote) {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			parts := strings.Split(xf, ",")
			cand := strings.TrimSpace(parts[len(parts)-1])
			if ip := net.ParseIP(cand); ip != nil {
				return ip.String()
			}
		}
	}
	return host
}

func (s *Server) rateLimit(ctx context.Context, ip, hwid string) bool {
	return s.rateLimitWith(ctx, ip, hwid, s.Cfg.RatePerHWID, "rate:hwid:")
}

// rateLimitFetch uses a smaller per-HWID bucket on a dedicated key, so a token
// holder cannot burn the heavy /payload/fetch path at the generic HWID rate.
func (s *Server) rateLimitFetch(ctx context.Context, ip, hwid string) bool {
	return s.rateLimitWith(ctx, ip, hwid, s.Cfg.RatePerHWIDFetch, "rate:hwid_fetch:")
}

func (s *Server) rateLimitWith(ctx context.Context, ip, hwid string, hwidLimit int, hwidPrefix string) bool {
	ok, _ := s.RDB.Allow(ctx, "rate:ip:"+ip, s.Cfg.RatePerIP)
	if !ok {
		return false
	}
	if hwid != "" {
		ok, _ = s.RDB.Allow(ctx, hwidPrefix+hwid, hwidLimit)
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

// isValidRPCMethod guards the canonical "method|token|timestamp|payload" HMAC:
// a method containing '|' could collide with a different valid tuple.
func isValidRPCMethod(m string) bool {
	if len(m) == 0 || len(m) > 64 {
		return false
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '.') {
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
	if err := readJSON(w, r, &req); err != nil || !isValidHWID(req.HWID) {
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
	if err := readJSON(w, r, &req); err != nil || req.LicenseKey == "" ||
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

	// Uniform failure response for any credential-related rejection.
	// Reasons are logged internally (abuse_log) but never leaked via HTTP:
	// otherwise an attacker learns which of license/challenge/HMAC was wrong.
	failAuth := func(licID *int64, reason string) {
		s.PG.LogAbuse(ctx, licID, ip, reason)
		authFailTotal.WithLabelValues(reason).Inc()
		authLoginTotal.WithLabelValues("fail").Inc()
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "")
	}

	// 1) consume challenge FIRST (one-shot GETDEL). One challenge = one attempt,
	// regardless of whether the license exists, is banned, or the HMAC matches.
	stored, err := s.RDB.TakeChallenge(ctx, req.HWID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "redis")
		return
	}
	if stored == "" || stored != req.Challenge {
		metricInc("challenge_consumed_fail_total", "/auth/login")
		failAuth(nil, "bad_challenge")
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		failAuth(nil, "challenge_decode")
		return
	}

	// Timing-side-channel defense: derive HKDF+HMAC BEFORE the license lookup
	// so the unknown_license path pays the same crypto cost as the full path.
	// expected is sunk via authSink below on every unknown path to keep the
	// compiler from eliding the work.
	salt := make([]byte, 0, len(req.HWID)+len(crypto.HKDFSalt))
	salt = append(salt, []byte(req.HWID)...)
	salt = append(salt, crypto.HKDFSalt...)
	derived, err := crypto.HKDF([]byte(req.LicenseKey), salt, nil, 32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "hkdf")
		return
	}
	expected := crypto.HMAC256(derived, nonce)

	// license exists and not banned
	lic, err := s.PG.LicenseByKey(ctx, req.LicenseKey)
	if errors.Is(err, store.ErrNotFound) {
		b := expected // prevent elision of HKDF+HMAC above
		authSink.Store(&b)
		// timing balance: pay KillStatus cost on unknown_license so attacker
		// cannot distinguish it from the bad_challenge_response / killed paths.
		_, _ = s.PG.KillStatus(ctx, 0)
		failAuth(nil, "unknown_license")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "db")
		return
	}
	if lic.Banned {
		// timing balance: match KillStatus cost of the killed/bad_resp paths.
		_, _ = s.PG.KillStatus(ctx, lic.ID)
		failAuth(&lic.ID, "banned")
		return
	}
	if killed, _ := s.PG.KillStatus(ctx, lic.ID); killed {
		failAuth(&lic.ID, "killed")
		return
	}
	if s.isRevoked(ctx, lic.ID) {
		failAuth(&lic.ID, "revoked")
		return
	}

	gotMAC, err := base64.StdEncoding.DecodeString(req.ChallengeResponse)
	if err != nil || !crypto.Equal(gotMAC, expected) {
		failAuth(&lic.ID, "bad_challenge_response")
		return
	}

	// 5) HWID bind + cooldown (atomic: see store.HWIDBindIfAllowed)
	if err := s.PG.HWIDBindIfAllowed(ctx, lic.ID, req.HWID, s.Cfg.HWIDCooldown); err != nil {
		if errors.Is(err, store.ErrHWIDCooldown) {
			s.PG.LogAbuse(ctx, &lic.ID, ip, "hwid_cooldown")
			writeErr(w, http.StatusUnauthorized, "hwid_cooldown", "hwid change within cooldown")
			return
		}
		writeErr(w, http.StatusInternalServerError, "server_error", "bind")
		return
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
	// session_key is the PRK. Per-use sub-keys (k_payload_aes, k_heartbeat,
	// k_watermark, k_rpc) are derived via crypto.HKDFExpand at point of use in
	// the /heartbeat, /payload/fetch and /rpc/call handlers — the client expands
	// the same way. session_key itself is returned to the client unchanged.

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

	authLoginTotal.WithLabelValues("success").Inc()
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
	if err := readJSON(w, r, &req); err != nil ||
		req.Token == "" || req.HMAC == "" || req.Timestamp == "" || req.NextNonce == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "missing fields")
		return
	}
	heartbeatTotal.Inc()
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
	if !s.rateLimit(ctx, clientIP(r), sess.HWID) {
		metricInc("rate_limited_total", "/session/heartbeat")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "rate_limited", "retry_after": 30,
		})
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
	kHeartbeat, err := crypto.HKDFExpand(sessionKey, infoHeartbeat, 32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "hkdf")
		return
	}
	expected := crypto.HMAC256(kHeartbeat, []byte(req.Timestamp))
	got, err := base64.StdEncoding.DecodeString(req.HMAC)
	if err != nil || !crypto.Equal(got, expected) {
		metricInc("hmac_fail_total", "/session/heartbeat")
		writeErr(w, http.StatusUnauthorized, "invalid_hmac", "")
		return
	}

	// Rotate nonce, renew TTL. Check kill + revocation.
	killed, _ := s.PG.KillStatus(ctx, sess.LicenseID)
	revoked := s.isRevoked(ctx, sess.LicenseID)
	if killed || revoked {
		// Kill: drop session + latest_token, never renew TTL.
		s.RDB.DeleteSession(ctx, req.Token)
		s.RDB.KillSessionsFor(ctx, sess.LicenseID)
		tp := req.Token
		if len(tp) > 8 {
			tp = tp[:8]
		}
		L().Infow("kill_enforced",
			"request_id", RequestID(ctx),
			"endpoint", "heartbeat",
			"token_prefix", tp,
			"revoked", revoked,
		)
		writeJSON(w, http.StatusOK, map[string]any{
			"kill":    true,
			"revoked": revoked,
		})
		return
	}

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
	if err := readJSON(w, r, &req); err != nil || req.Token == "" {
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
	if !s.rateLimitFetch(ctx, clientIP(r), sess.HWID) {
		metricInc("rate_limited_total", "/payload/fetch")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "rate_limited", "retry_after": 30,
		})
		return
	}

	// Uniform message across all 403 paths: a differing `message` leaks
	// "killed" vs "no payload" vs "banned" to a token holder (admin oracle).
	// Real reason is preserved in abuse_log via LogAbuse.
	lic, err := licenseByID(ctx, s.PG, sess.LicenseID)
	if err != nil {
		s.PG.LogAbuse(ctx, &sess.LicenseID, clientIP(r), "fetch_license_lookup")
		writeErr(w, http.StatusForbidden, "not_authorized", "")
		return
	}
	if killed, _ := s.PG.KillStatus(ctx, sess.LicenseID); killed {
		s.PG.LogAbuse(ctx, &sess.LicenseID, clientIP(r), "fetch_killed")
		writeErr(w, http.StatusForbidden, "not_authorized", "")
		return
	}

	pe, err := s.PG.LatestPayload(ctx, sess.LicenseID)
	if errors.Is(err, store.ErrNotFound) {
		s.PG.LogAbuse(ctx, &sess.LicenseID, clientIP(r), "fetch_no_payload")
		writeErr(w, http.StatusForbidden, "not_authorized", "")
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

	kWatermark, err := crypto.HKDFExpand(sessionKey, infoWatermark, 32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "hkdf")
		return
	}
	wm, err := buildWatermark(sess.HWID, lic.Key, kWatermark)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "watermark")
		return
	}

	plaintext := make([]byte, 0, len(wm)+len(pe))
	plaintext = append(plaintext, wm...)
	plaintext = append(plaintext, pe...)

	kPayloadAES, err := crypto.HKDFExpand(sessionKey, infoPayloadAES, 32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "hkdf")
		return
	}
	sealed, err := crypto.SealGCM(kPayloadAES, plaintext)
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
func buildWatermark(hwidHex, licenseKey string, watermarkKey []byte) ([]byte, error) {
	wm := make([]byte, 128)

	hwidBytes, err := hex.DecodeString(hwidHex)
	if err != nil || len(hwidBytes) != 32 {
		return nil, errors.New("hwid decode")
	}
	copy(wm[0:32], hwidBytes)

	lh := sha256sum([]byte(licenseKey))
	copy(wm[32:64], lh)

	binary.LittleEndian.PutUint64(wm[64:72], uint64(time.Now().Unix()))
	// TTL 24h; client enforces it after clock-rollback. Kill flag does NOT
	// revoke a payload the client already fetched — tighten here once we add
	// server-side payload revocation and reduce to ~1h to shrink the window.
	binary.LittleEndian.PutUint64(wm[72:80], 86400)

	nonce, err := crypto.RandBytes(16)
	if err != nil {
		return nil, err
	}
	copy(wm[80:96], nonce)

	sig := crypto.HMAC256(watermarkKey, wm[0:96])
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
	if err := readJSON(w, r, &req); err != nil ||
		req.Method == "" || req.Token == "" || req.Timestamp == "" || req.HMAC == "" ||
		!isValidRPCMethod(req.Method) {
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
	if !s.rateLimit(ctx, clientIP(r), sess.HWID) {
		metricInc("rate_limited_total", "/rpc/call")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "rate_limited", "retry_after": 30,
		})
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
	kRPC, err := crypto.HKDFExpand(sessionKey, infoRPC, 32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "hkdf")
		return
	}
	expected := crypto.HMAC256(kRPC, canon)
	got, err := base64.StdEncoding.DecodeString(req.HMAC)
	if err != nil || !crypto.Equal(got, expected) {
		metricInc("hmac_fail_total", "/rpc/call")
		writeErr(w, http.StatusUnauthorized, "invalid_hmac", "")
		return
	}

	// Anti-replay: timestamp is unique per (session, second); SET NX burns it.
	tokPfx := req.Token
	if len(tokPfx) > 8 {
		tokPfx = tokPfx[:8]
	}
	// Key uses sha256(token)[:16] (128 bits) to avoid cross-session collisions
	// a raw 32-bit prefix would allow (birthday at ~2^16 live sessions → DoS).
	tokHash := sha256.Sum256([]byte(req.Token))
	nonceKey := "rpc_nonce:" + hex.EncodeToString(tokHash[:16]) + ":" + req.Timestamp
	ok, err := s.RDB.TrySetOnce(ctx, nonceKey, 2*s.Cfg.TimestampSkew)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "redis")
		return
	}
	if !ok {
		metricInc("rpc_replay_blocked", "/rpc/call")
		rpcCallsTotal.WithLabelValues(req.Method, "replay").Inc()
		L().Warnw("rpc_replay_blocked",
			"request_id", RequestID(ctx),
			"token_prefix", tokPfx,
			"ts", req.Timestamp,
			"ip", clientIP(r),
		)
		writeErr(w, http.StatusUnauthorized, "invalid_hmac", "")
		return
	}

	// Dispatch.
	switch req.Method {
	case "ping":
		rpcCallsTotal.WithLabelValues(req.Method, "ok").Inc()
		writeJSON(w, http.StatusOK, map[string]any{"pong": true})
	default:
		rpcCallsTotal.WithLabelValues(req.Method, "unknown_method").Inc()
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
	L().Infow("sec-blind listening",
		"addr", addr,
		"session_ttl", s.Cfg.SessionTTL.String(),
		"heartbeat_s", s.Cfg.HeartbeatInterval,
	)
}
