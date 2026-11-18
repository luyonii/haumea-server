package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/secblind/server/internal/store"
)

// AdminConfig is wired from main.go: separate bind + token.
type AdminConfig struct {
	Addr  string // e.g. 127.0.0.1:8443; empty disables admin endpoint
	Token string // required; empty disables admin endpoint (fail-safe)
}

// adminAuth checks X-Admin-Token with constant-time compare.
func adminAuth(token string, h http.HandlerFunc) http.HandlerFunc {
	tb := []byte(token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("X-Admin-Token"))
		if len(tb) == 0 || len(got) != len(tb) || subtle.ConstantTimeCompare(got, tb) != 1 {
			writeErr(w, http.StatusForbidden, "forbidden", "")
			return
		}
		h(w, r)
	}
}

// RegisterAdmin mounts /api/v1/admin/revoke on an admin-only mux. main.go must
// pass a mux bound to a private listener (never 0.0.0.0).
func (s *Server) RegisterAdmin(mux *http.ServeMux, token string) {
	reg := func(path string, h http.HandlerFunc) {
		mux.Handle(path, observe(path, adminAuth(token, h)))
	}
	reg("/api/v1/admin/revoke", s.handleAdminRevoke)
}

func (s *Server) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	var req struct {
		LicenseKey string `json:"license_key"`
	}
	if err := readJSON(w, r, &req); err != nil || req.LicenseKey == "" || len(req.LicenseKey) > 64 {
		writeErr(w, http.StatusBadRequest, "bad_request", "license_key required")
		return
	}
	ctx := r.Context()
	lic, err := s.PG.LicenseByKey(ctx, req.LicenseKey)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "unknown license")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "db")
		return
	}
	if err := s.PG.RevokeLicense(ctx, lic.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "revoke")
		return
	}
	// TTL = max(session_ttl, 7d). Redis cache keeps subsequent checks cheap.
	ttl := s.Cfg.SessionTTL
	if ttl < 7*24*time.Hour {
		ttl = 7 * 24 * time.Hour
	}
	if err := s.RDB.SetRevoked(ctx, lic.ID, ttl); err != nil {
		L().Warnw("revoke redis write failed",
			"request_id", RequestID(ctx), "license_id", lic.ID, "err", err.Error())
	}
	// Drop any current session so the heartbeat kill path triggers on next beat.
	s.RDB.KillSessionsFor(ctx, lic.ID)
	if prev, _ := s.RDB.LatestToken(ctx, lic.ID); prev != "" {
		s.RDB.DeleteSession(ctx, prev)
	}
	licenseRevokedTotal.Inc()
	keyPfx := req.LicenseKey
	if len(keyPfx) > 8 {
		keyPfx = keyPfx[:8]
	}
	L().Infow("license_revoked",
		"request_id", RequestID(ctx),
		"license_id", lic.ID,
		"license_prefix", keyPfx,
	)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "license_id": lic.ID})
}

// isRevoked = Redis cache first, then DB. Used by login and heartbeat paths.
// Errors fail closed (treat as revoked) only when DB says so; Redis errors
// fall through to the DB lookup.
func (s *Server) isRevoked(ctx context.Context, licenseID int64) bool {
	if ok, err := s.RDB.IsRevoked(ctx, licenseID); err == nil && ok {
		return true
	}
	rev, err := s.PG.IsRevoked(ctx, licenseID)
	if err != nil {
		return false
	}
	return rev
}
