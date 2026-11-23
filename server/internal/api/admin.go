package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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
	reg("/api/v1/admin/license", s.handleAdminCreateLicense)
	reg("/api/v1/admin/license/{key}", s.handleAdminLicenseStatus)
	reg("/api/v1/admin/licenses", s.handleAdminListLicenses)
}

var adminPrefixRe = regexp.MustCompile(`^[A-Z0-9]{1,8}$`)

// generateLicenseKey returns "<prefix>-<32 hex uppercase>" (16 random bytes = 128 bits).
func generateLicenseKey(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "-" + strings.ToUpper(hex.EncodeToString(b[:])), nil
}

func (s *Server) handleAdminCreateLicense(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	var req struct {
		Prefix string `json:"prefix"`
		Note   string `json:"note"`
	}
	// Empty body is allowed: treat as defaults.
	if r.ContentLength != 0 {
		if err := readJSON(w, r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid json")
			return
		}
	}
	prefix := strings.TrimSpace(req.Prefix)
	if prefix == "" {
		prefix = "SB"
	}
	if !adminPrefixRe.MatchString(prefix) {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid prefix")
		return
	}
	// prefix(<=8) + "-" + 32 hex = <=41 chars, well under the 64 cap.
	var notePtr *string
	if n := strings.TrimSpace(req.Note); n != "" {
		if len(n) > 512 {
			writeErr(w, http.StatusBadRequest, "bad_request", "note too long")
			return
		}
		notePtr = &n
	}

	ctx := r.Context()
	var (
		key       string
		id        int64
		createdAt time.Time
	)
	// One retry on license_key uniqueness collision (SQLSTATE 23505).
	for attempt := 0; attempt < 2; attempt++ {
		k, err := generateLicenseKey(prefix)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "server_error", "rand failed")
			return
		}
		id, createdAt, err = s.PG.InsertLicense(ctx, k, notePtr)
		if err == nil {
			key = k
			break
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}
		writeErr(w, http.StatusInternalServerError, "server_error", "db")
		return
	}
	if key == "" {
		writeErr(w, http.StatusInternalServerError, "server_error", "key collision")
		return
	}
	licenseCreatedTotal.Inc()
	keyPfx := key
	if len(keyPfx) > 8 {
		keyPfx = keyPfx[:8]
	}
	L().Infow("license_created",
		"request_id", RequestID(ctx),
		"license_id", id,
		"license_prefix", keyPfx,
	)
	writeJSON(w, http.StatusCreated, map[string]any{
		"license_key": key,
		"license_id":  id,
		"created_at":  createdAt.UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) handleAdminLicenseStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	key := r.PathValue("key")
	if key == "" {
		// Fallback: Go <1.22 or when pattern was registered without {key}.
		key = strings.TrimPrefix(r.URL.Path, "/api/v1/admin/license/")
	}
	if key == "" || len(key) > 64 {
		writeErr(w, http.StatusBadRequest, "bad_request", "license key required")
		return
	}
	ctx := r.Context()
	st, err := s.PG.LicenseStatusByKey(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "unknown license")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "db")
		return
	}
	out := map[string]any{
		"license_key": st.Key,
		"license_id":  st.ID,
		"banned":      st.Banned,
		"revoked":     st.Revoked,
		"revoked_at":  nil,
		"hwid_bound":  st.HWID != nil,
		"hwid_hex":    nil,
		"bound_at":    nil,
		"killed":      st.Killed,
		"created_at":  st.CreatedAt.UTC().Format(time.RFC3339Nano),
		"note":        nil,
	}
	if st.RevokedAt != nil {
		out["revoked_at"] = st.RevokedAt.UTC().Format(time.RFC3339Nano)
	}
	if st.HWID != nil {
		h := *st.HWID
		if len(h) > 16 {
			h = h[:16]
		}
		out["hwid_hex"] = h
	}
	if st.BoundAt != nil {
		out["bound_at"] = st.BoundAt.UTC().Format(time.RFC3339Nano)
	}
	if st.Note != nil {
		out["note"] = *st.Note
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAdminListLicenses returns a JSON array of licenses sorted newest-first.
// Pagination is one knob: ?limit=N (default 100, max 500). No offset for now;
// a later cursor can replace it when real volume demands it.
func (s *Server) handleAdminListLicenses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.PG.ListLicenses(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "db")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, st := range rows {
		hwid := ""
		if st.HWID != nil {
			h := *st.HWID
			if len(h) > 16 {
				h = h[:16]
			}
			hwid = h
		}
		out = append(out, map[string]any{
			"id":         st.ID,
			"key":        st.Key,
			"hwid":       hwid,
			"banned":     st.Banned,
			"revoked":    st.Revoked,
			"killed":     st.Killed,
			"created_at": st.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, out)
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
		// Fail closed: a DB error means we cannot confirm "not revoked", so
		// treat as revoked rather than let a possibly-revoked license through.
		return true
	}
	return rev
}

// enforcementBlocked reports kill/revoke state for a license, failing CLOSED:
// a KillStatus DB error (or an unresolvable revoke check) returns true, so a
// transient Postgres/Redis outage cannot keep a killed/revoked session alive.
func (s *Server) enforcementBlocked(ctx context.Context, licenseID int64) (killed, revoked bool) {
	k, err := s.PG.KillStatus(ctx, licenseID)
	if err != nil {
		k = true
	}
	return k, s.isRevoked(ctx, licenseID)
}
