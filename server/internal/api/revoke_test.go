package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/secblind/server/internal/store"
)

// TestAdminAuthRejectsWrongToken — the auth guard alone, no DB. Covers the
// 403 path (bad token) and the fail-safe (empty token).
func TestAdminAuthRejectsWrongToken(t *testing.T) {
	handler := adminAuth("correct-token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name   string
		header string
		token  string
		want   int
	}{
		{"wrong_token", "wrong", "correct-token", 403},
		{"empty_token_fail_safe", "anything", "", 403},
		{"length_mismatch", "short", "correct-token", 403},
		{"correct_token", "correct-token", "correct-token", 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := adminAuth(c.token, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			r := httptest.NewRequest("POST", "/api/v1/admin/revoke", strings.NewReader("{}"))
			r.Header.Set("X-Admin-Token", c.header)
			w := httptest.NewRecorder()
			h(w, r)
			if w.Code != c.want {
				t.Fatalf("status=%d want %d", w.Code, c.want)
			}
		})
	}
	_ = handler
}

// TestAdminRevokeIntegration exercises the full handler against a real
// Postgres + Redis. Skipped unless SB_TEST_PG_DSN and SB_TEST_REDIS_ADDR are
// set; CI with these set gets coverage of the 404 and happy paths.
func TestAdminRevokeIntegration(t *testing.T) {
	dsn := os.Getenv("SB_TEST_PG_DSN")
	rAddr := os.Getenv("SB_TEST_REDIS_ADDR")
	if dsn == "" || rAddr == "" {
		t.Skip("set SB_TEST_PG_DSN and SB_TEST_REDIS_ADDR to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pg, err := store.OpenPG(ctx, dsn)
	if err != nil {
		t.Fatalf("pg: %v", err)
	}
	defer pg.Close()
	rdb := store.OpenRedis(rAddr)
	defer rdb.Close()

	s := &Server{PG: pg, RDB: rdb, Cfg: Config{SessionTTL: 15 * time.Minute}}

	// 404 on unknown license.
	t.Run("unknown_license_404", func(t *testing.T) {
		body := `{"license_key":"does-not-exist-xxxxxxxxxxxx"}`
		r := httptest.NewRequest("POST", "/api/v1/admin/revoke", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.handleAdminRevoke(w, r)
		if w.Code != 404 {
			t.Fatalf("status=%d want 404", w.Code)
		}
	})

	// Happy path requires an existing license row; skip gracefully if seed absent.
	licKey := os.Getenv("SB_TEST_LICENSE_KEY")
	if licKey == "" {
		t.Skip("set SB_TEST_LICENSE_KEY to run the happy-path case")
	}
	t.Run("happy_path_200", func(t *testing.T) {
		body := `{"license_key":"` + licKey + `"}`
		r := httptest.NewRequest("POST", "/api/v1/admin/revoke", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.handleAdminRevoke(w, r)
		if w.Code != 200 {
			t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
		}
		var out struct {
			Revoked bool `json:"revoked"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !out.Revoked {
			t.Fatalf("revoked=false, want true")
		}
	})
}
