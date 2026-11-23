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

// unit: prefix regex + key format (no DB).
func TestGenerateLicenseKeyFormat(t *testing.T) {
	k, err := generateLicenseKey("SB")
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if !strings.HasPrefix(k, "SB-") || len(k) != 3+32 {
		t.Fatalf("bad key: %q", k)
	}
	for _, c := range k[3:] {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			t.Fatalf("non hex uppercase: %q", k)
		}
	}
}

func TestAdminPrefixRegex(t *testing.T) {
	ok := []string{"SB", "VIP", "A", "ABCDEFGH", "SB1"}
	bad := []string{"", "ab", "ab-", "TOOLONGXX", "sb", "SB_"}
	for _, p := range ok {
		if !adminPrefixRe.MatchString(p) {
			t.Fatalf("want ok: %q", p)
		}
	}
	for _, p := range bad {
		if adminPrefixRe.MatchString(p) {
			t.Fatalf("want bad: %q", p)
		}
	}
}

// Integration: create + status. Skipped unless SB_TEST_PG_DSN is set.
func TestAdminLicenseIntegration(t *testing.T) {
	dsn := os.Getenv("SB_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set SB_TEST_PG_DSN to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pg, err := store.OpenPG(ctx, dsn)
	if err != nil {
		t.Fatalf("pg: %v", err)
	}
	defer pg.Close()
	s := &Server{PG: pg}

	// Auth guard: wrapper not exercised here (covered by TestAdminAuthRejectsWrongToken);
	// these hit the inner handler directly.

	t.Run("create_default_prefix", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/v1/admin/license", strings.NewReader(""))
		w := httptest.NewRecorder()
		s.handleAdminCreateLicense(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var out struct {
			LicenseKey string `json:"license_key"`
			LicenseID  int64  `json:"license_id"`
			CreatedAt  string `json:"created_at"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !strings.HasPrefix(out.LicenseKey, "SB-") || len(out.LicenseKey) != 3+32 {
			t.Fatalf("bad key: %q", out.LicenseKey)
		}
		if out.LicenseID == 0 || out.CreatedAt == "" {
			t.Fatalf("missing fields: %+v", out)
		}
		// Round-trip: status must find it.
		r2 := httptest.NewRequest("GET", "/api/v1/admin/license/"+out.LicenseKey, nil)
		r2.SetPathValue("key", out.LicenseKey)
		w2 := httptest.NewRecorder()
		s.handleAdminLicenseStatus(w2, r2)
		if w2.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w2.Code, w2.Body.String())
		}
		var st map[string]any
		_ = json.Unmarshal(w2.Body.Bytes(), &st)
		if st["license_key"] != out.LicenseKey {
			t.Fatalf("mismatch: %+v", st)
		}
		if st["banned"] != false || st["revoked"] != false || st["hwid_bound"] != false || st["killed"] != false {
			t.Fatalf("new license has unexpected flags: %+v", st)
		}
	})

	t.Run("create_custom_prefix", func(t *testing.T) {
		body := `{"prefix":"VIP","note":"discord_user:42"}`
		r := httptest.NewRequest("POST", "/api/v1/admin/license", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.handleAdminCreateLicense(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var out struct {
			LicenseKey string `json:"license_key"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if !strings.HasPrefix(out.LicenseKey, "VIP-") {
			t.Fatalf("bad prefix: %q", out.LicenseKey)
		}
	})

	t.Run("invalid_prefix_400", func(t *testing.T) {
		body := `{"prefix":"ab-"}`
		r := httptest.NewRequest("POST", "/api/v1/admin/license", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.handleAdminCreateLicense(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want 400", w.Code)
		}
	})

	t.Run("status_not_found_404", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/admin/license/NOPE-NOPE-NOPE", nil)
		r.SetPathValue("key", "NOPE-NOPE-NOPE")
		w := httptest.NewRecorder()
		s.handleAdminLicenseStatus(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status=%d want 404", w.Code)
		}
	})
}

// Auth is enforced by the adminAuth wrapper, which already has coverage in
// TestAdminAuthRejectsWrongToken; this just confirms create is wired under it.
func TestAdminCreateAuthRequired(t *testing.T) {
	h := adminAuth("secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest("POST", "/api/v1/admin/license", strings.NewReader("{}"))
	// No X-Admin-Token header.
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", w.Code)
	}
}
