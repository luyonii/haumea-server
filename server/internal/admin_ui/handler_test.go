package admin_ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Register must serve the embedded index.html at /admin/ui/ WITHOUT the
// X-Admin-Token header — the gate on /admin/ui/ would be a chicken-and-egg
// 403 before the JS can prompt for the token.
func TestRegister_ServesIndexUngated(t *testing.T) {
	mux := http.NewServeMux()
	Register(mux, "irrelevant")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/admin/ui/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	for _, want := range []string{
		"<title>Admin</title>",
		`id="data-head"`,
		`id="data-body"`,
		`src="app.js"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("index missing %q", want)
		}
	}
}

// The ES module and the stylesheet must also come through (the browser loads
// them as subresources of /admin/ui/).
func TestRegister_ServesAppJSAndCSS(t *testing.T) {
	mux := http.NewServeMux()
	Register(mux, "irrelevant")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	for _, path := range []string{"/admin/ui/app.js", "/admin/ui/style.css"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("%s: get: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status=%d want 200", path, resp.StatusCode)
		}
	}
}

// An unknown asset under /admin/ui/ falls to the static file server's 404,
// never a bare "index.html" fallback that would leak the root page.
func TestRegister_UnknownPath404(t *testing.T) {
	mux := http.NewServeMux()
	Register(mux, "irrelevant")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/admin/ui/nope-not-here.html")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d want 404", resp.StatusCode)
	}
}
