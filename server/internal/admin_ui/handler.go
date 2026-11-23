// Package admin_ui serves a vanilla HTML operator dashboard as embedded
// static files. It is designed to be mounted on the same private HTTP bind
// as the JSON admin endpoints (loopback locally, VPN subnet in production),
// never on a public listener.
package admin_ui

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"time"
)

//go:embed static
var staticFS embed.FS

// Record is a placeholder resource type. The dashboard renders a Records
// tab backed by a stub endpoint so the HTML/JS plumbing is wired end to
// end; real resources plug in by following the pattern documented in the
// package README.
type Record struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Register mounts two routes on mux:
//
//	GET  /admin/ui/            — embedded static assets (ungated; the JS
//	                             boots then prompts for the token and sends
//	                             it on every /api/* call)
//	GET  /admin/ui/api/records — placeholder JSON list, gated
//
// The gate compares X-Admin-Token constant-time against token. An empty
// token argument refuses every /api/* request (fail-safe). The static files
// leak nothing by themselves: no project data, no endpoints beyond what the
// server's Register call already declares. Defense in depth is the loopback
// bind + SSH-forward requirement, not another gate on the HTML.
func Register(mux *http.ServeMux, token string) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("admin_ui: embed subtree missing: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))

	tb := []byte(token)
	gate := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := []byte(r.Header.Get("X-Admin-Token"))
			if len(tb) == 0 || len(got) != len(tb) ||
				subtle.ConstantTimeCompare(got, tb) != 1 {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			h.ServeHTTP(w, r)
		})
	}

	mux.Handle("GET /admin/ui/", http.StripPrefix("/admin/ui/", files))
	mux.Handle("GET /admin/ui/api/records", gate(http.HandlerFunc(handleRecords)))
}

// handleRecords returns an empty list for now. Real storage, filtering,
// and pagination land when the first concrete resource is wired.
func handleRecords(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode([]Record{})
}
