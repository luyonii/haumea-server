// Package admin_ui serves a vanilla HTML operator dashboard as embedded
// static files. It is designed to be mounted on the same private HTTP bind
// as the JSON admin endpoints (loopback locally, VPN subnet in production),
// never on a public listener.
package admin_ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// Register mounts the dashboard's static assets at /admin/ui/ (ungated; the
// JS boots then prompts for the token and sends it on every /api/* call).
// Resource endpoints the dashboard calls live on the server's existing admin
// mux (/api/v1/admin/*), already gated by the same X-Admin-Token the JS
// collects. The static files leak nothing by themselves: no project data,
// no endpoints beyond what the server's own Register calls declared. Defense
// in depth is the loopback bind + SSH-forward requirement, not another gate
// on the HTML.
//
// token is currently unused here (kept in the signature so a future ungated
// /admin/ui/-scoped API can plug in without changing main.go).
func Register(mux *http.ServeMux, _ string) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("admin_ui: embed subtree missing: " + err.Error())
	}
	mux.Handle("GET /admin/ui/", http.StripPrefix("/admin/ui/", http.FileServer(http.FS(sub))))
}
