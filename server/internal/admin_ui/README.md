# admin_ui

Internal operator dashboard. Vanilla HTML + ES modules, embedded into the Go
binary via `//go:embed`. Served on the same private bind as the admin JSON
endpoints (`127.0.0.1:8443` locally, `10.x.x.x:8443` over VPN in production).
The `X-Admin-Token` header is the second factor behind the VPN peer identity,
not a public-internet boundary.

## Layout

```
server/internal/admin_ui/
├── handler.go       Register(mux, token): mounts /admin/ui/ and
│                    /admin/ui/api/records. Gated by subtle.ConstantTimeCompare.
├── static/
│   ├── index.html   Single page: top bar, sidebar, table,
│   │                detail side panel, edit modal.
│   ├── app.js       ES module. Exports fetchJSON, renderTable,
│   │                openModal, closeModal. Boots the first
│   │                resource on load.
│   └── style.css    Dark theme.
└── README.md        This file.
```

The `//go:embed static` directive at the top of `handler.go` picks up every
file under `static/`; rebuild (`go build`) after adding or editing assets.

## Wiring

Call `admin_ui.Register(adminMux, adminToken)` from the same place that calls
`srv.RegisterAdmin(...)` in `server/cmd/server/main.go`. Both share the private
bind; browsers that reach the VPN subnet load
`http://10.x.x.x:8443/admin/ui/` and the user is prompted for the token on
first load. The wire-up is intentionally not added yet — that is the next task.

## Adding a resource

Example: a `clients` resource.

1. **Go.** In `handler.go`, define the response type and a handler:

   ```go
   type Client struct {
       ID   int64  `json:"id"`
       Name string `json:"name"`
   }

   func handleClients(w http.ResponseWriter, _ *http.Request) {
       w.Header().Set("Content-Type", "application/json")
       _ = json.NewEncoder(w).Encode([]Client{})
   }
   ```

   Mount in `Register`:

   ```go
   mux.Handle("GET /admin/ui/api/clients", gate(http.HandlerFunc(handleClients)))
   ```

2. **HTML.** In `static/index.html`, append a sidebar entry:

   ```html
   <li class="resource" data-resource="clients">Clients</li>
   ```

3. **JS.** In `static/app.js`, add to the `RESOURCES` map:

   ```javascript
   clients: {
       path: '/admin/ui/api/clients',
       columns: ['id', 'name'],
   },
   ```

4. Rebuild (`go build ./...`). The new sidebar item renders automatically;
   clicking it fetches the endpoint and renders the table.

## Not included (yet)

- CRUD write operations (`POST`/`PATCH`/`DELETE`). The edit modal exists but
  the submit handler is a no-op; wire it when the first mutable resource lands.
- Paging / server-side filtering. `renderTable` does a full-list render; the
  filter input is cosmetic until real resource volume demands it.
- Tests. Scaffolding only.

## Deployment posture

Never mount `admin_ui.Register` on the public mux. The static files leak
nothing by themselves (no project data, no endpoints beyond those your
`Register` call added), but the `/admin/ui/` path is a tell that an admin
surface exists, so keeping the private bind is part of the defense.
