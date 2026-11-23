# admin_ui

Internal operator dashboard. Vanilla HTML + ES modules, embedded into the Go
binary via `//go:embed`. Served on the same private bind as the admin JSON
endpoints (`127.0.0.1:8443`). Reach it from a workstation with an SSH
local-forward:

    ssh -L 8443:127.0.0.1:8443 user@host

Open `http://localhost:8443/admin/ui/`. SSH-key access is the first factor;
the `X-Admin-Token` header is the second. Never bind on `0.0.0.0`.

## Layout

```
server/internal/admin_ui/
├── handler.go       Register(mux, _): mounts /admin/ui/ (static only;
│                    the resource endpoints live on the server's own
│                    admin mux at /api/v1/admin/*).
├── static/
│   ├── index.html   Single page: top bar, sidebar, table, detail
│   │                side panel, and modal(s).
│   ├── app.js       ES module. Exports fetchJSON, renderTable,
│   │                openModal, closeModal. Boots the first resource
│   │                on load. Row objects are kept off the DOM in a
│   │                WeakMap so untrusted strings never pass through
│   │                attributes.
│   └── style.css    Dark theme.
└── README.md        This file.
```

The `//go:embed static` directive at the top of `handler.go` picks up every
file under `static/`; rebuild (`go build`) after adding or editing assets.

## Wiring

Called from `server/cmd/server/main.go` on the admin mux, right after
`srv.RegisterAdmin(...)`. Both share the loopback bind; the operator reaches
`http://localhost:8443/admin/ui/` through an SSH local-forward and is
prompted for the token on first load. Static assets are **ungated** so the JS
can boot and prompt; the gate lives on the data endpoints (`/api/v1/admin/*`)
where the data actually is.

## Adding a resource

The licenses resource is the canonical example — a read-only endpoint plus a
create flow and a per-row revoke action.

### 1. Server endpoint

The admin JSON endpoints already route through `api.RegisterAdmin`; add a
new handler there (see `server/internal/api/admin.go`). For licenses:

```go
reg("/api/v1/admin/licenses", s.handleAdminListLicenses)  // GET
reg("/api/v1/admin/license",  s.handleAdminCreateLicense) // POST
reg("/api/v1/admin/revoke",   s.handleAdminRevoke)        // POST
```

Each handler writes JSON through `writeJSON` / `writeErr`. No new mount in
`admin_ui/handler.go` is needed.

### 2. Sidebar entry

In `static/index.html`:

```html
<li class="resource" data-resource="licenses">Licenses</li>
```

### 3. Resource spec (JS)

In `static/app.js`, add to `RESOURCES`:

```javascript
licenses: {
    path: '/api/v1/admin/licenses',
    columns: ['id', 'key', 'hwid', 'banned', 'revoked', 'killed', 'created_at'],
    labels:  ['ID', 'Key', 'HWID', 'Banned', 'Revoked', 'Killed', 'Created'],
    create: {                                      // optional — shows "+ New"
        modal:  'new-license-modal',
        formId: 'new-license-form',
        request: (form) => ({
            path: '/api/v1/admin/license',
            body: { prefix: ..., note: ... },
        }),
        onSuccess: (resp) => toast('Created ' + resp.license_key, 'ok'),
    },
    row: {                                         // optional — detail-panel button
        label:   'Revoke',
        danger:  true,
        hidden:  (row) => !!row.revoked,
        confirm: (row) => 'Revoke ' + row.key + '?',
        request: (row) => ({
            path: '/api/v1/admin/revoke',
            body: { license_key: row.key },
        }),
        onSuccess: (_, row) => toast('Revoked ' + row.key, 'ok'),
    },
},
```

### 4. Rebuild

`go build ./...` (or `.\dist\deploy-server.ps1` to also push to the VPS).

## Not included (yet)

- Paging / server-side filtering. `renderTable` does a full-list render; the
  filter input is cosmetic until real resource volume demands it.
- Column sort.
- Per-row inline edit (only create + per-row action land today).
- Tests. Scaffolding only.

## Deployment posture

Never mount `admin_ui.Register` on the public mux. The admin listener binds
loopback only; access comes through an SSH local-forward keyed on the
operator's SSH key. The static files leak nothing by themselves (no project
data, no endpoints beyond those your `Register` call added), but the
`/admin/ui/` path is a tell that an admin surface exists, so keeping the
loopback bind is part of the defense.
