// Vanilla ES-module operator dashboard. On load: prompts for a token
// (stored in sessionStorage), fetches the first resource, renders it in
// the table. Exports helpers so each new resource is a 3-line wire-up.

const TOKEN_KEY = 'admin_token';

function getToken() {
    let t = sessionStorage.getItem(TOKEN_KEY);
    if (!t) {
        t = window.prompt('Operator token:') || '';
        if (t) sessionStorage.setItem(TOKEN_KEY, t);
    }
    return t;
}

export async function fetchJSON(path, opts = {}) {
    const headers = new Headers(opts.headers || {});
    headers.set('X-Admin-Token', getToken());
    if (opts.body && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }
    const resp = await fetch(path, { ...opts, headers });
    if (resp.status === 403) {
        sessionStorage.removeItem(TOKEN_KEY);
        throw new Error('Forbidden — token cleared, reload to re-enter.');
    }
    if (!resp.ok) {
        throw new Error('HTTP ' + resp.status + ': ' + (await resp.text()));
    }
    const ct = resp.headers.get('Content-Type') || '';
    return ct.includes('application/json') ? resp.json() : resp.text();
}

// Row objects are kept off the DOM so untrusted field strings (key, note,
// hwid) never pass through attributes — only textContent, which never parses
// as HTML. The lookup is by <tr>; replacing tbody GC's its entries.
const rowMap = new WeakMap();

export function renderTable(tbody, rows, columns) {
    tbody.innerHTML = '';
    if (!rows || rows.length === 0) {
        const tr = document.createElement('tr');
        tr.className = 'empty';
        const td = document.createElement('td');
        td.colSpan = columns.length;
        td.textContent = 'No records.';
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }
    for (const row of rows) {
        const tr = document.createElement('tr');
        rowMap.set(tr, row);
        for (const col of columns) {
            const td = document.createElement('td');
            td.textContent = formatCell(row[col]);
            tr.appendChild(td);
        }
        tbody.appendChild(tr);
    }
}

function formatCell(v) {
    if (v == null) return '';
    if (v instanceof Date) return v.toISOString();
    return String(v);
}

export function openModal(id)  { document.getElementById(id)?.classList.remove('hidden'); }
export function closeModal(id) { document.getElementById(id)?.classList.add('hidden');    }

let toastTimer = null;
function toast(msg, kind = 'info') {
    const el = document.getElementById('toast');
    if (!el) return;
    el.textContent = msg;              // textContent only; no HTML path.
    el.className = 'toast ' + kind;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.className = 'toast hidden'; }, 6000);
}

// --- Resource registry ---------------------------------------------------
//
// Each entry wires a sidebar tab to a JSON endpoint and a column list the
// table renderer uses. `create` adds a "+ New" button + modal flow; `row`
// adds a per-row action button in the detail panel. See the licenses entry.
const RESOURCES = {
    licenses: {
        path: '/api/v1/admin/licenses',
        columns: ['id', 'key', 'hwid', 'banned', 'revoked', 'killed', 'created_at'],
        labels:  ['ID', 'Key', 'HWID', 'Banned', 'Revoked', 'Killed', 'Created'],
        create: {
            modal:  'new-license-modal',
            formId: 'new-license-form',
            // Serializes form values into the request body. Fields missing on
            // the form default to undefined so the server's own defaults win.
            request: (form) => ({
                path: '/api/v1/admin/license',
                body: {
                    // Normalize to match the server's ^[A-Z0-9]{1,8}$ regex so
                    // a lowercase typed prefix isn't rejected as invalid.
                    prefix: (form.get('prefix') || '').trim().toUpperCase(),
                    note:   (form.get('note')   || '').trim(),
                },
            }),
            onSuccess: (resp) => toast('Created ' + resp.license_key, 'ok'),
        },
        row: {
            label:   'Revoke',
            danger:  true,
            // Skipped-row guard: a license already revoked cannot be
            // double-revoked without noise, so the button is hidden for them.
            hidden:  (row) => !!row.revoked,
            confirm: (row) => 'Revoke ' + row.key + '? This cannot be undone.',
            request: (row) => ({
                path: '/api/v1/admin/revoke',
                body: { license_key: row.key },
            }),
            onSuccess: (_, row) => toast('Revoked ' + row.key, 'ok'),
        },
    },
};

let current = 'licenses';
let currentRow = null;

function renderHead(thead, labels) {
    thead.innerHTML = '';
    const tr = document.createElement('tr');
    for (const l of labels) {
        const th = document.createElement('th');
        th.textContent = l;
        tr.appendChild(th);
    }
    thead.appendChild(tr);
}

function updateChrome(spec) {
    const newBtn    = document.getElementById('new-btn');
    const actionBtn = document.getElementById('action-btn');
    if (spec.create) {
        newBtn.classList.remove('hidden');
    } else {
        newBtn.classList.add('hidden');
    }
    // Hide the action button by default; openDetail decides to show it.
    actionBtn.classList.add('hidden');
    actionBtn.classList.remove('btn-danger');
}

async function load(resource) {
    const spec = RESOURCES[resource];
    if (!spec) return;
    const thead = document.getElementById('data-head');
    const tbody = document.getElementById('data-body');
    renderHead(thead, spec.labels || spec.columns);
    updateChrome(spec);
    document.getElementById('detail-panel').classList.add('hidden');
    try {
        const rows = await fetchJSON(spec.path);
        renderTable(tbody, rows, spec.columns);
    } catch (e) {
        tbody.innerHTML = `<tr class="empty"><td colspan="${spec.columns.length}">${escapeHtml(e.message)}</td></tr>`;
    }
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[c]);
}

function openDetail(tr) {
    const row = rowMap.get(tr);
    if (!row) return;
    currentRow = row;

    const panel  = document.getElementById('detail-panel');
    const fields = document.getElementById('detail-fields');
    const actionBtn = document.getElementById('action-btn');
    fields.innerHTML = '';

    const spec = RESOURCES[current];
    for (const col of spec.columns) {
        const dt = document.createElement('dt');
        dt.textContent = col;
        const dd = document.createElement('dd');
        dd.textContent = formatCell(row[col]);
        fields.appendChild(dt);
        fields.appendChild(dd);
    }

    const row_action = spec.row;
    if (row_action && !(row_action.hidden && row_action.hidden(row))) {
        actionBtn.textContent = row_action.label;
        actionBtn.classList.remove('hidden');
        if (row_action.danger) actionBtn.classList.add('btn-danger');
    } else {
        actionBtn.classList.add('hidden');
    }
    panel.classList.remove('hidden');
}

async function doPost(path, body) {
    return fetchJSON(path, {
        method: 'POST',
        body: JSON.stringify(body || {}),
    });
}

document.addEventListener('click', (e) => {
    const closeTarget = e.target.closest?.('[data-close]');
    if (closeTarget) { closeModal(closeTarget.dataset.close); return; }

    const resEl = e.target.closest?.('.resource');
    if (resEl && resEl.dataset.resource) {
        for (const li of document.querySelectorAll('.resource')) li.classList.remove('active');
        resEl.classList.add('active');
        current = resEl.dataset.resource;
        load(current);
        return;
    }

    const tr = e.target.closest?.('tr[data-id], tr');
    if (tr && tr.closest('tbody') && rowMap.has(tr)) { openDetail(tr); return; }

    if (e.target.id === 'new-btn') {
        const spec = RESOURCES[current];
        if (spec.create) openModal(spec.create.modal);
        return;
    }
    if (e.target.id === 'refresh') { load(current); return; }

    if (e.target.id === 'action-btn') {
        const spec = RESOURCES[current];
        const ra = spec.row;
        if (!ra || !currentRow) return;
        const msg = ra.confirm ? ra.confirm(currentRow) : 'Confirm?';
        if (!window.confirm(msg)) return;
        const { path, body } = ra.request(currentRow);
        doPost(path, body).then((resp) => {
            ra.onSuccess?.(resp, currentRow);
            load(current);
        }).catch((err) => {
            toast(err.message, 'err');
        });
        return;
    }
});

document.getElementById('new-license-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    const spec = RESOURCES[current];
    if (!spec.create) return;
    const form = new FormData(e.target);
    const { path, body } = spec.create.request(form);
    doPost(path, body).then((resp) => {
        spec.create.onSuccess?.(resp);
        closeModal(spec.create.modal);
        e.target.reset();
        load(current);
    }).catch((err) => {
        toast(err.message, 'err');
    });
});

load(current);
