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
        tr.dataset.id = row.id;
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

// --- Resource registry ---------------------------------------------------
//
// Each entry wires a sidebar tab to a JSON endpoint and a column list the
// table renderer uses. Add new resources here plus a <li> in index.html
// and (optionally) a Go handler in handler.go.
const RESOURCES = {
    licenses: {
        path: '/api/v1/admin/licenses',
        columns: ['id', 'key', 'hwid', 'banned', 'revoked', 'killed', 'created_at'],
        labels:  ['ID', 'Key', 'HWID', 'Banned', 'Revoked', 'Killed', 'Created'],
    },
};

let current = 'licenses';

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

async function load(resource) {
    const spec = RESOURCES[resource];
    if (!spec) return;
    const thead = document.getElementById('data-head');
    const tbody = document.getElementById('data-body');
    renderHead(thead, spec.labels || spec.columns);
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
    const panel  = document.getElementById('detail-panel');
    const fields = document.getElementById('detail-fields');
    fields.innerHTML = '';
    const cells = tr.querySelectorAll('td');
    const cols  = RESOURCES[current].columns;
    for (let i = 0; i < cols.length; i++) {
        const dt = document.createElement('dt');
        dt.textContent = cols[i];
        const dd = document.createElement('dd');
        dd.textContent = cells[i].textContent;
        fields.appendChild(dt);
        fields.appendChild(dd);
    }
    panel.classList.remove('hidden');
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

    const tr = e.target.closest?.('tr[data-id]');
    if (tr) { openDetail(tr); return; }

    if (e.target.id === 'edit-btn')  { openModal('edit-modal'); return; }
    if (e.target.id === 'refresh')   { load(current);           return; }
});

document.getElementById('edit-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    // Placeholder: write handler lands with the first mutable resource.
    closeModal('edit-modal');
});

load(current);
