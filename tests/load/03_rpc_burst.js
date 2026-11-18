// RPC burst — tests Redis anti-replay (SET NX on timestamp per session).
// Server anti-replay key = (session_token, timestamp_seconds). Two calls in
// the same second from the same VU WILL replay by design, so we pace to
// 1 call/sec per VU and run 60s. 20 VUs × 60 = 1200 unique calls.
// To intentionally stress replay path, set SB_FORCE_REPLAY=1 (expect
// rpc_replay_blocked > 0 and no 5xx).
import { check, sleep } from 'k6';
import http from 'k6/http';
import { Counter } from 'k6/metrics';
import { loginOnce, hkdfExpand32, hmacB64, BASE } from './_lib.js';

const replayBlocked = new Counter('rpc_replay_blocked_total');
const okCalls = new Counter('rpc_ok_total');
const FORCE_REPLAY = __ENV.SB_FORCE_REPLAY === '1';

export const options = {
  scenarios: {
    rpc: {
      executor: 'constant-vus',
      vus: 20,
      duration: '60s',
    },
  },
  thresholds: {
    'http_req_duration{route:rpc}': ['p(95)<200'],
    // Replay path returns 401. 5xx must stay zero.
    'http_req_failed{route:rpc}':   ['rate<0.5'],
  },
};

const state = {};

function canonBytes(method, token, ts, payload) {
  const s = `${method}|${token}|${ts}|${payload}`;
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export default function () {
  let st = state[__VU];
  if (!st) {
    const ok = loginOnce(__VU);
    if (!ok) { sleep(1); return; }
    st = {
      token: ok.session.session_token,
      kRPC: hkdfExpand32(ok.session.session_key, 'sb.v1.rpc.hmac'),
    };
    state[__VU] = st;
  }

  const method = 'ping';
  const payload = '{}';
  const ts = FORCE_REPLAY
    ? '1700000000'                              // fixed ⇒ replay after 1st
    : Math.floor(Date.now() / 1000).toString();

  const r = http.post(`${BASE}/api/v1/rpc/call`,
    JSON.stringify({
      method,
      session_token: st.token,
      payload: JSON.parse(payload),
      timestamp: ts,
      hmac: hmacB64(st.kRPC, canonBytes(method, st.token, ts, payload)),
    }),
    { headers: { 'Content-Type': 'application/json' }, tags: { route: 'rpc' } });

  if (r.status === 200) okCalls.add(1);
  if (r.status === 401) {
    try { if ((r.json().error || '').indexOf('replay') >= 0) replayBlocked.add(1); } catch (_) {}
  }
  check(r, { 'no 5xx': (x) => x.status < 500 });
  if (!FORCE_REPLAY) sleep(1); // honor per-second anti-replay
}
