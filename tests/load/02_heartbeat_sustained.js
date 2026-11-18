// Login once per VU, then heartbeat loop for 10 minutes.
// Measures heartbeat latency P95 under sustained concurrency.
// Server rotates next_nonce every heartbeat; VU tracks it.
import { check, sleep } from 'k6';
import http from 'k6/http';
import { Trend } from 'k6/metrics';
import { loginOnce, hkdfExpand32, hmacB64, BASE } from './_lib.js';

const hbTrend = new Trend('heartbeat_rtt_ms', true);

export const options = {
  scenarios: {
    hb: {
      executor: 'constant-vus',
      vus: 100,
      duration: '10m',
    },
  },
  thresholds: {
    'http_req_duration{route:heartbeat}': ['p(95)<150'],
    'http_req_failed{route:heartbeat}':   ['rate<0.005'],
  },
};

const HB_INTERVAL_S = 10; // << server heartbeat_s to stay well under TTL

export function setup() { return {}; }

// VU-local state across iterations.
const state = {}; // keyed by __VU

export default function () {
  let st = state[__VU];
  if (!st) {
    const ok = loginOnce(__VU);
    if (!ok) { sleep(1); return; }
    st = {
      token: ok.session.session_token,
      kHb: hkdfExpand32(ok.session.session_key, 'sb.v1.heartbeat.hmac'),
      nextNonce: ok.session.next_nonce,
    };
    state[__VU] = st;
  }

  const ts = Math.floor(Date.now() / 1000).toString();
  const tsBytes = new Uint8Array(ts.length);
  for (let i = 0; i < ts.length; i++) tsBytes[i] = ts.charCodeAt(i);
  const body = {
    session_token: st.token,
    hmac: hmacB64(st.kHb, tsBytes),
    timestamp: ts,
    next_nonce: st.nextNonce,
  };
  const t0 = Date.now();
  const r = http.post(`${BASE}/api/v1/session/heartbeat`,
    JSON.stringify(body), { headers: { 'Content-Type': 'application/json' },
    tags: { route: 'heartbeat' } });
  hbTrend.add(Date.now() - t0);

  const ok = check(r, { 'hb 200': (x) => x.status === 200 });
  if (ok) {
    try { st.nextNonce = r.json().next_nonce; } catch (_) { /* keep old */ }
  } else {
    delete state[__VU]; // re-login next iter
  }
  sleep(HB_INTERVAL_S);
}
