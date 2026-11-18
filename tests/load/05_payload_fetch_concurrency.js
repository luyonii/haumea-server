// Concurrent /payload/fetch. Server does GCM seal per call; we measure
// server-side only.
//
// OUT-OF-BAND: client-side GCM decrypt throughput is NOT measured here.
// To benchmark decrypt, capture (iv, tag, ciphertext, session_key) from
// a successful response and run a dedicated micro-bench with the real
// C++ client (see integration/).
import { check } from 'k6';
import http from 'k6/http';
import { loginOnce, BASE } from './_lib.js';

export const options = {
  scenarios: {
    fetch: {
      executor: 'constant-vus',
      vus: 50,
      duration: '3m',
    },
  },
  thresholds: {
    'http_req_duration{route:fetch}': ['p(99)<500'],
    'checks{kind:no5xx}':             ['rate>0.999'],
  },
};

const state = {};

export default function () {
  let token = state[__VU];
  if (!token) {
    const ok = loginOnce(__VU);
    if (!ok) return;
    token = ok.session.session_token;
    state[__VU] = token;
  }
  const r = http.post(`${BASE}/api/v1/payload/fetch`,
    JSON.stringify({ session_token: token }),
    { headers: { 'Content-Type': 'application/json' }, tags: { route: 'fetch' } });

  check(r, { 'no 5xx': (x) => x.status < 500 }, { kind: 'no5xx' });
  // 200 OR 403 (no payload bound) are both valid end states — we only
  // care that the crypto+handlers stay healthy under load.
  check(r, {
    'ok or auth-shape': (x) => x.status === 200 || x.status === 403 || x.status === 401,
  });
}
