// Smoke: /api/v1/auth/challenge only.
import { check } from 'k6';
import { getChallenge, makeHWID } from './_lib.js';

export const options = {
  vus: 10,
  duration: '1m',
  thresholds: {
    'http_req_duration{route:challenge}': ['p(95)<100'],
    'http_req_failed{route:challenge}':   ['rate<0.01'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(95)', 'p(99)'],
};

export default function () {
  const hwid = makeHWID(__VU);
  const r = getChallenge(hwid);
  check(r, {
    'status 200': (x) => x.status === 200,
    'has nonce':  (x) => {
      try { return !!x.json().challenge; } catch (_) { return false; }
    },
  });
}
