// Deliberately exceeds configured per-IP / per-HWID rate limits.
// Validates 429 path + Retry-After header. No 5xx tolerated.
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { getChallenge, makeHWID } from './_lib.js';

const rate429 = new Counter('rate_limited_total');
const noRetryAfter = new Counter('missing_retry_after_total');

export const options = {
  scenarios: {
    flood: {
      executor: 'constant-arrival-rate',
      rate: 300,            // 300 req/s — should blow past per_ip_rpm:30
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 30,
      maxVUs: 60,
    },
  },
  thresholds: {
    'rate_limited_total':             ['count>100'],
    'http_req_failed{route:challenge}': ['rate<1.0'], // meaningless cap, shape only
    // zero 5xx is the real SLO:
    'checks{kind:no5xx}':             ['rate>0.999'],
    'missing_retry_after_total':      ['count<1'],
  },
};

export default function () {
  // Fixed HWID per VU so per-HWID bucket is also stressed.
  const hwid = makeHWID(__VU, 'flood');
  const r = getChallenge(hwid);

  check(r, { 'no 5xx': (x) => x.status < 500 }, { kind: 'no5xx' });

  if (r.status === 429) {
    rate429.add(1);
    const ra = r.headers['Retry-After'];
    // body also carries retry_after per server impl; header is best practice.
    if (!ra) {
      // server currently returns JSON {retry_after} but no Retry-After header;
      // count it so the metric surfaces the gap for reviewers.
      noRetryAfter.add(1);
    }
  }
}
