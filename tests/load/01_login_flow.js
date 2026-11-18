// Full challenge→login handshake under load.
// Each VU: new HWID per iteration (avoid HWID-binding collisions).
// Requires SB_LICENSES with enough keys; VUs cycle through them.
import { check } from 'k6';
import { Rate } from 'k6/metrics';
import { getChallenge, doLogin, makeHWID, pickLicense } from './_lib.js';

export const loginSuccess = new Rate('login_success_rate');

export const options = {
  scenarios: {
    login: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 50 }, // ramp
        { duration: '5m', target: 50 }, // steady
      ],
      gracefulRampDown: '15s',
    },
  },
  thresholds: {
    'http_req_duration{route:login}': ['p(95)<300'],
    'login_success_rate':             ['rate>0.99'],
  },
};

export default function () {
  const hwid = makeHWID(__VU, __ITER);
  const license = pickLicense(__VU);
  const ch = getChallenge(hwid);
  const okCh = check(ch, { 'challenge 200': (r) => r.status === 200 });
  if (!okCh) { loginSuccess.add(false); return; }
  const challenge = ch.json().challenge;
  const lg = doLogin(license, hwid, challenge);
  const okLg = check(lg, {
    'login 200':      (r) => r.status === 200,
    'has session':    (r) => { try { return !!r.json().session_token; } catch (_) { return false; } },
    'has nextNonce':  (r) => { try { return !!r.json().next_nonce; } catch (_) { return false; } },
  });
  loginSuccess.add(okLg);
}
