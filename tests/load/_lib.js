// Shared helpers for all Sec-blind k6 scenarios.
// Keeps HKDF + challenge_response in one place so scenarios stay short.

import http from 'k6/http';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';
import { check, fail } from 'k6';

export const BASE = __ENV.SB_BASE_URL || 'http://127.0.0.1:8080';
export const CERT_FILE = __ENV.CERT_FILE || 'cert.pem';

// Must mirror server/pkg/crypto/hkdf.go: HKDFSalt.
const HKDF_SALT_SUFFIX = 'SecBlind_HKDF_v1';

// License pool (seed in Postgres before running). CSV in env.
const RAW_LICS = (__ENV.SB_LICENSES || '').split(',').map(s => s.trim()).filter(Boolean);
export const LICENSES = RAW_LICS.length ? RAW_LICS : ['TEST-AAAA-0001'];

// --- helpers ---------------------------------------------------------------

// 64 lowercase hex chars (server rule: isValidHWID).
export function makeHWID(vu, seed) {
  const s = `vu-${vu}-${seed || __ITER || 0}-${Date.now()}`;
  const h = crypto.sha256(s, 'hex');
  return h; // 64 hex chars
}

export function pickLicense(vu) {
  return LICENSES[(vu - 1) % LICENSES.length];
}

// b64 of ArrayBuffer.
function b64(buf) {
  return encoding.b64encode(buf);
}

// Concatenate Uint8Arrays to a single ArrayBuffer.
function concat(...arrs) {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out.buffer;
}

function strBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

// HKDF-SHA256, output 32 bytes. Matches server's crypto.HKDF(ikm, salt, info=nil, 32).
// info is nil ⇒ single-block Expand: T(1) = HMAC(PRK, 0x01).
function hkdf32(ikmBytes, saltBytes) {
  // Extract: PRK = HMAC-SHA256(salt, IKM).
  const prk = crypto.hmac('sha256', saltBytes.buffer, ikmBytes.buffer, 'binary');
  // Expand T(1), info empty.
  const one = new Uint8Array([0x01]);
  const t1 = crypto.hmac('sha256', prk, one.buffer, 'binary');
  return t1; // 32 bytes ArrayBuffer
}

// Compute challenge_response = base64( HMAC256( HKDF(license, hwid||HKDF_SALT, nil, 32), nonce ) ).
export function challengeResponse(license, hwid, nonceB64) {
  const salt = concat(strBytes(hwid), strBytes(HKDF_SALT_SUFFIX));
  const derived = hkdf32(strBytes(license), new Uint8Array(salt));
  const nonce = encoding.b64decode(nonceB64, 'std'); // ArrayBuffer
  const mac = crypto.hmac('sha256', derived, nonce, 'binary');
  return b64(mac);
}

// HMAC256 → base64, used for heartbeat/RPC signatures.
export function hmacB64(keyBuf, dataBytes) {
  const mac = crypto.hmac('sha256', keyBuf, dataBytes.buffer, 'binary');
  return b64(mac);
}

// Derive sub-key from session_key via HKDF-Expand (info).
// Matches crypto.HKDFExpand(sessionKey, info, 32).
export function hkdfExpand32(sessionKeyB64, info) {
  const prk = encoding.b64decode(sessionKeyB64, 'std'); // ArrayBuffer
  const infoBytes = strBytes(info);
  const buf = concat(infoBytes, new Uint8Array([0x01]));
  return crypto.hmac('sha256', prk, buf, 'binary'); // 32 bytes
}

// --- API wrappers ----------------------------------------------------------

const jsonHeaders = { 'Content-Type': 'application/json' };

export function getChallenge(hwid) {
  const r = http.post(`${BASE}/api/v1/auth/challenge`,
    JSON.stringify({ hwid }), { headers: jsonHeaders, tags: { route: 'challenge' } });
  return r;
}

export function doLogin(license, hwid, challengeB64) {
  const body = {
    license_key: license,
    hwid,
    challenge: challengeB64,
    challenge_response: challengeResponse(license, hwid, challengeB64),
  };
  return http.post(`${BASE}/api/v1/auth/login`,
    JSON.stringify(body), { headers: jsonHeaders, tags: { route: 'login' } });
}

// Full challenge→login handshake. Returns parsed session or null.
export function loginOnce(vu) {
  const hwid = makeHWID(vu, 'login');
  const license = pickLicense(vu);
  const chR = getChallenge(hwid);
  if (chR.status !== 200) return null;
  const chJ = chR.json();
  if (!chJ || !chJ.challenge) return null;
  const lgR = doLogin(license, hwid, chJ.challenge);
  if (lgR.status !== 200) return null;
  const s = lgR.json();
  if (!s || !s.session_token || !s.session_key) return null;
  return { hwid, license, session: s };
}

export { check, fail };
