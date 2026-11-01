// Sends Web Push notifications (RFC 8291 encryption + RFC 8292 VAPID).
// Called only by the Supabase database trigger, which sends the shared secret,
// the VAPID key and the admin push subscriptions in the request body.
// Nothing secret is stored here: the secret is checked against its SHA-256 hash.

const SECRET_SHA256 = '7e00aeab80fb471c685260e31b1f6e3dfa54338a9dfb4909ac90d8a2053eb8f5';

const enc = new TextEncoder();
const b64uToBytes = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const bytesToB64u = (b) => {
  let s = '';
  new Uint8Array(b).forEach((x) => { s += String.fromCharCode(x); });
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}
async function sha256Hex(text) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text)));
  return [...d].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export async function vapidHeader(endpoint, jwk, pub, subject) {
  const aud = new URL(endpoint).origin;
  const header = bytesToB64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = bytesToB64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject })));
  const key = await crypto.subtle.importKey('jwk', { ...jwk, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(`${header}.${claims}`));
  return `vapid t=${header}.${claims}.${bytesToB64u(sig)}, k=${pub}`;
}

export async function encryptPayload(p256dh, authSecret, payloadText) {
  const uaPublic = b64uToBytes(p256dh);
  const auth = b64uToBytes(authSecret);
  const local = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', local.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, local.privateKey, 256));
  const prkKey = await hmac(auth, ecdh);
  const ikm = await hmac(prkKey, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic, new Uint8Array([1])));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, concat(enc.encode('Content-Encoding: aes128gcm\0'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, concat(enc.encode('Content-Encoding: nonce\0'), new Uint8Array([1])))).slice(0, 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const plain = concat(enc.encode(payloadText), new Uint8Array([2]));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, plain));
  const rs = new Uint8Array([0, 0, 16, 0]); // 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}

export async function onRequestPost({ request }) {
  let body;
  try { body = await request.json(); } catch (e) { return new Response('bad json', { status: 400 }); }
  if (!body || typeof body.secret !== 'string' || (await sha256Hex(body.secret)) !== SECRET_SHA256) {
    return new Response('forbidden', { status: 403 });
  }
  const { vapid, subject, message, subs } = body;
  const payload = JSON.stringify(message || {});
  const results = [];
  for (const s of subs || []) {
    try {
      const data = await encryptPayload(s.p256dh, s.auth, payload);
      const r = await fetch(s.endpoint, {
        method: 'POST',
        headers: {
          Authorization: await vapidHeader(s.endpoint, vapid.jwk, vapid.pub, subject || 'mailto:beaireadyco@gmail.com'),
          'Content-Encoding': 'aes128gcm',
          'Content-Type': 'application/octet-stream',
          TTL: '86400',
          Urgency: 'high',
        },
        body: data,
      });
      results.push({ endpoint: s.endpoint.slice(0, 40), status: r.status });
    } catch (e) {
      results.push({ endpoint: String(s.endpoint).slice(0, 40), error: String(e) });
    }
  }
  return new Response(JSON.stringify({ sent: results }), { headers: { 'Content-Type': 'application/json' } });
}

export function onRequestGet() {
  return new Response('ok');
}
