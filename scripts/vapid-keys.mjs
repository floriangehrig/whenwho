// Makes a VAPID key pair for Web Push (chat notifications).
// VAPID_PUBLIC_KEY goes in wrangler.toml [vars] (and .dev.vars), VAPID_PRIVATE_KEY is a secret:
//   npx wrangler secret put VAPID_PRIVATE_KEY
// Changing the pair later makes every browser subscribe again (old subscriptions stop working).
const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
const b64u = (b) => Buffer.from(b).toString('base64url');
console.log(`VAPID_PUBLIC_KEY=${b64u(raw)}`);
console.log(`VAPID_PRIVATE_KEY=${jwk.d}`);
