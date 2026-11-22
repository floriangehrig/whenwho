// npm run check (part 2): the page's CSP allows its inline <script> blocks by hash, not with 'unsafe-inline'.
// Editing a script in public/index.html changes its hash, so this recomputes them and fails when the script-src in
// src/worker.js (CSP) or public/_headers is out of date. `node scripts/check-csp.mjs --fix` rewrites both.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const root = new URL('..', import.meta.url).pathname;
const html = readFileSync(root + 'public/index.html', 'utf8');
const hashes = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]
  .map((m) => `'sha256-${createHash('sha256').update(m[1], 'utf8').digest('base64')}'`);
if (/<script(?![^>]*\bsrc=)[^>]+>/.test(html)) console.warn('warning: a <script ...> with attributes but no src: hash it here too');
const want = `script-src 'self' ${hashes.join(' ')} https://challenges.cloudflare.com`;

const fix = process.argv.includes('--fix'), errors = [];
for (const f of ['src/worker.js', 'public/_headers']) {
  const text = readFileSync(root + f, 'utf8');
  const re = /script-src [^;"\n]*/g;
  const found = text.match(re) || [];
  if (found.length !== 1) { errors.push(`${f}: expected one script-src, found ${found.length}`); continue; }
  if (found[0] === want) continue;
  if (fix) { writeFileSync(root + f, text.replace(re, want)); console.log(`updated ${f}`); }
  else errors.push(`${f}: script-src is out of date with the inline scripts in public/index.html. Run: node scripts/check-csp.mjs --fix`);
}
if (errors.length) { for (const e of errors) console.error('error: ' + e); process.exit(1); }
console.log(`CSP ok (${hashes.length} inline scripts hashed)`);
