// npm run check: makes sure "Download my data" and "Delete account" keep covering every table.
// Fails when a table from migrations/ is missing from USER_DATA in src/worker.js, or when a migration is newer than
// USER_DATA_REVIEWED (look at its tables / columns, update USER_DATA, then bump the marker).
// Warns when the privacy policy (PRIVACY_UPDATED in public/index.html) is older than the newest migration.
import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const root = new URL('..', import.meta.url).pathname;
const read = (f) => readFileSync(root + f, 'utf8');
const errors = [], warnings = [];

const migrations = readdirSync(root + 'migrations').filter((f) => /^\d{4}_.*\.sql$/.test(f)).sort();
const tables = new Set();
for (const f of migrations) {
  for (const m of read('migrations/' + f).matchAll(/CREATE TABLE(?: IF NOT EXISTS)?\s+([a-z_]+)/gi)) tables.add(m[1]);
}

const worker = read('src/worker.js');
const block = worker.match(/const USER_DATA = \{\n([\s\S]*?)\n\};/);
if (!block) errors.push('USER_DATA not found in src/worker.js');
const covered = new Set(block ? [...block[1].matchAll(/^  ([a-z_]+): \{/gm)].map((m) => m[1]) : []);
for (const t of tables) if (!covered.has(t)) errors.push(`Table "${t}" is not in USER_DATA (src/worker.js): add how it is exported and deleted, or skip it with a reason.`);
for (const t of covered) if (!tables.has(t)) errors.push(`USER_DATA lists "${t}", but no migration creates that table.`);

const reviewed = (worker.match(/USER_DATA_REVIEWED = '(\d{4})'/) || [])[1];
const newest = migrations.at(-1);
if (!reviewed) errors.push('USER_DATA_REVIEWED not found in src/worker.js');
else if (newest && newest.slice(0, 4) > reviewed)
  errors.push(`Migration ${newest} is newer than USER_DATA_REVIEWED ('${reviewed}'). Check its tables and columns for personal data, cover them in USER_DATA (export + delete) and the privacy policy, then set USER_DATA_REVIEWED = '${newest.slice(0, 4)}'.`);

const page = read('public/index.html');
const updated = (page.match(/const PRIVACY_UPDATED='(\d{4}-\d{2}-\d{2})'/) || [])[1];
let migDate = '';
try { migDate = execFileSync('git', ['log', '-1', '--format=%cs', '--', 'migrations/' + newest], { cwd: root, encoding: 'utf8' }).trim(); } catch {}
if (!migDate) migDate = new Date().toISOString().slice(0, 10); // not committed yet
if (updated && updated < migDate)
  warnings.push(`The privacy policy (PRIVACY_UPDATED ${updated}) is older than migration ${newest} (${migDate}). If it stores new personal data, describe it in renderPrivacy() and bump PRIVACY_UPDATED.`);

for (const w of warnings) console.warn('warning: ' + w);
for (const e of errors) console.error('error: ' + e);
if (errors.length) process.exit(1);
console.log(`ok: ${tables.size} tables covered by USER_DATA, reviewed up to ${reviewed}.`);
