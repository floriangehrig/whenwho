// whenwho: Cloudflare Worker + D1 (+ optional email via Resend)
//
// Bindings / variables:
//   DB        (required) D1 database
//   ASSETS    (optional) static assets binding serving /public; the single-file build inlines the page instead
//   RESEND_API_KEY (optional secret) Resend API key (sending access). With MAIL_FROM, turns on server-sent emails
//   MAIL_FROM (optional) sender address on a domain verified in Resend, e.g. noreply@example.com
//   MAIL_PER_DAY (optional) recipients of invites / test emails per account (or per poll without one) per day, default 50
//   SITE_URL  (optional) public address of the site, e.g. https://polls.example.workers.dev (used in emails sent by the cron job)
//   TURNSTILE_SITE_KEY (optional var) + TURNSTILE_SECRET (secret): bot check before a sign-in code is emailed.
//
// Accounts: anyone can sign in with a 6-digit code sent to their email (needs RESEND_API_KEY + MAIL_FROM).
// Only signed-in users can create polls, and only the account that owns a poll can manage it.
// Without RESEND_API_KEY + MAIL_FROM, codes are written to the log (local development only).
// Answers given while signed in belong to the account (its email), so names don't have to be unique for them.

const MAX_RANGE_DAYS = 92;
const MAX_RESPONSES = 300;
const MAX_MEETINGS = 100;
const ID_RE = /^[A-Za-z0-9]{6,20}$/;
const MAX_PARTICIPANTS = 500;
const SESSION_DAYS = 30;
const MAX_FAILS = 10;          // failed logins / name lookups per IP ...
const FAIL_WINDOW_MIN = 15;    // ... within this many minutes
const CODE_MINUTES = 10;       // a sign-in code is valid this long
const CODE_TRIES = 5;          // wrong guesses before a code is thrown away
const CODE_SENDS_IP = 5;       // sign-in emails per IP ...
const CODE_SENDS_EMAIL = 3;    // ... and per address, within FAIL_WINDOW_MIN
const MAX_POLLS_PER_USER = 100;
const MAIL_PER_DAY = 50;       // default for env.MAIL_PER_DAY (Resend's free plan allows 100 emails a day in total)

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) return secure(await servePage(request, env), url);
    try {
      return secure(await route(request, env, ctx, url), url);
    } catch (e) {
      if (e instanceof HttpError) return secure(json({ error: e.message, ...e.extra }, e.status), url);
      console.error(e);
      return secure(json({ error: 'Something went wrong on the server.' }, 500), url);
    }
  },
  // Cron trigger (optional): opens new polls in series on time and sends notification / reminder emails.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runScheduled(env));
  },
};

function servePage(request, env) {
  if (typeof INDEX_HTML !== 'undefined') return new Response(INDEX_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });
  return env.ASSETS.fetch(request);
}

// Security headers on every response. Poll and admin keys travel in URLs, so never leak them as a Referer.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  'frame-src https://challenges.cloudflare.com',
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join('; ');
function secure(res, url) {
  const r = new Response(res.body, res);
  const h = r.headers;
  h.set('x-content-type-options', 'nosniff');
  h.set('referrer-policy', 'same-origin');
  h.set('x-frame-options', 'DENY');
  h.set('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  if ((h.get('content-type') || '').startsWith('text/html')) h.set('content-security-policy', CSP);
  if (url.protocol === 'https:') h.set('strict-transport-security', 'max-age=31536000');
  return r;
}

class HttpError extends Error {
  constructor(status, message, extra = {}) { super(message); this.status = status; this.extra = extra; }
}
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });

async function route(request, env, ctx, url) {
  const parts = url.pathname.split('/').filter(Boolean); // ['api','polls',id,...]
  const m = request.method;
  const cookies = parseCookies(request);
  // A request that carries the session cookie and changes something must come from this site (CSRF guard).
  // Sign-in requests too, so another site can't sign a visitor into an attacker's account.
  if ((cookies.ww_session || parts[1] === 'auth') && m !== 'GET' && m !== 'HEAD' && request.headers.get('origin') !== url.origin)
    throw new HttpError(403, 'Request from another site was blocked');
  USERS.set(request, await getUser(env, cookies));
  if (parts[1] === 'config' && m === 'GET') return json({ emailEnabled: emailEnabled(env), turnstileSiteKey: env.TURNSTILE_SECRET ? env.TURNSTILE_SITE_KEY || '' : '' });
  if (parts[1] === 'auth') {
    if (parts[2] === 'code' && m === 'POST') return sendLoginCode(request, env, url);
    if (parts[2] === 'verify' && m === 'POST') return verifyLoginCode(request, env, url);
    if (parts[2] === 'logout' && m === 'POST') return logout(request, env, cookies, url);
    throw new HttpError(404, 'Not found');
  }
  if (parts[1] === 'me') {
    if (!parts[2] && m === 'GET') return me(request, env);
    if (!parts[2] && m === 'PATCH') return updateProfile(request, env);
    if (parts[2] === 'polls' && m === 'GET') return myPolls(request, env);
    throw new HttpError(404, 'Not found');
  }
  if (parts[1] !== 'polls') throw new HttpError(404, 'Not found');
  const id = parts[2];
  if (!id) {
    if (m === 'POST') return createPoll(request, env);
    throw new HttpError(405, 'Method not allowed');
  }
  if (!ID_RE.test(id)) throw new HttpError(404, 'Poll not found');
  const [, , , a, b, c, d, e] = parts;
  if (!a) {
    if (m === 'GET') return getPoll(request, env, ctx, url, id);
    if (m === 'PATCH') return updatePoll(request, env, id);
    if (m === 'DELETE') return deletePoll(request, env, id);
  }
  if (a === 'calendar.ics' && m === 'GET') return calendar(env, url, id);
  if (a === 'image' && m === 'GET') return pollImage(request, env, url, id);
  if (a === 'test-email' && m === 'POST') return testEmail(request, env, url, id);
  if (a === 'claim' && m === 'POST') return claimPoll(request, env, id);
  if (a === 'participants') {
    if (!b && m === 'GET') return listParticipants(request, env, id);
    if (!b && m === 'POST') return addParticipants(request, env, id);
    if (b && !c && m === 'PATCH') return updateParticipant(request, env, id, b);
    if (b && !c && m === 'DELETE') return deleteParticipant(request, env, url, id, b);
    if (b && c === 'merge' && m === 'POST') return mergeParticipant(request, env, id, b);
  }
  if (a === 'instances') {
    if (!b && m === 'POST') return createNextInstance(request, env, ctx, url, id);
    if (b && !c && m === 'PATCH') return updateInstance(request, env, id, b);
    if (b && !c && m === 'DELETE') return deleteInstance(request, env, id, b);
    if (b && c === 'responses' && !d && m === 'POST') return createResponse(request, env, id, b);
    if (b && c === 'recall' && !d && m === 'POST') return recall(request, env, id, b);
    if (b && c === 'meetings' && d && e === 'send' && m === 'POST') return sendInvite(request, env, url, id, b, d);
  }
  if (a === 'responses' && b) {
    if (m === 'GET') return getOwnResponse(request, env, id, b);
    if (m === 'PUT') return updateResponse(request, env, id, b);
    if (m === 'DELETE') return deleteResponse(request, env, id, b);
  }
  throw new HttpError(404, 'Not found');
}

// ---------- helpers ----------
const now = () => new Date().toISOString();
const today = () => new Date().toISOString().slice(0, 10);
const pad = (n) => String(n).padStart(2, '0');
const enc = new TextEncoder();
async function sha256(s) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(s));
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
}
function randomId(len = 10) {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  return [...crypto.getRandomValues(new Uint8Array(len))].map((x) => abc[x % abc.length]).join('');
}
function secret() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function safeEqual(x, y) {
  if (typeof x !== 'string' || typeof y !== 'string' || x.length !== y.length) return false;
  let r = 0;
  for (let i = 0; i < x.length; i++) r |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return r === 0;
}
async function body(request) {
  const text = await request.text();
  if (text.length > 200_000) throw new HttpError(413, 'Request too large');
  try { return text ? JSON.parse(text) : {}; } catch { throw new HttpError(400, 'Invalid JSON'); }
}
const str = (v, max, field, required = false) => {
  if (v == null || v === '') { if (required) throw new HttpError(400, `${field} is required`); return ''; }
  if (typeof v !== 'string') throw new HttpError(400, `${field} must be text`);
  const t = v.trim();
  if (required && !t) throw new HttpError(400, `${field} is required`);
  if (t.length > max) throw new HttpError(400, `${field} is too long (max ${max} characters)`);
  return t;
};
const EMAIL_RE = /^[^\s@,;<>"]+@[^\s@,;<>"]+\.[^\s@,;<>"]+$/;
const email = (v, field = 'Email') => {
  const e = str(v, 200, field);
  if (e && !EMAIL_RE.test(e)) throw new HttpError(400, `${field}: that address doesn’t look right`);
  return e;
};
// Names of people: no control characters (account answers use one as a marker in name_key).
const personName = (v) => {
  const n = str(v, 60, 'Name', true).replace(/\s+/g, ' ');
  if (/[\u0000-\u001f\u007f]/.test(n)) throw new HttpError(400, 'Name contains characters that aren’t allowed');
  return n;
};
// Icons and avatars are a single emoji (or empty). Pictures are small data URLs resized in the browser.
const EMOJI_RE = /^[\p{Extended_Pictographic}\p{Emoji_Component}\u200d\ufe0f\u20e3]{1,16}$/u;
const emojiIcon = (v, field) => {
  if (v == null || v === '') return '';
  if (typeof v !== 'string' || !EMOJI_RE.test(v) || !/[\p{Extended_Pictographic}\p{Regional_Indicator}]/u.test(v)) throw new HttpError(400, `${field}: pick an emoji`);
  return v;
};
const IMG_MAX = 150_000; // characters of the data URL (about 110 KB of picture)
const IMG_RE = /^data:image\/(webp|jpeg|png);base64,[A-Za-z0-9+/]+=*$/;
const imageData = (v, field) => {
  if (v == null || v === '') return null;
  if (typeof v !== 'string' || v.length > IMG_MAX || !IMG_RE.test(v)) throw new HttpError(400, `${field}: use a JPEG, PNG or WebP picture of up to 100 KB`);
  return v;
};
const isDate = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s + 'T00:00:00Z'));
const int = (v, lo, hi, field) => {
  const n = Number(v);
  if (!Number.isInteger(n) || n < lo || n > hi) throw new HttpError(400, `${field} must be a whole number from ${lo} to ${hi}`);
  return n;
};
const optInt = (v, lo, hi, field) => (v === null || v === '' || v === undefined ? null : int(v, lo, hi, field));
function addDays(d, n) { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); }
function addMonths(d, n) { const [y, m] = d.split('-').map(Number); const x = new Date(Date.UTC(y, m - 1 + n, 1)); return x.toISOString().slice(0, 10); }
function daysBetween(x, y) { return Math.round((Date.parse(y + 'T00:00:00Z') - Date.parse(x + 'T00:00:00Z')) / 86400000); }
function checkRange(s, e) {
  if (!isDate(s) || !isDate(e)) throw new HttpError(400, 'Pick a start and end date');
  if (e < s) throw new HttpError(400, 'The end date is before the start date');
  if (daysBetween(s, e) + 1 > MAX_RANGE_DAYS) throw new HttpError(400, `A poll can cover at most ${MAX_RANGE_DAYS} days`);
}
function datesOf(inst) { const out = []; for (let d = inst.start_date; d <= inst.end_date; d = addDays(d, 1)) out.push(d); return out; }
const effStatus = (inst) => (inst.status === 'closed' || inst.end_date < today() ? 'closed' : 'open');

// ---------- series periods ----------
function periodStart(poll, n) { return poll.unit === 'month' ? addMonths(poll.anchor, n * poll.every) : addDays(poll.anchor, n * 7 * poll.every); }
function periodEnd(poll, n) { return addDays(periodStart(poll, n + 1), -1); }
function openDate(poll, n) { return addDays(periodStart(poll, n), -poll.open_days); }
function periodDeadline(poll, n) { return poll.deadline_days == null ? null : addDays(periodStart(poll, n), -poll.deadline_days); }
function currentSeq(poll) {
  const t = today(); let n = 0;
  while (n < 5000 && openDate(poll, n + 1) <= t) n++;
  return n;
}
async function insertInstance(env, poll, seq, fields, notified) {
  const inst = { id: randomId(10), poll_id: poll.id, seq, status: 'open', note: '', meetings: '[]', opened_notified: notified ? 1 : 0, reminded: 0, created_at: now(), ...fields };
  const cols = Object.keys(inst);
  const r = await env.DB.prepare(`INSERT OR IGNORE INTO instances (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).bind(...cols.map((c) => inst[c])).run();
  return r.meta && r.meta.changes ? inst : null;
}
const seriesFields = (poll, n) => ({ start_date: periodStart(poll, n), end_date: periodEnd(poll, n), deadline: periodDeadline(poll, n) });
// Make sure the instance for the current period of a series exists. Returns the new instance if one was created.
async function ensureCurrent(env, poll) {
  if (poll.kind !== 'series') return null;
  const n = currentSeq(poll);
  const exists = await env.DB.prepare('SELECT id FROM instances WHERE poll_id = ? AND seq = ?').bind(poll.id, n).first();
  if (exists) return null;
  return insertInstance(env, poll, n, seriesFields(poll, n), false);
}

async function loadPoll(env, id) {
  const poll = await env.DB.prepare('SELECT * FROM polls WHERE id = ?').bind(id).first();
  if (!poll) throw new HttpError(404, 'Poll not found');
  return poll;
}
async function loadInstance(env, pollId, iid) {
  if (!ID_RE.test(iid)) throw new HttpError(404, 'Poll not found');
  const inst = await env.DB.prepare('SELECT * FROM instances WHERE id = ? AND poll_id = ?').bind(iid, pollId).first();
  if (!inst) throw new HttpError(404, 'This poll no longer exists');
  return inst;
}
// Old polls may still have an admin key. It is only used to move such a poll into an account (claimPoll).
async function adminKeyOk(request, poll) {
  const key = request.headers.get('x-admin-key');
  return !!key && safeEqual(await sha256('admin:' + key), poll.admin_hash);
}
// Admin of a poll: the signed-in account that owns it.
function isAdmin(request, poll) {
  const user = userOf(request);
  return !!user && !!poll.owner_id && poll.owner_id === user.id;
}
function requireAdmin(request, poll) {
  if (!isAdmin(request, poll)) throw new HttpError(403, 'Only the poll’s owner can do this. Sign in with the account that created it.');
}
async function passwordOk(poll, pw) {
  return !poll.password_hash || (!!pw && safeEqual(await sha256(poll.id + ':pw:' + pw), poll.password_hash));
}
async function checkPassword(request, poll) {
  const pw = request.headers.get('x-poll-password');
  if (!(await passwordOk(poll, pw)))
    throw new HttpError(401, pw ? 'Wrong password' : 'Password required', { needPassword: true, title: poll.title });
}
function publicPoll(poll, admin) {
  const p = {
    id: poll.id, title: poll.title, description: poll.description, kind: poll.kind,
    unit: poll.unit, every: poll.every, anchor: poll.anchor, openDays: poll.open_days, deadlineDays: poll.deadline_days,
    answerMode: poll.answer_mode, hourStart: poll.hour_start, hourEnd: poll.hour_end,
    hideResults: !!poll.hide_results, allowComments: !!poll.allow_comments, hasPassword: !!poll.password_hash,
    icon: poll.icon || '', image: poll.image ? poll.image_at || '1' : '', // image: version for /image?v=
  };
  if (admin) Object.assign(p, { adminEmail: poll.admin_email, notifyOpen: !!poll.notify_open, remindDays: poll.remind_days });
  return p;
}
function publicInstance(inst, extra = {}) {
  return { id: inst.id, seq: inst.seq, startDate: inst.start_date, endDate: inst.end_date, deadline: inst.deadline,
    status: effStatus(inst), manualStatus: inst.status, note: inst.note, meetings: JSON.parse(inst.meetings || '[]'), ...extra };
}

function validateEntries(entries, poll, dates) {
  if (entries == null) return {};
  if (typeof entries !== 'object' || Array.isArray(entries)) throw new HttpError(400, 'Invalid answers');
  const allowed = new Set(dates), out = {};
  const hourOk = (h) => Number.isInteger(h) && h >= poll.hour_start && h < poll.hour_end;
  for (const [k, v] of Object.entries(entries)) {
    if (!allowed.has(k)) continue;
    if (v === 'y' || v === 'm' || v === 'n') { out[k] = v; continue; }
    if (poll.answer_mode === 'days') throw new HttpError(400, 'This poll only takes whole days');
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const seen = new Set(), pick = (arr) => (Array.isArray(arr) ? arr : []).filter((h) => hourOk(h) && !seen.has(h) && seen.add(h)).sort((x, y) => x - y);
      const y = pick(v.y), m = pick(v.m), n = pick(v.n);
      if (y.length || m.length || n.length) out[k] = { y, m, n };
      continue;
    }
    throw new HttpError(400, 'Invalid answer for ' + k);
  }
  return out;
}

function validateMeetings(list) {
  if (!Array.isArray(list) || list.length > MAX_MEETINGS) throw new HttpError(400, 'Invalid meetings');
  return list.map((mt) => {
    if (!mt || typeof mt !== 'object') throw new HttpError(400, 'Invalid meeting');
    if (!isDate(mt.date)) throw new HttpError(400, 'Meeting needs a date');
    const out = {
      id: /^[A-Za-z0-9]{4,20}$/.test(mt.id || '') ? mt.id : randomId(8),
      date: mt.date, allDay: !!mt.allDay,
      title: str(mt.title, 120, 'Meeting title'), location: str(mt.location, 200, 'Location'), note: str(mt.note, 1000, 'Note'),
      sentAt: typeof mt.sentAt === 'string' && mt.sentAt.length < 40 ? mt.sentAt : undefined,
    };
    if (!out.allDay) {
      out.start = int(mt.start, 0, 23, 'Start hour');
      out.end = int(mt.end, 1, 24, 'End hour');
      if (out.end <= out.start) throw new HttpError(400, 'A meeting must end after it starts');
    }
    if (mt.participants === 'all' || mt.participants == null) out.participants = 'all';
    else if (Array.isArray(mt.participants) && mt.participants.length <= MAX_RESPONSES) {
      out.participants = mt.participants.map((p) => ({ id: ID_RE.test(p?.id || '') ? p.id : '', name: str(p?.name, 60, 'Participant name', true) }));
    } else throw new HttpError(400, 'Invalid participants');
    return out;
  }).sort((x, y) => (x.date + pad(x.start ?? 0)).localeCompare(y.date + pad(y.start ?? 0)));
}

// ---------- accounts and sessions ----------
const USERS = new WeakMap(); // request -> signed-in user (or null), set once per request in route()
const userOf = (request) => USERS.get(request) || null;
function parseCookies(request) {
  const out = {};
  for (const part of (request.headers.get('cookie') || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function sessionCookie(url, token, maxAge) {
  return `ww_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${url.protocol === 'https:' ? '; Secure' : ''}`;
}
async function getUser(env, cookies) {
  const token = cookies.ww_session;
  if (!token || token.length > 100) return null;
  const s = await env.DB.prepare(
    `SELECT u.id, u.email, u.name, u.avatar, u.created_at, u.avatar_img IS NOT NULL AS has_img
     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?`)
    .bind(await sha256('session:' + token), now()).first();
  return s ? { id: s.id, email: s.email, name: s.name || '', avatar: s.avatar || '', hasImg: !!s.has_img, created: s.created_at } : null;
}
const clientIp = (request) => request.headers.get('cf-connecting-ip') || 'local';
// login_attempts doubles as a rate-limit log; `key` is an IP or 'e:' + hash of an email address.
async function checkThrottle(env, request, kind, { key = clientIp(request), max = MAX_FAILS, msg } = {}) {
  const since = new Date(Date.now() - FAIL_WINDOW_MIN * 60000).toISOString();
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND kind = ? AND at > ?').bind(key, kind, since).first('n');
  if (n >= max) throw new HttpError(429, msg || `Too many failed attempts. Try again in ${FAIL_WINDOW_MIN} minutes.`);
}
const recordFail = (env, request, kind, key = clientIp(request)) =>
  env.DB.prepare('INSERT INTO login_attempts (ip, kind, at) VALUES (?, ?, ?)').bind(key, kind, now()).run();

async function startSession(env, url, userId) {
  const token = secret();
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)').bind(await sha256('session:' + token), userId, expires, now()).run();
  return sessionCookie(url, token, SESSION_DAYS * 86400);
}

// ---------- sign-in by email code ----------
async function verifyTurnstile(env, request, token) {
  if (!env.TURNSTILE_SECRET) return; // not configured (local development)
  if (typeof token !== 'string' || !token || token.length > 4000) throw new HttpError(400, 'Please complete the “I’m human” check');
  const form = new FormData();
  form.append('secret', env.TURNSTILE_SECRET);
  form.append('response', token);
  form.append('remoteip', clientIp(request));
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const out = await r.json().catch(() => ({}));
  if (!out.success) throw new HttpError(400, 'The “I’m human” check failed. Please try again.');
}
const codeHash = (mail, code) => sha256(`code:${mail}:${code}`);

async function sendLoginCode(request, env, url) {
  const b = await body(request);
  const mail = email(b.email);
  if (!mail) throw new HttpError(400, 'Enter your email address');
  const addr = mail.toLowerCase();
  const tooMany = `Too many sign-in emails. Try again in ${FAIL_WINDOW_MIN} minutes.`;
  await checkThrottle(env, request, 'code-send', { max: CODE_SENDS_IP, msg: tooMany });
  const ekey = 'e:' + (await sha256('mail:' + addr));
  await checkThrottle(env, request, 'code-send', { key: ekey, max: CODE_SENDS_EMAIL, msg: tooMany });
  await verifyTurnstile(env, request, b.turnstileToken);
  await recordFail(env, request, 'code-send');
  await recordFail(env, request, 'code-send', ekey);

  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  const code = String(n).padStart(6, '0');
  const expires = new Date(Date.now() + CODE_MINUTES * 60000).toISOString();
  await env.DB.prepare('INSERT OR REPLACE INTO login_codes (email, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, 0, ?)')
    .bind(addr, await codeHash(addr, code), expires, now()).run();

  const site = siteUrl(env, url.origin);
  const text = `Your whenwho sign-in code is:\n\n    ${code}\n\nIt is valid for ${CODE_MINUTES} minutes. Enter it on ${site} to sign in.\n\nIf you didn't ask for this, you can ignore this email: nobody can sign in without the code.`;
  if (emailEnabled(env)) {
    await sendEmail(env, {
      fromName: 'whenwho', to: [addr],
      subject: `Your sign-in code: ${code}`, text,
      html: emailHtml(`<h1 style="margin:0 0 8px;font-size:22px;line-height:1.3;color:#0B1F3A">Your sign-in code</h1>
        <p style="margin:0 0 20px;color:#334155">Enter this code on <a href="${escHtml(site)}" style="color:#1F5EFF">${escHtml(site.replace(/^https?:\/\//, ''))}</a> to sign in. It is valid for ${CODE_MINUTES} minutes.</p>
        <div style="margin:0 0 24px;padding:18px;background:#E8EFFF;border-radius:10px;text-align:center;font-size:32px;font-weight:700;letter-spacing:10px;color:#0B1F3A;font-family:ui-monospace,Menlo,Consolas,monospace">${code}</div>
        <p style="margin:0;font-size:13px;color:#5B6578">If you didn't ask for this, you can ignore this email: nobody can sign in without the code.</p>`,
        { preheader: `Your sign-in code is ${code}`, site }),
    });
  } else {
    console.log(`[dev] sign-in code for ${addr}: ${code}`); // email not set up: local development
  }
  // Same answer whether or not the address has an account.
  return json({ ok: true, minutes: CODE_MINUTES });
}

async function verifyLoginCode(request, env, url) {
  await checkThrottle(env, request, 'code');
  const b = await body(request);
  const addr = (email(b.email) || '').toLowerCase();
  const code = typeof b.code === 'string' ? b.code.replace(/\s+/g, '') : '';
  const wrong = new HttpError(401, 'That code is wrong or has expired. Check the latest email or ask for a new code.');
  if (!addr || !/^\d{6}$/.test(code)) throw new HttpError(400, 'Enter the 6-digit code from the email');
  const row = await env.DB.prepare('SELECT * FROM login_codes WHERE email = ?').bind(addr).first();
  if (!row || row.expires_at < now() || row.attempts >= CODE_TRIES) {
    if (row) await env.DB.prepare('DELETE FROM login_codes WHERE email = ?').bind(addr).run();
    await recordFail(env, request, 'code');
    throw wrong;
  }
  if (!safeEqual(await codeHash(addr, code), row.code_hash)) {
    await env.DB.prepare('UPDATE login_codes SET attempts = attempts + 1 WHERE email = ?').bind(addr).run();
    await recordFail(env, request, 'code');
    throw wrong;
  }
  // One-time: only the request that deletes the row may sign in.
  const del = await env.DB.prepare('DELETE FROM login_codes WHERE email = ? AND code_hash = ?').bind(addr, row.code_hash).run();
  if (!del.meta || !del.meta.changes) throw wrong;
  const t = now();
  await env.DB.prepare('INSERT INTO users (id, email, created_at, last_login_at) VALUES (?, ?, ?, ?) ON CONFLICT(email) DO UPDATE SET last_login_at = excluded.last_login_at')
    .bind('u_' + randomId(16), addr, t, t).run();
  const user = await env.DB.prepare('SELECT id, email FROM users WHERE email = ?').bind(addr).first();
  return json({ user: { email: user.email } }, 200, { 'set-cookie': await startSession(env, url, user.id) });
}
// { everywhere: true } ends all sessions of this account (e.g. after using a shared computer).
async function logout(request, env, cookies, url) {
  const b = await body(request);
  const user = userOf(request);
  if (b.everywhere && user) await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
  else if (cookies.ww_session) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256('session:' + cookies.ww_session)).run();
  return json({ ok: true }, 200, { 'set-cookie': sessionCookie(url, '', 0) });
}
function requireUser(request) {
  const user = userOf(request);
  if (!user) throw new HttpError(401, 'Please sign in first');
  return user;
}
// ---------- profile ----------
async function me(request, env) {
  const u = userOf(request);
  if (!u) return json({ user: null });
  const img = u.hasImg ? await env.DB.prepare('SELECT avatar_img FROM users WHERE id = ?').bind(u.id).first('avatar_img') : '';
  return json({ user: { name: u.name, email: u.email, avatar: u.avatar, avatarImg: img || '', since: u.created } });
}
// Body: { name?, avatar? (emoji or ''), avatarImg? (data URL or '') }. A new name also renames the account's answers.
async function updateProfile(request, env) {
  const user = requireUser(request);
  const b = await body(request), u = {};
  if (b.name !== undefined) u.name = b.name === '' ? '' : personName(b.name);
  if (b.avatar !== undefined) u.avatar = emojiIcon(b.avatar, 'Avatar');
  if (b.avatarImg !== undefined) u.avatar_img = imageData(b.avatarImg, 'Picture');
  const cols = Object.keys(u);
  if (!cols.length) return json({ ok: true });
  const stmts = [env.DB.prepare(`UPDATE users SET ${cols.map((c) => c + ' = ?').join(', ')} WHERE id = ?`).bind(...cols.map((c) => u[c]), user.id)];
  if (u.name) stmts.push(
    env.DB.prepare('UPDATE participants SET name = ? WHERE user_id = ?').bind(u.name, user.id),
    env.DB.prepare('UPDATE responses SET name = ? WHERE participant_id IN (SELECT id FROM participants WHERE user_id = ?)').bind(u.name, user.id));
  await env.DB.batch(stmts);
  return json({ ok: true });
}
// Polls the account owns (with their current round) and polls it answered.
async function myPolls(request, env) {
  const user = requireUser(request);
  const pic = (p) => (p.has_image ? p.image_at || '1' : '');
  const { results: owned } = await env.DB.prepare(
    `SELECT p.id, p.title, p.kind, p.icon, p.image_at, p.image IS NOT NULL AS has_image, p.created_at,
       i.start_date, i.end_date, i.status, i.deadline, (SELECT COUNT(*) FROM responses r WHERE r.instance_id = i.id) AS answers
     FROM polls p LEFT JOIN instances i ON i.id = (SELECT id FROM instances WHERE poll_id = p.id ORDER BY seq DESC LIMIT 1)
     WHERE p.owner_id = ? ORDER BY p.created_at DESC`).bind(user.id).all();
  const { results: answered } = await env.DB.prepare(
    `SELECT p.id, p.title, p.kind, p.icon, p.image_at, p.image IS NOT NULL AS has_image, pa.name,
       (SELECT MAX(r.updated_at) FROM responses r WHERE r.participant_id = pa.id) AS last
     FROM participants pa JOIN polls p ON p.id = pa.poll_id
     WHERE pa.user_id = ? AND (p.owner_id IS NULL OR p.owner_id != ?) ORDER BY last DESC`).bind(user.id, user.id).all();
  return json({
    polls: owned.map((p) => ({ id: p.id, title: p.title, kind: p.kind, icon: p.icon, image: pic(p), createdAt: p.created_at,
      current: p.start_date ? { startDate: p.start_date, endDate: p.end_date, deadline: p.deadline, answers: p.answers,
        status: effStatus({ status: p.status, end_date: p.end_date }) } : null })),
    answered: answered.map((p) => ({ id: p.id, title: p.title, kind: p.kind, icon: p.icon, image: pic(p), name: p.name, lastAnswered: p.last })),
  });
}
// Move a poll that was only reachable by its (old) admin link into the signed-in account.
async function claimPoll(request, env, id) {
  const user = requireUser(request);
  const poll = await loadPoll(env, id);
  if (!(await adminKeyOk(request, poll))) throw new HttpError(403, 'Admin link required');
  if (poll.owner_id && poll.owner_id !== user.id) throw new HttpError(409, 'This poll already belongs to another account');
  await env.DB.prepare('UPDATE polls SET owner_id = ? WHERE id = ?').bind(user.id, id).run();
  return json({ ok: true });
}

// ---------- polls ----------
function readPollSettings(b, existing) {
  const p = {}, has = (k) => b[k] !== undefined;
  if (!existing || has('title')) p.title = str(b.title, 120, 'Title', true);
  if (!existing || has('description')) p.description = str(b.description, 1000, 'Description');
  const kind = existing ? existing.kind : b.kind;
  if (!existing) {
    if (kind !== 'single' && kind !== 'series') throw new HttpError(400, 'Choose "one-off" or "recurring series"');
    p.kind = kind;
    if (kind === 'series') {
      if (b.unit !== 'week' && b.unit !== 'month') throw new HttpError(400, 'Repeat every week(s) or month(s)');
      p.unit = b.unit; p.every = int(b.every ?? 1, 1, 12, 'Repeat interval');
      if (p.unit === 'month') {
        if (typeof b.firstStart !== 'string' || !/^\d{4}-(0[1-9]|1[0-2])$/.test(b.firstStart.slice(0, 7))) throw new HttpError(400, 'Pick the first month');
        p.anchor = b.firstStart.slice(0, 7) + '-01';
      } else {
        if (!isDate(b.firstStart)) throw new HttpError(400, 'Pick the first start date');
        p.anchor = b.firstStart;
      }
      if (p.unit === 'week' && p.every * 7 > MAX_RANGE_DAYS) throw new HttpError(400, 'A poll can cover at most 13 weeks');
      if (p.unit === 'month' && p.every > 3) throw new HttpError(400, 'A poll can cover at most 3 months');
    }
  }
  if (kind === 'series') {
    if (!existing || has('openDays')) p.open_days = int(b.openDays ?? 11, 0, 90, 'Open days before');
    if (!existing || has('deadlineDays')) p.deadline_days = optInt(b.deadlineDays, 0, 90, 'Reply-by days before');
  }
  if (!existing || has('answerMode')) {
    const am = b.answerMode ?? 'both';
    if (!['days', 'slots', 'both'].includes(am)) throw new HttpError(400, 'Invalid answer type');
    p.answer_mode = am;
  }
  if (!existing || has('hourStart') || has('hourEnd')) {
    const hs = int(b.hourStart ?? existing?.hour_start ?? 8, 0, 23, 'First hour');
    const he = int(b.hourEnd ?? existing?.hour_end ?? 24, 1, 24, 'Last hour');
    if (he <= hs) throw new HttpError(400, 'The last hour must be after the first hour');
    p.hour_start = hs; p.hour_end = he;
  }
  if (!existing || has('hideResults')) p.hide_results = b.hideResults ? 1 : 0;
  if (!existing || has('allowComments')) p.allow_comments = b.allowComments === false ? 0 : 1;
  if (!existing || has('adminEmail')) p.admin_email = email(b.adminEmail, 'Your email');
  if (!existing || has('notifyOpen')) p.notify_open = b.notifyOpen ? 1 : 0;
  if (!existing || has('remindDays')) p.remind_days = optInt(b.remindDays, 0, 30, 'Reminder days');
  if (!existing || has('icon')) p.icon = emojiIcon(b.icon, 'Icon');
  if (!existing || has('image')) { p.image = imageData(b.image, 'Picture'); p.image_at = p.image ? now() : null; }
  return p;
}

async function createPoll(request, env) {
  const user = userOf(request);
  if (!user) throw new HttpError(401, 'Sign in to create polls.');
  const owned = await env.DB.prepare('SELECT COUNT(*) AS n FROM polls WHERE owner_id = ?').bind(user.id).first('n');
  if (owned >= MAX_POLLS_PER_USER) throw new HttpError(429, `You can have at most ${MAX_POLLS_PER_USER} polls. Delete an old one first.`);
  const b = await body(request);
  const p = readPollSettings(b, null);
  const id = randomId(10), t = now();
  p.id = id; p.owner_id = user.id;
  p.admin_hash = await sha256('admin:' + secret()); // column is required; admin links are no longer handed out
  p.password_hash = b.password ? await sha256(id + ':pw:' + str(b.password, 100, 'Password')) : null;
  p.created_at = t; p.updated_at = t;
  let first;
  if (p.kind === 'single') {
    checkRange(b.startDate, b.endDate);
    if (b.deadline && !isDate(b.deadline)) throw new HttpError(400, 'Invalid reply-by date');
    first = { start_date: b.startDate, end_date: b.endDate, deadline: b.deadline || null };
  }
  const cols = Object.keys(p);
  await env.DB.prepare(`INSERT INTO polls (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).bind(...cols.map((c) => p[c])).run();
  // The first poll of a series opens right away (it's the period currently due, or the first one if that's later).
  const seq = p.kind === 'series' ? currentSeq(p) : 0;
  await insertInstance(env, p, seq, first || seriesFields(p, seq), true);
  return json({ id }, 201);
}

async function getPoll(request, env, ctx, url, id) {
  const poll = await loadPoll(env, id);
  const admin = await isAdmin(request, poll);
  if (!admin) await checkPassword(request, poll);
  const created = await ensureCurrent(env, poll);
  if (created) ctx.waitUntil(notifyOpened(env, poll, created, url.origin).catch((e) => console.error(e)));
  const { results: all } = await env.DB.prepare('SELECT * FROM instances WHERE poll_id = ? ORDER BY seq').bind(id).all();
  if (!all.length) throw new HttpError(404, 'This poll has no open rounds');
  const open = all.filter((i) => effStatus(i) === 'open');
  let sel = url.searchParams.get('i') ? all.find((i) => i.id === url.searchParams.get('i')) : null;
  if (sel && !admin && effStatus(sel) !== 'open' && poll.hide_results) sel = null;
  if (!sel) sel = open.length ? open[open.length - 1] : all[all.length - 1];
  let counts = {};
  if (admin) {
    const { results } = await env.DB.prepare('SELECT instance_id, COUNT(*) AS n FROM responses WHERE poll_id = ? GROUP BY instance_id').bind(id).all();
    results.forEach((r) => (counts[r.instance_id] = r.n));
  }
  const listed = admin ? all : all.filter((i) => effStatus(i) === 'open' || i.id === sel.id);
  const out = {
    poll: publicPoll(poll, admin), isAdmin: admin, emailEnabled: emailEnabled(env),
    instances: listed.map((i) => publicInstance(i, admin ? { responses: counts[i.id] || 0 } : {})),
    instance: publicInstance(sel), dates: datesOf(sel),
  };
  if (admin && poll.kind === 'series') {
    const n = Math.max(...all.map((i) => i.seq)) + 1;
    out.next = { startDate: periodStart(poll, n), endDate: periodEnd(poll, n), opens: openDate(poll, n) };
  }
  if (admin || !poll.hide_results) {
    const { results } = await env.DB.prepare('SELECT id, name, email, comment, entries, updated_at FROM responses WHERE instance_id = ? ORDER BY created_at').bind(sel.id).all();
    out.responses = results.map((r) => ({ id: r.id, name: r.name, comment: r.comment, entries: JSON.parse(r.entries), updatedAt: r.updated_at, ...(admin ? { email: r.email } : {}) }));
    // Names already used in this poll (any round), so people can pick themselves. Account answers are found by account instead.
    const { results: ps } = await env.DB.prepare('SELECT id, name FROM participants WHERE poll_id = ? AND user_id IS NULL ORDER BY name COLLATE NOCASE').bind(id).all();
    out.participants = ps;
  }
  const user = userOf(request);
  if (user) { // signed in: their answers are linked to the account
    const part = await accountParticipant(env, id, user.id);
    out.me = { name: part ? part.name : user.name, email: user.email, participantId: part ? part.id : null,
      responseId: part ? (await answerIn(env, part.id, sel.id)) || null : null };
  }
  return json(out);
}

async function updatePoll(request, env, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  const b = await body(request);
  const p = readPollSettings(b, poll);
  if (b.password !== undefined) p.password_hash = b.password ? await sha256(id + ':pw:' + str(b.password, 100, 'Password')) : null;
  p.updated_at = now();
  const cols = Object.keys(p);
  await env.DB.prepare(`UPDATE polls SET ${cols.map((c) => c + ' = ?').join(', ')} WHERE id = ?`).bind(...cols.map((c) => p[c]), id).run();
  return json({ ok: true });
}

// The poll's picture. <img> can't send headers, so a password travels as ?pw= (like calendar.ics).
async function pollImage(request, env, url, id) {
  const poll = await env.DB.prepare('SELECT id, owner_id, password_hash, image FROM polls WHERE id = ?').bind(id).first();
  if (!poll || !poll.image) throw new HttpError(404, 'No picture');
  if (!isAdmin(request, poll) && !(await passwordOk(poll, url.searchParams.get('pw')))) throw new HttpError(401, 'Password required');
  const m = poll.image.match(/^data:(image\/(?:webp|jpeg|png));base64,(.+)$/);
  if (!m) throw new HttpError(404, 'No picture');
  const bytes = Uint8Array.from(atob(m[2]), (c) => c.charCodeAt(0));
  return new Response(bytes, { headers: { 'content-type': m[1], 'cache-control': 'private, max-age=31536000, immutable' } });
}

async function deletePoll(request, env, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM responses WHERE poll_id = ?').bind(id),
    env.DB.prepare('DELETE FROM participants WHERE poll_id = ?').bind(id),
    env.DB.prepare('DELETE FROM instances WHERE poll_id = ?').bind(id),
    env.DB.prepare('DELETE FROM polls WHERE id = ?').bind(id),
  ]);
  return json({ ok: true });
}

// ---------- instances ----------
async function createNextInstance(request, env, ctx, url, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  if (poll.kind !== 'series') throw new HttpError(400, 'Only recurring series have a next poll');
  const last = await env.DB.prepare('SELECT MAX(seq) AS s FROM instances WHERE poll_id = ?').bind(id).first('s');
  const n = last == null ? currentSeq(poll) : last + 1;
  const inst = await insertInstance(env, poll, n, seriesFields(poll, n), false);
  if (!inst) throw new HttpError(409, 'That poll already exists');
  ctx.waitUntil(notifyOpened(env, poll, inst, url.origin).catch((e) => console.error(e)));
  return json({ ok: true, id: inst.id }, 201);
}

async function updateInstance(request, env, id, iid) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  const inst = await loadInstance(env, id, iid);
  const b = await body(request), u = {}, has = (k) => b[k] !== undefined;
  if (has('status')) { if (!['open', 'closed'].includes(b.status)) throw new HttpError(400, 'Invalid status'); u.status = b.status; }
  if (has('note')) u.note = str(b.note, 1000, 'Note');
  if (has('deadline')) { if (b.deadline && !isDate(b.deadline)) throw new HttpError(400, 'Invalid reply-by date'); u.deadline = b.deadline || null; u.reminded = 0; }
  if (has('startDate') || has('endDate')) {
    const s = b.startDate ?? inst.start_date, e = b.endDate ?? inst.end_date;
    checkRange(s, e); u.start_date = s; u.end_date = e;
  }
  if (has('meetings')) u.meetings = JSON.stringify(validateMeetings(b.meetings));
  const cols = Object.keys(u);
  if (cols.length) await env.DB.prepare(`UPDATE instances SET ${cols.map((c) => c + ' = ?').join(', ')} WHERE id = ?`).bind(...cols.map((c) => u[c]), iid).run();
  return json({ ok: true, instance: publicInstance(await loadInstance(env, id, iid)) });
}

async function deleteInstance(request, env, id, iid) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  await loadInstance(env, id, iid);
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM instances WHERE poll_id = ?').bind(id).first('n');
  if (n <= 1) throw new HttpError(400, 'This is the only poll left. Delete the whole poll instead.');
  await env.DB.batch([
    env.DB.prepare('DELETE FROM responses WHERE instance_id = ?').bind(iid),
    env.DB.prepare('DELETE FROM instances WHERE id = ?').bind(iid),
  ]);
  return json({ ok: true });
}

// ---------- calendar (.ics) ----------
// Times are "floating" local times: 18:00 shows as 18:00 in every attendee's calendar.
function icsEscape(s) { return String(s || '').replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\r?\n/g, '\\n'); }
function icsFold(line) {
  if (enc.encode(line).length <= 75) return line;
  const out = []; let cur = '', len = 0;
  for (const ch of line) {
    const l = enc.encode(ch).length;
    if (len + l > (out.length ? 74 : 75)) { out.push(cur); cur = ''; len = 0; }
    cur += ch; len += l;
  }
  out.push(cur);
  return out.join('\r\n ');
}
function meetingToIcs(mt, poll, link) {
  const d = mt.date.replace(/-/g, '');
  const stamp = now().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  const lines = ['BEGIN:VEVENT', `UID:${mt.id}-${poll.id}@whenwho`, `DTSTAMP:${stamp}`];
  if (mt.allDay) lines.push(`DTSTART;VALUE=DATE:${d}`, `DTEND;VALUE=DATE:${addDays(mt.date, 1).replace(/-/g, '')}`);
  else {
    const endDate = mt.end === 24 ? addDays(mt.date, 1).replace(/-/g, '') : d;
    lines.push(`DTSTART:${d}T${pad(mt.start)}0000`, `DTEND:${endDate}T${pad(mt.end % 24)}0000`);
  }
  lines.push(`SUMMARY:${icsEscape(mt.title || poll.title)}`);
  if (mt.location) lines.push(`LOCATION:${icsEscape(mt.location)}`);
  lines.push(`DESCRIPTION:${icsEscape([mt.note, 'Who: ' + whoText(mt), link].filter(Boolean).join('\n'))}`, 'END:VEVENT');
  return lines;
}
function buildIcs(poll, meetings, link) {
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//whenwho//EN', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
    `X-WR-CALNAME:${icsEscape(poll.title)}`, ...meetings.flatMap((mt) => meetingToIcs(mt, poll, link)), 'END:VCALENDAR'];
  return lines.map(icsFold).join('\r\n') + '\r\n';
}
const whoText = (mt) => (mt.participants === 'all' ? 'Everyone' : mt.participants.map((p) => p.name).join(', '));
async function calendar(env, url, id) {
  const poll = await loadPoll(env, id);
  if (!(await passwordOk(poll, url.searchParams.get('pw')))) throw new HttpError(401, 'Password required');
  const { results } = await env.DB.prepare('SELECT id, meetings FROM instances WHERE poll_id = ? ORDER BY seq').bind(id).all();
  let meetings = results.flatMap((i) => JSON.parse(i.meetings || '[]'));
  const only = url.searchParams.get('m');
  if (only) meetings = meetings.filter((mt) => mt.id === only);
  const name = (only ? `${meetings[0]?.title || poll.title} ${meetings[0]?.date || ''}` : poll.title).replace(/[^\w\- ]+/g, '').trim() || 'meetings';
  return new Response(buildIcs(poll, meetings, `${url.origin}/?p=${poll.id}`), {
    headers: { 'content-type': 'text/calendar; charset=utf-8', 'content-disposition': `${url.searchParams.get('download') ? 'attachment' : 'inline'}; filename="${name}.ics"`, 'cache-control': 'no-cache' },
  });
}

// ---------- email (optional: Resend, https://resend.com/docs/api-reference/emails/send-email) ----------
const emailEnabled = (env) => !!(env.RESEND_API_KEY && env.MAIL_FROM);
const headerSafe = (s) => String(s || '').replace(/[\r\n<>"\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60);
const b64 = (bytes) => { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(s); };
// One message: { fromName, to: [..], bcc?: [..], replyTo?, subject, text, html, attachments?: [{ content: Uint8Array, filename }] }
async function sendEmail(env, m) {
  const payload = {
    from: `"${headerSafe(m.fromName) || 'whenwho'}" <${env.MAIL_FROM}>`,
    to: m.to, subject: String(m.subject).replace(/[\r\n]+/g, ' ').slice(0, 200), text: m.text, html: m.html,
    ...(m.bcc && m.bcc.length ? { bcc: m.bcc } : {}),
    ...(m.replyTo ? { reply_to: m.replyTo } : {}),
    ...(m.attachments ? { attachments: m.attachments.map((a) => ({ filename: a.filename, content: b64(a.content) })) } : {}),
  };
  const r = await fetch((env.RESEND_API_URL || 'https://api.resend.com') + '/emails', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (r.ok) return;
  const detail = await r.text().catch(() => '');
  console.error('resend', r.status, detail.slice(0, 300));
  if (r.status === 429) throw new HttpError(503, 'The site’s email limit is reached for now. Try again later (or tomorrow).');
  throw new HttpError(502, 'The email couldn’t be sent. Try again later.');
}
const siteUrl = (env, origin) => (env.SITE_URL || origin || '').replace(/\/+$/, '');
const fmtDay = (d) => new Date(d + 'T00:00:00Z').toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
const hh = (h) => `${pad(h % 24)}:00`;
const escHtml = (s) => String(s || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Branded HTML email (navy header, white card), matching the web app. Inline styles and tables so email clients render it.
// bodyHtml must already be escaped. button: optional { href, label } shown as a blue button above the body.
function emailHtml(bodyHtml, { preheader = '', button = null, site = '' } = {}) {
  const font = "Inter,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
  const btn = button ? `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 24px"><tr><td style="border-radius:8px;background:#1F5EFF">
    <a href="${escHtml(button.href)}" style="display:inline-block;padding:12px 22px;font-family:${font};font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:8px">${escHtml(button.label)}</a></td></tr></table>` : '';
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"></head>
<body style="margin:0;padding:0;background:#F5F7FB">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">${escHtml(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F5F7FB"><tr><td align="center" style="padding:24px 12px">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px">
    <tr><td style="background:#0B1F3A;border-radius:14px 14px 0 0;padding:18px 28px">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td style="width:28px;height:28px;background:#1F5EFF;border-radius:7px;text-align:center;vertical-align:middle;font-family:${font};font-size:15px;font-weight:700;color:#ffffff">✓</td>
        <td style="padding-left:10px;font-family:${font};font-size:18px;font-weight:700;color:#ffffff;letter-spacing:-0.2px">whenwho</td></tr></table></td></tr>
    <tr><td style="background:#ffffff;border:1px solid #E2E8F0;border-top:0;border-radius:0 0 14px 14px;padding:32px 28px;font-family:${font};font-size:15px;line-height:1.6;color:#0F172A">
      ${btn}${bodyHtml}</td></tr>
    <tr><td style="padding:16px 28px;font-family:${font};font-size:12px;line-height:1.5;color:#5B6578;text-align:center">
      Sent by whenwho${site ? ` · <a href="${escHtml(site)}" style="color:#5B6578">${escHtml(site.replace(/^https?:\/\//, ''))}</a>` : ''}</td></tr>
  </table></td></tr></table></body></html>`;
}
const linkify = (escaped) => escaped.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" style="color:#1F5EFF;word-break:break-all">$1</a>');
function periodText(poll, inst) {
  if (poll.unit === 'month' && inst.start_date.endsWith('-01') && addDays(inst.end_date, 1).endsWith('-01')) {
    const f = (d) => new Date(d + 'T00:00:00Z').toLocaleDateString('en-GB', { month: 'long', year: 'numeric', timeZone: 'UTC' });
    return f(inst.start_date) === f(inst.end_date) ? f(inst.start_date) : `${f(inst.start_date)} – ${f(inst.end_date)}`;
  }
  const f = (d) => new Date(d + 'T00:00:00Z').toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
  return `${f(inst.start_date)} – ${f(inst.end_date)}`;
}
// Emails started by a person (invites, test emails) count against a daily cap per account, or per poll without one.
async function mailQuota(env, poll, count) {
  const key = poll.owner_id || 'poll:' + poll.id;
  const since = new Date(Date.now() - 86400000).toISOString();
  const used = await env.DB.prepare('SELECT COALESCE(SUM(n), 0) AS n FROM mail_log WHERE user_id = ? AND at > ?').bind(key, since).first('n');
  const max = Number(env.MAIL_PER_DAY) || MAIL_PER_DAY;
  if (used + count > max) throw new HttpError(429, `Daily email limit reached (${max} recipients). Try again tomorrow.`);
  await env.DB.prepare('INSERT INTO mail_log (user_id, n, at) VALUES (?, ?, ?)').bind(key, count, now()).run();
}
async function sendMail(env, poll, { to, subject, text, attachments, quota = false }) {
  if (!emailEnabled(env)) throw new HttpError(400, 'Email isn’t set up for this site');
  const list = [...new Set(to.map((e) => e.toLowerCase()))].filter((e) => EMAIL_RE.test(e));
  if (quota) await mailQuota(env, poll, list.length);
  const pollLink = (text.match(/https?:\/\/[^\s]+\?p=[^\s]+/) || [])[0];
  const html = emailHtml(`<div style="white-space:pre-wrap">${linkify(escHtml(text))}</div>`, {
    preheader: subject, button: pollLink ? { href: pollLink, label: 'Open poll' } : null, site: siteUrl(env, ''),
  });
  let sent = 0;
  for (let i = 0; i < list.length; i += 49) { // max 50 recipients per message: send each batch as BCC
    const bcc = list.slice(i, i + 49);
    const to = (poll.admin_email || env.MAIL_FROM).toLowerCase();
    await sendEmail(env, {
      fromName: poll.title,
      to: [to],
      bcc: bcc.filter((e) => e !== to), subject, text, html,
      ...(poll.admin_email ? { replyTo: poll.admin_email } : {}),
      ...(attachments ? { attachments } : {}),
    });
    sent += bcc.length;
  }
  return sent;
}
const footer = (poll) => `\n\n—\nYou're getting this because you left your email address in the poll “${poll.title}”. To stop these emails, open the poll and remove your email from your answer.`;

async function sendInvite(request, env, url, id, iid, mid) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  const inst = await loadInstance(env, id, iid);
  const meetings = JSON.parse(inst.meetings || '[]');
  const mt = meetings.find((x) => x.id === mid);
  if (!mt) throw new HttpError(404, 'Meeting not found');
  const { results } = await env.DB.prepare('SELECT id, name, email FROM responses WHERE instance_id = ?').bind(iid).all();
  const invited = mt.participants === 'all' ? results : results.filter((r) => mt.participants.some((p) => p.id === r.id));
  const withMail = invited.filter((r) => r.email);
  if (!withMail.length) throw new HttpError(400, 'None of the invited people left an email address');
  const base = siteUrl(env, url.origin), link = `${base}/?p=${poll.id}`;
  const when = `${fmtDay(mt.date)}${mt.allDay ? ' (all day)' : `, ${hh(mt.start)}–${hh(mt.end)}`}`;
  const text = [`${mt.title || poll.title}`, '', `When: ${when}`, mt.location ? `Where: ${mt.location}` : null, `Who: ${whoText(mt)}`, mt.note ? `\n${mt.note}` : null,
    '', 'The calendar file is attached. Open it to add the meeting to your calendar.', `Poll: ${link}`].filter((x) => x !== null).join('\n') + footer(poll);
  const ics = buildIcs(poll, [mt], link);
  const sent = await sendMail(env, poll, { to: withMail.map((r) => r.email), subject: `${mt.title || poll.title}: ${when}`, text,
    attachments: [{ content: enc.encode(ics), filename: 'invite.ics', type: 'text/calendar', disposition: 'attachment' }], quota: true });
  mt.sentAt = now();
  await env.DB.prepare('UPDATE instances SET meetings = ? WHERE id = ?').bind(JSON.stringify(meetings), iid).run();
  return json({ ok: true, sent, missing: invited.filter((r) => !r.email).map((r) => r.name) });
}

async function testEmail(request, env, url, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  if (!poll.admin_email) throw new HttpError(400, 'Add your email in the poll settings first');
  await sendMail(env, poll, { to: [poll.admin_email], subject: `Test email from “${poll.title}”`, text: `Email sending works.\n\nPoll: ${siteUrl(env, url.origin)}/?p=${poll.id}`, quota: true });
  return json({ ok: true });
}

// Emails of people who answered the most recent earlier round of this series (with responses).
async function previousEmails(env, poll, inst) {
  const prev = await env.DB.prepare(
    'SELECT i.id FROM instances i WHERE i.poll_id = ? AND i.seq < ? AND EXISTS (SELECT 1 FROM responses r WHERE r.instance_id = i.id) ORDER BY i.seq DESC LIMIT 1'
  ).bind(poll.id, inst.seq).first('id');
  if (!prev) return [];
  const { results } = await env.DB.prepare("SELECT email FROM responses WHERE instance_id = ? AND email != ''").bind(prev).all();
  return results.map((r) => r.email);
}
async function notifyOpened(env, poll, inst, origin) {
  // claim the notification so it is sent once even if the cron job and a visitor race
  const claim = await env.DB.prepare('UPDATE instances SET opened_notified = 1 WHERE id = ? AND opened_notified = 0').bind(inst.id).run();
  if (!claim.meta || !claim.meta.changes) return;
  if (!poll.notify_open || !emailEnabled(env)) return;
  const to = await previousEmails(env, poll, inst);
  if (!to.length) return;
  const base = siteUrl(env, origin); if (!base) return;
  const period = periodText(poll, inst);
  const text = `The poll for ${period} is open.\n\nPlease mark when you're available${inst.deadline ? ` by ${fmtDay(inst.deadline)}` : ''}:\n${base}/?p=${poll.id}` + footer(poll);
  await sendMail(env, poll, { to, subject: `${poll.title}: when are you free in ${period}?`, text });
}
async function remind(env, poll, inst) {
  const claim = await env.DB.prepare('UPDATE instances SET reminded = 1 WHERE id = ? AND reminded = 0').bind(inst.id).run();
  if (!claim.meta || !claim.meta.changes || !emailEnabled(env)) return;
  const base = siteUrl(env); if (!base) return;
  const { results } = await env.DB.prepare("SELECT LOWER(email) AS e FROM responses WHERE instance_id = ? AND email != ''").bind(inst.id).all();
  const answered = new Set(results.map((r) => r.e));
  const to = (await previousEmails(env, poll, inst)).filter((e) => !answered.has(e.toLowerCase()));
  if (!to.length) return;
  const period = periodText(poll, inst);
  const text = `Reminder: please mark when you're available for ${period} by ${fmtDay(inst.deadline)}.\n\n${base}/?p=${poll.id}` + footer(poll);
  await sendMail(env, poll, { to, subject: `Reminder: ${poll.title} (${period})`, text });
}
async function runScheduled(env) {
  try {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now()),
      env.DB.prepare('DELETE FROM login_attempts WHERE at < ?').bind(new Date(Date.now() - 86400000).toISOString()),
      env.DB.prepare('DELETE FROM login_codes WHERE expires_at < ?').bind(now()),
      env.DB.prepare('DELETE FROM mail_log WHERE at < ?').bind(new Date(Date.now() - 2 * 86400000).toISOString()),
    ]);
  } catch (e) { console.error('cleanup', e); }
  const { results: polls } = await env.DB.prepare("SELECT * FROM polls WHERE kind = 'series' OR remind_days IS NOT NULL").all();
  const t = today();
  for (const poll of polls) {
    try {
      await ensureCurrent(env, poll);
      const { results: pending } = await env.DB.prepare('SELECT * FROM instances WHERE poll_id = ? AND opened_notified = 0').bind(poll.id).all();
      for (const inst of pending) if (effStatus(inst) === 'open') await notifyOpened(env, poll, inst, null);
      if (poll.remind_days != null) {
        const { results: due } = await env.DB.prepare("SELECT * FROM instances WHERE poll_id = ? AND reminded = 0 AND deadline IS NOT NULL AND deadline >= ?").bind(poll.id, t).all();
        for (const inst of due) if (effStatus(inst) === 'open' && addDays(inst.deadline, -poll.remind_days) <= t) await remind(env, poll, inst);
      }
    } catch (e) { console.error('scheduled', poll.id, e); }
  }
}

// ---------- responses ----------
// Guests: names are unique within a poll (case-insensitive) and identify a person across all rounds of a series.
// Signed-in people: the account identifies them; their name_key is acctKey(user id), so names may repeat.
const nameKey = (name) => String(name || '').trim().replace(/\s+/g, ' ').toLowerCase();
const acctKey = (userId) => '\u0001' + userId;
const accountParticipant = (env, pollId, userId) =>
  env.DB.prepare('SELECT * FROM participants WHERE poll_id = ? AND user_id = ?').bind(pollId, userId).first();
const findParticipant = (env, pollId, key) =>
  env.DB.prepare('SELECT * FROM participants WHERE poll_id = ? AND name_key = ?').bind(pollId, key).first();
const answerIn = (env, participantId, iid) =>
  env.DB.prepare('SELECT id FROM responses WHERE participant_id = ? AND instance_id = ? ORDER BY updated_at DESC LIMIT 1').bind(participantId, iid).first('id');
async function newParticipant(env, pollId, name, mail = '', userId = null) {
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM participants WHERE poll_id = ?').bind(pollId).first('n');
  if (n >= MAX_PARTICIPANTS) throw new HttpError(409, 'This poll has reached its maximum number of participants');
  const p = { id: randomId(12), poll_id: pollId, name, name_key: userId ? acctKey(userId) : nameKey(name), email: mail, user_id: userId, created_at: now() };
  await env.DB.prepare('INSERT INTO participants (id, poll_id, name, name_key, email, user_id, created_at) VALUES (?,?,?,?,?,?,?)')
    .bind(p.id, p.poll_id, p.name, p.name_key, p.email, p.user_id, p.created_at).run();
  return p;
}
const nameTaken = (name, participantId, responseId) =>
  new HttpError(409, `“${name}” has already answered this poll. If that's you, load your answer instead.`, { code: 'name_taken', participantId, responseId });

async function createResponse(request, env, id, iid) {
  const poll = await loadPoll(env, id);
  const admin = await isAdmin(request, poll);
  if (!admin) await checkPassword(request, poll);
  const inst = await loadInstance(env, id, iid);
  if (effStatus(inst) !== 'open' && !admin) throw new HttpError(409, 'This poll is closed');
  const b = await body(request);
  const name = personName(b.name);
  const comment = poll.allow_comments ? str(b.comment, 500, 'Comment') : '';
  const user = userOf(request);
  const mail = user ? user.email : email(b.email);
  const entries = validateEntries(b.entries, poll, datesOf(inst));
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM responses WHERE instance_id = ?').bind(iid).first('n');
  if (count >= MAX_RESPONSES) throw new HttpError(409, 'This poll has reached its maximum number of responses');
  let part;
  if (user) { // signed in: one participant per account, whatever name they give
    part = await accountParticipant(env, id, user.id);
    if (part) {
      const existing = await answerIn(env, part.id, iid);
      if (existing) throw new HttpError(409, 'You have already answered this poll', { code: 'own_answer', responseId: existing });
      if (part.name !== name) {
        await env.DB.batch([
          env.DB.prepare('UPDATE participants SET name = ? WHERE id = ?').bind(name, part.id),
          env.DB.prepare('UPDATE responses SET name = ? WHERE participant_id = ?').bind(name, part.id)]);
        part.name = name;
      }
    } else part = await newParticipant(env, id, name, user.email, user.id);
  } else {
    // Same name as an existing guest: that's this person (e.g. the next round of a series),
    // unless they already answered this round.
    part = await findParticipant(env, id, nameKey(name));
    if (part) {
      const existing = await answerIn(env, part.id, iid);
      if (existing) throw nameTaken(part.name, part.id, existing);
    } else part = await newParticipant(env, id, name);
  }
  const rid = randomId(12), editKey = secret(), t = now();
  await env.DB.prepare('INSERT INTO responses (id, poll_id, instance_id, name, email, comment, entries, edit_hash, participant_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .bind(rid, id, iid, part.name, mail, comment, JSON.stringify(entries), await sha256('edit:' + editKey), part.id, t, t).run();
  return json({ id: rid, editKey, name: part.name }, 201);
}
async function loadResponse(env, id, rid) {
  if (!ID_RE.test(rid)) throw new HttpError(404, 'Response not found');
  const r = await env.DB.prepare('SELECT * FROM responses WHERE id = ? AND poll_id = ?').bind(rid, id).first();
  if (!r) throw new HttpError(404, 'Response not found');
  return r;
}
// The person may edit while signed in to the account that gave the answer, with the secret edit key from their
// browser, or (guests only) by giving the response's name (x-edit-name).
async function canEditResponse(request, env, r) {
  const user = userOf(request);
  if (user && r.participant_id) {
    const owner = await env.DB.prepare('SELECT user_id FROM participants WHERE id = ?').bind(r.participant_id).first('user_id');
    if (owner && owner === user.id) return true;
  }
  const key = request.headers.get('x-edit-key');
  if (key && safeEqual(await sha256('edit:' + key), r.edit_hash)) return true;
  const raw = request.headers.get('x-edit-name');
  if (!raw || !r.participant_id) return false;
  await checkThrottle(env, request, 'name');
  let given; try { given = nameKey(decodeURIComponent(raw)); } catch { return false; }
  const part = await env.DB.prepare('SELECT name_key FROM participants WHERE id = ?').bind(r.participant_id).first();
  if (part && part.name_key === given) return true;
  await recordFail(env, request, 'name');
  return false;
}
// "Is that me?": find the participant for a name and their answer in this round.
async function recall(request, env, id, iid) {
  const poll = await loadPoll(env, id);
  if (!(await isAdmin(request, poll))) await checkPassword(request, poll);
  await loadInstance(env, id, iid);
  await checkThrottle(env, request, 'name');
  const b = await body(request);
  const part = await findParticipant(env, id, nameKey(personName(b.name)));
  if (!part) { await recordFail(env, request, 'name'); throw new HttpError(404, 'Nobody has answered under that name yet'); }
  return json({ participantId: part.id, name: part.name, responseId: (await answerIn(env, part.id, iid)) || null });
}
async function getOwnResponse(request, env, id, rid) {
  const poll = await loadPoll(env, id);
  const r = await loadResponse(env, id, rid);
  if (!(await isAdmin(request, poll)) && !(await canEditResponse(request, env, r))) throw new HttpError(403, 'Not your response');
  return json({ id: r.id, instanceId: r.instance_id, name: r.name, email: r.email, comment: r.comment, entries: JSON.parse(r.entries) });
}
async function updateResponse(request, env, id, rid) {
  const poll = await loadPoll(env, id);
  const r = await loadResponse(env, id, rid);
  const inst = await loadInstance(env, id, r.instance_id);
  const admin = isAdmin(request, poll), own = await canEditResponse(request, env, r);
  if (!own && !admin) throw new HttpError(403, 'Not your response');
  if (!admin) {
    await checkPassword(request, poll);
    if (effStatus(inst) !== 'open') throw new HttpError(409, 'This poll is closed');
  }
  const b = await body(request);
  let name = b.name !== undefined ? personName(b.name) : r.name;
  let mail = b.email !== undefined ? email(b.email) : r.email;
  const comment = b.comment !== undefined && poll.allow_comments ? str(b.comment, 500, 'Comment') : r.comment;
  const entries = b.entries !== undefined ? JSON.stringify(validateEntries(b.entries, poll, datesOf(inst))) : r.entries;
  let partId = r.participant_id;
  const cur = partId ? await env.DB.prepare('SELECT * FROM participants WHERE id = ?').bind(partId).first() : null;
  const stmts = [];
  const user = userOf(request);
  // A guest who signs in and edits their own answer: link that person to the account (if it has none in this poll yet).
  if (user && own && cur && !cur.user_id && !(await accountParticipant(env, id, user.id))) {
    stmts.push(env.DB.prepare('UPDATE participants SET user_id = ?, name_key = ?, email = ? WHERE id = ?').bind(user.id, acctKey(user.id), user.email, cur.id));
    cur.user_id = user.id; cur.name_key = acctKey(user.id);
  }
  if (cur && cur.user_id) {
    // Account answer: the name is only a label (it may repeat); the email is the account's.
    if (user && user.id === cur.user_id) mail = user.email;
    if (name !== cur.name) stmts.push(
      env.DB.prepare('UPDATE participants SET name = ? WHERE id = ?').bind(name, cur.id),
      env.DB.prepare('UPDATE responses SET name = ? WHERE participant_id = ?').bind(name, cur.id));
  } else if (!cur || cur.name_key !== nameKey(name)) {
    const other = await findParticipant(env, id, nameKey(name));
    if (other) {
      // The new name belongs to someone else: allowed only if they haven't answered this round (e.g. fixing a typo).
      const theirs = await answerIn(env, other.id, inst.id);
      if (theirs && theirs !== rid) throw nameTaken(other.name, other.id, theirs);
      partId = other.id; name = other.name;
      if (cur) { // drop the old participant if this was their only answer
        const left = await env.DB.prepare('SELECT COUNT(*) AS n FROM responses WHERE participant_id = ? AND id != ?').bind(cur.id, rid).first('n');
        if (!left) stmts.push(env.DB.prepare('DELETE FROM participants WHERE id = ?').bind(cur.id));
      }
    } else if (cur) {
      // Rename this person in every round.
      stmts.push(env.DB.prepare('UPDATE participants SET name = ?, name_key = ? WHERE id = ?').bind(name, nameKey(name), cur.id));
      stmts.push(env.DB.prepare('UPDATE responses SET name = ? WHERE participant_id = ?').bind(name, cur.id));
    } else partId = (user && own && !(await accountParticipant(env, id, user.id))
      ? await newParticipant(env, id, name, user.email, user.id) : await newParticipant(env, id, name)).id;
  }
  if (cur && !cur.user_id && cur.name_key === nameKey(name) && cur.name !== name) { // only the spelling changed
    stmts.push(env.DB.prepare('UPDATE participants SET name = ? WHERE id = ?').bind(name, cur.id));
    stmts.push(env.DB.prepare('UPDATE responses SET name = ? WHERE participant_id = ?').bind(name, cur.id));
  }
  stmts.push(env.DB.prepare('UPDATE responses SET name = ?, email = ?, comment = ?, entries = ?, participant_id = ?, updated_at = ? WHERE id = ?').bind(name, mail, comment, entries, partId, now(), rid));
  await env.DB.batch(stmts);
  return json({ ok: true, name });
}
async function deleteResponse(request, env, id, rid) {
  const poll = await loadPoll(env, id);
  const r = await loadResponse(env, id, rid);
  if (!(await isAdmin(request, poll)) && !(await canEditResponse(request, env, r))) throw new HttpError(403, 'Not allowed');
  await env.DB.prepare('DELETE FROM responses WHERE id = ?').bind(rid).run();
  return json({ ok: true });
}

// ---------- participants (admin) ----------
async function adminPoll(request, env, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  return poll;
}
async function loadParticipant(env, id, pid) {
  if (!ID_RE.test(pid)) throw new HttpError(404, 'Participant not found');
  const p = await env.DB.prepare('SELECT * FROM participants WHERE id = ? AND poll_id = ?').bind(pid, id).first();
  if (!p) throw new HttpError(404, 'Participant not found');
  return p;
}
async function listParticipants(request, env, id) {
  await adminPoll(request, env, id);
  const { results } = await env.DB.prepare(
    `SELECT p.id, p.name, p.email, p.user_id, COUNT(r.id) AS rounds, MAX(r.updated_at) AS last,
       (SELECT r2.email FROM responses r2 WHERE r2.participant_id = p.id AND r2.email != '' ORDER BY r2.updated_at DESC LIMIT 1) AS answer_email
     FROM participants p LEFT JOIN responses r ON r.participant_id = p.id
     WHERE p.poll_id = ? GROUP BY p.id ORDER BY p.name COLLATE NOCASE`).bind(id).all();
  return json({ participants: results.map((p) => ({ id: p.id, name: p.name, email: p.email || p.answer_email || '', account: !!p.user_id, rounds: p.rounds, lastAnswered: p.last })) });
}
// Body: { lines: "Anna\nBen, ben@example.com" }
async function addParticipants(request, env, id) {
  await adminPoll(request, env, id);
  const b = await body(request);
  const text = str(b.lines, 20000, 'Names', true);
  const added = [], skipped = [];
  for (const line of text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)) {
    const [rawName, ...rest] = line.split(',');
    const name = personName(rawName);
    const mail = email(rest.join(',').trim(), `Email for ${name}`);
    if (await findParticipant(env, id, nameKey(name))) { skipped.push(name); continue; }
    await newParticipant(env, id, name, mail);
    added.push(name);
  }
  return json({ added, skipped });
}
async function updateParticipant(request, env, id, pid) {
  await adminPoll(request, env, id);
  const p = await loadParticipant(env, id, pid);
  const b = await body(request);
  const name = b.name !== undefined ? personName(b.name) : p.name;
  const mail = p.user_id ? p.email : b.email !== undefined ? email(b.email) : p.email; // an account keeps its own email
  if (!p.user_id && nameKey(name) !== p.name_key && (await findParticipant(env, id, nameKey(name))))
    throw new HttpError(409, `“${name}” already exists in this poll. Use “Merge” to combine the two.`);
  await env.DB.batch([
    env.DB.prepare('UPDATE participants SET name = ?, name_key = ?, email = ? WHERE id = ?').bind(name, p.user_id ? p.name_key : nameKey(name), mail, pid),
    env.DB.prepare('UPDATE responses SET name = ? WHERE participant_id = ?').bind(name, pid),
  ]);
  return json({ ok: true });
}
// ?answers=1 also deletes their answers; otherwise the answers stay, no longer linked to a name.
async function deleteParticipant(request, env, url, id, pid) {
  await adminPoll(request, env, id);
  await loadParticipant(env, id, pid);
  await env.DB.batch([
    url.searchParams.get('answers') === '1'
      ? env.DB.prepare('DELETE FROM responses WHERE participant_id = ?').bind(pid)
      : env.DB.prepare('UPDATE responses SET participant_id = NULL WHERE participant_id = ?').bind(pid),
    env.DB.prepare('DELETE FROM participants WHERE id = ?').bind(pid),
  ]);
  return json({ ok: true });
}
// Body: { into: participantId }. Moves all answers of :pid to `into`; where both answered the same round, the newer answer wins.
async function mergeParticipant(request, env, id, pid) {
  await adminPoll(request, env, id);
  const src = await loadParticipant(env, id, pid);
  const b = await body(request);
  if (typeof b.into !== 'string' || b.into === pid) throw new HttpError(400, 'Pick someone else to merge into');
  const dst = await loadParticipant(env, id, b.into);
  if (src.user_id && dst.user_id) throw new HttpError(409, 'Both are signed-in accounts, so they can’t be merged');
  const { results } = await env.DB.prepare('SELECT id, instance_id, participant_id, updated_at FROM responses WHERE participant_id IN (?, ?)').bind(src.id, dst.id).all();
  const byRound = {}, drop = [];
  for (const r of results) {
    const keep = byRound[r.instance_id];
    if (!keep) { byRound[r.instance_id] = r; continue; }
    if (r.updated_at > keep.updated_at) { drop.push(keep.id); byRound[r.instance_id] = r; } else drop.push(r.id);
  }
  await env.DB.batch([
    ...drop.map((rid) => env.DB.prepare('DELETE FROM responses WHERE id = ?').bind(rid)),
    env.DB.prepare('UPDATE responses SET participant_id = ?, name = ? WHERE participant_id IN (?, ?)').bind(dst.id, dst.name, src.id, dst.id),
    env.DB.prepare('DELETE FROM participants WHERE id = ?').bind(src.id),
    // If the merged one was an account, the remaining person now belongs to that account.
    src.user_id
      ? env.DB.prepare('UPDATE participants SET user_id = ?, name_key = ?, email = ? WHERE id = ?').bind(src.user_id, src.name_key, src.email, dst.id)
      : env.DB.prepare("UPDATE participants SET email = CASE WHEN email = '' THEN ? ELSE email END WHERE id = ?").bind(src.email, dst.id),
  ]);
  return json({ ok: true, removedAnswers: drop.length });
}
