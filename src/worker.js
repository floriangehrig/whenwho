// when-who: Cloudflare Worker + D1 (+ optional email via Resend)
//
// Bindings / variables:
//   DB        (required) D1 database
//   ASSETS    (optional) static assets binding serving /public; the single-file build inlines the page instead
//   RESEND_API_KEY (optional secret) Resend API key (sending access). With MAIL_FROM, turns on server-sent emails
//   MAIL_FROM (optional) sender address on a domain verified in Resend, e.g. noreply@example.com
//   MAIL_PER_DAY (optional) recipients of invites per account (or per poll without one) per day, default 50
//   SITE_URL  (optional) public address of the site, e.g. https://polls.example.workers.dev (used in emails sent by the cron job)
//   TURNSTILE_SITE_KEY (optional var) + TURNSTILE_SECRET (secret): bot check before a sign-in code is emailed.
//   CAL_TOKEN_KEY (optional secret) encrypts stored calendar tokens; needed for Google / Outlook calendar sign-in, plus
//   GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET and / or MS_CLIENT_ID + MS_CLIENT_SECRET (secrets). Each provider shows up only when set.
//   AI        (optional) Workers AI binding: "fill my answer from text" (typed or spoken). Without it the ✨ button is hidden.
//   RETAIN_MONTHS (optional) delete polls with no activity for this many months, default 12; "0" turns it off
//   AI_MODEL  (optional) Workers AI text model, default AI_MODEL below. AI_PER_DAY (optional) text fills per person per day, default 20
//
// Accounts: anyone can sign in with a 6-digit code sent to their email (needs RESEND_API_KEY + MAIL_FROM).
// Only signed-in users can create polls, and only the account that owns a poll can manage it.
// Without RESEND_API_KEY + MAIL_FROM, codes are written to the log (local development only).
// Answers given while signed in belong to the account (its email), so names don't have to be unique for them.

const MAX_RANGE_DAYS = 92;
const MAX_RESPONSES = 300;
const MAX_MEETINGS = 100;
const MAX_MEETING_DAYS = 62; // longest multi-day meeting
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
const AI_PER_DAY = 20;         // default for env.AI_PER_DAY: text fills per account (or IP) per day (Workers AI free: 10,000 neurons/day)
const AI_MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';

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
  "script-src 'self' 'sha256-Oj3uvXq69ArbY39pGovS1YnziZRWGq8i0+q5fssWv6E=' 'sha256-IriAjNCDJsimHfcvZmdK1NPSB8sxz3g7Ya1NhMmxiQo=' https://challenges.cloudflare.com",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self' https://photon.komoot.io", // place search falls back to Photon from the browser when /api/places fails
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
  h.set('cross-origin-opener-policy', 'same-origin');
  h.set('permissions-policy', 'camera=(), microphone=(self), geolocation=()');
  if ((h.get('content-type') || '').startsWith('text/html')) h.set('content-security-policy', CSP);
  if (url.protocol === 'https:') h.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
  return r;
}

class HttpError extends Error {
  constructor(status, message, extra = {}) { super(message); this.status = status; this.extra = extra; }
}
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });

// Place suggestions for location fields: GET /api/places?q=…&lang=… asks Photon (photon.komoot.io, OpenStreetMap data,
// no key) from here instead of from the browser, so phone content blockers, tracking protection and shared mobile IPs
// (rate limits) can't stop it. Only the typed text goes out; answers are trimmed to the address parts and cached for a day.
const PLACE_KEYS = ['name', 'street', 'housenumber', 'postcode', 'city', 'town', 'village', 'district', 'state', 'country'];
async function placeSearch(url, ctx) {
  const q = (url.searchParams.get('q') || '').trim().slice(0, 120);
  if (q.length < 3) return json({ places: [] });
  const lang = ['de', 'en', 'fr'].includes(url.searchParams.get('lang')) ? url.searchParams.get('lang') : 'default'; // Photon refuses others (400)
  const key = new Request(`https://places.cache/?q=${encodeURIComponent(q.toLowerCase())}&lang=${lang}`);
  const cache = caches.default;
  const hit = await cache.match(key);
  if (hit) return hit;
  let r;
  try {
    r = await fetch(`https://photon.komoot.io/api/?q=${encodeURIComponent(q)}&limit=6&lang=${lang}`, { headers: { 'user-agent': 'when-who (https://when-who.app)' } });
  } catch (e) { console.log('places: photon fetch failed', String(e)); throw new HttpError(502, 'Place search is not available right now'); }
  // Photon refuses some Cloudflare locations (seen for requests served in Helsinki); the page then asks Photon itself.
  if (!r.ok) { console.log('places: photon status', r.status); throw new HttpError(r.status === 429 ? 429 : 502, 'Place search is not available right now'); }
  const j = await r.json().catch(() => ({}));
  const places = (j.features || []).map((f) => Object.fromEntries(PLACE_KEYS.filter((k) => f.properties && typeof f.properties[k] === 'string').map((k) => [k, f.properties[k].slice(0, 120)])));
  const res = json({ places }, 200, { 'cache-control': 'public, max-age=86400' });
  ctx.waitUntil(cache.put(key, res.clone()));
  return res;
}

async function route(request, env, ctx, url) {
  const parts = url.pathname.split('/').filter(Boolean); // ['api','polls',id,...]
  const m = request.method;
  const cookies = parseCookies(request);
  // A request that carries the session cookie and changes something must come from this site (CSRF guard).
  // Sign-in requests too, so another site can't sign a visitor into an attacker's account.
  if ((cookies.ww_session || parts[1] === 'auth') && m !== 'GET' && m !== 'HEAD' && request.headers.get('origin') !== url.origin)
    throw new HttpError(403, 'Request from another site was blocked');
  // Flood guard (Workers Rate Limiting bindings, in memory, no D1 writes): changes and place lookups per IP per minute,
  // so a script can't burn the free plan's daily D1 / Workers allowance. Missing bindings (local dev) = no limit.
  const rl = parts[1] === 'places' ? env.RL_PLACES : m !== 'GET' && m !== 'HEAD' ? env.RL_WRITE : null;
  if (rl && !(await rl.limit({ key: clientIp(request) })).success) throw new HttpError(429, 'Too many requests. Wait a minute and try again.');
  if (parts[1] === 'places' && m === 'GET') return placeSearch(url, ctx); // before the session lookup: it runs on every keystroke
  USERS.set(request, await getUser(env, cookies));
  if (parts[1] === 'config' && m === 'GET') return json({ emailEnabled: emailEnabled(env), turnstileSiteKey: env.TURNSTILE_SECRET ? env.TURNSTILE_SITE_KEY || '' : '', calProviders: calProviders(env), aiFill: !!env.AI, operator: env.OPERATOR_NAME || '', contact: env.CONTACT_EMAIL || '', address: env.OPERATOR_ADDRESS || '', phone: env.OPERATOR_PHONE || '', dpa: env.DPA_NAME || '' });
  if (parts[1] === 'oauth' && OAUTH[parts[2]] && m === 'GET') {
    if (parts[3] === 'start') return oauthStart(request, env, url, parts[2]);
    if (parts[3] === 'callback') return oauthCallback(request, env, url, parts[2]);
    throw new HttpError(404, 'Not found');
  }
  if (parts[1] === 'auth') {
    if (parts[2] === 'code' && m === 'POST') return sendLoginCode(request, env, url);
    if (parts[2] === 'verify' && m === 'POST') return verifyLoginCode(request, env, url);
    if (parts[2] === 'logout' && m === 'POST') return logout(request, env, cookies, url);
    throw new HttpError(404, 'Not found');
  }
  if (parts[1] === 'me') {
    if (!parts[2] && m === 'GET') return me(request, env);
    if (!parts[2] && m === 'PATCH') return updateProfile(request, env);
    if (parts[2] === 'email' && !parts[3] && m === 'POST') return sendEmailChangeCode(request, env, url);
    if (parts[2] === 'email' && parts[3] === 'verify' && !parts[4] && m === 'POST') return verifyEmailChange(request, env, url);
    if (parts[2] === 'polls' && m === 'GET') return myPolls(request, env);
    if (parts[2] === 'export' && !parts[3] && m === 'GET') return exportMe(request, env);
    if (parts[2] === 'delete' && !parts[3] && m === 'POST') return sendDeleteCode(request, env, url);
    if (parts[2] === 'delete' && parts[3] === 'verify' && !parts[4] && m === 'POST') return deleteAccount(request, env, url);
    if (parts[2] === 'calendar' && m === 'POST') return fetchCalendar(request, env);
    if (parts[2] === 'friends') {
      if (!parts[3] && m === 'GET') return listFriends(request, env);
      if (!parts[3] && m === 'POST') return addFriend(request, env, url);
      if (parts[3] && parts[4] === 'accept' && !parts[5] && m === 'POST') return acceptFriend(request, env, parts[3]);
      if (parts[3] && !parts[4] && m === 'DELETE') return deleteFriend(request, env, parts[3]);
    }
    if (parts[2] === 'favourites') {
      if (!parts[3] && m === 'POST') return addFavourite(request, env);
      if (parts[3] && !parts[4] && m === 'DELETE') return deleteFavourite(request, env, parts[3]);
    }
    if (parts[2] === 'groups') {
      if (!parts[3] && m === 'POST') return addGroup(request, env);
      if (parts[3] && !parts[4] && m === 'PATCH') return updateGroup(request, env, parts[3]);
      if (parts[3] && !parts[4] && m === 'DELETE') return deleteGroup(request, env, parts[3]);
    }
    if (parts[2] === 'contacts' && parts[3] && !parts[4] && m === 'GET') return accountContacts(request, env, parts[3]);
    if (parts[2] === 'calendars') {
      if (!parts[3] && m === 'GET') return listCalendars(request, env);
      if (!parts[3] && m === 'POST') return addCalendar(request, env);
      if (parts[3] && !parts[4] && m === 'PATCH') return updateCalendar(request, env, parts[3]);
      if (parts[3] && !parts[4] && m === 'DELETE') return deleteCalendar(request, env, parts[3]);
      if (parts[3] && parts[4] === 'busy' && !parts[5] && m === 'GET') return calendarBusy(request, env, url, parts[3]);
    }
    if (parts[2] === 'calendar-accounts' && parts[3]) {
      if (!parts[4] && m === 'DELETE') return deleteCalAccount(request, env, parts[3]);
      if (parts[4] === 'refresh' && m === 'POST') return refreshCalAccount(request, env, parts[3]);
    }
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
  if (a === 'calendar.ics' && m === 'GET') return calendar(request, env, url, id);
  if (a === 'image' && m === 'GET') return pollImage(request, env, url, id);
  if (a === 'invite' && m === 'POST') return invitePoll(request, env, url, id);
  if (a === 'claim' && m === 'POST') return claimPoll(request, env, id);
  if (a === 'meetings' && b === 'send' && !c && m === 'POST') return sendAllMeetings(request, env, url, id);
  if (a === 'chat') {
    if (!b && m === 'GET') return listChat(request, env, url, id);
    if (!b && m === 'POST') return postChat(request, env, id);
    if (b && !c && m === 'DELETE') return deleteChat(request, env, id, b);
    if (b && c === 'react' && !d && m === 'POST') return reactChat(request, env, id, b);
  }
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
    if (b && c === 'fill-text' && !d && m === 'POST') return fillFromText(request, env, id, b);
    if (b && c === 'suggest-text' && !d && m === 'POST') return suggestFromText(request, env, id, b);
    if (b && c === 'recall' && !d && m === 'POST') return recall(request, env, id, b);
    if (b && c === 'busy' && !d && m === 'PUT') return shareBusy(request, env, id, b);
    if (b && c === 'meetings' && d && e === 'send' && m === 'POST') return sendInvite(request, env, url, id, b, d);
  }
  if (a === 'responses' && b && c === 'votes' && !d && m === 'PUT') return voteMeetings(request, env, id, b);
  if (a === 'responses' && b && c === 'extra' && !d && m === 'PUT') return answerQuestions(request, env, id, b);
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
// Day pattern: which days of a round are offered. {wd:[0..6]|null (0 = Monday), dom:[from,to]|null}; null = every day.
// Several periods (e.g. Mon-Fri 17-22 and Sat-Sun 10-22): {wd, dom, periods:[{wd,dom,hs,he}]}, where the top-level
// wd/dom are the union of the periods (a superset, for older pages) and hour_start/hour_end span all of them.
const MAX_PERIODS = 10;
function parseDays(v) {
  if (v == null || v === '') return null;
  if (typeof v !== 'object' || Array.isArray(v)) throw new HttpError(400, 'Invalid day pattern');
  let wd = null, dom = null;
  if (v.wd != null) {
    if (!Array.isArray(v.wd) || !v.wd.length) throw new HttpError(400, 'Pick at least one weekday');
    if (v.wd.some((x) => !Number.isInteger(x) || x < 0 || x > 6)) throw new HttpError(400, 'Invalid weekday');
    wd = [...new Set(v.wd)].sort((a, b) => a - b);
    if (wd.length === 7) wd = null;
  }
  if (v.dom != null) {
    if (!Array.isArray(v.dom) || v.dom.length !== 2) throw new HttpError(400, 'Invalid days of the month');
    const a = int(v.dom[0], 1, 31, 'First day of the month'), b = int(v.dom[1], 1, 31, 'Last day of the month');
    if (b < a) throw new HttpError(400, 'The last day of the month is before the first');
    dom = a === 1 && b === 31 ? null : [a, b];
  }
  return wd || dom ? { wd, dom } : null;
}
function parsePattern(v) {
  const base = parseDays(v);
  if (!v || typeof v !== 'object' || v.periods == null) return base;
  if (!Array.isArray(v.periods) || !v.periods.length || v.periods.length > MAX_PERIODS) throw new HttpError(400, `Add 1 to ${MAX_PERIODS} periods`);
  const periods = v.periods.map((x) => {
    const d = parseDays(x) || { wd: null, dom: null };
    const hs = int(x.hs, 0, 23, 'First hour'), he = int(x.he, 1, 24, 'Last hour');
    if (he <= hs) throw new HttpError(400, 'The last hour must be after the first hour');
    return { wd: d.wd, dom: d.dom, hs, he };
  });
  const allWd = periods.some((p) => !p.wd), allDom = periods.some((p) => !p.dom);
  const wd = allWd ? null : [...new Set(periods.flatMap((p) => p.wd))].sort((a, b) => a - b);
  const dom = allDom ? null : [Math.min(...periods.map((p) => p.dom[0])), Math.max(...periods.map((p) => p.dom[1]))];
  return { wd: wd && wd.length < 7 ? wd : null, dom: dom && !(dom[0] === 1 && dom[1] === 31) ? dom : null, periods };
}
function patternOf(poll) { try { return poll.day_pattern ? JSON.parse(poll.day_pattern) : null; } catch (e) { return null; } }
function matchesPattern(d, pat) {
  if (!pat) return true;
  const x = new Date(d + 'T00:00:00Z');
  return (!pat.wd || pat.wd.includes((x.getUTCDay() + 6) % 7)) && (!pat.dom || (x.getUTCDate() >= pat.dom[0] && x.getUTCDate() <= pat.dom[1]));
}
// A typical week (weekly polls) has no days of the month, so dom is ignored there.
const isWeekDate = (d) => d >= WEEK0 && d <= '2001-01-07';
const dayMatch = (d, p) => matchesPattern(d, isWeekDate(d) ? (p.wd ? { wd: p.wd, dom: null } : null) : p);
// The periods that apply to date d (null = the poll has no periods).
function periodsOn(pat, d) { return pat && Array.isArray(pat.periods) ? pat.periods.filter((p) => dayMatch(d, p)) : null; }
function datesOf(inst, poll) {
  const pat = poll ? patternOf(poll) : null; const out = [];
  for (let d = inst.start_date; d <= inst.end_date; d = addDays(d, 1)) {
    const ps = periodsOn(pat, d);
    if (ps ? ps.length : !pat || dayMatch(d, pat)) out.push(d);
  }
  return out;
}
// Weekly schedule polls ask about a typical week. Their one round covers this fixed Monday-Sunday,
// so answers reuse the date-keyed format; the page only shows weekday names. It never closes by date.
const WEEK0 = '2001-01-01';
const isWeek0 = (inst) => inst.start_date === WEEK0;
const effStatus = (inst) => (inst.status === 'closed' || (!isWeek0(inst) && inst.end_date < today()) ? 'closed' : 'open');
const WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
// Email language: 'en' or 'de'. Polls store theirs (polls.lang, from the organiser's page language); sign-in codes use the request's.
const langOf = (x) => (x === 'de' ? 'de' : 'en');
const LOCALE = { en: 'en-GB', de: 'de-DE' };
// The page sends its language in x-lang. Actions by the poll's owner (create, settings, invites) set the poll's email language.
const reqLang = (request) => langOf(request.headers.get('x-lang'));
async function adoptLang(request, env, poll) {
  if (!request.headers.get('x-lang') || reqLang(request) === langOf(poll.lang)) return;
  poll.lang = reqLang(request);
  await env.DB.prepare('UPDATE polls SET lang = ? WHERE id = ?').bind(poll.lang, poll.id).run();
}
const WEEKDAYS_DE = ['Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag', 'Sonntag'];
const wdOf = (d) => (new Date(d + 'T00:00:00Z').getUTCDay() + 6) % 7; // 0 = Monday
// First date on or after `from` that falls on weekday wd.
const firstOnWeekday = (from, wd) => addDays(from, (wd - wdOf(from) + 7) % 7);

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
  // A new round of a series asks the same questions as the last one (without meeting links; place votes for a meeting stay behind).
  if (seq > 0 && fields.questions === undefined) {
    const prev = await env.DB.prepare('SELECT questions FROM instances WHERE poll_id = ? AND seq < ? ORDER BY seq DESC LIMIT 1').bind(poll.id, seq).first('questions');
    const qs = questionsOf({ questions: prev }).filter((q) => !q.meetings || q.type !== 'choice' || !q.place)
      .map(({ meetings, closed, at, ...q }) => ({ ...q, at: now() }));
    if (qs.length) fields = { ...fields, questions: JSON.stringify(qs) };
  }
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
// Password guesses are throttled per IP per poll and per poll overall (rotating IPs doesn't help). Once over the limit even
// the right password gets 429, so a guesser can't tell when they hit it. Requests without a password cost nothing.
const PW_FAILS_IP = 10;     // wrong poll passwords per IP per poll ...
const PW_FAILS_POLL = 50;   // ... and per poll from anywhere, within FAIL_WINDOW_MIN
async function guardedPasswordOk(env, request, poll, pw) {
  if (!poll.password_hash || !pw) return passwordOk(poll, pw);
  const msg = `Too many wrong passwords. Try again in ${FAIL_WINDOW_MIN} minutes.`;
  const ipKey = clientIp(request) + ':' + poll.id;
  await checkThrottle(env, request, 'pw', { key: ipKey, max: PW_FAILS_IP, msg });
  await checkThrottle(env, request, 'pw', { key: 'p:' + poll.id, max: PW_FAILS_POLL, msg });
  if (await passwordOk(poll, pw)) return true;
  await env.DB.batch([
    env.DB.prepare('INSERT INTO login_attempts (ip, kind, at) VALUES (?, ?, ?)').bind(ipKey, 'pw', now()),
    env.DB.prepare('INSERT INTO login_attempts (ip, kind, at) VALUES (?, ?, ?)').bind('p:' + poll.id, 'pw', now()),
  ]);
  return false;
}
async function checkPassword(env, request, poll) {
  const pw = request.headers.get('x-poll-password');
  if (!(await guardedPasswordOk(env, request, poll, pw)))
    throw new HttpError(401, pw ? 'Wrong password' : 'Password required', { needPassword: true, title: poll.title });
}
function publicPoll(poll, admin) {
  const p = {
    id: poll.id, title: poll.title, description: poll.description, kind: poll.kind,
    unit: poll.unit, every: poll.every, anchor: poll.anchor, openDays: poll.open_days, deadlineDays: poll.deadline_days,
    answerMode: poll.answer_mode, hourStart: poll.hour_start, hourEnd: poll.hour_end, dayPattern: patternOf(poll),
    hideResults: !!poll.hide_results, allowComments: !!poll.allow_comments, requireEmail: !!poll.require_email, invitedOnly: !!poll.invited_only, hasPassword: !!poll.password_hash,
    icon: poll.icon || '', image: poll.image ? poll.image_at || '1' : '', // image: version for /image?v=
  };
  if (admin) Object.assign(p, { notifyOpen: !!poll.notify_open, remindDays: poll.remind_days });
  return p;
}
function publicInstance(inst, extra = {}) {
  return { id: inst.id, seq: inst.seq, createdAt: inst.created_at, startDate: inst.start_date, endDate: inst.end_date, deadline: inst.deadline,
    status: effStatus(inst), manualStatus: inst.status, note: inst.note, meetings: JSON.parse(inst.meetings || '[]'), questions: questionsOf(inst), ...extra };
}

function validateEntries(entries, poll, dates) {
  if (entries == null) return {};
  if (typeof entries !== 'object' || Array.isArray(entries)) throw new HttpError(400, 'Invalid answers');
  const allowed = new Set(dates), out = {};
  const pat = patternOf(poll);
  for (const [k, v] of Object.entries(entries)) {
    if (!allowed.has(k)) continue;
    const ps = periodsOn(pat, k);
    const hourOk = (h) => Number.isInteger(h) && (ps ? ps.some((p) => h >= p.hs && h < p.he) : h >= poll.hour_start && h < poll.hour_end);
    if (v === 'y' || v === 'i' || v === 'm' || v === 'n') { out[k] = v; continue; }
    if (poll.answer_mode === 'days') throw new HttpError(400, 'This poll only takes whole days');
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const seen = new Set(), pick = (arr) => (Array.isArray(arr) ? arr : []).filter((h) => hourOk(h) && !seen.has(h) && seen.add(h)).sort((x, y) => x - y);
      const y = pick(v.y), i = pick(v.i), m = pick(v.m), n = pick(v.n);
      if (y.length || i.length || m.length || n.length) out[k] = i.length ? { y, i, m, n } : { y, m, n };
      continue;
    }
    throw new HttpError(400, 'Invalid answer for ' + k);
  }
  return out;
}

// Quick fill behind an answer: { rules: [{ pat, hs, he, st, off? }], base: {entries}, over?: {entries} }
// (base = marks from before the rules, over = days changed by hand after them).
// Returns the JSON to store, or '' when there are no rules.
const MAX_FILL_RULES = 20;
function parseFill(v, poll, dates) {
  if (v == null || v === '') return '';
  if (typeof v !== 'object' || Array.isArray(v) || !Array.isArray(v.rules)) throw new HttpError(400, 'Invalid quick fill');
  if (v.rules.length > MAX_FILL_RULES) throw new HttpError(400, `At most ${MAX_FILL_RULES} quick fill rules`);
  if (!v.rules.length) return '';
  const rules = v.rules.map((r) => {
    if (!r || typeof r !== 'object') throw new HttpError(400, 'Invalid quick fill');
    const pat = parseDays(r.pat), hs = int(r.hs, 0, 23, 'First hour'), he = int(r.he, 1, 24, 'Last hour');
    if (he <= hs) throw new HttpError(400, 'The last hour must be after the first hour');
    if (!['y', 'i', 'm', 'x'].includes(r.st)) throw new HttpError(400, 'Invalid quick fill');
    return { pat, hs, he, st: r.st, ...(r.off === true ? { off: true } : {}) }; // off = switched off, kept in the list
  });
  // over = days changed by hand after the rules ('n' = cleared by hand); they sit on top of the rules
  const over = validateEntries(v.over, poll, dates);
  return JSON.stringify({ rules, base: validateEntries(v.base, poll, dates), ...(Object.keys(over).length ? { over } : {}) });
}

// old: the meetings saved before, so only newly added ones get an 'at' stamp (older ones never had one).
function validateMeetings(list, poll, old = []) {
  const known = new Set(old.map((x) => x.id)), wasProposed = new Set(old.filter((x) => x.proposed).map((x) => x.id));
  if (!Array.isArray(list) || list.length > MAX_MEETINGS) throw new HttpError(400, 'Invalid meetings');
  const weekly = poll.kind === 'weekly';
  return list.map((mt) => {
    if (!mt || typeof mt !== 'object') throw new HttpError(400, 'Invalid meeting');
    if (!isDate(mt.date)) throw new HttpError(400, 'Meeting needs a date');
    // Weekly polls: the date only picks the weekday (inside WEEK0); `repeat` says when the series runs.
    let repeat;
    if (weekly) {
      if (mt.date < WEEK0 || mt.date > addDays(WEEK0, 6)) throw new HttpError(400, 'Invalid weekday');
      const r = mt.repeat;
      if (!r || typeof r !== 'object') throw new HttpError(400, 'A weekly meeting needs a start date');
      if (!isDate(r.from)) throw new HttpError(400, 'Pick the date of the first meeting');
      if (![1, 2, 4].includes(r.every)) throw new HttpError(400, 'Repeat every 1, 2 or 4 weeks');
      if (r.until != null && r.until !== '' && (!isDate(r.until) || r.until < r.from)) throw new HttpError(400, 'The end date is before the first meeting');
      repeat = { from: r.from, every: r.every, until: r.until || null };
    }
    const out = {
      id: /^[A-Za-z0-9]{4,20}$/.test(mt.id || '') ? mt.id : randomId(8),
      date: mt.date, allDay: !!mt.allDay,
      title: str(mt.title, 120, 'Meeting title'), location: str(mt.location, 200, 'Location'), note: str(mt.note, 1000, 'Note'),
      extra: str(mt.extra, 1000, 'Extra description') || undefined,
      sentAt: typeof mt.sentAt === 'string' && mt.sentAt.length < 40 ? mt.sentAt : undefined,
      at: !mt.proposed && wasProposed.has(mt.id) ? now() // a proposal that was just confirmed
        : typeof mt.at === 'string' && /^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(mt.at) ? mt.at : known.has(mt.id) ? undefined : now(), // when it was added (activity feed)
      proposed: mt.proposed ? true : undefined, // put up for a vote (responses.votes); not in .ics or emails until confirmed
      ...(repeat ? { repeat } : {}),
    };
    // endDate: last day of a multi-day all-day meeting (trip, offsite, holiday); one-off meetings only.
    if (mt.endDate != null && mt.endDate !== '' && mt.endDate !== mt.date) {
      if (weekly || !out.allDay || !isDate(mt.endDate) || mt.endDate < mt.date || mt.endDate > addDays(mt.date, MAX_MEETING_DAYS - 1))
        throw new HttpError(400, 'Invalid end date');
      out.endDate = mt.endDate;
    }
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

  const site = siteUrl(env, url.origin), de = reqLang(request) === 'de';
  const host = site.replace(/^https?:\/\//, ''), mins = CODE_MINUTES;
  const ignore = de ? 'Falls du das nicht angefordert hast, kannst du diese E-Mail ignorieren: Ohne den Code kann sich niemand anmelden.'
    : "If you didn't ask for this, you can ignore this email: nobody can sign in without the code.";
  const text = de ? `Dein when-who-Anmeldecode:\n\n    ${code}\n\nEr ist ${mins} Minuten gültig. Gib ihn auf ${site} ein, um dich anzumelden.\n\n${ignore}`
    : `Your when-who sign-in code is:\n\n    ${code}\n\nIt is valid for ${mins} minutes. Enter it on ${site} to sign in.\n\n${ignore}`;
  const intro = de ? `Gib diesen Code auf <a href="${escHtml(site)}" style="color:#1F5EFF">${escHtml(host)}</a> ein, um dich anzumelden. Er ist ${mins} Minuten gültig.`
    : `Enter this code on <a href="${escHtml(site)}" style="color:#1F5EFF">${escHtml(host)}</a> to sign in. It is valid for ${mins} minutes.`;
  if (emailEnabled(env)) {
    await sendEmail(env, {
      fromName: 'when-who', to: [addr],
      subject: de ? `Dein Anmeldecode: ${code}` : `Your sign-in code: ${code}`, text,
      html: emailHtml(`<h1 style="margin:0 0 8px;font-size:22px;line-height:1.3;color:#0B1F3A">${de ? 'Dein Anmeldecode' : 'Your sign-in code'}</h1>
        <p style="margin:0 0 20px;color:#334155">${intro}</p>
        <div style="margin:0 0 24px;padding:18px;background:#E8EFFF;border-radius:10px;text-align:center;font-size:32px;font-weight:700;letter-spacing:10px;color:#0B1F3A;font-family:ui-monospace,Menlo,Consolas,monospace">${code}</div>
        <p style="margin:0;font-size:13px;color:#5B6578">${escHtml(ignore)}</p>`,
        { preheader: de ? `Dein Anmeldecode ist ${code}` : `Your sign-in code is ${code}`, site, lang: de ? 'de' : 'en' }),
    });
  } else {
    console.log(`[dev] sign-in code for ${addr}: ${code}\n${text}`); // email not set up: local development
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
  const signupName = typeof b.name === 'string' && b.name.trim() ? personName(b.name) : '';
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
  // Sign-up sends a name: it becomes the profile name of a new account (an existing account keeps its own).
  await env.DB.prepare('INSERT INTO users (id, email, name, created_at, last_login_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(email) DO UPDATE SET last_login_at = excluded.last_login_at')
    .bind('u_' + randomId(16), addr, signupName, t, t).run();
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
  const cal = await env.DB.prepare('SELECT COUNT(*) AS n, SUM(auto) AS auto, (SELECT url FROM user_calendars WHERE user_id = ?1 AND url IS NOT NULL ORDER BY position, created_at LIMIT 1) AS url FROM user_calendars WHERE user_id = ?1').bind(u.id).first();
  // Feed URLs are secrets: the page only learns which host the first one points at.
  return json({ user: { name: u.name, email: u.email, avatar: u.avatar, avatarImg: img || '', since: u.created,
    calendar: cal.url ? icalHost(cal.url) : '', calendars: cal.n || 0, calendarsAuto: cal.auto || 0,
    friendRequests: (await friendRequestCount(env, u)) || 0 } });
}
// Body: { name?, avatar? (emoji or ''), avatarImg? (data URL or ''), icalUrl? (iCal feed or '') }. A new name also renames the account's answers.
async function updateProfile(request, env) {
  const user = requireUser(request);
  const b = await body(request), u = {};
  if (b.name !== undefined) u.name = b.name === '' ? '' : personName(b.name);
  if (b.avatar !== undefined) u.avatar = emojiIcon(b.avatar, 'Avatar');
  if (b.avatarImg !== undefined) u.avatar_img = imageData(b.avatarImg, 'Picture');
  if (b.icalUrl !== undefined) u.ical_url = b.icalUrl === '' || b.icalUrl === null ? null : icalUrl(b.icalUrl);
  // Older pages save a single link here: it becomes one of the account's calendars too.
  if (u.ical_url) await insertIcal(env, user.id, u.ical_url, '');
  const cols = Object.keys(u);
  if (!cols.length) return json({ ok: true });
  const stmts = [env.DB.prepare(`UPDATE users SET ${cols.map((c) => c + ' = ?').join(', ')} WHERE id = ?`).bind(...cols.map((c) => u[c]), user.id)];
  if (u.name) stmts.push(
    env.DB.prepare('UPDATE participants SET name = ? WHERE user_id = ?').bind(u.name, user.id),
    env.DB.prepare('UPDATE responses SET name = ? WHERE participant_id IN (SELECT id FROM participants WHERE user_id = ?)').bind(u.name, user.id));
  await env.DB.batch(stmts);
  return json({ ok: true });
}
// ---------- change the account's email ----------
// Step 1, body { email }: emails a 6-digit code to the new address. It is kept in login_codes under
// 'change:<user id>:<address>', so it can't be used to sign in. Step 2, body { email, code }: moves the account
// to the new address and updates the copies of it in the account's polls (participants, answers, owned polls).
// Stores a 6-digit code (hashed) under `key` in login_codes and emails it to `to`. Keys other than a plain address
// ('change:…', 'delete:…') can't be used to sign in.
async function mailCode(env, url, key, to, de, { title, intro, ignore }) {
  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  await env.DB.prepare('INSERT OR REPLACE INTO login_codes (email, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, 0, ?)')
    .bind(key, await codeHash(key, code), new Date(Date.now() + CODE_MINUTES * 60000).toISOString(), now()).run();
  const text = `${intro}\n\n    ${code}\n\n${ignore}`;
  if (!emailEnabled(env)) { console.log(`[dev] code for ${key} -> ${to}: ${code}`); return; }
  await sendEmail(env, {
    fromName: 'when-who', to: [to], subject: `${title}: ${code}`, text,
    html: emailHtml(`<h1 style="margin:0 0 8px;font-size:22px;line-height:1.3;color:#0B1F3A">${escHtml(title)}</h1>
      <p style="margin:0 0 20px;color:#334155">${escHtml(intro)}</p>
      <div style="margin:0 0 24px;padding:18px;background:#E8EFFF;border-radius:10px;text-align:center;font-size:32px;font-weight:700;letter-spacing:10px;color:#0B1F3A;font-family:ui-monospace,Menlo,Consolas,monospace">${code}</div>
      <p style="margin:0;font-size:13px;color:#5B6578">${escHtml(ignore)}</p>`,
      { preheader: de ? `Dein Code ist ${code}` : `Your code is ${code}`, site: siteUrl(env, url.origin), lang: de ? 'de' : 'en' }),
  });
}
// Checks a code made by mailCode and uses it up. Throws 401 when it's wrong, expired or out of tries.
async function takeCode(env, request, key, code) {
  const wrong = new HttpError(401, 'That code is wrong or has expired. Check the latest email or ask for a new code.');
  const row = await env.DB.prepare('SELECT * FROM login_codes WHERE email = ?').bind(key).first();
  if (!row || row.expires_at < now() || row.attempts >= CODE_TRIES) {
    if (row) await env.DB.prepare('DELETE FROM login_codes WHERE email = ?').bind(key).run();
    await recordFail(env, request, 'code');
    throw wrong;
  }
  if (!safeEqual(await codeHash(key, code), row.code_hash)) {
    await env.DB.prepare('UPDATE login_codes SET attempts = attempts + 1 WHERE email = ?').bind(key).run();
    await recordFail(env, request, 'code');
    throw wrong;
  }
  const del = await env.DB.prepare('DELETE FROM login_codes WHERE email = ? AND code_hash = ?').bind(key, row.code_hash).run();
  if (!del.meta || !del.meta.changes) throw wrong;
}
const changeKey = (userId, addr) => `change:${userId}:${addr}`;
async function sendEmailChangeCode(request, env, url) {
  const user = requireUser(request);
  const b = await body(request);
  const addr = (email(b.email) || '').toLowerCase();
  if (!addr) throw new HttpError(400, 'Enter your new email address');
  if (addr === user.email.toLowerCase()) throw new HttpError(400, 'That’s already your email address');
  const tooMany = `Too many emails. Try again in ${FAIL_WINDOW_MIN} minutes.`;
  await checkThrottle(env, request, 'code-send', { max: CODE_SENDS_IP, msg: tooMany });
  const ekey = 'e:' + (await sha256('mail:' + addr));
  await checkThrottle(env, request, 'code-send', { key: ekey, max: CODE_SENDS_EMAIL, msg: tooMany });
  await checkThrottle(env, request, 'code-send', { key: 'u:' + user.id, max: CODE_SENDS_EMAIL, msg: tooMany });
  await recordFail(env, request, 'code-send');
  await recordFail(env, request, 'code-send', ekey);
  await recordFail(env, request, 'code-send', 'u:' + user.id);
  // One change in progress per account.
  await env.DB.prepare('DELETE FROM login_codes WHERE substr(email, 1, ?) = ?').bind(`change:${user.id}:`.length, `change:${user.id}:`).run();
  const de = reqLang(request) === 'de', mins = CODE_MINUTES;
  await mailCode(env, url, changeKey(user.id, addr), addr, de, {
    title: de ? 'Neue E-Mail-Adresse bestätigen' : 'Confirm your new email address',
    intro: de ? `Gib diesen Code auf when-who ein, um diese Adresse für dein Konto zu verwenden. Er ist ${mins} Minuten gültig.`
      : `Enter this code on when-who to use this address for your account. It is valid for ${mins} minutes.`,
    ignore: de ? 'Falls du das nicht warst, ignoriere diese E-Mail: Ohne den Code ändert sich nichts.'
      : "If this wasn't you, ignore this email: nothing changes without the code.",
  });
  return json({ ok: true, minutes: CODE_MINUTES });
}
async function verifyEmailChange(request, env, url) {
  const user = requireUser(request);
  await checkThrottle(env, request, 'code');
  const b = await body(request);
  const addr = (email(b.email) || '').toLowerCase();
  const code = typeof b.code === 'string' ? b.code.replace(/\s+/g, '') : '';
  if (!addr || !/^\d{6}$/.test(code)) throw new HttpError(400, 'Enter the 6-digit code from the email');
  await takeCode(env, request, changeKey(user.id, addr), code);
  // They proved they own the address, so it's fine to say it's taken.
  if (await env.DB.prepare('SELECT 1 FROM users WHERE email = ? AND id != ?').bind(addr, user.id).first())
    throw new HttpError(409, 'That address already has its own account on when-who. Pick another address.');
  const old = user.email.toLowerCase();
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET email = ? WHERE id = ?').bind(addr, user.id),
    // Copies of the address in the polls: this account's participants and answers, legacy organiser address of own polls.
    env.DB.prepare('UPDATE participants SET email = ? WHERE user_id = ?').bind(addr, user.id),
    env.DB.prepare('UPDATE responses SET email = ? WHERE participant_id IN (SELECT id FROM participants WHERE user_id = ?)').bind(addr, user.id),
    env.DB.prepare('UPDATE polls SET admin_email = ? WHERE owner_id = ? AND LOWER(admin_email) = ?').bind(addr, user.id, old),
    // Friend requests that already reached this account follow it (to_id stays the same).
    env.DB.prepare('UPDATE OR IGNORE friends SET to_email = ? WHERE to_id = ?').bind(addr, user.id),
  ]);
  // Let the old address know, in case it wasn't them.
  if (emailEnabled(env)) {
    const de = reqLang(request) === 'de', site = siteUrl(env, url.origin), help = env.CONTACT_EMAIL;
    const text = de ? `Die E-Mail-Adresse deines when-who-Kontos wurde von ${old} auf ${addr} geändert. Anmeldecodes gehen ab jetzt an die neue Adresse.${help ? '\n\nWarst du das nicht? Antworte auf diese E-Mail.' : ''}`
      : `The email address of your when-who account was changed from ${old} to ${addr}. Sign-in codes now go to the new address.${help ? "\n\nWasn't you? Reply to this email." : ''}`;
    await sendEmail(env, { fromName: 'when-who', to: [old], replyTo: help || undefined,
      subject: de ? 'Deine E-Mail-Adresse wurde geändert' : 'Your email address was changed', text,
      html: emailHtml(`<div style="white-space:pre-wrap">${escHtml(text)}</div>`, { site, lang: de ? 'de' : 'en' }) }).catch(() => {});
  }
  return json({ ok: true, email: addr });
}
// ---------- your data: export and account deletion (GDPR Art. 15, 17, 20) ----------
// USER_DATA lists EVERY table (npm run check fails otherwise). Per table: `rows` = the SQL whose rows go into the export,
// `del` = what deleting the account removes, or `skip` = why the table holds nothing to hand out or delete.
// Deletion runs top to bottom in one batch, so tables found through participants / owned polls come before those.
// Every ? is the user id (the number is counted from the SQL); MINE = my participant rows (my answers in any poll), OWNED = polls I own.
// After adding a migration: cover its tables / columns here, then bump USER_DATA_REVIEWED to its number.
const USER_DATA_REVIEWED = '0022';
const MINE = 'SELECT id FROM participants WHERE user_id = ?';
const OWNED = 'SELECT id FROM polls WHERE owner_id = ?';
const USER_DATA = {
  responses: { rows: `SELECT * FROM responses WHERE participant_id IN (${MINE}) OR poll_id IN (${OWNED})`,
    del: `DELETE FROM responses WHERE participant_id IN (${MINE}) OR poll_id IN (${OWNED})` },
  shared_busy: { rows: `SELECT * FROM shared_busy WHERE participant_id IN (${MINE}) OR poll_id IN (${OWNED})`,
    del: `DELETE FROM shared_busy WHERE participant_id IN (${MINE}) OR poll_id IN (${OWNED})` },
  participants: { rows: `SELECT * FROM participants WHERE user_id = ? OR poll_id IN (${OWNED})`,
    del: `DELETE FROM participants WHERE user_id = ? OR poll_id IN (${OWNED})` },
  messages: { rows: `SELECT * FROM messages WHERE user_id = ? OR poll_id IN (${OWNED})`,
    del: `DELETE FROM messages WHERE user_id = ? OR poll_id IN (${OWNED})` }, // my reactions on others' messages: dropReactions()
  chat_reads: { rows: 'SELECT * FROM chat_reads WHERE user_id = ?',
    del: `DELETE FROM chat_reads WHERE user_id = ? OR poll_id IN (${OWNED})` },
  instances: { rows: `SELECT * FROM instances WHERE poll_id IN (${OWNED})`,
    del: `DELETE FROM instances WHERE poll_id IN (${OWNED})` },
  polls: { rows: `SELECT * FROM polls WHERE owner_id = ? OR id IN (SELECT poll_id FROM participants WHERE user_id = ?)`,
    del: 'DELETE FROM polls WHERE owner_id = ?' }, // export: polls I own in full, polls I answered for their titles
  favourites: { rows: 'SELECT * FROM favourites WHERE user_id = ?', del: 'DELETE FROM favourites WHERE user_id = ?' },
  contact_groups: { rows: 'SELECT * FROM contact_groups WHERE user_id = ?', del: 'DELETE FROM contact_groups WHERE user_id = ?' },
  friends: { rows: 'SELECT * FROM friends WHERE from_id = ? OR to_id = ?', del: 'DELETE FROM friends WHERE from_id = ? OR to_id = ?' },
  user_calendars: { rows: 'SELECT * FROM user_calendars WHERE user_id = ?', del: 'DELETE FROM user_calendars WHERE user_id = ?' },
  calendar_accounts: { rows: 'SELECT * FROM calendar_accounts WHERE user_id = ?', del: 'DELETE FROM calendar_accounts WHERE user_id = ?' }, // tokens revoked first
  oauth_states: { skip: 'calendar sign-ins in progress (deleted after an hour)', del: 'DELETE FROM oauth_states WHERE user_id = ?' },
  mail_log: { rows: 'SELECT * FROM mail_log WHERE user_id = ?', del: 'DELETE FROM mail_log WHERE user_id = ?' },
  sessions: { skip: 'sign-in tokens', del: 'DELETE FROM sessions WHERE user_id = ?' },
  login_codes: { skip: 'one-time codes (expire after 10 minutes)',
    del: "DELETE FROM login_codes WHERE email = (SELECT email FROM users WHERE id = ?) OR email LIKE 'change:' || ? || ':%' OR email = 'delete:' || ?" },
  login_attempts: { skip: 'rate-limit log by IP or hashed key (deleted after 24 hours)', del: "DELETE FROM login_attempts WHERE ip = 'u:' || ?" },
  users: { rows: 'SELECT * FROM users WHERE id = ?', del: 'DELETE FROM users WHERE id = ?' },
};
// Columns never handed out: secrets and hashes (the export is the person's data, not keys to it).
const byUser = (env, sql, uid) => env.DB.prepare(sql).bind(...Array((sql.match(/\?/g) || []).length).fill(uid));
const SECRET_COL = /hash$|token|verifier|^password/;
const cleanRow = (r) => Object.fromEntries(Object.entries(r).filter(([k]) => !SECRET_COL.test(k)).map(([k, v]) => {
  if (typeof v === 'string' && /^[\[{]/.test(v)) { try { return [k, JSON.parse(v)]; } catch {} }
  return [k, v];
}));
async function exportMe(request, env) {
  const user = requireUser(request);
  const msg = `You can download your data a few times every ${FAIL_WINDOW_MIN} minutes. Try again later.`;
  await checkThrottle(env, request, 'export', { key: 'u:' + user.id, max: 5, msg });
  await recordFail(env, request, 'export', 'u:' + user.id);
  const out = { exported_at: now(), site: 'when-who', note: 'All data when-who stores about your account, one list per database table. Polls you own include everyone’s answers and chat, like you see them in the app.' };
  for (const [table, d] of Object.entries(USER_DATA)) {
    if (!d.rows) continue;
    const { results } = await byUser(env, d.rows, user.id).all();
    out[table] = results.map(cleanRow);
  }
  // Polls I only answered: just enough to know which poll it was.
  out.polls = out.polls.map((p) => (p.owner_id === user.id ? p : { id: p.id, title: p.title, owned: false }));
  const day = now().slice(0, 10);
  return new Response(JSON.stringify(out, null, 2), { headers: {
    'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
    'content-disposition': `attachment; filename="when-who-data-${day}.json"` } });
}
async function sendDeleteCode(request, env, url) {
  const user = requireUser(request);
  const tooMany = `Too many emails. Try again in ${FAIL_WINDOW_MIN} minutes.`;
  await checkThrottle(env, request, 'code-send', { key: 'u:' + user.id, max: CODE_SENDS_EMAIL, msg: tooMany });
  await recordFail(env, request, 'code-send', 'u:' + user.id);
  const de = reqLang(request) === 'de', mins = CODE_MINUTES;
  await mailCode(env, url, 'delete:' + user.id, user.email, de, {
    title: de ? 'Konto löschen bestätigen' : 'Confirm deleting your account',
    intro: de ? `Gib diesen Code auf when-who ein, um dein Konto und alle deine Daten endgültig zu löschen. Er ist ${mins} Minuten gültig.`
      : `Enter this code on when-who to delete your account and all your data for good. It is valid for ${mins} minutes.`,
    ignore: de ? 'Falls du das nicht warst, ignoriere diese E-Mail: Ohne den Code wird nichts gelöscht.'
      : "If this wasn't you, ignore this email: nothing is deleted without the code.",
  });
  return json({ ok: true, minutes: CODE_MINUTES });
}
// My reactions on messages that stay (in other people's polls): reactions = { emoji: [user ids] }.
async function dropReactions(env, uid) {
  const { results } = await env.DB.prepare("SELECT id, reactions FROM messages WHERE user_id != ? AND reactions LIKE '%' || ? || '%'").bind(uid, uid).all();
  return results.map((m) => {
    let r = {}; try { r = JSON.parse(m.reactions || '{}'); } catch {}
    for (const e of Object.keys(r)) { r[e] = (r[e] || []).filter((x) => x !== uid); if (!r[e].length) delete r[e]; }
    return env.DB.prepare('UPDATE messages SET reactions = ?, updated_at = ? WHERE id = ?').bind(JSON.stringify(r), now(), m.id);
  });
}
async function deleteAccount(request, env, url) {
  const user = requireUser(request);
  await checkThrottle(env, request, 'code');
  const b = await body(request);
  const code = typeof b.code === 'string' ? b.code.replace(/\s+/g, '') : '';
  if (!/^\d{6}$/.test(code)) throw new HttpError(400, 'Enter the 6-digit code from the email');
  await takeCode(env, request, 'delete:' + user.id, code);
  const owned = await env.DB.prepare('SELECT COUNT(*) AS n FROM polls WHERE owner_id = ?').bind(user.id).first('n');
  // Best effort: tell Google to forget calendar grants (Microsoft has no revoke endpoint).
  const { results: accts } = await env.DB.prepare("SELECT refresh_token FROM calendar_accounts WHERE user_id = ? AND provider = 'google'").bind(user.id).all();
  for (const a of accts) {
    try {
      const tok = await unseal(env, a.refresh_token);
      await fetch('https://oauth2.googleapis.com/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: tok }), signal: AbortSignal.timeout(5000) });
    } catch (e) { console.error('revoke', e); }
  }
  await env.DB.batch([
    ...(await dropReactions(env, user.id)),
    ...Object.values(USER_DATA).map((d) => byUser(env, d.del, user.id)),
  ]);
  if (emailEnabled(env)) {
    const de = reqLang(request) === 'de';
    const text = de ? `Dein when-who-Konto (${user.email}) wurde gelöscht${owned ? `, zusammen mit ${owned} Umfrage${owned === 1 ? '' : 'n'}` : ''}. Deine Antworten und Nachrichten in anderen Umfragen sind ebenfalls gelöscht.`
      : `Your when-who account (${user.email}) has been deleted${owned ? `, along with ${owned} poll${owned === 1 ? '' : 's'}` : ''}. Your answers and messages in other polls were deleted too.`;
    await sendEmail(env, { fromName: 'when-who', to: [user.email], replyTo: env.CONTACT_EMAIL || undefined,
      subject: de ? 'Dein Konto wurde gelöscht' : 'Your account was deleted', text,
      html: emailHtml(`<div style="white-space:pre-wrap">${escHtml(text)}</div>`, { site: siteUrl(env, url.origin), lang: de ? 'de' : 'en' }) }).catch(() => {});
  }
  return json({ ok: true, polls: owned }, 200, { 'set-cookie': sessionCookie(url, '', 0) });
}
// ---------- friends ----------
// A request goes to an email address and is accepted by that person (friends.status 'pending' -> 'ok').
// Contacts (people I added to my polls by email, no account) aren't stored here: they come from my polls' participants.
// The answer is the same whether or not the address has an account, so nobody can probe for accounts.
const UID_RE = /^[A-Za-z0-9_]{4,40}$/;
const MAX_FRIENDS = 500, MAX_FRIEND_PENDING = 50;
// Requests to my address made before my account existed (or before the row knew it) become mine.
const claimFriendRequests = (env, user) =>
  env.DB.prepare('UPDATE friends SET to_id = ? WHERE to_id IS NULL AND to_email = ?').bind(user.id, user.email.toLowerCase()).run();
const friendRequestCount = (env, user) =>
  env.DB.prepare("SELECT COUNT(*) AS n FROM friends WHERE status = 'pending' AND (to_id = ? OR (to_id IS NULL AND to_email = ?))")
    .bind(user.id, user.email.toLowerCase()).first('n');
const personOut = (u) => ({ uid: u.id, name: u.name || u.email.split('@')[0], email: u.email, avatar: u.avatar || '', avatarImg: u.avatar_img || '' });
// Accepted friends of a user: [{ id (friends row), user row }].
async function friendRows(env, userId) {
  const { results } = await env.DB.prepare(
    `SELECT f.id AS fid, u.id, u.email, u.name, u.avatar, u.avatar_img FROM friends f
     JOIN users u ON u.id = CASE WHEN f.from_id = ?1 THEN f.to_id ELSE f.from_id END
     WHERE f.status = 'ok' AND (f.from_id = ?1 OR f.to_id = ?1) ORDER BY COALESCE(NULLIF(u.name, ''), u.email) COLLATE NOCASE`).bind(userId).all();
  return results;
}
// Signed-in people from my polls and owners of polls I answered, who aren't friends or asked yet.
async function friendSuggestions(env, user) {
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.email, u.name, u.avatar, u.avatar_img FROM users u WHERE u.id != ?1 AND u.id IN (
       SELECT pa.user_id FROM participants pa JOIN polls p ON p.id = pa.poll_id WHERE p.owner_id = ?1 AND pa.user_id IS NOT NULL
       UNION SELECT p.owner_id FROM participants pa JOIN polls p ON p.id = pa.poll_id WHERE pa.user_id = ?1 AND p.owner_id IS NOT NULL)
     AND NOT EXISTS (SELECT 1 FROM friends f WHERE (f.from_id = ?1 AND (f.to_id = u.id OR f.to_email = LOWER(u.email)))
                                             OR (f.from_id = u.id AND (f.to_id = ?1 OR f.to_email = ?2)))
     ORDER BY COALESCE(NULLIF(u.name, ''), u.email) COLLATE NOCASE LIMIT 20`).bind(user.id, user.email.toLowerCase()).all();
  return results;
}
async function listFriends(request, env) {
  const user = requireUser(request);
  await claimFriendRequests(env, user);
  const friends = await friendRows(env, user.id);
  const { results: incoming } = await env.DB.prepare(
    `SELECT f.id AS fid, u.id, u.email, u.name, u.avatar, u.avatar_img FROM friends f JOIN users u ON u.id = f.from_id
     WHERE f.status = 'pending' AND f.to_id = ? ORDER BY f.created_at DESC`).bind(user.id).all();
  // My open requests: only the address I typed (and the name of an account I picked from suggestions, which I saw already).
  const { results: outgoing } = await env.DB.prepare(
    "SELECT id, to_email, created_at FROM friends WHERE status = 'pending' AND from_id = ? ORDER BY created_at DESC").bind(user.id).all();
  const sugg = await friendSuggestions(env, user);
  // Contacts: guests I added to my polls by email (no account needed), newest name per address. Friends' addresses are left out.
  const { results: guests } = await env.DB.prepare(
    `SELECT pa.name, LOWER(TRIM(pa.email)) AS email, MAX(pa.created_at) AS at FROM participants pa JOIN polls p ON p.id = pa.poll_id
     WHERE p.owner_id = ? AND pa.user_id IS NULL AND pa.email != '' GROUP BY LOWER(TRIM(pa.email))
     ORDER BY pa.name COLLATE NOCASE LIMIT 500`).bind(user.id).all();
  const known = new Set([user.email.toLowerCase(), ...friends.map((u) => u.email.toLowerCase())]);
  const { results: favs } = await env.DB.prepare('SELECT id, name, email FROM favourites WHERE user_id = ? ORDER BY name COLLATE NOCASE').bind(user.id).all();
  const { results: grps } = await env.DB.prepare('SELECT id, name, icon, members FROM contact_groups WHERE user_id = ? ORDER BY name COLLATE NOCASE').bind(user.id).all();
  return json({
    favourites: favs.map((f) => ({ id: f.id, name: f.name, email: f.email })),
    groups: grps.map((g) => ({ id: g.id, name: g.name, icon: g.icon, members: jsonList(g.members) })),
    contacts: guests.filter((g) => EMAIL_RE.test(g.email) && !known.has(g.email)).map((g) => ({ name: g.name, email: g.email })),
    friends: friends.map((u) => ({ id: u.fid, ...personOut(u) })),
    incoming: incoming.map((u) => ({ id: u.fid, ...personOut(u) })),
    outgoing: outgoing.map((r) => ({ id: r.id, email: r.to_email, at: r.created_at })),
    suggestions: sugg.map((u) => ({ uid: u.id, name: u.name || u.email.split('@')[0], avatar: u.avatar || '', avatarImg: u.avatar_img || '' })),
  });
}
// Body: { email } or { uid } (a suggestion). Always { ok: true } (plus { friends: true } when they had already asked me).
async function addFriend(request, env, url) {
  const user = requireUser(request);
  const b = await body(request);
  let addr, toId = null;
  if (b.uid !== undefined) {
    if (typeof b.uid !== 'string' || !UID_RE.test(b.uid)) throw new HttpError(400, 'Pick someone from the list');
    const s = (await friendSuggestions(env, user)).find((u) => u.id === b.uid);
    if (!s) throw new HttpError(400, 'Pick someone from the list');
    addr = s.email.toLowerCase(); toId = s.id;
  } else {
    addr = email(b.email || '').toLowerCase();
    if (!addr) throw new HttpError(400, 'Enter an email address');
  }
  if (addr === user.email.toLowerCase()) throw new HttpError(400, 'That’s your own address');
  if (!toId) toId = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(addr).first('id');
  // They asked me already: that's a yes from both sides.
  if (toId) {
    const theirs = await env.DB.prepare("SELECT id, status FROM friends WHERE from_id = ? AND (to_id = ? OR to_email = ?)")
      .bind(toId, user.id, user.email.toLowerCase()).first();
    if (theirs) {
      if (theirs.status !== 'ok') await env.DB.prepare("UPDATE friends SET status = 'ok', to_id = ? WHERE id = ?").bind(user.id, theirs.id).run();
      return json({ ok: true });
    }
  }
  const mine = await env.DB.prepare('SELECT id FROM friends WHERE from_id = ? AND to_email = ?').bind(user.id, addr).first();
  if (mine) return json({ ok: true }); // asked before: don't email again
  const counts = await env.DB.prepare(
    "SELECT SUM(status = 'ok') AS ok, SUM(status = 'pending' AND from_id = ?1) AS pending FROM friends WHERE from_id = ?1 OR to_id = ?1").bind(user.id).first();
  if ((counts.ok || 0) >= MAX_FRIENDS) throw new HttpError(409, `You can have at most ${MAX_FRIENDS} friends`);
  if ((counts.pending || 0) >= MAX_FRIEND_PENDING) throw new HttpError(409, 'Too many open friend requests. Wait for some answers first.');
  await env.DB.prepare('INSERT INTO friends (id, from_id, to_email, to_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(randomId(12), user.id, addr, toId, 'pending', now()).run();
  // Tell them, the same way whether or not they have an account (counts against the daily email cap).
  const site = siteUrl(env, url.origin), de = reqLang(request) === 'de', who = user.name || user.email;
  const link = `${site}/?account`;
  const subject = de ? `${who} möchte dich als Freund*in auf when-who hinzufügen` : `${who} wants to add you as a friend on when-who`;
  const text = de
    ? `${who} (${user.email}) möchte dich auf when-who als Freund*in hinzufügen. Dann könnt ihr euch gegenseitig ganz einfach zu Umfragen einladen.\n\nMelde dich mit dieser E-Mail-Adresse an, um die Anfrage anzunehmen oder abzulehnen:\n${link}\n\n—\nDu bekommst diese E-Mail, weil ${who} deine Adresse eingegeben hat. Wenn du nichts tust, passiert nichts.`
    : `${who} (${user.email}) would like to add you as a friend on when-who, so you can easily invite each other to polls.\n\nSign in with this email address to accept or decline:\n${link}\n\n—\nYou're getting this because ${who} entered your address. If you do nothing, nothing happens.`;
  if (emailEnabled(env)) {
    await mailQuota(env, { owner_id: user.id }, 1);
    await sendEmail(env, { fromName: user.name || 'when-who', to: [addr], replyTo: user.email, subject, text,
      html: emailHtml(`<div style="white-space:pre-wrap">${linkify(escHtml(text))}</div>`,
        { preheader: subject, button: { href: link, label: de ? 'Anfrage ansehen' : 'See the request' }, site, lang: de ? 'de' : 'en' }) });
  } else console.log(`[dev] friend request to ${addr}:\n${text}`);
  return json({ ok: true });
}
async function acceptFriend(request, env, fid) {
  const user = requireUser(request);
  if (!ID_RE.test(fid)) throw new HttpError(404, 'Request not found');
  await claimFriendRequests(env, user);
  const r = await env.DB.prepare("UPDATE friends SET status = 'ok' WHERE id = ? AND to_id = ? AND status = 'pending'").bind(fid, user.id).run();
  if (!r.meta || !r.meta.changes) throw new HttpError(404, 'Request not found');
  return json({ ok: true });
}
// Decline a request, take back my own, or end a friendship.
async function deleteFriend(request, env, fid) {
  const user = requireUser(request);
  if (!ID_RE.test(fid)) throw new HttpError(404, 'Request not found');
  await claimFriendRequests(env, user);
  await env.DB.prepare('DELETE FROM friends WHERE id = ? AND (from_id = ? OR to_id = ?)').bind(fid, user.id, user.id).run();
  return json({ ok: true });
}
// ---------- favourites ----------
// A private starred list (name + email) per account, shown first when adding people. Nobody is told.
const MAX_FAVOURITES = 500;
// Body: { name, email }. Starring an address again updates the name.
async function addFavourite(request, env) {
  const user = requireUser(request);
  const b = await body(request);
  const addr = email(b.email || '').toLowerCase();
  if (!addr) throw new HttpError(400, 'Enter an email address');
  const name = String(b.name || '').trim().slice(0, 60) || addr.split('@')[0];
  const had = await env.DB.prepare('SELECT id FROM favourites WHERE user_id = ? AND email = ?').bind(user.id, addr).first('id');
  if (had) { await env.DB.prepare('UPDATE favourites SET name = ? WHERE id = ?').bind(name, had).run(); return json({ id: had }); }
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM favourites WHERE user_id = ?').bind(user.id).first('n');
  if (n >= MAX_FAVOURITES) throw new HttpError(409, `You can have at most ${MAX_FAVOURITES} favourites`);
  const id = randomId(12);
  await env.DB.prepare('INSERT INTO favourites (id, user_id, name, email, created_at) VALUES (?, ?, ?, ?, ?)').bind(id, user.id, name, addr, now()).run();
  return json({ id });
}
async function deleteFavourite(request, env, fid) {
  const user = requireUser(request);
  if (!ID_RE.test(fid)) throw new HttpError(404, 'Not found');
  await env.DB.prepare('DELETE FROM favourites WHERE id = ? AND user_id = ?').bind(fid, user.id).run();
  return json({ ok: true });
}
// ---------- contact groups ----------
// Private named sets of people (name + email) per account, added to a poll in one go from the Add-people popup.
const MAX_GROUPS = 50, MAX_GROUP_MEMBERS = 100;
const jsonList = (v) => { try { const a = JSON.parse(v || '[]'); return Array.isArray(a) ? a : []; } catch { return []; } };
// Body: { name, icon, members: [{ name, email }] }; partial = PATCH (only the fields sent).
function groupInput(b, partial) {
  const out = {}, has = (k) => Object.prototype.hasOwnProperty.call(b, k);
  if (!partial || has('name')) out.name = str(b.name, 40, 'Group name', true);
  if (!partial || has('icon')) out.icon = emojiIcon(b.icon, 'Icon');
  if (!partial || has('members')) {
    if (!Array.isArray(b.members)) throw new HttpError(400, 'Members must be a list');
    const seen = new Set(), list = [];
    for (const x of b.members) {
      if (!x || typeof x !== 'object') throw new HttpError(400, 'Members must be a list');
      const addr = email(x.email || '').toLowerCase();
      if (!addr) throw new HttpError(400, 'Every person needs an email address.');
      if (seen.has(addr)) continue; seen.add(addr);
      list.push({ name: x.name ? personName(x.name) : addr.split('@')[0], email: addr });
    }
    if (list.length > MAX_GROUP_MEMBERS) throw new HttpError(409, `A group can have at most ${MAX_GROUP_MEMBERS} people`);
    out.members = list;
  }
  return out;
}
async function addGroup(request, env) {
  const user = requireUser(request);
  const g = groupInput(await body(request), false);
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM contact_groups WHERE user_id = ?').bind(user.id).first('n');
  if (n >= MAX_GROUPS) throw new HttpError(409, `You can have at most ${MAX_GROUPS} groups`);
  const id = randomId(12), at = now();
  await env.DB.prepare('INSERT INTO contact_groups (id, user_id, name, icon, members, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, user.id, g.name, g.icon, JSON.stringify(g.members), at, at).run();
  return json({ id });
}
async function updateGroup(request, env, gid) {
  const user = requireUser(request);
  if (!ID_RE.test(gid)) throw new HttpError(404, 'Group not found');
  const g = groupInput(await body(request), true), sets = [], vals = [];
  if ('name' in g) { sets.push('name = ?'); vals.push(g.name); }
  if ('icon' in g) { sets.push('icon = ?'); vals.push(g.icon); }
  if ('members' in g) { sets.push('members = ?'); vals.push(JSON.stringify(g.members)); }
  sets.push('updated_at = ?'); vals.push(now());
  const r = await env.DB.prepare(`UPDATE contact_groups SET ${sets.join(', ')} WHERE id = ? AND user_id = ?`).bind(...vals, gid, user.id).run();
  if (!r.meta || !r.meta.changes) throw new HttpError(404, 'Group not found');
  return json({ ok: true });
}
async function deleteGroup(request, env, gid) {
  const user = requireUser(request);
  if (!ID_RE.test(gid)) throw new HttpError(404, 'Group not found');
  await env.DB.prepare('DELETE FROM contact_groups WHERE id = ? AND user_id = ?').bind(gid, user.id).run();
  return json({ ok: true });
}

// ---------- chat ----------
// One chat per poll (a series shares it). Readable and writable by everyone signed in (invited-only polls: the owner and invited people).
// The page polls for new messages while the chat is open; there are no emails, only unread counts.
const CHAT_MAX_LEN = 2000, CHAT_PAGE = 200, CHAT_MAX_PER_POLL = 5000, CHAT_BURST = 30, CHAT_BURST_MIN = 10;
async function chatAllowed(env, poll, user) {
  if (!user || !poll.allow_comments) return false; // allow_comments = the poll's Chat switch (also covers the guest Comment field)
  if (poll.owner_id && poll.owner_id === user.id) return true;
  if (!poll.invited_only) return true;
  // Invited-only: in the poll as this account, or invited as a guest with this account's email.
  if (await accountParticipant(env, poll.id, user.id)) return true;
  return !!(await env.DB.prepare('SELECT 1 FROM participants WHERE poll_id = ? AND user_id IS NULL AND LOWER(email) = ? LIMIT 1').bind(poll.id, user.email.toLowerCase()).first());
}
// Throws unless the signed-in person may use this poll's chat. Returns { poll, user, owner }.
async function chatAccess(request, env, id) {
  const user = requireUser(request);
  const poll = await loadPoll(env, id);
  const owner = isAdmin(request, poll);
  if (!owner) await checkPassword(env, request, poll);
  if (!poll.allow_comments) throw new HttpError(403, 'The chat is turned off for this poll');
  if (!(await chatAllowed(env, poll, user))) throw new HttpError(403, 'Only invited people can join this chat');
  return { poll, user, owner };
}
// Unread messages in a poll's chat for a user (written by others after they last read it).
// tagged: only those that tag the user (<@user id> in the body).
const chatUnread = (env, pollId, userId, tagged) => env.DB.prepare(
  `SELECT COUNT(*) AS n FROM messages m WHERE m.poll_id = ?1 AND m.user_id != ?2
   AND m.created_at > COALESCE((SELECT read_at FROM chat_reads WHERE poll_id = ?1 AND user_id = ?2), '')${tagged ? " AND instr(m.body, '<@' || ?2 || '>') > 0" : ''}`).bind(pollId, userId).first('n');
const markChatRead = (env, pollId, userId) => env.DB.prepare(
  'INSERT INTO chat_reads (poll_id, user_id, read_at) VALUES (?, ?, ?) ON CONFLICT (poll_id, user_id) DO UPDATE SET read_at = excluded.read_at')
  .bind(pollId, userId, now()).run();
const CHAT_EMOJI = ['👍', '❤️', '😂', '✅', '🙏', '😮'];
const REF_RE = /^(d:\d{4}-\d\d-\d\d|m:[A-Za-z0-9_-]{1,24})$/;
// reactions go out as { emoji: { n, mine } }, so other people's ids stay on the server.
function rxOut(raw, user) {
  let r; try { r = JSON.parse(raw || '{}'); } catch { r = {}; }
  const out = {};
  for (const [e, ids] of Object.entries(r)) if (Array.isArray(ids) && ids.length) out[e] = { n: ids.length, mine: ids.includes(user.id) };
  return out;
}
// Tags and attachments are inline tokens in the body: <@user id> (a person in the chat), <#m:meeting id> (a meeting).
const CHAT_TOKEN_RE = /<@[A-Za-z0-9_]{4,40}>|<#m:[A-Za-z0-9_-]{1,24}>/g, CHAT_MAX_TOKENS = 20;
// re: id of the quoted message; rq: its author and start (null once it's deleted), from the q_* columns of chatSelect.
const msgOut = (m, user) => ({ id: m.id, uid: m.user_id, body: m.body, at: m.created_at, mine: m.user_id === user.id,
  ref: m.ref || null, rx: rxOut(m.reactions, user), upd: m.updated_at || null, re: m.reply_to || null,
  rq: m.reply_to && m.q_uid ? { uid: m.q_uid, body: String(m.q_body || '').slice(0, 140) } : null });
const chatSelect = 'SELECT m.*, q.user_id AS q_uid, substr(q.body, 1, 300) AS q_body FROM messages m LEFT JOIN messages q ON q.id = m.reply_to';
// ?after=<iso>: only messages from then on (>=, the page drops ones it has). Without it: the newest CHAT_PAGE plus who wrote them.
async function listChat(request, env, url, id) {
  const { poll, user, owner } = await chatAccess(request, env, id);
  const after = url.searchParams.get('after'), t0 = now(); // t0 before the query, so nothing written meanwhile is skipped next time
  let msgs;
  if (after) {
    if (!/^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(after)) throw new HttpError(400, 'Invalid time');
    ({ results: msgs } = await env.DB.prepare(`${chatSelect} WHERE m.poll_id = ? AND COALESCE(m.updated_at, m.created_at) >= ? ORDER BY COALESCE(m.updated_at, m.created_at), m.id LIMIT ?`)
      .bind(id, after, CHAT_PAGE).all());
  } else {
    ({ results: msgs } = await env.DB.prepare(`SELECT * FROM (${chatSelect} WHERE m.poll_id = ? ORDER BY m.created_at DESC LIMIT ?) ORDER BY created_at, id`)
      .bind(id, CHAT_PAGE).all());
  }
  // now: the server's clock, so the page can ask for "messages after this" even while the chat is empty.
  const out = { messages: msgs.map((m) => msgOut(m, user)), owner: poll.owner_id || null, canDeleteAll: owner, now: t0, me: user.id }; // me: to spot my tags
  // Who wrote them and who is in the chat (members can be tagged). Pictures only on the first load;
  // a later message from someone new makes the page reload once.
  if (!after) {
    // Members: account participants, accounts invited by email that haven't answered yet, and everyone who opened or wrote in the chat.
    const { results: mem } = await env.DB.prepare(
      `SELECT user_id FROM participants WHERE poll_id = ?1 AND user_id IS NOT NULL
       UNION SELECT u.id FROM participants p JOIN users u ON u.email = LOWER(p.email) WHERE p.poll_id = ?1 AND p.user_id IS NULL AND p.email IS NOT NULL
       UNION SELECT user_id FROM chat_reads WHERE poll_id = ?1
       UNION SELECT user_id FROM messages WHERE poll_id = ?1`).bind(id).all();
    out.members = [...new Set([...(poll.owner_id ? [poll.owner_id] : []), ...mem.map((r) => r.user_id)])];
    const ids = [...new Set([user.id, ...out.members, ...msgs.map((m) => m.user_id), ...msgs.map((m) => m.q_uid).filter(Boolean)])];
    out.people = {};
    for (let i = 0; i < ids.length; i += 90) { // D1 caps bound parameters per query
      const part = ids.slice(i, i + 90);
      const { results: us } = await env.DB.prepare(`SELECT id, email, name, avatar, avatar_img FROM users WHERE id IN (${part.map(() => '?').join(',')})`).bind(...part).all();
      for (const u of us) { const p = personOut(u); delete p.email; delete p.uid; out.people[u.id] = p; }
    }
  }
  if (!after || msgs.some((m) => m.user_id !== user.id && m.created_at >= after)) await markChatRead(env, id, user.id);
  return json(out);
}
// Body: { body }.
async function postChat(request, env, id) {
  const { user } = await chatAccess(request, env, id);
  const b = await body(request);
  const text = str(b.body, CHAT_MAX_LEN, 'Message', true);
  const ref = b.ref == null || b.ref === '' ? null : String(b.ref);
  if (ref && !REF_RE.test(ref)) throw new HttpError(400, 'Invalid thread');
  if ((text.match(CHAT_TOKEN_RE) || []).length > CHAT_MAX_TOKENS) throw new HttpError(400, 'Too many tags in one message');
  const replyTo = b.reply_to == null || b.reply_to === '' ? null : String(b.reply_to);
  let q = null;
  if (replyTo) {
    q = ID_RE.test(replyTo) ? await env.DB.prepare('SELECT user_id, body FROM messages WHERE id = ? AND poll_id = ?').bind(replyTo, id).first() : null;
    if (!q) throw new HttpError(400, 'Invalid reply');
  }
  const since = new Date(Date.now() - CHAT_BURST_MIN * 60000).toISOString();
  const c = await env.DB.prepare('SELECT COUNT(*) AS total, SUM(user_id = ? AND created_at > ?) AS recent FROM messages WHERE poll_id = ?').bind(user.id, since, id).first();
  if ((c.recent || 0) >= CHAT_BURST) throw new HttpError(429, 'You’re sending a lot of messages. Wait a few minutes.');
  if ((c.total || 0) >= CHAT_MAX_PER_POLL) throw new HttpError(409, 'This chat is full. Delete old messages first.');
  const m = { id: randomId(12), poll_id: id, user_id: user.id, body: text, created_at: now(), ref, reactions: '{}', reply_to: replyTo, q_uid: q && q.user_id, q_body: q && q.body };
  await env.DB.batch([
    env.DB.prepare('INSERT INTO messages (id, poll_id, user_id, body, created_at, ref, reply_to) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(m.id, id, user.id, text, m.created_at, ref, replyTo),
    env.DB.prepare('INSERT INTO chat_reads (poll_id, user_id, read_at) VALUES (?, ?, ?) ON CONFLICT (poll_id, user_id) DO UPDATE SET read_at = excluded.read_at')
      .bind(id, user.id, m.created_at),
  ]);
  return json({ message: msgOut(m, user) }, 201);
}
// Your own message, or any message in a poll you own.
async function deleteChat(request, env, id, mid) {
  const { user, owner } = await chatAccess(request, env, id);
  if (!ID_RE.test(mid)) throw new HttpError(404, 'Message not found');
  const m = await env.DB.prepare('SELECT user_id FROM messages WHERE id = ? AND poll_id = ?').bind(mid, id).first();
  if (!m) throw new HttpError(404, 'Message not found');
  if (m.user_id !== user.id && !owner) throw new HttpError(403, 'You can only delete your own messages');
  await env.DB.prepare('DELETE FROM messages WHERE id = ?').bind(mid).run();
  return json({ ok: true });
}
// Body: { emoji }. Toggles the caller's reaction; counts toward the same burst limit as posting.
async function reactChat(request, env, id, mid) {
  const { user } = await chatAccess(request, env, id);
  if (!ID_RE.test(mid)) throw new HttpError(404, 'Message not found');
  const b = await body(request);
  if (!CHAT_EMOJI.includes(b.emoji)) throw new HttpError(400, 'Invalid reaction');
  const m = await env.DB.prepare(`${chatSelect} WHERE m.id = ? AND m.poll_id = ?`).bind(mid, id).first();
  if (!m) throw new HttpError(404, 'Message not found');
  let r; try { r = JSON.parse(m.reactions || '{}'); } catch { r = {}; }
  const ids = Array.isArray(r[b.emoji]) ? r[b.emoji] : [];
  if (ids.includes(user.id)) r[b.emoji] = ids.filter((x) => x !== user.id); else r[b.emoji] = [...ids, user.id].slice(-500);
  if (!r[b.emoji].length) delete r[b.emoji];
  m.reactions = JSON.stringify(r); m.updated_at = now();
  await env.DB.prepare('UPDATE messages SET reactions = ?, updated_at = ? WHERE id = ?').bind(m.reactions, m.updated_at, mid).run();
  return json({ message: msgOut(m, user) });
}
// ---------- external calendar (iCal feed) ----------
// The page parses the calendar itself; the Worker only fetches the feed (browsers can't, because of CORS).
// Waiting on the fetch costs no CPU time, so this stays within the Free plan.
const ICAL_MAX_BYTES = 3 * 1024 * 1024;
const ICAL_PER_WINDOW = 20; // feed fetches per IP within FAIL_WINDOW_MIN
function icalUrl(raw) {
  const bad = () => new HttpError(400, 'Enter an iCal link (https:// or webcal://)');
  if (typeof raw !== 'string') throw bad();
  let s = raw.trim();
  if (!s || s.length > 2000) throw bad();
  s = s.replace(/^webcals?:\/\//i, 'https://');
  let u;
  try { u = new URL(s); } catch (e) { throw bad(); }
  const host = u.hostname.toLowerCase();
  if (u.protocol !== 'https:' || u.username || u.password || !host.includes('.') || host === 'localhost' || host.endsWith('.localhost')
    || host.endsWith('.local') || host.endsWith('.internal') || /^[\d.]+$/.test(host) || host.startsWith('[')) throw bad();
  return u.toString();
}
// Body: { url? }. Without a url, a signed-in person's first saved iCal calendar is used. Returns the feed as text/calendar.
async function fetchCalendar(request, env) {
  const b = await body(request), user = userOf(request);
  let url;
  if (b.url) url = icalUrl(b.url);
  else {
    if (!user) throw new HttpError(400, 'Enter an iCal link (https:// or webcal://)');
    url = await env.DB.prepare('SELECT url FROM user_calendars WHERE user_id = ? AND url IS NOT NULL ORDER BY position, created_at LIMIT 1').bind(user.id).first('url')
      || await env.DB.prepare('SELECT ical_url FROM users WHERE id = ?').bind(user.id).first('ical_url');
    if (!url) throw new HttpError(404, 'No calendar is saved on your account');
  }
  await checkThrottle(env, request, 'ical', { max: ICAL_PER_WINDOW, msg: `Too many calendar imports. Try again in ${FAIL_WINDOW_MIN} minutes.` });
  await recordFail(env, request, 'ical');
  return icsResponse(await fetchIcalText(url));
}
const icsResponse = (text) => new Response(text, { headers: { 'content-type': 'text/calendar; charset=utf-8', 'cache-control': 'no-store' } });
// Downloads an iCal feed (size-capped) and checks that it is one.
async function fetchIcalText(url) {
  let res;
  try {
    // Follow redirects by hand, so every hop passes the same checks as the link itself (https, no local or IP hosts).
    for (let hop = 0; ; hop++) {
      res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(10000), headers: { accept: 'text/calendar, */*;q=0.5', 'user-agent': 'when-who calendar import' } });
      if (res.status < 300 || res.status > 399 || !res.headers.get('location')) break;
      if (hop >= 4) throw new HttpError(502, 'Could not reach that calendar');
      url = icalUrl(new URL(res.headers.get('location'), url).toString());
    }
  } catch (e) { if (e instanceof HttpError) throw e; throw new HttpError(502, 'Could not reach that calendar'); }
  if (!res.ok) throw new HttpError(502, `The calendar link answered with an error (${res.status})`);
  // Read with a size cap, so a huge or endless response can't run us out of memory.
  const reader = res.body.getReader(), chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > ICAL_MAX_BYTES) { reader.cancel(); throw new HttpError(413, 'That calendar is too large (over 3 MB)'); }
    chunks.push(value);
  }
  const buf = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) { buf.set(c, at); at += c.byteLength; }
  const text = new TextDecoder().decode(buf);
  if (!/BEGIN:VCALENDAR/i.test(text.slice(0, 2000))) throw new HttpError(422, "That link didn't return a calendar (.ics)");
  return text;
}

// ---------- calendars on the account (iCal links + Google / Outlook accounts) ----------
// Each calendar has an `auto` switch: on, the page greys out the owner's busy hours on polls they answer.
// iCal feeds are returned raw and parsed in the page; Google / Outlook events come back as JSON.
// Event titles pass straight through to the owner's browser and are never stored.
const MAX_CALENDARS = 50;       // per account, all kinds
const MAX_ICAL = 20;            // iCal links per account
const MAX_CAL_ACCOUNTS = 5;     // Google / Outlook accounts per when-who account
const CAL_PER_WINDOW = 150;     // calendar fetches per when-who account within FAIL_WINDOW_MIN
const CAL_ID_RE = /^[A-Za-z0-9]{6,30}$/;
const BUSY_MAX_DAYS = 130;
const OAUTH = {
  google: {
    name: 'Google', id: 'GOOGLE_CLIENT_ID', secret: 'GOOGLE_CLIENT_SECRET',
    auth: 'https://accounts.google.com/o/oauth2/v2/auth', token: 'https://oauth2.googleapis.com/token',
    scope: 'openid email https://www.googleapis.com/auth/calendar.readonly',
    contacts: 'https://www.googleapis.com/auth/contacts.readonly https://www.googleapis.com/auth/contacts.other.readonly',
    extra: { access_type: 'offline', prompt: 'consent' },
  },
  microsoft: {
    name: 'Outlook', id: 'MS_CLIENT_ID', secret: 'MS_CLIENT_SECRET',
    auth: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', token: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    scope: 'openid email offline_access User.Read Calendars.Read',
    contacts: 'Contacts.Read',
    extra: { prompt: 'select_account' },
  },
};
const providerOn = (env, p) => !!(OAUTH[p] && env[OAUTH[p].id] && env[OAUTH[p].secret] && env.CAL_TOKEN_KEY);
const calProviders = (env) => ({ google: providerOn(env, 'google'), microsoft: providerOn(env, 'microsoft') });
const calColor = (c) => (typeof c === 'string' && /^#[0-9a-fA-F]{6}$/.test(c) ? c.toLowerCase() : '');
// Whether the provider granted reading contacts (Google: contacts.readonly; Microsoft: Contacts.Read, maybe as a full URI).
const hasContacts = (acct) => /contacts\.read/i.test(acct.scope || '');
const icalHost = (url) => { try { return new URL(url).host; } catch (e) { return ''; } };

// Tokens are stored encrypted (AES-GCM, key derived from the CAL_TOKEN_KEY secret).
let TOKEN_KEY = null;
async function tokenKey(env) {
  if (!env.CAL_TOKEN_KEY) throw new HttpError(503, 'Calendar sign-in isn’t set up on this site');
  if (!TOKEN_KEY || TOKEN_KEY.raw !== env.CAL_TOKEN_KEY) {
    const k = await crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', enc.encode('cal-token:' + env.CAL_TOKEN_KEY)), 'AES-GCM', false, ['encrypt', 'decrypt']);
    TOKEN_KEY = { raw: env.CAL_TOKEN_KEY, k };
  }
  return TOKEN_KEY.k;
}
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (u8) => b64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function seal(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await tokenKey(env), enc.encode(text)));
  return b64(iv) + '.' + b64(ct);
}
async function unseal(env, s) {
  const [iv, ct] = String(s).split('.');
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, await tokenKey(env), unb64(ct)));
}

async function listCalendars(request, env) {
  const user = requireUser(request);
  const [a, c] = await env.DB.batch([
    env.DB.prepare('SELECT id, provider, email, status, scope FROM calendar_accounts WHERE user_id = ? ORDER BY created_at').bind(user.id),
    env.DB.prepare('SELECT id, account_id, url, name, color, auto FROM user_calendars WHERE user_id = ? ORDER BY position, created_at').bind(user.id),
  ]);
  // iCal links are secrets: the page only learns which host they point at.
  return json({
    providers: calProviders(env),
    accounts: a.results.map((x) => ({ id: x.id, provider: x.provider, email: x.email, status: x.status, contacts: hasContacts(x) })),
    calendars: c.results.map((x) => ({ id: x.id, accountId: x.account_id || null, name: x.name, color: x.color || '', auto: !!x.auto, host: x.url ? icalHost(x.url) : '' })),
  });
}
async function ownCalendar(env, user, cid) {
  if (!CAL_ID_RE.test(cid || '')) throw new HttpError(404, 'Calendar not found');
  const c = await env.DB.prepare('SELECT * FROM user_calendars WHERE id = ? AND user_id = ?').bind(cid, user.id).first();
  if (!c) throw new HttpError(404, 'Calendar not found');
  return c;
}
async function ownCalAccount(env, user, aid) {
  if (!CAL_ID_RE.test(aid || '')) throw new HttpError(404, 'Calendar account not found');
  const a = await env.DB.prepare('SELECT * FROM calendar_accounts WHERE id = ? AND user_id = ?').bind(aid, user.id).first();
  if (!a) throw new HttpError(404, 'Calendar account not found');
  return a;
}
// Adds an iCal calendar. Returns the existing one if the link is already there.
async function insertIcal(env, userId, url, name, auto = 1) {
  const have = await env.DB.prepare('SELECT id FROM user_calendars WHERE user_id = ? AND url = ?').bind(userId, url).first('id');
  if (have) return { id: have, existed: true };
  const n = await env.DB.prepare('SELECT COUNT(*) AS n, SUM(url IS NOT NULL) AS i, MAX(position) AS p FROM user_calendars WHERE user_id = ?').bind(userId).first();
  if (n.n >= MAX_CALENDARS || (n.i || 0) >= MAX_ICAL) throw new HttpError(400, `At most ${MAX_ICAL} calendar links per account`);
  const id = randomId(12);
  await env.DB.prepare('INSERT INTO user_calendars (id, user_id, url, name, auto, position, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, userId, url, name || icalHost(url) || 'Calendar', auto ? 1 : 0, (n.p || 0) + 1, now()).run();
  return { id, existed: false };
}
// Body: { url, name? }
async function addCalendar(request, env) {
  const user = requireUser(request);
  const b = await body(request);
  const url = icalUrl(b.url);
  const name = str(b.name, 60, 'Name');
  const r = await insertIcal(env, user.id, url, name);
  if (r.existed) throw new HttpError(409, 'That calendar is already on your account');
  return json({ id: r.id });
}
// Body: { name?, auto? }
async function updateCalendar(request, env, cid) {
  const user = requireUser(request);
  const c = await ownCalendar(env, user, cid);
  const b = await body(request);
  const name = b.name !== undefined ? str(b.name, 60, 'Name', true) : c.name;
  const auto = b.auto !== undefined ? (b.auto ? 1 : 0) : c.auto;
  await env.DB.prepare('UPDATE user_calendars SET name = ?, auto = ? WHERE id = ?').bind(name, auto, c.id).run();
  return json({ ok: true });
}
async function deleteCalendar(request, env, cid) {
  const user = requireUser(request);
  const c = await ownCalendar(env, user, cid);
  if (!c.url) throw new HttpError(400, 'Turn this calendar off, or disconnect its account');
  await env.DB.batch([
    env.DB.prepare('DELETE FROM user_calendars WHERE id = ?').bind(c.id),
    // The old single-link column, so the removed link is really gone.
    env.DB.prepare('UPDATE users SET ical_url = NULL WHERE id = ? AND ical_url = ?').bind(user.id, c.url),
  ]);
  return json({ ok: true });
}
async function deleteCalAccount(request, env, aid) {
  const user = requireUser(request);
  const a = await ownCalAccount(env, user, aid);
  // Best effort: tell Google to forget the grant. (Microsoft has no revoke endpoint for this.)
  if (a.provider === 'google') {
    try {
      const tok = await unseal(env, a.refresh_token);
      await fetch('https://oauth2.googleapis.com/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: tok }), signal: AbortSignal.timeout(5000) });
    } catch (e) { console.error('revoke', e); }
  }
  await env.DB.batch([
    env.DB.prepare('DELETE FROM user_calendars WHERE account_id = ? AND user_id = ?').bind(a.id, user.id),
    env.DB.prepare('DELETE FROM calendar_accounts WHERE id = ?').bind(a.id),
  ]);
  return json({ ok: true });
}
async function refreshCalAccount(request, env, aid) {
  const user = requireUser(request);
  const a = await ownCalAccount(env, user, aid);
  await calThrottle(env, request, user);
  await syncCalendars(env, a, await accessToken(env, a));
  return json({ ok: true });
}
async function calThrottle(env, request, user) {
  const key = 'u:' + user.id;
  await checkThrottle(env, request, 'cal', { key, max: CAL_PER_WINDOW, msg: `Too many calendar requests. Try again in ${FAIL_WINDOW_MIN} minutes.` });
  await recordFail(env, request, 'cal', key);
}

// ---------- OAuth (Google / Outlook) ----------
// SITE_URL decides the address (under `wrangler dev` the request URL carries the production host); it must match
// the redirect URI registered with Google / Microsoft. Local testing: --var SITE_URL:http://localhost:8787.
// After a contacts sign-in started from a poll (ret = poll id), go back to that poll's People tab instead of the Account page.
const oauthBack = (env, url, result, ret, p) => new Response(null, { status: 302, headers: { location: ret
  ? `${siteUrl(env, url.origin)}/?p=${ret}&contacts=${result === 'ok' ? p : 'err-' + result}`
  : `${siteUrl(env, url.origin)}/?account&cal=${result}` } });
const redirectUri = (env, url, p) => `${siteUrl(env, url.origin)}/api/oauth/${p}/callback`;
async function oauthStart(request, env, url, p) {
  if (!providerOn(env, p)) throw new HttpError(404, 'Not found');
  const user = userOf(request);
  if (!user) return oauthBack(env, url, 'signin');
  await checkThrottle(env, request, 'oauth', { key: 'u:' + user.id, max: 20, msg: `Too many tries. Try again in ${FAIL_WINDOW_MIN} minutes.` });
  await recordFail(env, request, 'oauth', 'u:' + user.id);
  const state = secret(), verifier = secret() + secret();
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(verifier))));
  // ?contacts=1 also asks to read contacts (for adding people to a poll); ?ret=<poll id> comes back to that poll.
  const contacts = url.searchParams.get('contacts') === '1', retRaw = url.searchParams.get('ret') || '';
  const ret = ID_RE.test(retRaw) ? retRaw : null;
  await env.DB.prepare('INSERT INTO oauth_states (state, user_id, provider, verifier, created_at, ret) VALUES (?, ?, ?, ?, ?, ?)').bind(state, user.id, p, verifier, now(), ret).run();
  const o = OAUTH[p];
  const q = new URLSearchParams({ client_id: env[o.id], redirect_uri: redirectUri(env, url, p), response_type: 'code', scope: contacts ? `${o.scope} ${o.contacts}` : o.scope, state,
    code_challenge: challenge, code_challenge_method: 'S256', ...o.extra });
  if (contacts && p === 'google') q.set('include_granted_scopes', 'true');
  const hint = url.searchParams.get('hint');
  if (hint && EMAIL_RE.test(hint) && hint.length <= 200) q.set('login_hint', hint);
  return new Response(null, { status: 302, headers: { location: `${o.auth}?${q}` } });
}
// The id_token comes straight from the provider's token endpoint over TLS, so its claims can be read without checking the signature.
function idClaims(idToken) {
  try {
    const part = String(idToken).split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(new TextDecoder().decode(unb64(part + '='.repeat((4 - (part.length % 4)) % 4))));
  } catch (e) { return {}; }
}
async function tokenRequest(env, p, params) {
  const o = OAUTH[p];
  const res = await fetch(o.token, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({ client_id: env[o.id], client_secret: env[o.secret], ...params }), signal: AbortSignal.timeout(10000) });
  const out = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, out };
}
async function oauthCallback(request, env, url, p) {
  if (!OAUTH[p]) throw new HttpError(404, 'Not found');
  const user = userOf(request), qs = url.searchParams, state = qs.get('state') || '';
  if (!user) return oauthBack(env, url, 'signin');
  const st = state && state.length <= 100 ? await env.DB.prepare('SELECT * FROM oauth_states WHERE state = ?').bind(state).first() : null;
  if (st) await env.DB.prepare('DELETE FROM oauth_states WHERE state = ?').bind(state).run();
  const ret = st && st.ret && ID_RE.test(st.ret) ? st.ret : null, back = (r) => oauthBack(env, url, r, ret, p);
  if (!st || st.user_id !== user.id || st.provider !== p || Date.now() - Date.parse(st.created_at) > 15 * 60000) return back('error');
  if (qs.get('error') || !qs.get('code')) return back('denied');
  try {
    const t = await tokenRequest(env, p, { grant_type: 'authorization_code', code: qs.get('code'), redirect_uri: redirectUri(env, url, p), code_verifier: st.verifier });
    if (!t.ok || !t.out.access_token || !t.out.refresh_token) { console.error('oauth token', p, t.status, t.out.error); return back('error'); }
    const cl = idClaims(t.out.id_token);
    const mail = String(cl.email || cl.preferred_username || '').slice(0, 200).toLowerCase();
    const sealed = { r: await seal(env, t.out.refresh_token), a: await seal(env, t.out.access_token), exp: Date.now() + (+t.out.expires_in || 3600) * 1000 };
    const scope = String(t.out.scope || '').slice(0, 1000);
    let acct = await env.DB.prepare('SELECT * FROM calendar_accounts WHERE user_id = ? AND provider = ? AND email = ?').bind(user.id, p, mail).first();
    if (acct) {
      await env.DB.prepare("UPDATE calendar_accounts SET refresh_token = ?, access_token = ?, expires_at = ?, status = 'ok', scope = ? WHERE id = ?").bind(sealed.r, sealed.a, sealed.exp, scope, acct.id).run();
    } else {
      const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM calendar_accounts WHERE user_id = ?').bind(user.id).first('n');
      if (n >= MAX_CAL_ACCOUNTS) return back('toomany');
      acct = { id: randomId(12), user_id: user.id, provider: p, email: mail };
      await env.DB.prepare('INSERT INTO calendar_accounts (id, user_id, provider, email, refresh_token, access_token, expires_at, status, created_at, scope) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(acct.id, user.id, p, mail, sealed.r, sealed.a, sealed.exp, 'ok', now(), scope).run();
    }
    await syncCalendars(env, acct, t.out.access_token);
    return back('ok');
  } catch (e) {
    console.error('oauth callback', p, e);
    return back('error');
  }
}
// A valid access token for the account, refreshed when it is about to expire.
// A refused refresh token marks the account as needing to be reconnected.
async function accessToken(env, acct) {
  if (acct.status === 'expired') throw new HttpError(409, `Reconnect your ${OAUTH[acct.provider].name} calendar`, { reconnect: true });
  if (acct.access_token && acct.expires_at > Date.now() + 60000) return unseal(env, acct.access_token);
  const p = acct.provider;
  const params = { grant_type: 'refresh_token', refresh_token: await unseal(env, acct.refresh_token) };
  if (p === 'microsoft') params.scope = hasContacts(acct) ? `${OAUTH[p].scope} ${OAUTH[p].contacts}` : OAUTH[p].scope;
  const t = await tokenRequest(env, p, params);
  if (!t.ok || !t.out.access_token) {
    if (t.out.error === 'invalid_grant' || t.status === 401) {
      await env.DB.prepare("UPDATE calendar_accounts SET status = 'expired', access_token = NULL WHERE id = ?").bind(acct.id).run();
      throw new HttpError(409, `Reconnect your ${OAUTH[p].name} calendar`, { reconnect: true });
    }
    throw new HttpError(502, `Couldn’t reach ${OAUTH[p].name}. Try again later.`);
  }
  const a = await seal(env, t.out.access_token), exp = Date.now() + (+t.out.expires_in || 3600) * 1000;
  // Microsoft hands out a new refresh token each time; keep it.
  const r = t.out.refresh_token ? await seal(env, t.out.refresh_token) : acct.refresh_token;
  await env.DB.prepare('UPDATE calendar_accounts SET access_token = ?, expires_at = ?, refresh_token = ? WHERE id = ?').bind(a, exp, r, acct.id).run();
  return t.out.access_token;
}
async function providerGet(acct, token, apiUrl, headers = {}) {
  let res;
  try { res = await fetch(apiUrl, { headers: { authorization: `Bearer ${token}`, accept: 'application/json', ...headers }, signal: AbortSignal.timeout(10000) }); }
  catch (e) { throw new HttpError(502, `Couldn’t reach ${OAUTH[acct.provider].name}. Try again later.`); }
  if (res.status === 401) throw new HttpError(409, `Reconnect your ${OAUTH[acct.provider].name} calendar`, { reconnect: true });
  if (!res.ok) throw new HttpError(502, `${OAUTH[acct.provider].name} answered with an error (${res.status})`);
  return res.json();
}
// Brings the account's calendar list up to date. New calendars: the main one greys out busy times, others start off.
async function syncCalendars(env, acct, token) {
  let list;
  if (acct.provider === 'google') {
    const r = await providerGet(acct, token, 'https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=100&fields=items(id,summary,summaryOverride,primary,backgroundColor)');
    list = (r.items || []).map((x) => ({ ext: x.id, name: x.summaryOverride || x.summary || x.id, color: x.backgroundColor, main: !!x.primary }));
  } else {
    const r = await providerGet(acct, token, 'https://graph.microsoft.com/v1.0/me/calendars?$top=100&$select=id,name,hexColor,isDefaultCalendar');
    list = (r.value || []).map((x) => ({ ext: x.id, name: x.name || 'Calendar', color: x.hexColor, main: !!x.isDefaultCalendar }));
  }
  list = list.filter((x) => typeof x.ext === 'string' && x.ext.length <= 500);
  const { results: have } = await env.DB.prepare('SELECT id, ext_id FROM user_calendars WHERE account_id = ?').bind(acct.id).all();
  const known = new Set(have.map((x) => x.ext_id)), wanted = new Set(list.map((x) => x.ext));
  const total = await env.DB.prepare('SELECT COUNT(*) AS n, MAX(position) AS p FROM user_calendars WHERE user_id = ?').bind(acct.user_id).first();
  let room = MAX_CALENDARS - total.n + have.filter((x) => !wanted.has(x.ext_id)).length, pos = (total.p || 0) + 1;
  const stmts = have.filter((x) => !wanted.has(x.ext_id)).map((x) => env.DB.prepare('DELETE FROM user_calendars WHERE id = ?').bind(x.id));
  for (const x of list) {
    if (known.has(x.ext)) { stmts.push(env.DB.prepare('UPDATE user_calendars SET color = ? WHERE account_id = ? AND ext_id = ?').bind(calColor(x.color), acct.id, x.ext)); continue; }
    if (room-- <= 0) break;
    stmts.push(env.DB.prepare('INSERT INTO user_calendars (id, user_id, account_id, ext_id, name, color, auto, position, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(randomId(12), acct.user_id, acct.id, x.ext, String(x.name).slice(0, 60), calColor(x.color), x.main ? 1 : 0, pos++, now()));
  }
  if (stmts.length) await env.DB.batch(stmts);
}
const clip = (s, n) => String(s || '').slice(0, n);
// The account's address book as [{ name, email }] (Google: contacts + "other contacts"; Outlook: contacts). Nothing is stored:
// the page shows them in the add-people popup and only the people picked are sent back. 409 { consent } = sign in again with contacts.
const CONTACT_PAGES = 4;
async function accountContacts(request, env, aid) {
  const user = requireUser(request);
  const acct = await ownCalAccount(env, user, aid);
  if (!providerOn(env, acct.provider)) throw new HttpError(404, 'Not found');
  if (!hasContacts(acct)) throw new HttpError(409, `Allow when-who to read your ${OAUTH[acct.provider].name} contacts`, { consent: true });
  await calThrottle(env, request, user);
  const token = await accessToken(env, acct), out = new Map();
  const add = (name, mail) => { const e = String(mail || '').trim().toLowerCase();
    if (e.length <= 200 && EMAIL_RE.test(e) && !out.has(e)) out.set(e, { name: clip(String(name || '').trim(), 60) || e.split('@')[0], email: e }); };
  if (acct.provider === 'google') {
    const get = async (base) => { let page = '';
      for (let i = 0; i < CONTACT_PAGES; i++) {
        const r = await providerGet(acct, token, base + (page ? '&pageToken=' + encodeURIComponent(page) : ''));
        for (const x of r.connections || r.otherContacts || []) { const n = (x.names || [])[0]; for (const m of x.emailAddresses || []) add(n && n.displayName, m.value); }
        if (!(page = r.nextPageToken)) break;
      } };
    await get('https://people.googleapis.com/v1/people/me/connections?personFields=names,emailAddresses&pageSize=1000');
    await get('https://people.googleapis.com/v1/otherContacts?readMask=names,emailAddresses&pageSize=1000');
  } else {
    let next = 'https://graph.microsoft.com/v1.0/me/contacts?$top=999&$select=displayName,emailAddresses';
    for (let i = 0; i < CONTACT_PAGES && next && next.startsWith('https://graph.microsoft.com/'); i++) {
      const r = await providerGet(acct, token, next);
      for (const x of r.value || []) for (const m of x.emailAddresses || []) add(x.displayName || m.name, m.address);
      next = r['@odata.nextLink'];
    }
  }
  return json({ contacts: [...out.values()].sort((a, b) => a.name.localeCompare(b.name)) });
}
// GET ?from=<ms>&to=<ms>. iCal: the raw feed. Google / Outlook: { events: [{ s, e, allDay, title }] },
// with s / e in ms (timed) or 'YYYY-MM-DD' (all-day, end exclusive). Free and cancelled events are left out.
async function calendarBusy(request, env, url, cid) {
  const user = requireUser(request);
  const c = await ownCalendar(env, user, cid);
  await calThrottle(env, request, user);
  if (c.url) return icsResponse(await fetchIcalText(c.url));
  const from = +url.searchParams.get('from'), to = +url.searchParams.get('to');
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from || to - from > BUSY_MAX_DAYS * 86400000) throw new HttpError(400, 'Invalid time range');
  const acct = await env.DB.prepare('SELECT * FROM calendar_accounts WHERE id = ?').bind(c.account_id).first();
  if (!acct) throw new HttpError(404, 'Calendar not found');
  const token = await accessToken(env, acct);
  const tMin = new Date(from).toISOString(), tMax = new Date(to).toISOString(), events = [];
  if (acct.provider === 'google') {
    let page = '';
    for (let i = 0; i < 3; i++) {
      const q = new URLSearchParams({ singleEvents: 'true', maxResults: '2500', timeMin: tMin, timeMax: tMax, fields: 'items(summary,start,end,status,transparency),nextPageToken' });
      if (page) q.set('pageToken', page);
      const r = await providerGet(acct, token, `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(c.ext_id)}/events?${q}`);
      for (const x of r.items || []) {
        if (x.status === 'cancelled' || x.transparency === 'transparent' || !x.start || !x.end) continue;
        if (x.start.date) events.push({ s: x.start.date, e: x.end.date || x.start.date, allDay: true, title: clip(x.summary, 200) });
        else { const s = Date.parse(x.start.dateTime), e = Date.parse(x.end.dateTime); if (s < e) events.push({ s, e, allDay: false, title: clip(x.summary, 200) }); }
      }
      if (!(page = r.nextPageToken)) break;
    }
  } else {
    const q = new URLSearchParams({ startDateTime: tMin, endDateTime: tMax, $top: '500', $select: 'subject,start,end,showAs,isAllDay,isCancelled' });
    let next = `https://graph.microsoft.com/v1.0/me/calendars/${encodeURIComponent(c.ext_id)}/calendarView?${String(q).replace(/%24/g, '$')}`;
    for (let i = 0; i < 3 && next; i++) {
      if (!next.startsWith('https://graph.microsoft.com/')) break;
      const r = await providerGet(acct, token, next, { prefer: 'outlook.timezone="UTC"' });
      for (const x of r.value || []) {
        if (x.isCancelled || x.showAs === 'free' || !x.start || !x.end) continue;
        if (x.isAllDay) events.push({ s: x.start.dateTime.slice(0, 10), e: x.end.dateTime.slice(0, 10), allDay: true, title: clip(x.subject, 200) });
        else { const s = Date.parse(x.start.dateTime + 'Z'), e = Date.parse(x.end.dateTime + 'Z'); if (s < e) events.push({ s, e, allDay: false, title: clip(x.subject, 200) }); }
      }
      next = r['@odata.nextLink'];
    }
  }
  return json({ events });
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
       (SELECT MAX(r.updated_at) FROM responses r WHERE r.participant_id = pa.id) AS last,
       i.start_date, i.end_date, i.status, i.deadline, (SELECT COUNT(*) FROM responses r WHERE r.instance_id = i.id) AS answers
     FROM participants pa JOIN polls p ON p.id = pa.poll_id
     LEFT JOIN instances i ON i.id = (SELECT id FROM instances WHERE poll_id = p.id ORDER BY seq DESC LIMIT 1)
     WHERE pa.user_id = ? AND (p.owner_id IS NULL OR p.owner_id != ?) ORDER BY last DESC`).bind(user.id, user.id).all();
  // Unread chat messages per poll (others' messages since I last read that chat), only for polls I can chat in.
  const { results: ur } = await env.DB.prepare(
    `SELECT m.poll_id, COUNT(*) AS n FROM messages m LEFT JOIN chat_reads cr ON cr.poll_id = m.poll_id AND cr.user_id = ?1
     WHERE m.user_id != ?1 AND m.created_at > COALESCE(cr.read_at, '') AND m.poll_id IN (
       SELECT id FROM polls WHERE owner_id = ?1 UNION SELECT poll_id FROM participants WHERE user_id = ?1)
       AND m.poll_id IN (SELECT id FROM polls WHERE allow_comments = 1)
     GROUP BY m.poll_id`).bind(user.id).all();
  const unread = Object.fromEntries(ur.map((r) => [r.poll_id, r.n]));
  const current = (p) => (p.start_date ? { startDate: p.start_date, endDate: p.end_date, deadline: p.deadline, answers: p.answers,
    status: effStatus({ status: p.status, end_date: p.end_date }) } : null);
  return json({
    polls: owned.map((p) => ({ id: p.id, title: p.title, kind: p.kind, icon: p.icon, image: pic(p), createdAt: p.created_at, unread: unread[p.id] || 0,
      current: current(p) })),
    answered: answered.map((p) => ({ id: p.id, title: p.title, kind: p.kind, icon: p.icon, image: pic(p), name: p.name, lastAnswered: p.last,
      unread: unread[p.id] || 0, current: current(p) })),
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
    if (!['single', 'series', 'weekly'].includes(kind)) throw new HttpError(400, 'Choose "one-off", "recurring" or "weekly schedule"');
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
  if (!existing || has('dayPattern')) {
    let pat = parsePattern(b.dayPattern);
    if (pat && pat.periods) {
      const ps = pat.periods;
      if (ps.length === 1) pat = ps[0].wd || ps[0].dom ? { wd: ps[0].wd, dom: ps[0].dom } : null;
      p.hour_start = Math.min(...ps.map((x) => x.hs)); p.hour_end = Math.max(...ps.map((x) => x.he));
    }
    p.day_pattern = pat ? JSON.stringify(pat) : null;
  }
  if (!existing || has('hideResults')) p.hide_results = b.hideResults ? 1 : 0;
  if (!existing || has('allowComments')) p.allow_comments = b.allowComments === false ? 0 : 1;
  if (!existing || has('requireEmail')) p.require_email = b.requireEmail ? 1 : 0;
  if (has('invitedOnly')) p.invited_only = b.invitedOnly ? 1 : 0; // only when sent: the column needs migration 0014
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
  p.id = id; p.owner_id = user.id; p.lang = reqLang(request);
  p.admin_hash = await sha256('admin:' + secret()); // column is required; admin links are no longer handed out
  p.password_hash = b.password ? await sha256(id + ':pw:' + str(b.password, 100, 'Password')) : null;
  p.created_at = t; p.updated_at = t;
  let first;
  if (p.kind === 'single') {
    checkRange(b.startDate, b.endDate);
    if (b.deadline && !isDate(b.deadline)) throw new HttpError(400, 'Invalid reply-by date');
    first = { start_date: b.startDate, end_date: b.endDate, deadline: b.deadline || null };
    if (!datesOf(first, p).length) throw new HttpError(400, 'None of the days in this range match the chosen days');
  } else if (p.kind === 'weekly') {
    if (b.deadline && !isDate(b.deadline)) throw new HttpError(400, 'Invalid reply-by date');
    first = { start_date: WEEK0, end_date: addDays(WEEK0, 6), deadline: b.deadline || null };
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
  if (!admin) await checkPassword(env, request, poll);
  // The owner opened a poll that was about to be deleted for being old: keep it (counts as activity).
  if (admin && poll.retention_warned_at) await env.DB.prepare('UPDATE polls SET retention_warned_at = NULL, updated_at = ? WHERE id = ?').bind(now(), id).run();
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
    instance: publicInstance(sel), dates: datesOf(sel, poll),
  };
  if (admin && poll.kind === 'series') {
    const n = Math.max(...all.map((i) => i.seq)) + 1;
    out.next = { startDate: periodStart(poll, n), endDate: periodEnd(poll, n), opens: openDate(poll, n) };
  }
  // Questions: options people suggested are always sent (labels only), so everyone can vote on them.
  const qs = questionsOf(sel), added = qs.length ? await addedOptions(env, sel.id) : new Map();
  if (qs.some((q) => q.add)) out.added = Object.fromEntries(added);
  if (admin || !poll.hide_results) {
    const { results } = await env.DB.prepare('SELECT id, name, email, comment, entries, votes, extra, updated_at FROM responses WHERE instance_id = ? ORDER BY created_at').bind(sel.id).all();
    const props = proposedIds(sel);
    out.responses = results.map((r) => ({ id: r.id, name: r.name, comment: r.comment, entries: JSON.parse(r.entries), updatedAt: r.updated_at,
      ...(admin ? { email: r.email } : {}), ...(props.size ? { votes: parseVotes(r.votes, props) } : {}),
      ...(qs.length ? { extra: extraFor(r.extra, qs, added, admin) } : {}) }));
    // Names already used in this poll (any round), so people can pick themselves. Account answers are found by account instead.
    const { results: ps } = await env.DB.prepare('SELECT id, name FROM participants WHERE poll_id = ? AND user_id IS NULL ORDER BY name COLLATE NOCASE').bind(id).all();
    out.participants = ps;
    out.participantCount = await env.DB.prepare('SELECT COUNT(*) AS n FROM participants WHERE poll_id = ?').bind(id).first('n');
    if (!admin) { // read-only People tab: names and whether they answered this round (no ids or emails)
      const { results: pp } = await env.DB.prepare(
        `SELECT p.name, p.user_id IS NOT NULL AS account, EXISTS (SELECT 1 FROM responses r WHERE r.participant_id = p.id AND r.instance_id = ?) AS answered
         FROM participants p WHERE p.poll_id = ? ORDER BY p.name COLLATE NOCASE`).bind(sel.id, id).all();
      out.people = pp.map((p) => ({ name: p.name, account: !!p.account, answered: !!p.answered }));
    }
    // Busy hours others chose to share with this poll (same visibility as answers; the caller's own is left out).
    const caller = userOf(request);
    const { results: sb } = await env.DB.prepare(
      `SELECT p.id, p.name, p.user_id, s.hours, s.updated_at FROM shared_busy s JOIN participants p ON p.id = s.participant_id
       WHERE s.instance_id = ? AND p.share_busy = 1 ORDER BY p.name COLLATE NOCASE`).bind(sel.id).all();
    out.busy = sb.filter((r) => !caller || r.user_id !== caller.id)
      .map((r) => ({ pid: r.id, name: r.name, hours: JSON.parse(r.hours), updatedAt: r.updated_at }));
  }
  const user = userOf(request);
  if (user) { // signed in: their answers are linked to the account
    const part = await accountParticipant(env, id, user.id);
    out.me = { name: part ? part.name : user.name, email: user.email, participantId: part ? part.id : null, shareBusy: !!(part && part.share_busy),
      responseId: part ? (await answerIn(env, part.id, sel.id)) || null : null };
    // Invited-only polls: in the poll as this account, or invited as a guest with this account's email (linked on first answer).
    if (poll.invited_only) out.me.invited = !!part || !!(await env.DB.prepare('SELECT 1 FROM participants WHERE poll_id = ? AND user_id IS NULL AND LOWER(email) = ? LIMIT 1').bind(id, user.email.toLowerCase()).first());
    const can = !!poll.allow_comments && (admin || !poll.invited_only || out.me.invited); // chat: everyone signed in, or the invited
    out.chat = { can, off: !poll.allow_comments, unread: can ? (await chatUnread(env, id, user.id)) || 0 : 0 };
    if (out.chat.unread) out.chat.mentions = (await chatUnread(env, id, user.id, true)) || 0; // unread messages that tag me
    if (can) { // header peek (newest message) and message counts per day / meeting thread
      const [last, refs] = await env.DB.batch([
        env.DB.prepare('SELECT m.body, m.created_at, m.user_id, u.name, u.email FROM messages m LEFT JOIN users u ON u.id = m.user_id WHERE m.poll_id = ? ORDER BY m.created_at DESC LIMIT 1').bind(id),
        env.DB.prepare('SELECT ref, COUNT(*) AS n FROM messages WHERE poll_id = ? AND ref IS NOT NULL GROUP BY ref').bind(id),
      ]);
      const l = last.results[0];
      if (l) out.chat.last = { name: l.name || (l.email || '').split('@')[0] || '?', body: l.body.slice(0, 120), at: l.created_at, mine: l.user_id === user.id };
      out.chat.refs = Object.fromEntries(refs.results.map((r) => [r.ref, r.n]));
    }
  }
  return json(out);
}

async function updatePoll(request, env, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  const b = await body(request);
  const p = readPollSettings(b, poll);
  if (b.password !== undefined) p.password_hash = b.password ? await sha256(id + ':pw:' + str(b.password, 100, 'Password')) : null;
  if (request.headers.get('x-lang')) p.lang = reqLang(request);
  p.updated_at = now();
  const cols = Object.keys(p);
  await env.DB.prepare(`UPDATE polls SET ${cols.map((c) => c + ' = ?').join(', ')} WHERE id = ?`).bind(...cols.map((c) => p[c]), id).run();
  return json({ ok: true });
}

// The poll's picture. <img> can't send headers, so a password travels as ?pw= (like calendar.ics).
async function pollImage(request, env, url, id) {
  const poll = await env.DB.prepare('SELECT id, owner_id, password_hash, image FROM polls WHERE id = ?').bind(id).first();
  if (!poll || !poll.image) throw new HttpError(404, 'No picture');
  if (!isAdmin(request, poll) && !(await guardedPasswordOk(env, request, poll, url.searchParams.get('pw')))) throw new HttpError(401, 'Password required');
  const m = poll.image.match(/^data:(image\/(?:webp|jpeg|png));base64,(.+)$/);
  if (!m) throw new HttpError(404, 'No picture');
  const bytes = Uint8Array.from(atob(m[2]), (c) => c.charCodeAt(0));
  return new Response(bytes, { headers: { 'content-type': m[1], 'cache-control': 'private, max-age=31536000, immutable' } });
}

async function deletePoll(request, env, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  await env.DB.batch(pollDeleteStmts(env, id));
  return json({ ok: true });
}
// Everything stored for one poll (answers, people, rounds, chat, shared busy hours), poll row last.
const pollDeleteStmts = (env, id) => ['responses', 'participants', 'instances', 'messages', 'chat_reads', 'shared_busy']
  .map((t) => env.DB.prepare(`DELETE FROM ${t} WHERE poll_id = ?`).bind(id))
  .concat(env.DB.prepare('DELETE FROM polls WHERE id = ?').bind(id));

// Storage limitation (GDPR Art. 5(1)(e)): a poll with no activity for RETAIN_MONTHS is deleted with everything in it.
// Activity = the poll or its settings changing, an answer given or edited, a chat message or someone reading the chat,
// and for a single poll (or a series round with meetings) its dates: a poll isn't old before its last day has passed.
// RETAIN_WARN_DAYS before that the owner gets an email (retention_warned_at); opening the poll as its owner keeps it
// (getPoll clears the mark and counts as a change). A poll is deleted only with a warning newer than its last activity:
// one older than the warn cutoff belongs to an earlier quiet spell, so the poll is warned again instead.
// Runs once a day from the cron job, a few polls at a time so one run stays small.
const RETAIN_MONTHS = 12;    // default for env.RETAIN_MONTHS ("0" turns the clean-up off)
const RETAIN_WARN_DAYS = 14; // warning email this many days before deletion
const RETAIN_BATCH = 25;     // polls warned and polls deleted per daily run at most
const STALE_SQL = `MAX(p.updated_at, p.created_at) < ?1
       AND NOT EXISTS (SELECT 1 FROM responses r WHERE r.poll_id = p.id AND r.updated_at >= ?1)
       AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.poll_id = p.id AND COALESCE(m.updated_at, m.created_at) >= ?1)
       AND NOT EXISTS (SELECT 1 FROM chat_reads c WHERE c.poll_id = p.id AND c.read_at >= ?1)
       AND NOT EXISTS (SELECT 1 FROM instances i WHERE i.poll_id = p.id AND i.end_date >= ?2
                       AND (p.kind = 'single' OR i.meetings <> '[]'))`;
async function deleteStalePolls(env, at = new Date()) {
  const months = env.RETAIN_MONTHS != null ? Number(env.RETAIN_MONTHS) : RETAIN_MONTHS;
  if (!(months > 0)) return { warned: 0, deleted: 0 };
  const d = new Date(at); d.setUTCMonth(d.getUTCMonth() - months);
  const delCut = d.toISOString();
  const warnCut = new Date(d.getTime() + RETAIN_WARN_DAYS * 86400000).toISOString();
  const warnedBy = new Date(at.getTime() - RETAIN_WARN_DAYS * 86400000).toISOString();
  // 1. Delete: quiet for the full period and warned (in this quiet spell) at least RETAIN_WARN_DAYS ago.
  const { results: gone } = await env.DB.prepare(`SELECT p.id FROM polls p WHERE ${STALE_SQL}
       AND p.retention_warned_at IS NOT NULL AND p.retention_warned_at <= ?3 AND p.retention_warned_at >= ?4 LIMIT ?5`)
    .bind(delCut, delCut.slice(0, 10), warnedBy, warnCut, RETAIN_BATCH).all();
  for (const { id } of gone) {
    await env.DB.batch(pollDeleteStmts(env, id));
    console.log('retention: deleted poll', id);
  }
  // 2. Warn: quiet for the period minus RETAIN_WARN_DAYS, and no warning in this quiet spell yet.
  const { results: due } = await env.DB.prepare(`SELECT p.* FROM polls p WHERE ${STALE_SQL}
       AND (p.retention_warned_at IS NULL OR p.retention_warned_at < ?1) LIMIT ?3`)
    .bind(warnCut, warnCut.slice(0, 10), RETAIN_BATCH).all();
  for (const poll of due) {
    try { await retentionWarning(env, poll, months, new Date(at.getTime() + RETAIN_WARN_DAYS * 86400000).toISOString().slice(0, 10)); }
    catch (e) { console.error('retention warning', poll.id, e); continue; } // not marked: tried again tomorrow
    await env.DB.prepare('UPDATE polls SET retention_warned_at = ? WHERE id = ?').bind(at.toISOString(), poll.id).run();
  }
  return { warned: due.length, deleted: gone.length };
}
// The owner's "will be deleted" email. Polls without an address to write to are still marked, so they go after the wait too.
async function retentionWarning(env, poll, months, onDay) {
  const owner = await ownerOf(env, poll);
  const to = ((owner && owner.email) || poll.admin_email || '').toLowerCase();
  const site = siteUrl(env, ''), link = `${site}/?p=${poll.id}`, de = poll.lang === 'de';
  const day = fmtDay(onDay, poll.lang);
  const subject = de ? `Deine Umfrage „${poll.title}“ wird am ${day} gelöscht` : `Your poll “${poll.title}” will be deleted on ${day}`;
  const text = de
    ? `In deiner Umfrage „${poll.title}“ ist seit ${months} Monaten nichts mehr passiert. Damit keine alten Daten liegen bleiben, löschen wir sie am ${day} mit allen Antworten und Nachrichten.\n\nWillst du sie behalten? Öffne sie einfach, während du angemeldet bist:\n${link}\n\nWenn du nichts tust, wird sie gelöscht.`
    : `Nothing has happened in your poll “${poll.title}” for ${months} months. So old data doesn't pile up, we'll delete it on ${day}, with all its answers and messages.\n\nWant to keep it? Just open it while signed in:\n${link}\n\nIf you do nothing, it will be deleted.`;
  if (!to || !EMAIL_RE.test(to)) return;
  if (!emailEnabled(env)) { console.log(`[dev] retention warning to ${to}:\n${subject}\n${text}`); return; }
  await sendEmail(env, {
    fromName: 'when-who', to: [to], subject, text,
    html: emailHtml(`<div style="white-space:pre-wrap">${linkify(escHtml(text))}</div>`,
      { preheader: subject, button: { href: link, label: de ? 'Umfrage behalten' : 'Keep my poll' }, site, lang: langOf(poll.lang) }),
  });
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
  if ((has('startDate') || has('endDate')) && poll.kind !== 'weekly') {
    const s = b.startDate ?? inst.start_date, e = b.endDate ?? inst.end_date;
    checkRange(s, e); u.start_date = s; u.end_date = e;
  }
  if (has('meetings')) u.meetings = JSON.stringify(validateMeetings(b.meetings, poll, JSON.parse(inst.meetings || '[]')));
  if (has('questions')) {
    const qs = validateQuestions(b.questions, u.meetings ? JSON.parse(u.meetings) : JSON.parse(inst.meetings || '[]'), questionsOf(inst));
    u.questions = qs.length ? JSON.stringify(qs) : null;
  }
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
    env.DB.prepare('DELETE FROM shared_busy WHERE instance_id = ?').bind(iid),
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
// A weekly meeting's first date: its weekday, on or after repeat.from.
const meetingStart = (mt) => (mt.repeat ? firstOnWeekday(mt.repeat.from, wdOf(mt.date)) : mt.date);
function meetingToIcs(mt, poll, link) {
  // Older single-day "all day" meetings of a poll that takes hours: export them over the poll's hours instead.
  if (mt.allDay && !mt.endDate && poll.answer_mode !== 'days' && poll.hour_end > poll.hour_start)
    mt = { ...mt, allDay: false, start: poll.hour_start, end: Math.min(24, poll.hour_end) };
  const day = meetingStart(mt), d = day.replace(/-/g, '');
  const stamp = now().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  const lines = ['BEGIN:VEVENT', `UID:${mt.id}-${poll.id}@whenwho`, `DTSTAMP:${stamp}`];
  if (mt.allDay) lines.push(`DTSTART;VALUE=DATE:${d}`, `DTEND;VALUE=DATE:${addDays(mt.endDate || day, 1).replace(/-/g, '')}`);
  else {
    const endDate = mt.end === 24 ? addDays(day, 1).replace(/-/g, '') : d;
    lines.push(`DTSTART:${d}T${pad(mt.start)}0000`, `DTEND:${endDate}T${pad(mt.end % 24)}0000`);
  }
  if (mt.repeat) { // floating times, so UNTIL is floating too (and must match DTSTART's type)
    const until = mt.repeat.until ? `;UNTIL=${mt.repeat.until.replace(/-/g, '')}${mt.allDay ? '' : 'T235959'}` : '';
    lines.push(`RRULE:FREQ=WEEKLY;INTERVAL=${mt.repeat.every}${until}`);
  }
  lines.push(`SUMMARY:${icsEscape(mt.title || poll.title)}`);
  if (mt.location) lines.push(`LOCATION:${icsEscape(mt.location)}`);
  lines.push(`DESCRIPTION:${icsEscape([mt.note, mt.extra, 'Who: ' + whoText(mt), link].filter(Boolean).join('\n'))}`, 'END:VEVENT');
  return lines;
}
function buildIcs(poll, meetings, link) {
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//when-who//EN', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
    `X-WR-CALNAME:${icsEscape(poll.title)}`, ...meetings.flatMap((mt) => meetingToIcs(mt, poll, link)), 'END:VCALENDAR'];
  return lines.map(icsFold).join('\r\n') + '\r\n';
}
const whoText = (mt) => (mt.participants === 'all' ? 'Everyone' : mt.participants.map((p) => p.name).join(', '));
async function calendar(request, env, url, id) {
  const poll = await loadPoll(env, id);
  if (!(await guardedPasswordOk(env, request, poll, url.searchParams.get('pw')))) throw new HttpError(401, 'Password required');
  const { results } = await env.DB.prepare('SELECT id, meetings FROM instances WHERE poll_id = ? ORDER BY seq').bind(id).all();
  let meetings = results.flatMap((i) => JSON.parse(i.meetings || '[]')).filter((mt) => !mt.proposed);
  const only = url.searchParams.get('m');
  if (only) meetings = meetings.filter((mt) => mt.id === only);
  const name = (only ? `${meetings[0]?.title || poll.title} ${meetings[0] ? meetingStart(meetings[0]) : ''}` : poll.title).replace(/[^\w\- ]+/g, '').trim() || 'meetings';
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
    from: `"${headerSafe(m.fromName) || 'when-who'}" <${env.MAIL_FROM}>`,
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
const fmtDay = (d, lang) => new Date(d + 'T00:00:00Z').toLocaleDateString(LOCALE[langOf(lang)], { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
const hh = (h) => `${pad(h % 24)}:00`;
const shortDay = (d, lang) => new Date(d + 'T00:00:00Z').toLocaleDateString(LOCALE[langOf(lang)], { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
// "Monday 12 January 2026, 19:00–21:00", or for a weekly meeting "Every Tuesday, 19:00–21:00, from 13 Jan 2026 until 30 Jun 2026".
function meetingWhen(mt, lang) {
  const de = langOf(lang) === 'de';
  const time = mt.allDay ? (de ? ' (ganztägig)' : ' (all day)') : `, ${hh(mt.start)}–${hh(mt.end)}`;
  if (!mt.repeat && mt.endDate) return `${fmtDay(mt.date, lang)} – ${fmtDay(mt.endDate, lang)}${time}`;
  if (!mt.repeat) return fmtDay(mt.date, lang) + time;
  const r = mt.repeat, i = wdOf(mt.date);
  if (de) {
    const wd = WEEKDAYS_DE[i];
    const every = r.every === 1 ? `Jeden ${wd}` : r.every === 2 ? `Jeden zweiten ${wd}` : `Alle ${r.every} Wochen am ${wd}`;
    return `${every}${time}, ab ${shortDay(meetingStart(mt), lang)}${r.until ? ` bis ${shortDay(r.until, lang)}` : ''}`;
  }
  const wd = WEEKDAYS[i];
  const every = r.every === 1 ? `Every ${wd}` : r.every === 2 ? `Every other ${wd}` : `Every ${r.every} weeks on ${wd}`;
  return `${every}${time}, from ${shortDay(meetingStart(mt))}${r.until ? ` until ${shortDay(r.until)}` : ''}`;
}
const escHtml = (s) => String(s || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Branded HTML email (navy header with the logo, white card), matching the web app. The logo is public/logo-email.png on `site`
// (email clients block data: and SVG images); without a site address it falls back to a plain check mark. Inline styles and tables so email clients render it.
// bodyHtml must already be escaped. button: optional { href, label } shown as a blue button above the body.
function emailHtml(bodyHtml, { preheader = '', button = null, site = '', lang = 'en' } = {}) {
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
        ${site ? `<td style="width:28px;height:28px;vertical-align:middle"><img src="${escHtml(site)}/logo-email.png" width="28" height="28" alt="" style="display:block;border:0;width:28px;height:28px;border-radius:7px"></td>`
          : `<td style="width:28px;height:28px;background:#1F5EFF;border-radius:7px;text-align:center;vertical-align:middle;font-family:${font};font-size:15px;font-weight:700;color:#ffffff">✓</td>`}
        <td style="padding-left:10px;font-family:${font};font-size:18px;font-weight:700;color:#ffffff;letter-spacing:-0.2px">when-who</td></tr></table></td></tr>
    <tr><td style="background:#ffffff;border:1px solid #E2E8F0;border-top:0;border-radius:0 0 14px 14px;padding:32px 28px;font-family:${font};font-size:15px;line-height:1.6;color:#0F172A">
      ${btn}${bodyHtml}</td></tr>
    <tr><td style="padding:16px 28px;font-family:${font};font-size:12px;line-height:1.5;color:#5B6578;text-align:center">
      ${lang === 'de' ? 'Gesendet von' : 'Sent by'} when-who${site ? ` · <a href="${escHtml(site)}" style="color:#5B6578">${escHtml(site.replace(/^https?:\/\//, ''))}</a>`
        + ` · <a href="${escHtml(site)}/?imprint" style="color:#5B6578">Impressum</a> · <a href="${escHtml(site)}/?privacy" style="color:#5B6578">${lang === 'de' ? 'Datenschutz' : 'Privacy'}</a>` : ''}</td></tr>
  </table></td></tr></table></body></html>`;
}
const linkify = (escaped) => escaped.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" style="color:#1F5EFF;word-break:break-all">$1</a>');
function periodText(poll, inst) {
  const loc = LOCALE[langOf(poll.lang)];
  if (isWeek0(inst)) return poll.lang === 'de' ? 'eine typische Woche' : 'a typical week';
  if (poll.unit === 'month' && inst.start_date.endsWith('-01') && addDays(inst.end_date, 1).endsWith('-01')) {
    const f = (d) => new Date(d + 'T00:00:00Z').toLocaleDateString(loc, { month: 'long', year: 'numeric', timeZone: 'UTC' });
    return f(inst.start_date) === f(inst.end_date) ? f(inst.start_date) : `${f(inst.start_date)} – ${f(inst.end_date)}`;
  }
  const f = (d) => new Date(d + 'T00:00:00Z').toLocaleDateString(loc, { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
  return `${f(inst.start_date)} – ${f(inst.end_date)}`;
}
// Emails started by a person (invites) count against a daily cap per account, or per poll without one.
async function mailQuota(env, poll, count) {
  const key = poll.owner_id || 'poll:' + poll.id;
  const since = new Date(Date.now() - 86400000).toISOString();
  const used = await env.DB.prepare('SELECT COALESCE(SUM(n), 0) AS n FROM mail_log WHERE user_id = ? AND at > ?').bind(key, since).first('n');
  const max = Number(env.MAIL_PER_DAY) || MAIL_PER_DAY;
  if (used + count > max) throw new HttpError(429, `Daily email limit reached (${max} recipients). Try again tomorrow.`);
  await env.DB.prepare('INSERT INTO mail_log (user_id, n, at) VALUES (?, ?, ?)').bind(key, count, now()).run();
}
const ownerOf = (env, poll) => poll.owner_id ? env.DB.prepare('SELECT name, email FROM users WHERE id = ?').bind(poll.owner_id).first() : null;
async function sendMail(env, poll, { to, subject, text, attachments, quota = false, fromName, replyTo }) {
  if (!emailEnabled(env)) throw new HttpError(400, 'Email isn’t set up for this site');
  const list = [...new Set(to.map((e) => e.toLowerCase()))].filter((e) => EMAIL_RE.test(e));
  if (quota) await mailQuota(env, poll, list.length);
  // Sender name = the owner's account name, so people see who the email is from (poll title only without one).
  // The owner's (verified) account email gets the copy and the replies. polls.admin_email is a legacy
  // fallback for old polls nobody has claimed; it can no longer be set.
  const owner = await ownerOf(env, poll);
  const sender = fromName || (owner && owner.name) || poll.title;
  const ownerMail = (owner && owner.email) || poll.admin_email || '';
  const reply = replyTo || ownerMail;
  const pollLink = (text.match(/https?:\/\/[^\s]+\?p=[^\s]+/) || [])[0];
  const html = emailHtml(`<div style="white-space:pre-wrap">${linkify(escHtml(text))}</div>`, {
    preheader: subject, button: pollLink ? { href: pollLink, label: poll.lang === 'de' ? 'Umfrage öffnen' : 'Open poll' } : null,
    site: siteUrl(env, ''), lang: langOf(poll.lang),
  });
  let sent = 0;
  for (let i = 0; i < list.length; i += 49) { // max 50 recipients per message: send each batch as BCC
    const bcc = list.slice(i, i + 49);
    const to = (ownerMail || env.MAIL_FROM).toLowerCase();
    await sendEmail(env, {
      fromName: sender,
      to: [to],
      bcc: bcc.filter((e) => e !== to), subject, text, html,
      ...(reply ? { replyTo: reply } : {}),
      ...(attachments ? { attachments } : {}),
    });
    sent += bcc.length;
  }
  return sent;
}
const footer = (poll) => poll.lang === 'de'
  ? `\n\n—\nDu bekommst diese E-Mail, weil du in der Umfrage „${poll.title}“ deine E-Mail-Adresse angegeben hast. Um keine E-Mails mehr zu bekommen, öffne die Umfrage und entferne deine E-Mail-Adresse aus deiner Antwort.`
  : `\n\n—\nYou're getting this because you left your email address in the poll “${poll.title}”. To stop these emails, open the poll and remove your email from your answer.`;
const seriesFooter = (poll) => poll.lang === 'de'
  ? `\n\n—\nDu bekommst diese E-Mail, weil du an der Umfrage „${poll.title}“ teilnimmst. Um keine E-Mails mehr zu bekommen, entferne deine E-Mail-Adresse aus deiner Antwort in der Umfrage oder antworte auf diese E-Mail und bitte die Organisatorin oder den Organisator, dich von der Liste zu nehmen.`
  : `\n\n—\nYou're getting this because you're a participant in the poll “${poll.title}”. To stop these emails, remove your email from your answer in the poll, or reply to ask the organiser to take you off the list.`;

async function sendInvite(request, env, url, id, iid, mid) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  await adoptLang(request, env, poll);
  const inst = await loadInstance(env, id, iid);
  const meetings = JSON.parse(inst.meetings || '[]');
  const mt = meetings.find((x) => x.id === mid);
  if (!mt) throw new HttpError(404, 'Meeting not found');
  if (mt.proposed) throw new HttpError(400, 'Confirm this meeting before sending it');
  const { results } = await env.DB.prepare('SELECT id, name, email FROM responses WHERE instance_id = ?').bind(iid).all();
  const invited = mt.participants === 'all' ? results : results.filter((r) => mt.participants.some((p) => p.id === r.id));
  const withMail = invited.filter((r) => r.email);
  if (!withMail.length) throw new HttpError(400, 'None of the invited people left an email address');
  const base = siteUrl(env, url.origin), link = `${base}/?p=${poll.id}`;
  const de = poll.lang === 'de', when = meetingWhen(mt, poll.lang);
  const L = de ? { when: 'Wann', where: 'Wo', map: 'Karte', who: 'Wer', all: 'Alle', poll: 'Umfrage',
    ics: 'Die Kalenderdatei ist angehängt. Öffne sie, um den Termin in deinen Kalender zu übernehmen.' }
    : { when: 'When', where: 'Where', map: 'Map', who: 'Who', all: 'Everyone', poll: 'Poll',
      ics: 'The calendar file is attached. Open it to add the meeting to your calendar.' };
  const who = mt.participants === 'all' ? L.all : whoText(mt);
  const text = [`${mt.title || poll.title}`, '', `${L.when}: ${when}`, mt.location ? `${L.where}: ${mt.location}\n${L.map}: https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(mt.location)}` : null, `${L.who}: ${who}`, mt.note || mt.extra ? `\n${[mt.note, mt.extra].filter(Boolean).join('\n\n')}` : null,
    '', L.ics, `${L.poll}: ${link}`].filter((x) => x !== null).join('\n') + footer(poll);
  const ics = buildIcs(poll, [mt], link);
  const sent = await sendMail(env, poll, { to: withMail.map((r) => r.email), subject: `${mt.title || poll.title}: ${when}`, text,
    attachments: [{ content: enc.encode(ics), filename: 'invite.ics', type: 'text/calendar', disposition: 'attachment' }], quota: true });
  mt.sentAt = now();
  await env.DB.prepare('UPDATE instances SET meetings = ? WHERE id = ?').bind(JSON.stringify(meetings), iid).run();
  return json({ ok: true, sent, missing: invited.filter((r) => !r.email).map((r) => r.name) });
}

// "Email all meetings": every meeting of the poll (all rounds) in one email to the people the owner picks,
// with the .ics of all of them attached and the subscription link. Body: { ids: [participantId], emails: [address], message? }.
async function sendAllMeetings(request, env, url, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  await adoptLang(request, env, poll);
  const b = await body(request);
  const message = str(b.message, 1000, 'Message');
  const ids = Array.isArray(b.ids) ? b.ids.filter((x) => typeof x === 'string' && ID_RE.test(x)) : [];
  const extra = Array.isArray(b.emails) ? b.emails.filter((x) => typeof x === 'string').map((x) => x.trim().toLowerCase()).filter(Boolean) : [];
  if (ids.length > 500 || extra.length > 50) throw new HttpError(400, 'Too many people');
  if (extra.some((e) => !EMAIL_RE.test(e))) throw new HttpError(400, 'Invalid email');
  const { results } = await env.DB.prepare('SELECT meetings FROM instances WHERE poll_id = ? ORDER BY seq').bind(id).all();
  const meetings = results.flatMap((i) => JSON.parse(i.meetings || '[]')).filter((mt) => !mt.proposed);
  if (!meetings.length) throw new HttpError(400, 'There are no meetings yet');
  const want = new Set(ids);
  const rows = ids.length ? (await participantRows(env, id, '')).filter((p) => want.has(p.id)) : [];
  const missing = rows.filter((p) => !EMAIL_RE.test(p.mail_to)).map((p) => p.name);
  const to = [...new Set([...rows.filter((p) => EMAIL_RE.test(p.mail_to)).map((p) => p.mail_to.toLowerCase()), ...extra])];
  if (!to.length) throw new HttpError(400, 'None of the picked people has an email address');

  const base = siteUrl(env, url.origin), link = `${base}/?p=${poll.id}`;
  // The subscription link needs the poll password if there is one: take it from the owner's request when it's right.
  const pw = request.headers.get('x-poll-password');
  const pwq = poll.password_hash && (await passwordOk(poll, pw)) ? `?pw=${encodeURIComponent(pw)}` : '';
  const feed = `${base}/api/polls/${poll.id}/calendar.ics${pwq}`;
  const de = poll.lang === 'de';
  const L = de ? { where: 'Wo', who: 'Wer', all: 'Alle', poll: 'Umfrage', past: (n) => `(+ ${n} vergangene${n === 1 ? 'r Termin' : ' Termine'} in der Kalenderdatei)`,
    head: (n) => `${n === 1 ? 'Der Termin' : `Alle ${n} Termine`} für „${poll.title}“:`,
    ics: 'Alle Termine sind als Kalenderdatei angehängt. Öffne sie, um sie in deinen Kalender zu übernehmen.',
    sub: 'Oder abonnieren (dein Kalender bleibt dann aktuell, wenn Termine dazukommen oder sich ändern):',
    google: 'Google Kalender: Weitere Kalender › Per URL', footer: `\n\n—\nDu bekommst diese E-Mail, weil dir die Organisatorin oder der Organisator von „${poll.title}“ die Termine geschickt hat.`,
    subject: `Termine: ${poll.title}` }
    : { where: 'Where', who: 'Who', all: 'Everyone', poll: 'Poll', past: (n) => `(+ ${n} past meeting${n === 1 ? '' : 's'} in the calendar file)`,
      head: (n) => `${n === 1 ? 'The meeting' : `All ${n} meetings`} for “${poll.title}”:`,
      ics: 'All meetings are attached as a calendar file. Open it to add them to your calendar.',
      sub: 'Or subscribe (your calendar then stays up to date as meetings are added or changed):',
      google: 'Google Calendar: Other calendars › From URL', footer: `\n\n—\nYou're getting this because the organiser of “${poll.title}” sent you its meetings.`,
      subject: `Meetings: ${poll.title}` };
  const today = now().slice(0, 10);
  const lastDay = (mt) => (mt.repeat ? mt.repeat.until || '9999-12-31' : mt.endDate || mt.date);
  const sorted = [...meetings].sort((x, y) => meetingStart(x).localeCompare(meetingStart(y)) || (x.start || 0) - (y.start || 0));
  const upcoming = sorted.filter((mt) => lastDay(mt) >= today), past = sorted.length - upcoming.length;
  const block = (mt) => [`• ${mt.title || poll.title}`, `  ${meetingWhen(mt, poll.lang)}`, mt.location ? `  ${L.where}: ${mt.location}` : null,
    `  ${L.who}: ${mt.participants === 'all' ? L.all : whoText(mt)}`, ...[mt.note, mt.extra].filter(Boolean).map((x) => '  ' + x.replace(/\n/g, '\n  '))]
    .filter((x) => x !== null).join('\n');
  const text = [message || null, message ? '' : null, L.head(sorted.length), '', (upcoming.length ? upcoming : sorted).map(block).join('\n\n'),
    upcoming.length && past ? '\n' + L.past(past) : null, '', L.ics, '', L.sub, feed.replace(/^https?:/, 'webcal:'), `${L.google}: ${feed}`, '', `${L.poll}: ${link}`]
    .filter((x) => x !== null).join('\n') + L.footer;
  const name = poll.title.replace(/[^\w\- ]+/g, '').trim() || 'meetings';
  const sent = await sendMail(env, poll, { to, subject: L.subject, text, quota: true,
    attachments: [{ content: enc.encode(buildIcs(poll, sorted, link)), filename: `${name}.ics` }] });
  return json({ ok: true, sent, missing });
}

// "Invite by email" for the poll itself: sent from MAIL_FROM (the site's domain), everyone in BCC, replies go to the organiser.
// Who gets it, one of:
//   { people: [{ name, email }] }  adds them to the poll's participants (or finds them), then emails those with an address
//   { ids: [participantId] }       participants of this poll, e.g. "Resend" or a selection in the People tab
//   { remind: true }               everyone with an address who hasn't answered the current round
//   { emails: [...] }              legacy: plain addresses, not added as participants
// Participants who are emailed get invited_at set. Already-invited people (and { remind }) get a reminder wording.
async function invitePoll(request, env, url, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, poll);
  await adoptLang(request, env, poll);
  const b = await body(request);
  const message = str(b.message, 1000, 'Message');
  const inst = await latestInstance(env, id);
  let emails = [], pids = [], missing = [], again = !!b.remind, added = null;
  if (Array.isArray(b.people) || b.remind || Array.isArray(b.ids)) {
    let want;
    if (Array.isArray(b.people)) { added = await upsertPeople(env, id, peopleInput(b), userOf(request)); want = new Set(added.ids.filter(Boolean)); }
    else if (Array.isArray(b.ids)) {
      if (b.ids.length > 500) throw new HttpError(400, 'Too many people');
      want = new Set(b.ids.filter((x) => typeof x === 'string' && ID_RE.test(x)));
    }
    const rows = (await participantRows(env, id, inst && inst.id)).filter((p) => (b.remind ? !p.here : want.has(p.id)));
    const withMail = rows.filter((p) => EMAIL_RE.test(p.mail_to));
    missing = rows.filter((p) => !EMAIL_RE.test(p.mail_to)).map((p) => p.name);
    if (!b.remind && withMail.length && withMail.every((p) => p.invited_at)) again = true;
    emails = withMail.map((p) => p.mail_to.toLowerCase()); pids = withMail.map((p) => p.id);
    if (!emails.length) {
      if (added) return json({ ok: true, sent: 0, missing, ...added });
      throw new HttpError(400, b.remind ? 'Everyone with an email address has answered' : 'None of them has an email address');
    }
  } else {
    if (!Array.isArray(b.emails)) throw new HttpError(400, 'emails must be a list');
    emails = [...new Set(b.emails.filter((e) => typeof e === 'string').map((e) => e.trim().toLowerCase()).filter((e) => e.length <= 200 && EMAIL_RE.test(e)))];
    if (!emails.length) throw new HttpError(400, 'Enter at least one email address');
  }
  emails = [...new Set(emails)];
  if (emails.length > 200) throw new HttpError(400, 'At most 200 addresses at once');
  const user = userOf(request) || {};
  const deadline = inst && inst.status === 'open' && inst.deadline ? inst.deadline.slice(0, 10) : null;
  const link = `${siteUrl(env, url.origin)}/?p=${poll.id}`;
  let text, subject;
  if (poll.lang === 'de') {
    const who = user.name || 'Jemand';
    text = [message || (again ? `Eine Erinnerung: ${who} möchte wissen, wann du für „${poll.title}“ Zeit hast.` : `${who} möchte wissen, wann du für „${poll.title}“ Zeit hast.`), '',
      poll.description ? poll.description + '\n' : null,
      poll.invited_only ? 'Melde dich mit dieser E-Mail-Adresse an und trag hier ein, wann du Zeit hast:' : 'Trag hier ein, wann du Zeit hast (kein Konto nötig):', link,
      deadline ? `\nBitte antworte bis ${fmtDay(deadline, 'de')}.` : null].filter((x) => x !== null).join('\n')
      + `\n\n—\nDu bekommst diese E-Mail, weil ${user.name || 'jemand'} dich zu einer Umfrage auf when-who eingeladen hat.`;
    subject = `${again ? 'Erinnerung: Wann' : 'Wann'} hast du Zeit? ${poll.title}`;
  } else {
    const who = user.name || 'The organiser';
    text = [message || (again ? `A reminder: ${who} would like to know when you're free for “${poll.title}”.` : `${who} would like to know when you're free for “${poll.title}”.`), '',
      poll.description ? poll.description + '\n' : null,
      poll.invited_only ? 'Sign in with this email address and mark your availability here:' : 'Mark your availability here (no account needed):', link,
      deadline ? `\nPlease answer by ${fmtDay(deadline)}.` : null].filter((x) => x !== null).join('\n')
      + `\n\n—\nYou're getting this because ${who} invited you to a poll on when-who.`;
    subject = `${again ? 'Reminder: when' : 'When'} are you free? ${poll.title}`;
  }
  const sent = await sendMail(env, poll, { to: emails, subject, text, quota: true });
  if (pids.length) {
    const at = now();
    await env.DB.batch(pids.map((pid) => env.DB.prepare('UPDATE participants SET invited_at = ? WHERE id = ?').bind(at, pid)));
  }
  return json({ ok: true, sent, missing, ...(added || {}) });
}


// Who gets series emails: everyone in the poll's participant list who has an email address, not only last round's answers.
// Accounts: the account's email. Guests who answered: the email on their latest answer (removing it there stops the emails).
// Guests who never answered (added by the owner in Participants): the email the owner gave them.
// Skips anyone who already answered `inst`.
async function participantEmails(env, poll, inst) {
  const { results } = await env.DB.prepare(
    `SELECT u.email AS ue, p.email AS pe,
       (SELECT r.email FROM responses r WHERE r.participant_id = p.id ORDER BY r.updated_at DESC LIMIT 1) AS re,
       EXISTS (SELECT 1 FROM responses r WHERE r.participant_id = p.id AND r.instance_id = ?) AS here
     FROM participants p LEFT JOIN users u ON u.id = p.user_id WHERE p.poll_id = ?`).bind(inst.id, poll.id).all();
  return results.filter((r) => !r.here).map((r) => (r.ue || (r.re !== null ? r.re : r.pe) || '').trim()).filter(Boolean);
}
async function notifyOpened(env, poll, inst, origin) {
  // claim the notification so it is sent once even if the cron job and a visitor race
  const claim = await env.DB.prepare('UPDATE instances SET opened_notified = 1 WHERE id = ? AND opened_notified = 0').bind(inst.id).run();
  if (!claim.meta || !claim.meta.changes) return;
  if (!poll.notify_open || !emailEnabled(env)) return;
  const to = await participantEmails(env, poll, inst);
  if (!to.length) return;
  const base = siteUrl(env, origin); if (!base) return;
  const period = periodText(poll, inst);
  if (poll.lang === 'de') {
    const text = `Die Umfrage für ${period} ist offen.\n\nBitte trag ein, wann du Zeit hast${inst.deadline ? ` (bis ${fmtDay(inst.deadline, 'de')})` : ''}:\n${base}/?p=${poll.id}` + seriesFooter(poll);
    await sendMail(env, poll, { to, subject: `${poll.title}: Wann hast du Zeit (${period})?`, text });
    return;
  }
  const text = `The poll for ${period} is open.\n\nPlease mark when you're available${inst.deadline ? ` by ${fmtDay(inst.deadline)}` : ''}:\n${base}/?p=${poll.id}` + seriesFooter(poll);
  await sendMail(env, poll, { to, subject: `${poll.title}: when are you free in ${period}?`, text });
}
async function remind(env, poll, inst) {
  const claim = await env.DB.prepare('UPDATE instances SET reminded = 1 WHERE id = ? AND reminded = 0').bind(inst.id).run();
  if (!claim.meta || !claim.meta.changes || !emailEnabled(env)) return;
  const base = siteUrl(env); if (!base) return;
  const to = await participantEmails(env, poll, inst);
  if (!to.length) return;
  const period = periodText(poll, inst);
  const de = poll.lang === 'de';
  const text = (de ? `Erinnerung: Bitte trag bis ${fmtDay(inst.deadline, 'de')} ein, wann du für ${period} Zeit hast.`
    : `Reminder: please mark when you're available for ${period} by ${fmtDay(inst.deadline)}.`) + `\n\n${base}/?p=${poll.id}` + seriesFooter(poll);
  await sendMail(env, poll, { to, subject: `${de ? 'Erinnerung' : 'Reminder'}: ${poll.title} (${period})`, text });
}
async function runScheduled(env) {
  try {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now()),
      env.DB.prepare('DELETE FROM login_attempts WHERE at < ?').bind(new Date(Date.now() - 86400000).toISOString()),
      env.DB.prepare('DELETE FROM login_codes WHERE expires_at < ?').bind(now()),
      env.DB.prepare('DELETE FROM mail_log WHERE at < ?').bind(new Date(Date.now() - 2 * 86400000).toISOString()),
      env.DB.prepare('DELETE FROM oauth_states WHERE created_at < ?').bind(new Date(Date.now() - 3600000).toISOString()),
    ]);
  } catch (e) { console.error('cleanup', e); }
  if (new Date().getUTCHours() === 3) { try { await deleteStalePolls(env); } catch (e) { console.error('retention', e); } }
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
// A guest who gives the email of an existing account: their answers belong to that account, signed in or not.
const accountByEmail = (env, mail) => mail
  ? env.DB.prepare('SELECT id, email FROM users WHERE email = ?').bind(mail.trim().toLowerCase()).first() : null;
// Links a guest participant to the account with this email, unless the account is already someone in this poll.
async function linkGuestToAccount(env, pollId, partId, mail) {
  const acct = await accountByEmail(env, mail);
  if (!acct || !partId || await accountParticipant(env, pollId, acct.id)) return;
  await env.DB.prepare('UPDATE participants SET user_id = ?, name_key = ?, email = ? WHERE id = ? AND user_id IS NULL')
    .bind(acct.id, acctKey(acct.id), acct.email, partId).run();
}
// Invited-only polls: the answer must come from a signed-in account that the owner invited, either as that account
// or as a guest row with the account's email (that row then becomes the account's). The owner can always answer.
async function requireInvited(env, poll, user, admin) {
  if (!poll.invited_only || admin) return;
  if (!user) throw new HttpError(403, 'Only invited people can answer this poll. Sign in with the email address you were invited with.', { code: 'invite_only' });
  if (await accountParticipant(env, poll.id, user.id)) return;
  const g = await env.DB.prepare('SELECT id FROM participants WHERE poll_id = ? AND user_id IS NULL AND LOWER(email) = ? LIMIT 1').bind(poll.id, user.email.toLowerCase()).first();
  if (!g) throw new HttpError(403, 'Only invited people can answer this poll, and this account isn’t invited.', { code: 'not_invited' });
  await env.DB.prepare('UPDATE participants SET user_id = ?, name_key = ?, email = ? WHERE id = ?').bind(user.id, acctKey(user.id), user.email, g.id).run();
}
// ---------- shared busy hours ----------
// PUT /api/polls/:id/instances/:iid/busy { share, hours? }: the caller's account participant turns sharing on / off.
// hours = { "YYYY-MM-DD": [0..23] } for this round's dates, worked out in the sharer's browser from their own calendars.
// Turning it off deletes everything they shared with this poll.
const BUSY_PER_DAY = 300;
async function shareBusy(request, env, id, iid) {
  const user = requireUser(request);
  const poll = await loadPoll(env, id);
  const admin = await isAdmin(request, poll);
  if (!admin) await checkPassword(env, request, poll);
  const inst = await loadInstance(env, id, iid);
  await requireInvited(env, poll, user, admin);
  const part = await accountParticipant(env, id, user.id);
  if (!part) throw new HttpError(409, 'Answer the poll first, then you can share your busy times');
  const b = await body(request);
  if (!b.share) {
    await env.DB.batch([
      env.DB.prepare('UPDATE participants SET share_busy = 0 WHERE id = ?').bind(part.id),
      env.DB.prepare('DELETE FROM shared_busy WHERE participant_id = ?').bind(part.id),
    ]);
    return json({ ok: true, share: false });
  }
  const stmts = [env.DB.prepare('UPDATE participants SET share_busy = 1 WHERE id = ?').bind(part.id)];
  if (b.hours !== undefined) {
    if (!b.hours || typeof b.hours !== 'object' || Array.isArray(b.hours)) throw new HttpError(400, 'Invalid busy times');
    const dates = new Set(datesOf(inst, poll)), keys = Object.keys(b.hours), out = {};
    if (keys.length > 400) throw new HttpError(400, 'Invalid busy times');
    for (const k of keys) {
      const v = b.hours[k];
      if (!dates.has(k) || !Array.isArray(v) || v.length > 24 || !v.every((h) => Number.isInteger(h) && h >= 0 && h <= 23)) throw new HttpError(400, 'Invalid busy times');
      if (v.length) out[k] = [...new Set(v)].sort((x, y) => x - y);
    }
    const key = 'u:' + user.id, since = new Date(Date.now() - 86400000).toISOString();
    const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND kind = ? AND at > ?').bind(key, 'busy', since).first('n');
    if (n >= BUSY_PER_DAY) throw new HttpError(429, 'Too many updates. Try again later.');
    await recordFail(env, request, 'busy', key);
    stmts.push(env.DB.prepare(
      `INSERT INTO shared_busy (instance_id, participant_id, poll_id, hours, updated_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (instance_id, participant_id) DO UPDATE SET hours = excluded.hours, updated_at = excluded.updated_at`)
      .bind(inst.id, part.id, id, JSON.stringify(out), now()));
  }
  await env.DB.batch(stmts);
  return json({ ok: true, share: true });
}

const nameTaken = (name, participantId, responseId) =>
  new HttpError(409, `“${name}” has already answered this poll. If that's you, load your answer instead.`, { code: 'name_taken', participantId, responseId });

// ---------- Workers AI helpers (Fill with AI, Suggest with AI) ----------
// Per account (or IP) per day, shared by both; login_attempts rows are kept for a day.
async function aiQuota(request, env, user) {
  const key = user ? 'u:' + user.id : clientIp(request), max = Number(env.AI_PER_DAY) || AI_PER_DAY;
  const since = new Date(Date.now() - 86400000).toISOString();
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND kind = ? AND at > ?').bind(key, 'ai', since).first('n');
  if (n >= max) throw new HttpError(429, `You can fill from text ${max} times a day. Try again tomorrow.`);
  await recordFail(env, request, 'ai', key);
}
// Runs the model with a JSON schema and returns the parsed object (or null).
async function aiJson(env, system, text, schema) {
  let out;
  try {
    out = await env.AI.run(env.AI_MODEL || AI_MODEL, {
      messages: [{ role: 'system', content: system }, { role: 'user', content: text }],
      response_format: { type: 'json_schema', json_schema: schema },
      max_tokens: 600, temperature: 0,
    });
  } catch (e) {
    console.log('AI failed', e && e.message);
    throw new HttpError(503, 'The text helper is busy or used up for today. Try again later.');
  }
  let res = out && out.response;
  if (typeof res === 'string') { const j = res.match(/\{[\s\S]*\}/); try { res = j ? JSON.parse(j[0]) : null; } catch { res = null; } }
  return res && typeof res === 'object' ? res : null;
}
const isoWd = (d) => (new Date(d + 'T00:00:00Z').getUTCDay() + 6) % 7; // 0 = Monday
// "weekdays" / "weekend" / "mon".."sun" (or longer names) → weekday indexes.
const fillWds = (v) => v === 'weekdays' ? [0, 1, 2, 3, 4] : v === 'weekend' ? [5, 6] : FILL_WD.indexOf(v.slice(0, 3)) >= 0 ? [FILL_WD.indexOf(v.slice(0, 3))] : [];

// ---------- fill an answer from text (Workers AI) ----------
// The person types or says when they're free; the model turns it into a few rules, which the Worker checks and
// expands to days and hours of this round. Nothing is saved: the page puts the result into the answer being edited.
const FILL_WD = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
const FILL_SCHEMA = {
  type: 'object',
  properties: {
    rules: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          days: { type: 'array', items: { type: 'string' } },
          from: { type: 'integer' }, to: { type: 'integer' },
          status: { type: 'string', enum: ['available', 'if_needed', 'maybe', 'not_available'] },
        },
        required: ['days', 'from', 'to', 'status'],
      },
    },
  },
  required: ['rules'],
};
function fillPrompt(poll, dates, lang) {
  const weekly = poll.kind === 'weekly', slots = poll.answer_mode !== 'days';
  const t = today(), wdOf = (d) => FILL_WD[(new Date(d + 'T00:00:00Z').getUTCDay() + 6) % 7];
  const list = weekly ? '' : dates.length <= 62 ? dates.map((d) => `${d} ${wdOf(d)}`).join(', ') : `${dates[0]} to ${dates[dates.length - 1]}`;
  return [
    'You turn a person\'s description of when they are free into JSON rules for a scheduling poll.',
    weekly ? 'The poll asks about a typical week, so use weekday names only.' : `Today is ${t} (${wdOf(t)}). The poll's dates: ${list}.`,
    slots ? `Hours run from ${poll.hour_start} to ${poll.hour_end} (24-hour clock; "to" is exclusive, so 18-21 means 18:00 until 21:00).`
      : `The poll only asks about whole days: always use from ${poll.hour_start} and to ${poll.hour_end}.`,
    'Each rule: days = list of "all", weekday names (mon tue wed thu fri sat sun), "weekdays", "weekend" or dates (YYYY-MM-DD);',
    'from / to = hours; status = available | if_needed | maybe | not_available.',
    'Rules apply in order and later rules override earlier ones, so put general rules first and exceptions after them.',
    '"Morning" = 8-12, "afternoon" = 12-17, "evening" = 17-22, "all day" = the full hour range. Days that aren\'t mentioned stay unchanged.',
    `The text may be in ${lang === 'de' ? 'German or English' : 'English or German'}. Answer only with JSON like {"rules":[{"days":["weekdays"],"from":18,"to":22,"status":"available"}]}.`,
  ].join('\n');
}
async function fillFromText(request, env, id, iid) {
  if (!env.AI) throw new HttpError(503, 'Filling from text isn’t available here');
  const poll = await loadPoll(env, id);
  const admin = isAdmin(request, poll);
  if (!admin) await checkPassword(env, request, poll);
  const inst = await loadInstance(env, id, iid);
  if (effStatus(inst) !== 'open' && !admin) throw new HttpError(409, 'This poll is closed');
  const b = await body(request);
  const text = str(b.text, 500, 'Text', true);
  const user = userOf(request);
  await requireInvited(env, poll, user, admin);
  await aiQuota(request, env, user);
  const dates = datesOf(inst, poll);
  const res = await aiJson(env, fillPrompt(poll, dates, reqLang(request)), text, FILL_SCHEMA);
  const raw = res && Array.isArray(res.rules) ? res.rules.slice(0, 40) : null;
  if (!raw) throw new HttpError(502, 'Couldn’t understand that. Try saying it differently.');
  const ST = { available: 'y', if_needed: 'i', maybe: 'm', not_available: 'x' };
  const inDates = new Set(dates), rules = [];
  for (const r of raw) {
    if (!r || typeof r !== 'object' || !ST[r.status] || !Array.isArray(r.days)) continue;
    const want = new Set();
    for (const x of r.days.slice(0, 100)) {
      const v = String(x).toLowerCase().trim();
      if (v === 'all') dates.forEach((d) => want.add(d));
      else if (inDates.has(v)) want.add(v);
      else { const wds = fillWds(v); dates.forEach((d) => { if (wds.includes(isoWd(d))) want.add(d); }); }
    }
    let hs = Math.max(poll.hour_start, Math.min(23, Math.round(Number(r.from)))), he = Math.min(poll.hour_end, Math.max(1, Math.round(Number(r.to))));
    if (poll.answer_mode === 'days' || !Number.isFinite(hs) || !Number.isFinite(he)) { hs = poll.hour_start; he = poll.hour_end; }
    if (he <= hs || !want.size) continue;
    rules.push({ dates: dates.filter((d) => want.has(d)), hs, he, st: ST[r.status] });
  }
  if (!rules.length) throw new HttpError(422, 'None of the poll’s days or hours match that.');
  return json({ rules });
}

// ---------- Suggest with AI (organiser's meeting planner) ----------
// The organiser describes the meetings they want; the model turns that into the planner's Suggest settings, and the page
// runs its normal Suggest with them. Only the text (and how many people are selected) is sent, no answers or names.
const SUGGEST_SCHEMA = {
  type: 'object',
  properties: {
    count: { type: 'integer' }, per: { type: 'string', enum: ['total', 'week', 'month'] },
    hours: { type: 'integer' }, min_people: { type: 'integer' }, gap_days: { type: 'integer' },
    count_if_needed: { type: 'boolean' }, count_maybe: { type: 'boolean' },
    days: { type: 'array', items: { type: 'string' } }, dates: { type: 'array', items: { type: 'string' } },
    from: { type: 'integer' }, to: { type: 'integer' },
  },
  required: ['count', 'per', 'hours', 'min_people', 'gap_days', 'count_if_needed', 'count_maybe', 'days', 'dates', 'from', 'to'],
};
function suggestPrompt(poll, dates, tot, lang) {
  const weekly = poll.kind === 'weekly', slots = poll.answer_mode !== 'days';
  const t = today(), wd = (d) => FILL_WD[isoWd(d)];
  const wk = (n) => { const a = addDays(t, 7 * n - isoWd(t)); return `${a} to ${addDays(a, 6)}`; };
  const list = weekly ? '' : dates.length <= 62 ? dates.map((d) => `${d} ${wd(d)}`).join(', ') : `${dates[0]} to ${dates[dates.length - 1]}`;
  return [
    'You turn an organiser\'s description of the meetings they want into JSON settings for a meeting planner.',
    'The planner then picks the times when most people are free; you only fill in the settings.',
    weekly ? 'The poll is about a typical week: use weekday names in "days" and leave "dates" empty.'
      : `Today is ${t} (${wd(t)}). This week = ${wk(0)}, next week = ${wk(1)} (Monday to Sunday). The poll's dates: ${list}.`,
    `${tot} people are selected to come.`,
    'Fields: count = how many meetings (0 = as many as fit, only when no number is given); "a meeting" / "one" / "ein Treffen" = 1;',
    'per = total | week | month (count is per week / month, e.g. "twice a week" = 2 + week);',
    slots ? `hours = length of each meeting in hours (0 = not said); from / to = the hours to look in, between ${poll.hour_start} and ${poll.hour_end} (24-hour clock, "to" exclusive).`
      : `The poll asks about whole days: hours = 0, from = ${poll.hour_start}, to = ${poll.hour_end}.`,
    'min_people = at least this many people free (0 = everyone, or not said); gap_days = keep meetings at least this many days apart (0 = not said);',
    'count_if_needed = count "if needed" answers as free (default true); count_maybe = count "maybe" answers as free (default false);',
    'days = which weekdays are allowed: "all", "weekdays", "weekend" or weekday names (mon tue wed thu fri sat sun). "Not on Friday" = the other six days;',
    'dates = only these dates (YYYY-MM-DD from the poll\'s dates), e.g. for "next week" or "before the 15th"; empty = any date.',
    '"Morning" = 8-12, "afternoon" = 12-17, "evening" = 17-22, "lunch" = 12-14. Leave everything the text doesn\'t mention at its default',
    `(count 0, per total, hours 0, min_people 0, gap_days 0, days ["all"], dates [], from ${poll.hour_start}, to ${poll.hour_end}).`,
    `The text may be in ${lang === 'de' ? 'German or English' : 'English or German'}. Answer only with the JSON object.`,
  ].join('\n');
}
async function suggestFromText(request, env, id, iid) {
  if (!env.AI) throw new HttpError(503, 'Filling from text isn’t available here');
  const poll = await loadPoll(env, id);
  requireAdmin(request, poll);
  const inst = await loadInstance(env, id, iid);
  const b = await body(request);
  const text = str(b.text, 500, 'Text', true);
  const tot = int(b.people ?? 1, 1, 999, 'People');
  await aiQuota(request, env, userOf(request));
  const dates = datesOf(inst, poll), slots = poll.answer_mode !== 'days';
  const r = await aiJson(env, suggestPrompt(poll, dates, tot, reqLang(request)), text, SUGGEST_SCHEMA);
  if (!r) throw new HttpError(502, 'Couldn’t understand that. Try saying it differently.');
  const num = (v, lo, hi, d = 0) => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d; };
  const span = Math.max(1, poll.hour_end - poll.hour_start);
  const s = {
    n: num(r.count, 0, 99), per: r.per === 'week' || r.per === 'month' ? r.per : 'all',
    len: slots ? num(r.hours, 0, span) : 0, min: num(r.min_people, 0, tot), gap: num(r.gap_days, 0, 60),
    ifn: r.count_if_needed !== false, maybe: r.count_maybe === true,
  };
  if (s.min >= tot) s.min = 0; // everyone = the default
  const wd = new Set();
  for (const x of Array.isArray(r.days) ? r.days.slice(0, 20) : []) {
    const v = String(x).toLowerCase().trim();
    if (v === 'all') [0, 1, 2, 3, 4, 5, 6].forEach((i) => wd.add(i)); else fillWds(v).forEach((i) => wd.add(i));
  }
  if (!wd.size) [0, 1, 2, 3, 4, 5, 6].forEach((i) => wd.add(i));
  let hs = num(r.from, poll.hour_start, poll.hour_end - 1, poll.hour_start), he = num(r.to, poll.hour_start + 1, poll.hour_end, poll.hour_end);
  if (!slots || he <= hs) { hs = poll.hour_start; he = poll.hour_end; }
  if (s.len && s.len > he - hs) s.len = he - hs;
  const inDates = new Set(dates);
  const only = poll.kind === 'weekly' || !Array.isArray(r.dates) ? [] : [...new Set(r.dates.slice(0, 400).map((x) => String(x).trim()).filter((x) => inDates.has(x)))].sort();
  return json({ s, wd: [...wd].sort(), hs, he, dates: only.length && only.length < dates.length ? only : null });
}

async function createResponse(request, env, id, iid) {
  const poll = await loadPoll(env, id);
  const admin = await isAdmin(request, poll);
  if (!admin) await checkPassword(env, request, poll);
  const inst = await loadInstance(env, id, iid);
  if (effStatus(inst) !== 'open' && !admin) throw new HttpError(409, 'This poll is closed');
  const b = await body(request);
  const user = userOf(request);
  await requireInvited(env, poll, user, admin);
  // Signed in: the name shown to others is the account's profile name (typed name only while the profile has none).
  const name = user && user.name ? user.name : personName(b.name);
  const comment = poll.allow_comments ? str(b.comment, 500, 'Comment') : '';
  const mail = user ? user.email : email(b.email);
  if (poll.require_email && !mail && !admin) throw new HttpError(400, 'This poll asks for your email address');
  const entries = validateEntries(b.entries, poll, datesOf(inst, poll));
  const fill = parseFill(b.fill, poll, datesOf(inst, poll));
  const extra = await validateExtra(env, b.extra, inst, null, { admin, needReq: true });
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
    // Email of an account that's already in this poll and hasn't answered this round: that's this person.
    const acct = await accountByEmail(env, mail);
    const ap = acct && await accountParticipant(env, id, acct.id);
    if (ap && !(await answerIn(env, ap.id, iid))) part = ap;
    else {
      // Same name as an existing guest: that's this person (e.g. the next round of a series),
      // unless they already answered this round.
      part = await findParticipant(env, id, nameKey(name));
      if (part) {
        const existing = await answerIn(env, part.id, iid);
        if (existing) throw nameTaken(part.name, part.id, existing);
      } else part = await newParticipant(env, id, name);
      if (acct && !ap) await linkGuestToAccount(env, id, part.id, mail);
    }
  }
  const rid = randomId(12), editKey = secret(), t = now();
  await env.DB.prepare('INSERT INTO responses (id, poll_id, instance_id, name, email, comment, entries, edit_hash, participant_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .bind(rid, id, iid, part.name, mail, comment, JSON.stringify(entries), await sha256('edit:' + editKey), part.id, t, t).run();
  if (fill) await env.DB.prepare('UPDATE responses SET fill = ? WHERE id = ?').bind(fill, rid).run(); // column from migration 0015
  if (extra) await env.DB.prepare('UPDATE responses SET extra = ? WHERE id = ?').bind(extra, rid).run(); // column from migration 0022
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
  if (!(await isAdmin(request, poll))) await checkPassword(env, request, poll);
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
  return json({ id: r.id, instanceId: r.instance_id, name: r.name, email: r.email, comment: r.comment, entries: JSON.parse(r.entries),
    fill: r.fill ? JSON.parse(r.fill) : null, votes: parseVotes(r.votes, proposedIds(await loadInstance(env, id, r.instance_id))), extra: parseExtra(r.extra) });
}
// ---- votes on proposed meetings: responses.votes = JSON array of the meeting ids the person ticked.
const proposedIds = (inst) => new Set(JSON.parse(inst.meetings || '[]').filter((x) => x.proposed).map((x) => x.id));
function parseVotes(raw, props) { let v; try { v = JSON.parse(raw || '[]'); } catch { v = []; } return Array.isArray(v) ? v.filter((x) => props.has(x)) : []; }
// PUT /api/polls/:id/responses/:rid/votes { votes: [meetingId] } — by the answer's owner (same rule as editing it) or the organiser.
async function voteMeetings(request, env, id, rid) {
  const poll = await loadPoll(env, id);
  const r = await loadResponse(env, id, rid);
  const inst = await loadInstance(env, id, r.instance_id);
  const admin = await isAdmin(request, poll);
  if (!admin && !(await canEditResponse(request, env, r))) throw new HttpError(403, 'Not your response');
  if (!admin) await checkPassword(env, request, poll);
  const b = await body(request);
  const props = proposedIds(inst);
  if (!Array.isArray(b.votes) || b.votes.length > MAX_MEETINGS) throw new HttpError(400, 'Invalid votes');
  if (b.votes.some((x) => typeof x !== 'string' || !props.has(x))) throw new HttpError(400, 'That option is no longer up for a vote');
  const votes = [...new Set(b.votes)];
  await env.DB.prepare('UPDATE responses SET votes = ? WHERE id = ?').bind(votes.length ? JSON.stringify(votes) : null, r.id).run();
  return json({ ok: true, votes });
}
// ---- questions: extra info for a round or its meetings, and votes on options (e.g. places).
// instances.questions = the organiser's list; responses.extra = { a: { qid: answer }, add: { qid: [{ id, label }] } }.
// Answers: choice → [option id], text → string, yesno → { y: bool, n?: count }. `add` = options this person suggested
// (questions with add: true); they live in the person's own answer so they go away with it.
const MAX_QUESTIONS = 20, MAX_Q_OPTIONS = 30, MAX_ADD_OPTIONS = 5;
const QID_RE = /^[A-Za-z0-9]{4,20}$/;
const Q_TYPES = ['choice', 'text', 'yesno'];
function questionsOf(inst) { try { const q = JSON.parse(inst.questions || '[]'); return Array.isArray(q) ? q : []; } catch { return []; } }
function parseExtra(raw) { try { const x = JSON.parse(raw || 'null'); return x && typeof x === 'object' && !Array.isArray(x) ? x : {}; } catch { return {}; } }
function validateQuestions(list, meetings, old = []) {
  if (!Array.isArray(list) || list.length > MAX_QUESTIONS) throw new HttpError(400, `Up to ${MAX_QUESTIONS} questions per round`);
  const mids = new Set(meetings.map((m) => m.id)), prev = new Map(old.map((q) => [q.id, q])), seen = new Set();
  return list.map((q) => {
    if (!q || typeof q !== 'object' || !Q_TYPES.includes(q.type)) throw new HttpError(400, 'Invalid question');
    const id = QID_RE.test(q.id || '') && !seen.has(q.id) ? q.id : randomId(8);
    seen.add(id);
    const out = { id, type: q.type, label: str(q.label, 120, 'Question', true), help: str(q.help, 300, 'Question note') || undefined,
      req: q.req ? true : undefined, vis: q.vis === 'owner' ? 'owner' : 'all', closed: q.closed ? true : undefined,
      at: prev.get(id)?.at || now() }; // when it was added (chat timeline)
    const ms = Array.isArray(q.meetings) ? [...new Set(q.meetings.filter((x) => typeof x === 'string' && mids.has(x)))] : [];
    if (ms.length) out.meetings = ms;
    if (q.type === 'choice') {
      const opts = Array.isArray(q.options) ? q.options : [];
      if (opts.length > MAX_Q_OPTIONS) throw new HttpError(400, `Up to ${MAX_Q_OPTIONS} options per question`);
      const os = new Set();
      out.options = opts.map((o) => {
        const oid = QID_RE.test(o?.id || '') && !os.has(o.id) ? o.id : randomId(8);
        os.add(oid);
        return { id: oid, label: str(o?.label, 120, 'Option', true) };
      });
      out.multi = q.multi ? true : undefined; out.add = q.add ? true : undefined; out.place = q.place ? true : undefined;
      if (!out.options.length && !out.add) throw new HttpError(400, 'Add an option, or let people add their own');
    }
    if (q.type === 'yesno' && q.count) out.count = { label: str(q.count.label, 60, 'Count label'), max: int(q.count.max ?? 10, 1, 99, 'Highest number') };
    return out;
  });
}
// Options people suggested in this round: Map question id → [{ id, label }] (from every answer's `add`).
async function addedOptions(env, iid, skipRid) {
  const { results } = await env.DB.prepare('SELECT id, extra FROM responses WHERE instance_id = ? AND extra IS NOT NULL').bind(iid).all();
  const out = new Map();
  for (const r of results) {
    if (r.id === skipRid) continue;
    for (const [qid, list] of Object.entries(parseExtra(r.extra).add || {})) {
      if (!Array.isArray(list)) continue;
      if (!out.has(qid)) out.set(qid, []);
      out.get(qid).push(...list.filter((o) => o && typeof o.id === 'string' && typeof o.label === 'string'));
    }
  }
  return out;
}
// Option ids valid for a choice question: the organiser's plus everyone's suggestions.
const optionIds = (q, added) => new Set([...(q.options || []), ...(added.get(q.id) || [])].map((o) => o.id));
// Checks a person's answers to the round's questions. old = what they had (closed questions keep it unless the organiser edits).
// needReq: required questions must be answered (saving My answer; not for quick answers from a meeting card).
async function validateExtra(env, raw, inst, rid, { old = {}, admin = false, needReq = false } = {}) {
  const qs = questionsOf(inst);
  if (!qs.length) return null;
  if (raw != null && (typeof raw !== 'object' || Array.isArray(raw))) throw new HttpError(400, 'Invalid answers to questions');
  const x = raw || {}, a = x.a && typeof x.a === 'object' ? x.a : {}, addIn = x.add && typeof x.add === 'object' ? x.add : {};
  const added = await addedOptions(env, inst.id, rid);
  const outA = {}, outAdd = {};
  for (const q of qs) {
    if (q.closed && !admin) { // closed: keep what was there
      if (old.a && old.a[q.id] !== undefined) outA[q.id] = old.a[q.id];
      if (old.add && old.add[q.id]) outAdd[q.id] = old.add[q.id];
      continue;
    }
    let v = a[q.id];
    if (q.type === 'choice') {
      const valid = optionIds(q, added);
      if (q.add && Array.isArray(addIn[q.id])) {
        const labels = new Set([...(q.options || []), ...(added.get(q.id) || [])].map((o) => o.label.toLowerCase()));
        const mine = [];
        for (const o of addIn[q.id].slice(0, MAX_ADD_OPTIONS)) {
          const label = str(o?.label, 120, 'Option');
          if (!label || labels.has(label.toLowerCase()) || !QID_RE.test(o.id || '') || valid.has(o.id)) continue;
          labels.add(label.toLowerCase()); valid.add(o.id); mine.push({ id: o.id, label });
        }
        if (mine.length) outAdd[q.id] = mine;
      }
      v = Array.isArray(v) ? [...new Set(v.filter((o) => typeof o === 'string' && valid.has(o)))] : [];
      if (!q.multi) v = v.slice(0, 1);
      if (v.length) outA[q.id] = v;
    } else if (q.type === 'text') {
      v = str(typeof v === 'string' ? v : '', 500, q.label);
      if (v) outA[q.id] = v;
    } else if (v && typeof v === 'object' && typeof v.y === 'boolean') {
      outA[q.id] = { y: v.y, ...(v.y && q.count && v.n != null && v.n !== '' ? { n: int(v.n, 0, q.count.max, q.count.label || 'Number') } : {}) };
    }
    if (needReq && q.req && !admin && outA[q.id] === undefined) throw new HttpError(400, `Please answer: ${q.label}`, { code: 'question', question: q.id });
  }
  const out = { ...(Object.keys(outA).length ? { a: outA } : {}), ...(Object.keys(outAdd).length ? { add: outAdd } : {}) };
  return Object.keys(out).length ? JSON.stringify(out) : null;
}
// What the caller may see of someone's answers: the organiser and the answer's owner everything, others only vis 'all'.
function extraFor(raw, qs, added, full) {
  const x = parseExtra(raw), a = {};
  for (const q of qs) {
    let v = x.a && x.a[q.id];
    if (v === undefined || (!full && q.vis === 'owner')) continue;
    if (q.type === 'choice') { const ok = optionIds(q, added); v = Array.isArray(v) ? v.filter((o) => ok.has(o)) : []; if (!v.length) continue; }
    a[q.id] = v;
  }
  return Object.keys(a).length ? a : undefined;
}
// PUT /api/polls/:id/responses/:rid/extra { extra } — answer questions without re-saving the availability (meeting cards).
async function answerQuestions(request, env, id, rid) {
  const poll = await loadPoll(env, id);
  const r = await loadResponse(env, id, rid);
  const inst = await loadInstance(env, id, r.instance_id);
  const admin = await isAdmin(request, poll);
  if (!admin && !(await canEditResponse(request, env, r))) throw new HttpError(403, 'Not your response');
  if (!admin) {
    await checkPassword(env, request, poll);
    if (effStatus(inst) !== 'open') throw new HttpError(409, 'This poll is closed');
  }
  const b = await body(request);
  const extra = await validateExtra(env, b.extra, inst, r.id, { old: parseExtra(r.extra), admin });
  await env.DB.prepare('UPDATE responses SET extra = ? WHERE id = ?').bind(extra, r.id).run();
  return json({ ok: true, extra: parseExtra(extra) });
}
async function updateResponse(request, env, id, rid) {
  const poll = await loadPoll(env, id);
  const r = await loadResponse(env, id, rid);
  const inst = await loadInstance(env, id, r.instance_id);
  const admin = isAdmin(request, poll), own = await canEditResponse(request, env, r);
  if (!own && !admin) throw new HttpError(403, 'Not your response');
  if (!admin) {
    await checkPassword(env, request, poll);
    if (effStatus(inst) !== 'open') throw new HttpError(409, 'This poll is closed');
  }
  await requireInvited(env, poll, userOf(request), admin);
  const b = await body(request);
  let name = b.name !== undefined ? personName(b.name) : r.name;
  let mail = b.email !== undefined ? email(b.email) : r.email;
  const comment = b.comment !== undefined && poll.allow_comments ? str(b.comment, 500, 'Comment') : r.comment;
  const entries = b.entries !== undefined ? JSON.stringify(validateEntries(b.entries, poll, datesOf(inst, poll))) : r.entries;
  const fill = b.fill !== undefined ? parseFill(b.fill, poll, datesOf(inst, poll)) : undefined;
  const extra = b.extra !== undefined ? await validateExtra(env, b.extra, inst, rid, { old: parseExtra(r.extra), admin: !own && admin, needReq: true }) : undefined;
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
    // Account answer: the name is the account's profile name (it may repeat); the email is the account's.
    if (user && user.id === cur.user_id) { mail = user.email; if (user.name) name = user.name; }
    else name = cur.name; // the owner editing someone else's account answer can't rename them
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
  if (poll.require_email && !mail && !admin) throw new HttpError(400, 'This poll asks for your email address');
  stmts.push(env.DB.prepare('UPDATE responses SET name = ?, email = ?, comment = ?, entries = ?, participant_id = ?, updated_at = ? WHERE id = ?').bind(name, mail, comment, entries, partId, now(), rid));
  if (fill !== undefined) stmts.push(env.DB.prepare('UPDATE responses SET fill = ? WHERE id = ?').bind(fill, rid));
  if (extra !== undefined) stmts.push(env.DB.prepare('UPDATE responses SET extra = ? WHERE id = ?').bind(extra, rid));
  await env.DB.batch(stmts);
  if (mail && !(cur && cur.user_id)) await linkGuestToAccount(env, id, partId, mail);
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
const latestInstance = (env, pollId) => env.DB.prepare('SELECT * FROM instances WHERE poll_id = ? ORDER BY seq DESC LIMIT 1').bind(pollId).first();
// Every participant with the address emails actually go to (`mail_to`, same rule as participantEmails)
// and whether they answered `instId` (`here`).
async function participantRows(env, pollId, instId) {
  const { results } = await env.DB.prepare(
    `SELECT p.id, p.name, p.email, p.user_id, p.invited_at, u.email AS ue, COUNT(r.id) AS rounds, MAX(r.updated_at) AS last,
       (SELECT r2.email FROM responses r2 WHERE r2.participant_id = p.id AND r2.email != '' ORDER BY r2.updated_at DESC LIMIT 1) AS answer_email,
       (SELECT r3.email FROM responses r3 WHERE r3.participant_id = p.id ORDER BY r3.updated_at DESC LIMIT 1) AS re,
       EXISTS (SELECT 1 FROM responses r4 WHERE r4.participant_id = p.id AND r4.instance_id = ?) AS here
     FROM participants p LEFT JOIN users u ON u.id = p.user_id LEFT JOIN responses r ON r.participant_id = p.id
     WHERE p.poll_id = ? GROUP BY p.id ORDER BY p.name COLLATE NOCASE`).bind(instId || '', pollId).all();
  return results.map((p) => ({ ...p, mail_to: (p.ue || (p.re !== null ? p.re : p.email) || '').trim() }));
}
async function listParticipants(request, env, id) {
  await adminPoll(request, env, id);
  const inst = await latestInstance(env, id);
  const rows = await participantRows(env, id, inst && inst.id);
  return json({ participants: rows.map((p) => ({ id: p.id, name: p.name, email: p.email || p.answer_email || '', account: !!p.user_id,
    rounds: p.rounds, lastAnswered: p.last, invitedAt: p.invited_at || null, answeredNow: !!p.here, canMail: !!p.mail_to })) });
}
// People from the page: [{ name, email }] (email required, except friends picked by { uid }). Legacy: "Anna\nBen, ben@example.com".
function peopleInput(b) {
  let list;
  if (Array.isArray(b.people)) list = b.people;
  else list = str(b.lines, 20000, 'Names', true).split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
    .map((l) => { const [n, ...rest] = l.split(','); return { name: n, email: rest.join(',').trim() }; });
  if (!list.length) throw new HttpError(400, 'Add at least one person');
  if (list.length > 200) throw new HttpError(400, 'At most 200 people at once');
  return list.map((x) => {
    const name = personName(x && x.name), uid = x && x.uid;
    if (uid !== undefined && uid !== null && (typeof uid !== 'string' || !UID_RE.test(uid))) throw new HttpError(400, 'Pick someone from your friends');
    const mail = email((x && x.email) || '', `Email for ${name}`).toLowerCase();
    if (!mail && !uid) throw new HttpError(400, `${name} needs an email address`);
    return { name, email: mail, ...(uid ? { uid } : {}) };
  });
}
// Adds people, or finds them if they're already in the poll (same email, or same guest name).
// A guest found by name without an email gets the new one. Returns the participant ids per person (null = skipped).
// A friend ({ uid }, accepted friends of `me` only) is added as their account, so their signed-in answer lands in the same row.
async function upsertPeople(env, id, people, me = null) {
  const added = [], updated = [], skipped = [], ids = [];
  const friends = people.some((x) => x.uid) ? new Map((me ? await friendRows(env, me.id) : []).map((u) => [u.id, u])) : null;
  for (const x of people) {
    if (x.uid) {
      const f = friends.get(x.uid);
      if (!f) throw new HttpError(400, 'Pick someone from your friends');
      const name = f.name || x.name, mail = f.email.toLowerCase();
      let p = await accountParticipant(env, id, f.id);
      if (p) { skipped.push(p.name); ids.push(p.id); continue; }
      // A guest row with their address (added by email earlier) becomes their account's row.
      p = await env.DB.prepare('SELECT * FROM participants WHERE poll_id = ? AND user_id IS NULL AND LOWER(email) = ? LIMIT 1').bind(id, mail).first();
      if (p) {
        await env.DB.prepare('UPDATE participants SET user_id = ?, name_key = ?, email = ? WHERE id = ?').bind(f.id, acctKey(f.id), f.email, p.id).run();
        updated.push(p.name); ids.push(p.id); continue;
      }
      p = await newParticipant(env, id, name, f.email, f.id);
      added.push(name); ids.push(p.id); continue;
    }
    let p = x.email ? await env.DB.prepare(
      `SELECT p.* FROM participants p LEFT JOIN users u ON u.id = p.user_id WHERE p.poll_id = ? AND (LOWER(p.email) = ? OR LOWER(u.email) = ?) LIMIT 1`)
      .bind(id, x.email, x.email).first() : null;
    if (!p) {
      p = await findParticipant(env, id, nameKey(x.name));
      if (p && x.email) {
        if (p.email && p.email.toLowerCase() !== x.email) { skipped.push(`${x.name} (already there with another email)`); ids.push(null); continue; }
        if (!p.email) { await env.DB.prepare('UPDATE participants SET email = ? WHERE id = ?').bind(x.email, p.id).run(); updated.push(x.name); ids.push(p.id); continue; }
      }
    }
    if (p) { skipped.push(p.name); ids.push(p.id); continue; }
    p = await newParticipant(env, id, x.name, x.email);
    added.push(x.name); ids.push(p.id);
  }
  return { added, updated, skipped, ids };
}
// Body: { people: [{ name, email }] } or legacy { lines }
async function addParticipants(request, env, id) {
  await adminPoll(request, env, id);
  const r = await upsertPeople(env, id, peopleInput(await body(request)), userOf(request));
  return json(r);
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
    env.DB.prepare('DELETE FROM shared_busy WHERE participant_id = ?').bind(pid),
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
    env.DB.prepare('DELETE FROM shared_busy WHERE participant_id IN (?, ?)').bind(src.id, dst.id), // re-shared on their next visit
    // If the merged one was an account, the remaining person now belongs to that account.
    src.user_id
      ? env.DB.prepare('UPDATE participants SET user_id = ?, name_key = ?, email = ? WHERE id = ?').bind(src.user_id, src.name_key, src.email, dst.id)
      : env.DB.prepare("UPDATE participants SET email = CASE WHEN email = '' THEN ? ELSE email END WHERE id = ?").bind(src.email, dst.id),
    env.DB.prepare('UPDATE participants SET invited_at = ? WHERE id = ? AND (invited_at IS NULL OR invited_at < ?)').bind(src.invited_at, dst.id, src.invited_at),
  ]);
  return json({ ok: true, removedAnswers: drop.length });
}
