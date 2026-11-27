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
//   AI_MODEL  (optional) Workers AI text model, default AI_MODEL below. AI_PER_DAY (optional) text fills per person per day, default 20. HELP_PER_DAY (optional) help assistant questions per day, default 40
//
// Accounts: anyone can sign in with a 6-digit code sent to their email (needs RESEND_API_KEY + MAIL_FROM).
// Only signed-in users can create polls, and only the account that owns a poll can manage it.
// Without RESEND_API_KEY + MAIL_FROM, codes are written to the log (local development only).
// Answers given while signed in belong to the account (its email), so names don't have to be unique for them.

const MAX_RANGE_DAYS = 365;
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
const HELP_PER_DAY = 40;       // default for env.HELP_PER_DAY: help assistant questions per account (or IP) per day

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (isMcpPath(url.pathname)) return mcpEntry(request, env, ctx, url); // AI assistants: OAuth + MCP (see the MCP section)
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
  "script-src 'self' 'sha256-Oj3uvXq69ArbY39pGovS1YnziZRWGq8i0+q5fssWv6E=' 'sha256-yDGzI2FFZe3k2mSmVK8AN3UQu2Ppw1+PVryLtC/qJLg=' https://challenges.cloudflare.com",
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
  if (!INTERNAL.has(request)) USERS.set(request, await getUser(env, cookies)); // MCP tool calls come with their user set (callApi)
  if (parts[1] === 'config' && m === 'GET') return json({ emailEnabled: emailEnabled(env), turnstileSiteKey: env.TURNSTILE_SECRET ? env.TURNSTILE_SITE_KEY || '' : '', calProviders: calProviders(env), aiFill: !!env.AI, help: !!env.AI, personalLinks: !!env.LINK_KEY, push: pushOn(env) ? env.VAPID_PUBLIC_KEY : null, operator: env.OPERATOR_NAME || '', contact: env.CONTACT_EMAIL || '', address: env.OPERATOR_ADDRESS || '', phone: env.OPERATOR_PHONE || '', dpa: env.DPA_NAME || '' });
  if (parts[1] === 'help' && !parts[2]) { if (m === 'POST') return helpAsk(request, env); throw new HttpError(405, 'Method not allowed'); }
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
  if (parts[1] === 'connect' && parts[2] && !parts[3]) { // consent screen for an AI assistant (MCP)
    if (m === 'GET') return connectInfo(request, env, parts[2]);
    if (m === 'POST') return connectAnswer(request, env, url, parts[2]);
  }
  if (parts[1] === 'users' && parts[2] && parts[3] === 'avatar' && !parts[4] && m === 'GET') return userAvatar(request, env, parts[2]);
  if (parts[1] === 'me') {
    if (!parts[2] && m === 'GET') return me(request, env);
    if (!parts[2] && m === 'PATCH') return updateProfile(request, env);
    if (parts[2] === 'email' && !parts[3] && m === 'POST') return sendEmailChangeCode(request, env, url);
    if (parts[2] === 'email' && parts[3] === 'verify' && !parts[4] && m === 'POST') return verifyEmailChange(request, env, url);
    if (parts[2] === 'polls' && !parts[3] && m === 'GET') return myPolls(request, env);
    if (parts[2] === 'polls' && parts[3] && parts[4] === 'hidden' && !parts[5] && m === 'PUT') return setPollHidden(request, env, parts[3]);
    if (parts[2] === 'poll-busy' && !parts[3] && m === 'GET') return pollBusy(request, env, url);
    if (parts[2] === 'upcoming' && !parts[3] && m === 'GET') return upcoming(request, env, url);
    if (parts[2] === 'todo' && !parts[3] && m === 'GET') return myTodo(request, env);
    if (parts[2] === 'export' && !parts[3] && m === 'GET') return exportMe(request, env);
    if (parts[2] === 'delete' && !parts[3] && m === 'POST') return sendDeleteCode(request, env, url);
    if (parts[2] === 'delete' && parts[3] === 'verify' && !parts[4] && m === 'POST') return deleteAccount(request, env, url);
    if (parts[2] === 'calendar' && m === 'POST') return fetchCalendar(request, env);
    if (parts[2] === 'connections') {
      if (!parts[3] && m === 'GET') return listConnections(request, env);
      if (parts[3] && !parts[4] && m === 'DELETE') return deleteConnection(request, env, parts[3]);
    }
    if (parts[2] === 'notify' && !parts[3] && (m === 'GET' || m === 'PUT')) return meNotify(request, env);
    if (parts[2] === 'push') {
      if (!parts[3] && m === 'POST') return savePushSub(request, env);
      if (!parts[3] && m === 'DELETE') return deletePushSub(request, env);
      if (parts[3] === 'test' && !parts[4] && m === 'POST') return testPush(request, env);
    }
    if (parts[2] === 'friends') {
      if (!parts[3] && m === 'GET') return listFriends(request, env);
      if (!parts[3] && m === 'POST') return addFriend(request, env, url);
      if (parts[3] && parts[4] === 'accept' && !parts[5] && m === 'POST') return acceptFriend(request, env, parts[3]);
      if (parts[3] && !parts[4] && m === 'DELETE') return deleteFriend(request, env, parts[3]);
    }
    if (parts[2] === 'favourites') {
      if (!parts[3] && m === 'POST') return addFavourite(request, env);
      if (parts[3] && !parts[4] && m === 'PATCH') return editFavourite(request, env, parts[3]);
      if (parts[3] && !parts[4] && m === 'DELETE') return deleteFavourite(request, env, parts[3]);
    }
    if (parts[2] === 'groups') {
      if (!parts[3] && m === 'POST') return addGroup(request, env);
      if (parts[3] && !parts[4] && m === 'PATCH') return updateGroup(request, env, url, parts[3]);
      if (parts[3] && !parts[4] && m === 'DELETE') return deleteGroup(request, env, parts[3]);
    }
    if (parts[2] === 'presets') {
      if (!parts[3] && m === 'GET') return listPresets(request, env);
      if (!parts[3] && m === 'POST') return savePreset(request, env);
      if (parts[3] && !parts[4] && m === 'PATCH') return updatePreset(request, env, parts[3]);
      if (parts[3] && !parts[4] && m === 'DELETE') return deletePreset(request, env, parts[3]);
    }
    if (parts[2] === 'contacts' && parts[3] === 'lookup' && !parts[4] && m === 'POST') return lookupContacts(request, env);
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
  if (id === 'generate-text' && !parts[3]) { if (m === 'POST') return pollFromText(request, env); throw new HttpError(405, 'Method not allowed'); }
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
  if (a === 'watch' && !b && m === 'PUT') return setWatch(request, env, id);
  if (a === 'notify' && !b && m === 'PUT') return setPollNotify(request, env, id);
  if (a === 'meetings' && b === 'send' && !c && m === 'POST') return sendAllMeetings(request, env, url, id);
  if (a === 'chat') {
    if (!b && m === 'GET') return listChat(request, env, url, id);
    if (!b && m === 'POST') return postChat(request, env, ctx, id);
    if (b === 'mute' && !c && m === 'PUT') return muteChat(request, env, id);
    if (b && !c && m === 'DELETE') return deleteChat(request, env, id, b);
    if (b && c === 'react' && !d && m === 'POST') return reactChat(request, env, id, b);
  }
  if (a === 'participants') {
    if (!b && m === 'GET') return listParticipants(request, env, id);
    if (!b && m === 'POST') return addParticipants(request, env, id);
    if (b && !c && m === 'PATCH') return updateParticipant(request, env, id, b);
    if (b && !c && m === 'DELETE') return deleteParticipant(request, env, url, id, b);
    if (b && c === 'merge' && m === 'POST') return mergeParticipant(request, env, id, b);
    if (b && c === 'role' && m === 'PUT') return setParticipantRole(request, env, id, b);
    if (b && c === 'link' && !d && m === 'GET') return participantLink(request, env, id, b, false);
    if (b && c === 'link' && d === 'reset' && m === 'POST') return participantLink(request, env, id, b, true);
  }
  if (a === 'groups') {
    if (!b && m === 'POST') return linkGroup(request, env, url, id);
    if (b && !c && m === 'DELETE') return unlinkGroup(request, env, url, id, b);
  }
  if (a === 'instances') {
    if (!b && m === 'POST') return createNextInstance(request, env, ctx, url, id);
    if (b && !c && m === 'PATCH') return updateInstance(request, env, ctx, id, b);
    if (b && !c && m === 'DELETE') return deleteInstance(request, env, id, b);
    if (b && c === 'responses' && !d && m === 'POST') return createResponse(request, env, ctx, id, b);
    if (b && c === 'fill-text' && !d && m === 'POST') return fillFromText(request, env, id, b);
    if (b && c === 'suggest-text' && !d && m === 'POST') return suggestFromText(request, env, id, b);
    if (b && c === 'questions-text' && !d && m === 'POST') return questionsFromText(request, env, id, b);
    if (b && c === 'questions' && d === 'remind' && m === 'POST') return remindQuestions(request, env, url, id, b);
    if (b && c === 'recall' && !d && m === 'POST') return recall(request, env, id, b);
    if (b && c === 'busy' && !d && m === 'PUT') return shareBusy(request, env, id, b);
    if (b && c === 'form' && !d && m === 'GET') return getForm(request, env, url, id, b);
    if (b && c === 'form' && !d && m === 'PUT') return saveForm(request, env, ctx, url, id, b);
    if (b && c === 'form' && !d && m === 'DELETE') return deleteForm(request, env, url, id, b);
    if (b && c === 'meetings' && d && e === 'send' && m === 'POST') return sendInvite(request, env, url, id, b, d);
  }
  if (a === 'responses' && b && c === 'votes' && !d && m === 'PUT') return voteMeetings(request, env, ctx, id, b);
  if (a === 'responses' && b) {
    if (m === 'GET') return getOwnResponse(request, env, id, b);
    if (m === 'PUT') return updateResponse(request, env, ctx, id, b);
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
// paused: rules the organiser switched off. Kept with the pattern so the page can show them again; nothing that
// decides which days or hours are offered reads them.
function parsePeriod(x) {
  if (!x || typeof x !== 'object') throw new HttpError(400, 'Invalid day pattern');
  const d = parseDays(x) || { wd: null, dom: null };
  const hs = int(x.hs, 0, 23, 'First hour'), he = int(x.he, 1, 24, 'Last hour');
  if (he <= hs) throw new HttpError(400, 'The last hour must be after the first hour');
  return { wd: d.wd, dom: d.dom, hs, he };
}
function parsePattern(v) {
  const pat = parseActivePattern(v);
  if (!v || typeof v !== 'object' || v.paused == null) return pat;
  const n = v.periods == null ? 1 : v.periods.length;
  if (!Array.isArray(v.paused) || n + v.paused.length > MAX_PERIODS) throw new HttpError(400, `Add 1 to ${MAX_PERIODS} periods`);
  if (!v.paused.length) return pat;
  return { ...(pat || { wd: null, dom: null }), paused: v.paused.map(parsePeriod) };
}
function parseActivePattern(v) {
  const base = parseDays(v);
  if (!v || typeof v !== 'object' || v.periods == null) return base;
  if (!Array.isArray(v.periods) || !v.periods.length || v.periods.length > MAX_PERIODS) throw new HttpError(400, `Add 1 to ${MAX_PERIODS} periods`);
  const periods = v.periods.map(parsePeriod);
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
// The hours offered on date d (whole hours, sorted; gaps where periods don't touch).
function hoursOn(poll, pat, d) {
  const ps = periodsOn(pat, d), out = [];
  for (let h = 0; h < 24; h++) if (ps ? ps.some((p) => h >= p.hs && h < p.he) : h >= poll.hour_start && h < poll.hour_end) out.push(h);
  return out;
}
// polls.auto_meetings: every offered date's runs of hours without a gap, one meeting each (whole days when the poll takes days only).
function autoWindows(poll, inst) {
  const pat = patternOf(poll), out = [];
  for (const d of datesOf(inst, poll)) {
    if (poll.answer_mode === 'days') { out.push({ date: d, allDay: true }); continue; }
    let s = null, prev = null;
    for (const h of [...hoursOn(poll, pat, d), 99]) {
      if (s !== null && h !== prev + 1) { out.push({ date: d, allDay: false, start: s, end: prev + 1 }); s = null; }
      if (s === null) s = h;
      prev = h;
    }
  }
  return out;
}
const autoKey = (m) => m.date + (m.allDay ? '' : ':' + m.start + '-' + m.end);
// Keep hand-made meetings and auto ones that still fit, drop auto ones that don't, add the missing ones (up to MAX_MEETINGS).
function syncAutoMeetings(poll, inst) {
  const old = jsonList(inst.meetings), wins = autoWindows(poll, inst), want = new Set(wins.map(autoKey));
  const list = old.filter((m) => !m.auto || want.has(autoKey(m))), have = new Set(list.filter((m) => m.auto).map(autoKey));
  for (const w of wins) {
    if (list.length >= MAX_MEETINGS) break;
    if (have.has(autoKey(w))) continue;
    list.push({ ...w, auto: true, title: '', location: poll.meet_location || '', note: poll.meet_note || '', participants: 'all',
      ...(poll.kind === 'weekly' ? { repeat: { from: firstOnWeekday(today(), wdOf(w.date)), every: 1, until: null } } : {}) });
  }
  return validateMeetings(list, poll, old);
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
    // Questions marked repeat (the default) come along with their questionnaires, without links to the old round's meetings.
    // After-meeting questions stay after-meeting questions (for all meetings of the new round) and keep who.
    const keepWho = (w) => (w && w.mode === 'people' ? w : { mode: !w || w.mode === 'free' || w.mode === 'meeting' ? 'all' : w.mode });
    const copyLink = (x) => (isAfter(x) ? { link: afterLink(x.link), who: x.who || { mode: 'meeting' } } : { link: { to: 'poll' }, who: keepWho(x.who) });
    // Copies of every-round questions (tpl) don't come along: the poll's list adds them fresh below.
    const items = itemsOf({ questions: prev }), qs = items.filter((x) => x.type !== 'group').map(normQ).filter((q) => q && q.repeat !== false && !q.tpl && !q.mtpl);
    const used = new Set(qs.map((q) => q.grp).filter(Boolean));
    const out = items.filter((x) => (x.type === 'group' ? used.has(x.id) : qs.some((q) => q.id === x.id)))
      .map((x) => (x.type === 'group' ? x : normQ(x)))
      .map(({ closed, at, ...q }) => ({ ...q, ...copyLink(q), at: now() }));
    if (out.length) fields = { ...fields, questions: JSON.stringify(out) };
  }
  if (poll.kind === 'series' && poll.round_questions) { // the poll's questions for every round
    const items = itemsOf({ questions: fields.questions }), add = roundQuestionCopies(jsonList(poll.round_questions), items);
    if (add.length) fields = { ...fields, questions: JSON.stringify([...items, ...add]) };
  }
  if (poll.auto_meetings) fields = { ...fields, meetings: JSON.stringify(syncAutoMeetings(poll, { ...fields, meetings: '[]' })) };
  if (poll.meet_apply) { const r = applyMeetDefaults(poll, null, { meetings: fields.meetings || '[]', questions: fields.questions || null }); if (r.meetings) fields = { ...fields, meetings: r.meetings }; if (r.questions) fields = { ...fields, questions: r.questions }; }
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
// Roles: the owning account, plus accounts in the poll's participants the owner gave a role (participants.role, 0026).
// Each capability needs at least that rank: see (viewer: organiser view, read only), edit (editor: meetings, questions, rounds),
// manage (admin: settings, people, emails, others' answers), own (owner: delete the poll, set roles).
const ROLE_RANK = { viewer: 1, editor: 2, admin: 3, owner: 4 };
const CAP_RANK = { see: 1, edit: 2, manage: 3, own: 4 };
const POLL_ROLES = ['admin', 'editor', 'viewer'];
const ROLES = new WeakMap(); // request -> Map(poll id -> role)
async function roleOf(request, env, poll) {
  const user = userOf(request);
  if (!user) return null;
  if (poll.owner_id && poll.owner_id === user.id) return 'owner';
  let m = ROLES.get(request);
  if (!m) ROLES.set(request, (m = new Map()));
  if (!m.has(poll.id)) {
    const r = await env.DB.prepare("SELECT role FROM participants WHERE poll_id = ? AND user_id = ? AND role != '' LIMIT 1").bind(poll.id, user.id).first('role');
    m.set(poll.id, POLL_ROLES.includes(r) ? r : null);
  }
  return m.get(poll.id);
}
const roleCan = (role, cap = 'see') => (ROLE_RANK[role] || 0) >= CAP_RANK[cap];
const capsOf = (role) => ({ see: roleCan(role, 'see'), edit: roleCan(role, 'edit'), manage: roleCan(role, 'manage'), own: roleCan(role, 'own') });
// Organiser of a poll with at least this capability (default: see = any role).
async function isAdmin(request, env, poll, cap = 'see') {
  return roleCan(await roleOf(request, env, poll), cap);
}
const CAP_MSG = { see: 'Only the poll’s organisers can see this.', edit: 'Only the poll’s owner, admins and editors can do this.',
  manage: 'Only the poll’s owner and admins can do this.', own: 'Only the poll’s owner can do this. Sign in with the account that created it.' };
async function requireAdmin(request, env, poll, cap = 'manage') {
  if (!(await isAdmin(request, env, poll, cap))) throw new HttpError(403, CAP_MSG[cap]);
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
  if (!poll.password_hash || (await roleOf(request, env, poll))) return; // organisers (any role) don't need the password
  const pw = request.headers.get('x-poll-password');
  if (!(await guardedPasswordOk(env, request, poll, pw)))
    throw new HttpError(401, pw ? 'Wrong password' : 'Password required', { needPassword: true, title: poll.title });
}
function publicPoll(poll, admin, edit = admin) {
  const p = {
    id: poll.id, title: poll.title, description: poll.description, kind: poll.kind,
    unit: poll.unit, every: poll.every, anchor: poll.anchor, openDays: poll.open_days, deadlineDays: poll.deadline_days,
    answerMode: poll.answer_mode, hourStart: poll.hour_start, hourEnd: poll.hour_end, dayPattern: patternOf(poll),
    hideResults: !!poll.hide_results, allowComments: !!poll.allow_comments, requireEmail: !!poll.require_email, invitedOnly: !!poll.invited_only, hasPassword: !!poll.password_hash,
    icon: poll.icon || '', image: poll.image ? poll.image_at || '1' : '', // image: version for /image?v=
  };
  if (admin) Object.assign(p, { notifyOpen: !!poll.notify_open, remindDays: poll.remind_days, remindQuestions: !!poll.remind_questions });
  if (edit) Object.assign(p, { meetLocation: poll.meet_location || '', meetNote: poll.meet_note || '', meetQuestions: jsonList(poll.meet_questions), autoMeetings: !!poll.auto_meetings, meetApply: !!poll.meet_apply, ...(poll.kind === 'series' ? { roundQuestions: jsonList(poll.round_questions) } : {}) }); // planner defaults for new meetings; series: questions for every round
  return p;
}
function publicInstance(inst, extra = {}) {
  return { id: inst.id, seq: inst.seq, createdAt: inst.created_at, startDate: inst.start_date, endDate: inst.end_date, deadline: inst.deadline,
    status: effStatus(inst), manualStatus: inst.status, note: inst.note, meetings: JSON.parse(inst.meetings || '[]'), questions: questionsOf(inst), groups: groupsOf(inst), ...extra };
}

function validateEntries(entries, poll, dates) {
  if (entries == null) return {};
  if (typeof entries !== 'object' || Array.isArray(entries)) throw new HttpError(400, 'Invalid answers');
  const allowed = new Set(dates), out = {};
  const pat = patternOf(poll);
  for (const [k, v] of Object.entries(entries)) {
    if (!allowed.has(k)) continue;
    const ok = new Set(hoursOn(poll, pat, k)), hourOk = (h) => Number.isInteger(h) && ok.has(h);
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
      if (!Number.isInteger(r.every) || r.every < 1 || r.every > 8) throw new HttpError(400, 'Repeat every 1 to 8 weeks');
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
      // vote = which vote it belongs to (several per round), one = pick-one vote; only on proposals
      vote: mt.proposed && /^[A-Za-z0-9]{4,20}$/.test(mt.vote || '') ? mt.vote : undefined,
      one: mt.proposed && mt.one ? true : undefined,
      ...(repeat ? { repeat } : {}),
      inc: validateInc(mt.inc),
      auto: mt.auto ? true : undefined, // made from the poll's times (polls.auto_meetings); kept in sync until its time is changed by hand
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

// inc = which parts of the answers go into the meeting's description (rendered live by meetingAnswerText):
// { who: who's coming at its time, comments: answer comments, qs: [{ id, each: per person (else a summary) }] }.
function validateInc(x) {
  if (x == null) return undefined;
  if (typeof x !== 'object' || Array.isArray(x)) throw new HttpError(400, 'Invalid answers to include');
  const seen = new Set(), qs = [];
  for (const q of Array.isArray(x.qs) ? x.qs.slice(0, MAX_QUESTIONS) : []) {
    if (!q || !QID_RE.test(q.id || '') || seen.has(q.id)) continue;
    seen.add(q.id); qs.push({ id: q.id, ...(q.each ? { each: true } : {}) });
  }
  const out = { ...(x.who ? { who: true } : {}), ...(x.comments ? { comments: true } : {}), ...(qs.length ? { qs } : {}) };
  return Object.keys(out).length ? out : undefined;
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
    `SELECT u.id, u.email, u.name, u.avatar, u.bio, u.created_at, u.avatar_img IS NOT NULL AS has_img, u.busy_polls
     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?`)
    .bind(await sha256('session:' + token), now()).first();
  return s ? { id: s.id, email: s.email, name: s.name || '', avatar: s.avatar || '', bio: s.bio || '', hasImg: !!s.has_img, created: s.created_at, busyPolls: !!s.busy_polls } : null;
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
  await claimGuestRows(env, user).catch((e) => console.error('claimGuestRows', e)); // never blocks signing in
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
  return json({ user: { name: u.name, email: u.email, avatar: u.avatar, avatarImg: img || '', bio: u.bio, since: u.created,
    calendar: cal.url ? icalHost(cal.url) : '', calendars: cal.n || 0, calendarsAuto: cal.auto || 0, busyPolls: !!u.busyPolls,
    friendRequests: (await friendRequestCount(env, u)) || 0 } });
}
// Body: { name?, bio? (one line, shown only to the person), avatar? (emoji or ''), avatarImg? (data URL or ''), icalUrl? (iCal feed or ''), busyPolls? (grey out busy hours from my other polls) }. A new name also renames the account's answers.
async function updateProfile(request, env) {
  const user = requireUser(request);
  const b = await body(request), u = {};
  if (b.name !== undefined) u.name = b.name === '' ? '' : personName(b.name);
  if (b.bio !== undefined) u.bio = str(b.bio, 160, 'Description').replace(/\s+/g, ' ').trim();
  if (b.avatar !== undefined) u.avatar = emojiIcon(b.avatar, 'Avatar');
  if (b.avatarImg !== undefined) u.avatar_img = imageData(b.avatarImg, 'Picture');
  if (b.busyPolls !== undefined) u.busy_polls = b.busyPolls ? 1 : 0;
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
  await claimGuestRows(env, { id: user.id, email: addr }).catch((e) => console.error('claimGuestRows', e));
  // Let the old address know, in case it wasn't them.
  if (emailEnabled(env)) {
    const de = reqLang(request) === 'de', site = siteUrl(env, url.origin), help = env.CONTACT_EMAIL;
    const text = de ? `Die E-Mail-Adresse deines when-who-Kontos wurde von ${old} auf ${addr} geändert. Anmeldecodes gehen ab jetzt an die neue Adresse.${help ? '\n\nWarst du das nicht? Antworte auf diese E-Mail.' : ''}`
      : `The email address of your when-who account was changed from ${old} to ${addr}. Sign-in codes now go to the new address.${help ? "\n\nWasn't you? Reply to this email." : ''}`;
    await sendEmail(env, { fromName: 'when-who', to: [old], replyTo: help || undefined,
      subject: de ? 'Deine E-Mail-Adresse wurde geändert' : 'Your email address was changed', text,
      html: emailHtml(mailBlocks({ title: de ? 'Deine E-Mail-Adresse wurde geändert' : 'Your email address was changed', intro: text.split('\n\n') }),
        { site, lang: de ? 'de' : 'en' }) }).catch(() => {});
  }
  return json({ ok: true, email: addr });
}
// ---------- your data: export and account deletion (GDPR Art. 15, 17, 20) ----------
// USER_DATA lists EVERY table (npm run check fails otherwise). Per table: `rows` = the SQL whose rows go into the export,
// `del` = what deleting the account removes, or `skip` = why the table holds nothing to hand out or delete.
// Deletion runs top to bottom in one batch, so tables found through participants / owned polls come before those.
// Every ? is the user id (the number is counted from the SQL); MINE = my participant rows (my answers in any poll), OWNED = polls I own.
// After adding a migration: cover its tables / columns here, then bump USER_DATA_REVIEWED to its number.
const USER_DATA_REVIEWED = '0041';
const MINE = 'SELECT id FROM participants WHERE user_id = ?';
const OWNED = 'SELECT id FROM polls WHERE owner_id = ?';
const USER_DATA = {
  responses: { rows: `SELECT * FROM responses WHERE participant_id IN (${MINE}) OR poll_id IN (${OWNED})`,
    del: `DELETE FROM responses WHERE participant_id IN (${MINE}) OR poll_id IN (${OWNED})` },
  form_answers: { rows: `SELECT * FROM form_answers WHERE participant_id IN (${MINE}) OR poll_id IN (${OWNED})`,
    del: `DELETE FROM form_answers WHERE participant_id IN (${MINE}) OR poll_id IN (${OWNED})` }, // answers to questions
  shared_busy: { rows: `SELECT * FROM shared_busy WHERE participant_id IN (${MINE}) OR poll_id IN (${OWNED})`,
    del: `DELETE FROM shared_busy WHERE participant_id IN (${MINE}) OR poll_id IN (${OWNED})` },
  poll_groups: { rows: `SELECT * FROM poll_groups WHERE poll_id IN (${OWNED})`,
    del: `DELETE FROM poll_groups WHERE poll_id IN (${OWNED})` }, // my contact groups linked to my polls (name + icon copy)
  participants: { rows: `SELECT * FROM participants WHERE user_id = ? OR poll_id IN (${OWNED})`,
    del: `DELETE FROM participants WHERE user_id = ? OR poll_id IN (${OWNED})` },
  messages: { rows: `SELECT * FROM messages WHERE user_id = ? OR poll_id IN (${OWNED})`,
    del: `DELETE FROM messages WHERE user_id = ? OR poll_id IN (${OWNED})` }, // my reactions on others' messages: dropReactions()
  chat_reads: { rows: 'SELECT * FROM chat_reads WHERE user_id = ?',
    del: `DELETE FROM chat_reads WHERE user_id = ? OR poll_id IN (${OWNED})` },
  answer_watch: { rows: 'SELECT * FROM answer_watch WHERE user_id = ?',
    del: `DELETE FROM answer_watch WHERE user_id = ? OR poll_id IN (${OWNED})` }, // notification settings per poll (prefs)
  poll_events: { rows: 'SELECT id, poll_id, instance_id, kind, name, at FROM poll_events WHERE actor_id = ?',
    del: `DELETE FROM poll_events WHERE actor_id = ? OR poll_id IN (${OWNED})` }, // 3-day log of what happened, for notifications
  instances: { rows: `SELECT * FROM instances WHERE poll_id IN (${OWNED})`,
    del: `DELETE FROM instances WHERE poll_id IN (${OWNED})` },
  poll_hidden: { rows: 'SELECT * FROM poll_hidden WHERE user_id = ?',
    del: `DELETE FROM poll_hidden WHERE user_id = ? OR poll_id IN (${OWNED})` }, // polls I hid from my overview
  polls: { rows: `SELECT * FROM polls WHERE owner_id = ? OR id IN (SELECT poll_id FROM participants WHERE user_id = ?)`,
    del: 'DELETE FROM polls WHERE owner_id = ?' }, // export: polls I own in full, polls I answered for their titles
  favourites: { rows: 'SELECT * FROM favourites WHERE user_id = ?', del: 'DELETE FROM favourites WHERE user_id = ?' },
  contact_groups: { rows: 'SELECT * FROM contact_groups WHERE user_id = ?', del: 'DELETE FROM contact_groups WHERE user_id = ?' },
  poll_presets: { rows: 'SELECT * FROM poll_presets WHERE user_id = ?', del: 'DELETE FROM poll_presets WHERE user_id = ?' },
  friends: { rows: 'SELECT * FROM friends WHERE from_id = ? OR to_id = ?', del: 'DELETE FROM friends WHERE from_id = ? OR to_id = ?' },
  user_calendars: { rows: 'SELECT * FROM user_calendars WHERE user_id = ?', del: 'DELETE FROM user_calendars WHERE user_id = ?' },
  calendar_accounts: { rows: 'SELECT * FROM calendar_accounts WHERE user_id = ?', del: 'DELETE FROM calendar_accounts WHERE user_id = ?' }, // tokens revoked first
  oauth_states: { skip: 'calendar sign-ins in progress (deleted after an hour)', del: 'DELETE FROM oauth_states WHERE user_id = ?' },
  push_subs: { rows: "SELECT id, substr(endpoint, 1, instr(substr(endpoint, 9), '/') + 7) AS push_service, lang, created_at FROM push_subs WHERE user_id = ?",
    del: 'DELETE FROM push_subs WHERE user_id = ?' }, // devices with chat notifications; the push address and keys stay out of the export
  mcp_grants: { rows: 'SELECT id, client_name, created_at, used_at, refresh_exp FROM mcp_grants WHERE user_id = ?',
    del: 'DELETE FROM mcp_grants WHERE user_id = ?' }, // AI assistants connected with MCP (token hashes stay out of the export)
  mcp_requests: { skip: 'MCP sign-ins in progress (deleted after 10 minutes)', del: 'DELETE FROM mcp_requests WHERE user_id = ?' },
  mcp_clients: { skip: 'names and return addresses of apps that registered for MCP, not linked to a person' },
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
    ...Object.values(USER_DATA).filter((d) => d.del).map((d) => byUser(env, d.del, user.id)),
  ]);
  if (emailEnabled(env)) {
    const de = reqLang(request) === 'de';
    const text = de ? `Dein when-who-Konto (${user.email}) wurde gelöscht${owned ? `, zusammen mit ${owned} Umfrage${owned === 1 ? '' : 'n'}` : ''}. Deine Antworten und Nachrichten in anderen Umfragen sind ebenfalls gelöscht.`
      : `Your when-who account (${user.email}) has been deleted${owned ? `, along with ${owned} poll${owned === 1 ? '' : 's'}` : ''}. Your answers and messages in other polls were deleted too.`;
    await sendEmail(env, { fromName: 'when-who', to: [user.email], replyTo: env.CONTACT_EMAIL || undefined,
      subject: de ? 'Dein Konto wurde gelöscht' : 'Your account was deleted', text,
      html: emailHtml(mailBlocks({ title: de ? 'Dein Konto wurde gelöscht' : 'Your account was deleted', intro: text }),
        { site: siteUrl(env, url.origin), lang: de ? 'de' : 'en' }) }).catch(() => {});
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
// Accounts behind contact addresses, so contacts show the person's own avatar: Map email -> { account, avatar, avatarImg }.
// The picture goes as a URL (GET /api/users/:uid/avatar, signed-in only), not inline: hundreds of contacts would be megabytes.
async function accountsByEmail(env, emails) {
  const list = [...new Set(emails.filter((e) => typeof e === 'string' && e).map((e) => e.toLowerCase()))], out = new Map();
  for (let i = 0; i < list.length; i += 90) {
    const part = list.slice(i, i + 90);
    const { results } = await env.DB.prepare(
      `SELECT id, LOWER(email) AS email, avatar, LENGTH(avatar_img) AS img FROM users WHERE LOWER(email) IN (${part.map(() => '?').join(',')})`).bind(...part).all();
    for (const u of results) out.set(u.email, { account: true, avatar: u.avatar || '', avatarImg: u.img ? `/api/users/${u.id}/avatar?v=${u.img}` : '' });
  }
  return out;
}
// An account's avatar on a person in a poll (People tab, answers): only for signed-in callers, like contacts and chat.
const AV_COLS = 'u.id AS av_uid, u.avatar AS av, LENGTH(u.avatar_img) AS av_img';
const avOut = (r, on) => (on && r.av_uid ? { avatar: r.av || '', avatarImg: r.av_img ? `/api/users/${r.av_uid}/avatar?v=${r.av_img}` : '' } : {});
const withAccount = (accts, x) => { const a = x && x.email && accts.get(x.email.toLowerCase()); return a ? { ...x, ...a } : x; };
async function userAvatar(request, env, uid) {
  if (!UID_RE.test(uid)) throw new HttpError(404, 'No picture');
  const sig = new URL(request.url).searchParams.get('s');
  if (!(sig && pushOn(env) && sig === await avatarSig(env, uid))) requireUser(request);
  const img = await env.DB.prepare('SELECT avatar_img FROM users WHERE id = ?').bind(uid).first('avatar_img');
  const m = (img || '').match(/^data:(image\/(?:webp|jpeg|png));base64,(.+)$/);
  if (!m) throw new HttpError(404, 'No picture');
  const bytes = Uint8Array.from(atob(m[2]), (c) => c.charCodeAt(0));
  return new Response(bytes, { headers: { 'content-type': m[1], 'cache-control': 'private, max-age=3600' } });
}
// Notification icons: the browser / OS loads them without the session cookie, so a push carries a signed link to the
// sender's picture (only that picture; key derived from the VAPID secret, which every push already needs).
async function avatarSig(env, uid) {
  const k = await crypto.subtle.importKey('raw', enc.encode('avatar:' + env.VAPID_PRIVATE_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(uid)))).slice(0, 22);
}
const avatarIcon = async (env, u) => (u && u.avatar_img ? `/api/users/${u.id}/avatar?v=${u.avatar_img.length}&s=${await avatarSig(env, u.id)}` : '');
// Body: { emails: [...] } (contacts imported in the browser, which the server never stores). Returns { accounts: { email: { account, avatar, avatarImg } } }.
async function lookupContacts(request, env) {
  requireUser(request);
  const b = await body(request);
  if (!Array.isArray(b.emails) || b.emails.length > 500) throw new HttpError(400, 'At most 500 addresses at once');
  const accts = await accountsByEmail(env, b.emails.filter((e) => typeof e === 'string' && e.length <= 200 && EMAIL_RE.test(e)));
  return json({ accounts: Object.fromEntries(accts) });
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
  // Contacts: people in my polls with an address, guests and accounts alike (so a guest who signs up stays a contact), one
  // per address: the account's profile name, else the newest name I gave them. Friends' addresses are left out.
  const { results: guests } = await env.DB.prepare(
    `SELECT COALESCE(NULLIF(u.name, ''), pa.name) AS name, LOWER(TRIM(COALESCE(u.email, pa.email))) AS email, MAX(pa.created_at) AS at
     FROM participants pa JOIN polls p ON p.id = pa.poll_id LEFT JOIN users u ON u.id = pa.user_id
     WHERE p.owner_id = ? AND COALESCE(u.email, pa.email, '') != '' GROUP BY LOWER(TRIM(COALESCE(u.email, pa.email)))
     ORDER BY name COLLATE NOCASE LIMIT 500`).bind(user.id).all();
  const known = new Set([user.email.toLowerCase(), ...friends.map((u) => u.email.toLowerCase())]);
  const { results: favs } = await env.DB.prepare('SELECT id, name, email, note, name_pref FROM favourites WHERE user_id = ? ORDER BY name COLLATE NOCASE').bind(user.id).all();
  // The name a saved contact goes by in polls I own (their account name, else the newest name they answered under, else
  // the poll's name for them). Only from people in my polls: never an account name looked up by address alone
  // (saving an address must not reveal whose account it is).
  const { results: seen } = favs.length ? await env.DB.prepare(
    `SELECT LOWER(TRIM(COALESCE(u.email, pa.email))) AS email, COALESCE(NULLIF(u.name, ''), r.name, pa.name) AS name,
       MAX(COALESCE(r.updated_at, pa.created_at)) AS at
     FROM participants pa JOIN polls p ON p.id = pa.poll_id LEFT JOIN users u ON u.id = pa.user_id
       LEFT JOIN responses r ON r.participant_id = pa.id
     WHERE p.owner_id = ?1 AND LOWER(TRIM(COALESCE(u.email, pa.email))) IN (SELECT email FROM favourites WHERE user_id = ?1)
     GROUP BY LOWER(TRIM(COALESCE(u.email, pa.email)))`).bind(user.id).all() : { results: [] };
  const seenName = new Map(seen.map((g) => [g.email, String(g.name || '').trim()]));
  for (const f of favs) {
    const other = seenName.get(f.email) || '';
    f.other = other && other.toLowerCase() !== f.name.toLowerCase() ? other : '';
    if (f.other && f.name_pref === 'theirs') { // follow their name
      await env.DB.prepare('UPDATE favourites SET name = ? WHERE id = ?').bind(other.slice(0, 60), f.id).run();
      f.name = other.slice(0, 60); f.other = '';
    }
  }
  const { results: grps } = await env.DB.prepare('SELECT id, name, icon, members FROM contact_groups WHERE user_id = ? ORDER BY name COLLATE NOCASE').bind(user.id).all();
  const groups = grps.map((g) => ({ id: g.id, name: g.name, icon: g.icon, members: jsonList(g.members) }));
  const contacts = guests.filter((g) => EMAIL_RE.test(g.email) && !known.has(g.email)).map((g) => ({ name: g.name, email: g.email }));
  const accts = await accountsByEmail(env, [...favs, ...contacts, ...groups.flatMap((g) => g.members)].map((x) => x && x.email));
  return json({
    favourites: favs.map((f) => withAccount(accts, { id: f.id, name: f.name, email: f.email, note: f.note || '',
      namePref: f.name_pref || '', ...(f.other ? { other: f.other } : {}) })),
    groups: groups.map((g) => ({ ...g, members: g.members.map((x) => withAccount(accts, x)) })),
    contacts: contacts.map((x) => withAccount(accts, x)),
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
      html: emailHtml(mailBlocks({ title: subject,
        intro: [de ? `${who} (${user.email}) möchte dich auf when-who als Freund*in hinzufügen. Dann könnt ihr euch gegenseitig ganz einfach zu Umfragen einladen.`
          : `${who} (${user.email}) would like to add you as a friend on when-who, so you can easily invite each other to polls.`,
          de ? 'Melde dich mit dieser E-Mail-Adresse an, um die Anfrage anzunehmen oder abzulehnen.' : 'Sign in with this email address to accept or decline.'],
        button: { href: link, label: de ? 'Anfrage ansehen' : 'See the request' }, orLink: de ? 'Oder öffne diesen Link:' : 'Or open this link:',
        foot: de ? `Du bekommst diese E-Mail, weil ${who} deine Adresse eingegeben hat. Wenn du nichts tust, passiert nichts.`
          : `You're getting this because ${who} entered your address. If you do nothing, nothing happens.` }),
        { preheader: subject, site, lang: de ? 'de' : 'en' }) });
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
// ---------- favourites (shown as "Contacts") ----------
// A private saved list (name + email + note) per account, shown first when adding people. Nobody is told.
// The email is the key (one row per address). name_pref: '' = ask when they go by another name in my polls,
// 'mine' = keep my name (also shown for them in polls I manage, contactNames), 'theirs' = follow their name.
const MAX_FAVOURITES = 500;
const NAME_PREFS = ['', 'mine', 'theirs'];
const favNote = (v) => String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, 120);
// Body: { name, email, note? }. Saving an address again updates the name (and the note when sent).
async function addFavourite(request, env) {
  const user = requireUser(request);
  const b = await body(request);
  const addr = email(b.email || '').toLowerCase();
  if (!addr) throw new HttpError(400, 'Enter an email address');
  if (addr === user.email.toLowerCase()) throw new HttpError(400, 'That’s your own address');
  const name = String(b.name || '').trim().slice(0, 60) || addr.split('@')[0];
  const note = b.note === undefined ? null : favNote(b.note);
  const had = await env.DB.prepare('SELECT id FROM favourites WHERE user_id = ? AND email = ?').bind(user.id, addr).first('id');
  if (had) {
    await env.DB.prepare('UPDATE favourites SET name = ?, note = COALESCE(?, note) WHERE id = ?').bind(name, note, had).run();
    return json({ id: had });
  }
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM favourites WHERE user_id = ?').bind(user.id).first('n');
  if (n >= MAX_FAVOURITES) throw new HttpError(409, `You can have at most ${MAX_FAVOURITES} contacts`);
  const id = randomId(12);
  await env.DB.prepare('INSERT INTO favourites (id, user_id, name, email, note, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(id, user.id, name, addr, note || '', now()).run();
  return json({ id });
}
// Body: any of { name, email, note, namePref }. The new email must not be saved already (one address = one contact).
async function editFavourite(request, env, fid) {
  const user = requireUser(request);
  if (!ID_RE.test(fid)) throw new HttpError(404, 'Contact not found');
  const row = await env.DB.prepare('SELECT * FROM favourites WHERE id = ? AND user_id = ?').bind(fid, user.id).first();
  if (!row) throw new HttpError(404, 'Contact not found');
  const b = await body(request), has = (k) => Object.prototype.hasOwnProperty.call(b, k);
  let addr = row.email, name = row.name, note = row.note || '', pref = row.name_pref || '';
  if (has('email')) {
    addr = email(String(b.email || '')).toLowerCase();
    if (!addr) throw new HttpError(400, 'Enter an email address');
    if (addr === user.email.toLowerCase()) throw new HttpError(400, 'That’s your own address');
    if (addr !== row.email) {
      const dup = await env.DB.prepare('SELECT id FROM favourites WHERE user_id = ? AND email = ?').bind(user.id, addr).first('id');
      if (dup) throw new HttpError(409, 'That address is already in your contacts');
      pref = ''; // another person now: ask again
    }
  }
  if (has('name')) name = String(b.name || '').trim().slice(0, 60) || addr.split('@')[0];
  if (has('note')) note = favNote(b.note);
  if (has('namePref')) {
    if (!NAME_PREFS.includes(b.namePref)) throw new HttpError(400, 'Pick which name to use');
    pref = b.namePref;
  }
  await env.DB.prepare('UPDATE favourites SET name = ?, email = ?, note = ?, name_pref = ? WHERE id = ?')
    .bind(name, addr, note, pref, fid).run();
  return json({ ok: true });
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
// The caller's own address is dropped (you can't be your own contact).
function groupInput(b, partial, user) {
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
      if (seen.has(addr) || addr === user.email.toLowerCase()) continue; seen.add(addr);
      list.push({ name: x.name ? personName(x.name) : addr.split('@')[0], email: addr });
    }
    if (list.length > MAX_GROUP_MEMBERS) throw new HttpError(409, `A group can have at most ${MAX_GROUP_MEMBERS} people`);
    out.members = list;
  }
  return out;
}
// ---------- poll presets (an account's saved starting points for new polls) ----------
const MAX_PRESETS = 50, PRESET_KEYS = ['title', 'description', 'kind', 'unit', 'every', 'openDays', 'deadlineDays', 'answerMode', 'hourStart', 'hourEnd',
  'dayPattern', 'hideResults', 'allowComments', 'requireEmail', 'invitedOnly', 'notifyOpen', 'remindDays', 'remindQuestions', 'icon', 'days', 'questions', 'folder', 'meetLocation', 'meetNote', 'meetQuestions', 'roundQuestions', 'autoMeetings', 'meetApply'];
// Questions without this round's meetings or people: links go to the whole poll (after-meeting ones to all meetings), "people" becomes everyone.
function presetQuestions(list) {
  if (!Array.isArray(list)) throw new HttpError(400, 'Invalid questions');
  const reset = list.map((x) => {
    if (!x || typeof x !== 'object') return x;
    const after = isAfter(x);
    return { ...x, link: after ? afterLink(x.link) : { to: 'poll' },
      who: { mode: after && x.who && (x.who.mode === 'meeting' || x.who.mode === 'free') ? x.who.mode : 'all' } };
  });
  return validateQuestions(reset, [], [], new Set()).map(({ at, tpl, ...q }) => q);
}
// Questions for every round of a series (poll setting round_questions): templates with a stable id; each new round gets a copy
// (tpl = the template's id) linked to the whole poll, for everyone. People's own options live in their answers, so they start fresh.
const MAX_ROUND_QS = 10;
function roundQuestionTpls(list) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) throw new HttpError(400, 'Invalid questions');
  if (list.length > MAX_ROUND_QS) throw new HttpError(400, `Up to ${MAX_ROUND_QS} questions for every round`);
  const qs = list.filter((x) => x && typeof x === 'object' && x.type !== 'group')
    .map(({ grp, own, tpl, ...x }) => ({ ...x, link: { to: 'poll' }, who: { mode: 'all' } }));
  return validateQuestions(qs, [], [], new Set()).map(({ at, link, who, closed, repeat, ...q }) =>
    q.options ? { ...q, options: q.options.map((o) => ({ label: o.label })) } : q);
}
// A round's copies of the templates it doesn't have yet (by tpl), within the per-round limit.
function roundQuestionCopies(tpls, items) {
  const have = new Set(items.map((x) => x.tpl).filter(Boolean)), t = now();
  const labels = new Set(items.filter((x) => x.type !== 'group').map((x) => String(x.label || '').trim().toLowerCase())); // the same question asked by hand
  let room = MAX_QUESTIONS - items.filter((x) => x.type !== 'group').length;
  const out = [];
  for (const x of tpls) {
    if (!x || have.has(x.id) || labels.has(String(x.label || '').trim().toLowerCase()) || room <= 0) continue;
    room--;
    out.push({ ...x, id: randomId(8), tpl: x.id, link: { to: 'poll' }, who: { mode: 'all' }, at: t,
      ...(x.options ? { options: x.options.map((o) => ({ id: randomId(8), label: o.label })) } : {}) });
  }
  return out;
}
// Questions for every new meeting (poll setting meet_questions, planner Details): templates with an id (for meet_apply copies), without links or who.
// The page links them to the meetings it creates. Same checks as a round's questions.
const MAX_MEET_QS = 5;
function meetQuestionTpls(list) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) throw new HttpError(400, 'Invalid questions');
  if (list.length > MAX_MEET_QS) throw new HttpError(400, `Up to ${MAX_MEET_QS} questions for new meetings`);
  const qs = list.filter((x) => x && typeof x === 'object' && x.type !== 'group')
    .map(({ grp, own, ...x }) => ({ ...x, link: { to: 'poll' }, who: { mode: 'all' } }));
  return validateQuestions(qs, [], [], new Set()).map(({ at, link, who, closed, repeat, mtpl, mh, ...q }) =>
    q.options ? { ...q, options: q.options.map((o) => ({ label: o.label })) } : q);
}
// polls.meet_apply: the meeting defaults go to every meeting of the open rounds (auto-made and existing ones too) and follow changes.
// Location / description: meetings still showing the old default (or nothing) get the new one; hand-set ones stay.
// Questions: each meeting gets a copy of each template (mtpl = template id, mh = signature of the template it was copied from),
// while the round has room. A copy nobody edited (its signature still matches mh) follows the template; option ids are kept by label
// so answers survive. An edited copy keeps mtpl (so its meeting gets no second one) but loses mh: it stops following.
// Copies of removed templates go unless edited or answered.
const mqSig = (q) => { const s = JSON.stringify([q.type, q.label || '', q.help || '', q.icon || '', !!q.req, q.vis || 'all', !!q.place, !!q.add,
  (q.options || []).map((o) => o.label), q.rating || null, q.count || null]); let h = 5381; for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0; return h.toString(36); };
function applyMeetDefaults(poll, old, inst, answered = new Set()) {
  const meetings = jsonList(inst.meetings), items = itemsOf(inst), tpls = jsonList(poll.meet_questions).filter((x) => x && x.id);
  const oLoc = (old || poll).meet_location || '', oNote = (old || poll).meet_note || '', loc = poll.meet_location || '', note = poll.meet_note || '';
  let mChanged = false;
  const ms = meetings.map((m) => {
    if (m.cancelled) return m;
    const u = { ...m };
    if (!m.location || m.location === oLoc) u.location = loc;
    if (!m.note || m.note === oNote) u.note = note;
    if (u.location !== m.location || u.note !== m.note) mChanged = true;
    return u;
  });
  const byTpl = new Map(tpls.map((x) => [x.id, x])), live = new Set(ms.filter((m) => !m.cancelled).map((m) => m.id)), t = now(), out = [];
  let qChanged = false;
  for (const q of items) {
    if (q.type === 'group' || !q.mtpl) { out.push(q); continue; }
    const tp = byTpl.get(q.mtpl), clean = q.mh && mqSig(q) === q.mh;
    const gone = !(q.link && q.link.to === 'meetings' && (q.link.ids || []).some((id) => live.has(id))); // its meeting was deleted
    if (gone) { qChanged = true; if (answered.has(q.id) || !clean) { const { mtpl, mh, ...r } = q; out.push(r); } continue; }
    if (!clean) { if (q.mh) { qChanged = true; const { mh, ...r } = q; out.push(r); } else out.push(q); continue; } // edited by hand: stays (no mh = stopped following)
    if (!tp) { qChanged = true; if (answered.has(q.id)) { const { mh, ...r } = q; out.push(r); } continue; } // template removed: unanswered copies go
    const sig = mqSig(tp);
    if (sig === q.mh) { out.push(q); continue; }
    const byLabel = new Map((q.options || []).map((o) => [o.label, o.id]));
    const { id: _i, ...tb } = tp;
    out.push({ id: q.id, ...tb, mtpl: tp.id, mh: sig, link: q.link, who: q.who, at: q.at, ...(q.grp ? { grp: q.grp } : {}), ...(q.closed ? { closed: true } : {}),
      ...(tp.options ? { options: tp.options.map((o) => ({ id: byLabel.get(o.label) || randomId(8), label: o.label })) } : {}) });
    qChanged = true;
  }
  let room = MAX_QUESTIONS - out.filter((x) => x.type !== 'group').length;
  const have = new Set(out.filter((q) => q.mtpl && q.link && q.link.to === 'meetings').flatMap((q) => (q.link.ids || []).map((id) => id + ':' + q.mtpl)));
  const order = ms.filter((m) => !m.cancelled).sort((a, b) => (a.date + (a.start ?? 0)).localeCompare(b.date + (b.start ?? 0)));
  for (const m of order) for (const tp of tpls) {
    if (room <= 0 || have.has(m.id + ':' + tp.id)) continue;
    room--; qChanged = true; have.add(m.id + ':' + tp.id);
    const { id: _i, ...tb } = tp;
    out.push({ ...tb, id: randomId(8), mtpl: tp.id, mh: mqSig(tp), link: { to: 'meetings', ids: [m.id] }, who: { mode: tp.place || m.proposed ? 'all' : 'meeting' }, at: t,
      ...(tp.options ? { options: tp.options.map((o) => ({ id: randomId(8), label: o.label })) } : {}) });
  }
  return { meetings: mChanged ? JSON.stringify(ms) : null, questions: qChanged ? JSON.stringify(out) : null };
}
// Question ids someone answered in round iid (form answers).
async function answeredQids(env, iid) {
  const { results } = await env.DB.prepare('SELECT extra FROM form_answers WHERE instance_id = ? AND extra IS NOT NULL').bind(iid).all();
  const out = new Set();
  for (const r of results || []) for (const k of Object.keys(parseExtra(r.extra).a || {})) out.add(k);
  return out;
}
// Apply the meeting defaults to round inst (loaded row) and store what changed. Returns true when it wrote.
async function storeMeetDefaults(env, poll, old, inst) {
  if (!poll.meet_apply) return false;
  const r = applyMeetDefaults(poll, old, inst, await answeredQids(env, inst.id));
  if (!r.meetings && !r.questions) return false;
  const u = {};
  if (r.meetings) u.meetings = r.meetings;
  if (r.questions) u.questions = r.questions;
  const cols = Object.keys(u);
  await env.DB.prepare(`UPDATE instances SET ${cols.map((c) => c + ' = ?').join(', ')} WHERE id = ? AND meetings IS ? AND questions IS ?`)
    .bind(...cols.map((c) => u[c]), inst.id, inst.meetings, inst.questions).run();
  return true;
}
// The poll's open rounds (the last 3, like resyncAutoMeetings) get the meeting defaults.
async function syncMeetDefaults(env, poll, old) {
  if (!poll.meet_apply) return;
  const { results } = await env.DB.prepare('SELECT * FROM instances WHERE poll_id = ? ORDER BY seq DESC LIMIT 3').bind(poll.id).all();
  for (const inst of results || []) if (effStatus(inst) === 'open') await storeMeetDefaults(env, poll, old, inst);
}
function presetData(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) throw new HttpError(400, 'Invalid preset');
  if (d.scope === 'questions') { // a question preset: just questions (a questionnaire, one question or a round's set)
    const q = { scope: 'questions' }, ic = emojiIcon(d.icon, 'Icon');
    if (ic) q.icon = ic;
    if (d.folder !== undefined && d.folder !== null) { const f = str(d.folder, 40, 'Group').trim(); if (f) q.folder = f; }
    q.questions = presetQuestions(d.questions);
    if (!q.questions.length) throw new HttpError(400, 'A question preset needs at least one question');
    const s = JSON.stringify(q);
    if (s.length > 64000) throw new HttpError(413, 'This preset is too large');
    return s;
  }
  const out = {};
  for (const k of PRESET_KEYS) if (d[k] !== undefined && d[k] !== null) out[k] = d[k];
  // Same checks as creating a poll (dates aren't part of a preset).
  readPollSettings({ ...out, firstStart: out.unit === 'month' ? '2000-01' : '2000-01-03', title: out.title || 'x' }, null);
  if (out.days !== undefined) out.days = int(out.days, 1, MAX_RANGE_DAYS, 'Days');
  if (out.folder !== undefined) { out.folder = str(out.folder, 40, 'Group').trim(); if (!out.folder) delete out.folder; } // the picker's group for my presets
  if (out.questions !== undefined) out.questions = presetQuestions(out.questions);
  if (out.meetQuestions !== undefined) { out.meetQuestions = meetQuestionTpls(out.meetQuestions); if (!out.meetQuestions.length) delete out.meetQuestions; }
  if (out.roundQuestions !== undefined) { out.roundQuestions = out.kind === 'series' ? roundQuestionTpls(out.roundQuestions) : []; if (!out.roundQuestions.length) delete out.roundQuestions; }
  const s = JSON.stringify(out);
  if (s.length > 64000) throw new HttpError(413, 'This preset is too large');
  return s;
}
async function listPresets(request, env) {
  const user = requireUser(request);
  const { results } = await env.DB.prepare('SELECT id, name, icon, data, updated_at FROM poll_presets WHERE user_id = ? ORDER BY name COLLATE NOCASE').bind(user.id).all();
  return json({ presets: results.map((r) => ({ id: r.id, name: r.name, icon: r.icon, data: JSON.parse(r.data), updatedAt: r.updated_at })) });
}
// POST /api/me/presets { name, icon, data } — saving under a name you already use replaces that preset.
async function savePreset(request, env) {
  const user = requireUser(request);
  const b = await body(request);
  const name = str(b.name, 60, 'Preset name', true), icon = emojiIcon(b.icon, 'Icon'), data = presetData(b.data), at = now();
  const old = await env.DB.prepare('SELECT id FROM poll_presets WHERE user_id = ? AND LOWER(name) = ?').bind(user.id, name.toLowerCase()).first('id');
  if (old) {
    await env.DB.prepare('UPDATE poll_presets SET name = ?, icon = ?, data = ?, updated_at = ? WHERE id = ?').bind(name, icon, data, at, old).run();
    return json({ id: old, replaced: true });
  }
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM poll_presets WHERE user_id = ?').bind(user.id).first('n');
  if (n >= MAX_PRESETS) throw new HttpError(409, `You can have at most ${MAX_PRESETS} presets`);
  const id = randomId(12);
  await env.DB.prepare('INSERT INTO poll_presets (id, user_id, name, icon, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, user.id, name, icon, data, at, at).run();
  return json({ id }, 201);
}
async function updatePreset(request, env, pid) {
  const user = requireUser(request);
  if (!ID_RE.test(pid)) throw new HttpError(404, 'Preset not found');
  const b = await body(request), sets = [], vals = [];
  if (b.name !== undefined) {
    const name = str(b.name, 60, 'Preset name', true);
    const clash = await env.DB.prepare('SELECT 1 FROM poll_presets WHERE user_id = ? AND LOWER(name) = ? AND id != ?').bind(user.id, name.toLowerCase(), pid).first();
    if (clash) throw new HttpError(409, 'You already have a preset with this name');
    sets.push('name = ?'); vals.push(name);
  }
  if (b.icon !== undefined) { sets.push('icon = ?'); vals.push(emojiIcon(b.icon, 'Icon')); }
  if (b.data !== undefined) { sets.push('data = ?'); vals.push(presetData(b.data)); }
  else if (b.folder !== undefined) { // move to another group: only the folder changes
    const old = await env.DB.prepare('SELECT data FROM poll_presets WHERE id = ? AND user_id = ?').bind(pid, user.id).first('data');
    if (!old) throw new HttpError(404, 'Preset not found');
    sets.push('data = ?'); vals.push(presetData({ ...JSON.parse(old), folder: b.folder || undefined }));
  }
  sets.push('updated_at = ?'); vals.push(now());
  const r = await env.DB.prepare(`UPDATE poll_presets SET ${sets.join(', ')} WHERE id = ? AND user_id = ?`).bind(...vals, pid, user.id).run();
  if (!r.meta || !r.meta.changes) throw new HttpError(404, 'Preset not found');
  return json({ ok: true });
}
async function deletePreset(request, env, pid) {
  const user = requireUser(request);
  if (!ID_RE.test(pid)) throw new HttpError(404, 'Preset not found');
  await env.DB.prepare('DELETE FROM poll_presets WHERE id = ? AND user_id = ?').bind(pid, user.id).run();
  return json({ ok: true });
}

async function addGroup(request, env) {
  const user = requireUser(request);
  const g = groupInput(await body(request), false, user);
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM contact_groups WHERE user_id = ?').bind(user.id).first('n');
  if (n >= MAX_GROUPS) throw new HttpError(409, `You can have at most ${MAX_GROUPS} groups`);
  const id = randomId(12), at = now();
  await env.DB.prepare('INSERT INTO contact_groups (id, user_id, name, icon, members, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, user.id, g.name, g.icon, JSON.stringify(g.members), at, at).run();
  return json({ id });
}
async function updateGroup(request, env, url, gid) {
  const user = requireUser(request);
  if (!ID_RE.test(gid)) throw new HttpError(404, 'Group not found');
  const g = groupInput(await body(request), true, user), sets = [], vals = [];
  const old = await env.DB.prepare('SELECT name, icon, members FROM contact_groups WHERE id = ? AND user_id = ?').bind(gid, user.id).first();
  if (!old) throw new HttpError(404, 'Group not found');
  if ('name' in g) { sets.push('name = ?'); vals.push(g.name); }
  if ('icon' in g) { sets.push('icon = ?'); vals.push(g.icon); }
  if ('members' in g) { sets.push('members = ?'); vals.push(JSON.stringify(g.members)); }
  sets.push('updated_at = ?'); vals.push(now());
  const r = await env.DB.prepare(`UPDATE contact_groups SET ${sets.join(', ')} WHERE id = ? AND user_id = ?`).bind(...vals, gid, user.id).run();
  if (!r.meta || !r.meta.changes) throw new HttpError(404, 'Group not found');
  const sync = await syncGroup(env, url, user, gid, jsonList(old.members), g.members || jsonList(old.members), g.name ?? old.name, g.icon ?? old.icon);
  return json({ ok: true, ...sync });
}
async function deleteGroup(request, env, gid) {
  const user = requireUser(request);
  if (!ID_RE.test(gid)) throw new HttpError(404, 'Group not found');
  const r = await env.DB.prepare('DELETE FROM contact_groups WHERE id = ? AND user_id = ?').bind(gid, user.id).run();
  // Polls it was linked to keep its people, now ungrouped.
  if (r.meta && r.meta.changes) await env.DB.batch([
    env.DB.prepare(`UPDATE participants SET group_id = NULL WHERE group_id = ? AND poll_id IN (SELECT id FROM polls WHERE owner_id = ?)`).bind(gid, user.id),
    env.DB.prepare(`DELETE FROM poll_groups WHERE group_id = ? AND poll_id IN (SELECT id FROM polls WHERE owner_id = ?)`).bind(gid, user.id)]);
  return json({ ok: true });
}
// Group linked to a poll: the group's members are added as people (group_id = the group) and kept in sync with it:
// new members are added (and invited when the poll's group members were), removed ones leave the poll unless they answered
// (then they stay, ungrouped). The poll keeps a copy of the group's name and icon.
async function groupPollPeople(env, pollId, gid) {
  const { results } = await env.DB.prepare(
    `SELECT p.id, p.invited_at, LOWER(COALESCE(u.email, p.email)) AS mail, LOWER(p.email) AS pmail,
       EXISTS (SELECT 1 FROM responses r WHERE r.participant_id = p.id) AS answered
     FROM participants p LEFT JOIN users u ON u.id = p.user_id WHERE p.poll_id = ? AND p.group_id = ?`).bind(pollId, gid).all();
  return results;
}
// Adds `members` to the poll and marks the rows (not already in another group) as the group's. Returns the upsert result.
async function addGroupPeople(env, pollId, gid, members, user) {
  if (!members.length) return { added: [], updated: [], skipped: [], ids: [] };
  const r = { added: [], updated: [], skipped: [], ids: [] };
  for (let i = 0; i < members.length; i += 200) {
    const part = await upsertPeople(env, pollId, members.slice(i, i + 200).map((m) => ({ name: m.name, email: m.email })), user);
    for (const k of Object.keys(r)) r[k].push(...part[k]);
  }
  const ids = r.ids.filter(Boolean);
  if (ids.length) await env.DB.batch(ids.map((pid) => env.DB.prepare('UPDATE participants SET group_id = ? WHERE id = ? AND group_id IS NULL').bind(gid, pid)));
  return r;
}
async function syncGroup(env, url, user, gid, oldMembers, newMembers, name, icon) {
  const { results: links } = await env.DB.prepare(
    'SELECT pg.poll_id FROM poll_groups pg JOIN polls p ON p.id = pg.poll_id WHERE pg.group_id = ? AND p.owner_id = ?').bind(gid, user.id).all();
  if (!links.length) return {};
  const had = new Set(oldMembers.map((m) => m.email)), keep = new Set(newMembers.map((m) => m.email));
  const gone = new Set([...had].filter((e) => !keep.has(e)));
  const syncErrors = [];
  for (const { poll_id: pid } of links) {
    try {
      await env.DB.prepare('UPDATE poll_groups SET name = ?, icon = ? WHERE poll_id = ? AND group_id = ?').bind(name, icon, pid, gid).run();
      const rows = await groupPollPeople(env, pid, gid);
      const inPoll = new Set(rows.flatMap((p) => [p.mail, p.pmail]).filter(Boolean));
      // Leaving: gone from the group (and not someone who is still a member under their account's address).
      const out = rows.filter((p) => (gone.has(p.mail) || gone.has(p.pmail)) && !keep.has(p.mail) && !keep.has(p.pmail));
      const stmts = [];
      for (const p of out) stmts.push(...(p.answered
        ? [env.DB.prepare('UPDATE participants SET group_id = NULL WHERE id = ?').bind(p.id)]
        : removeParticipantStmts(env, p.id, false)));
      if (stmts.length) await env.DB.batch(stmts);
      const fresh = newMembers.filter((m) => !inPoll.has(m.email));
      if (!fresh.length) continue;
      const r = await addGroupPeople(env, pid, gid, fresh, user);
      // Invite the new ones when the group's people in this poll were invited already.
      const newIds = r.ids.filter(Boolean).filter((x) => !rows.some((p) => p.id === x));
      if (newIds.length && emailEnabled(env) && rows.some((p) => p.invited_at)) {
        const poll = await loadPoll(env, pid);
        await inviteIds(env, url, poll, user, newIds, { again: false }).catch((e) => syncErrors.push(String(e.message || e)));
      }
    } catch (e) { syncErrors.push(String(e.message || e)); }
  }
  return syncErrors.length ? { syncErrors } : {};
}
// Body: { groupId }. Links one of my groups to my poll and adds its members.
async function linkGroup(request, env, url, id) {
  await adminPoll(request, env, id);
  const user = requireUser(request);
  const b = await body(request);
  if (typeof b.groupId !== 'string' || !ID_RE.test(b.groupId)) throw new HttpError(404, 'Group not found');
  const g = await env.DB.prepare('SELECT id, name, icon, members FROM contact_groups WHERE id = ? AND user_id = ?').bind(b.groupId, user.id).first();
  if (!g) throw new HttpError(404, 'Group not found');
  await env.DB.prepare('INSERT OR IGNORE INTO poll_groups (poll_id, group_id, name, icon, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(id, g.id, g.name, g.icon, now()).run();
  const members = jsonList(g.members).filter((m) => m && EMAIL_RE.test(m.email || '') && m.email !== user.email.toLowerCase());
  return json(await addGroupPeople(env, id, g.id, members, user));
}
// Unlinks a group from the poll; its people stay, ungrouped. ?people=1 also removes the ones who haven't answered.
async function unlinkGroup(request, env, url, id, gid) {
  await adminPoll(request, env, id);
  if (!ID_RE.test(gid)) throw new HttpError(404, 'Group not found');
  const rows = await groupPollPeople(env, id, gid);
  const stmts = [env.DB.prepare('DELETE FROM poll_groups WHERE poll_id = ? AND group_id = ?').bind(id, gid),
    env.DB.prepare('UPDATE participants SET group_id = NULL WHERE poll_id = ? AND group_id = ?').bind(id, gid)];
  if (url.searchParams.get('people') === '1') for (const p of rows) if (!p.answered) stmts.push(...removeParticipantStmts(env, p.id, false));
  await env.DB.batch(stmts);
  return json({ ok: true });
}

// ---------- chat ----------
// One chat per poll (a series shares it). Readable and writable by everyone signed in (invited-only polls: the owner and invited people).
// The page polls for new messages while the chat is open; no emails, but Web Push to members who turned notifications on (pushChat).
const CHAT_MAX_LEN = 2000, CHAT_PAGE = 200, CHAT_MAX_PER_POLL = 5000, CHAT_BURST = 30, CHAT_BURST_MIN = 10;
async function chatAllowed(env, poll, user) {
  if (!user || !poll.allow_comments) return false; // allow_comments = the poll's Chat switch (also covers the guest Comment field)
  if (poll.owner_id && poll.owner_id === user.id) return true;
  if (!poll.invited_only) return true;
  // Invited-only: in the poll as this account, or invited as a guest with this account's email.
  if (await accountParticipant(env, poll.id, user.id)) return true;
  return !!(await env.DB.prepare('SELECT 1 FROM participants WHERE poll_id = ? AND user_id IS NULL AND LOWER(email) = ? LIMIT 1').bind(poll.id, user.email.toLowerCase()).first());
}
// Throws unless the caller may use this poll's chat. Returns { poll, user, owner }.
// write = false (reading): guests too, when they can open the poll (invited-only polls: through their personal link); user is then null.
async function chatAccess(request, env, id, write = true) {
  const user = write ? requireUser(request) : userOf(request);
  const poll = await loadPoll(env, id);
  const owner = !!user && await isAdmin(request, env, poll, 'manage');
  if (!(user && await isAdmin(request, env, poll))) await checkPassword(env, request, poll);
  if (!poll.allow_comments) throw new HttpError(403, 'The chat is turned off for this poll');
  if (user ? !(await chatAllowed(env, poll, user)) : !(await chatReadable(request, env, poll))) throw new HttpError(403, 'Only invited people can join this chat');
  return { poll, user, owner };
}
// Guests (no account) may read the chat when the poll is open to everyone with the link, or through their personal link.
async function chatReadable(request, env, poll) {
  if (!poll.allow_comments) return false;
  return !poll.invited_only || !!(await personByKey(request, env, poll.id));
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
// Members (?1 = poll id): account participants, accounts invited by email that haven't answered yet, and everyone who opened or wrote in the chat.
const CHAT_MEMBERS_SQL = `SELECT user_id FROM participants WHERE poll_id = ?1 AND user_id IS NOT NULL
  UNION SELECT u.id FROM participants p JOIN users u ON u.email = LOWER(p.email) WHERE p.poll_id = ?1 AND p.user_id IS NULL AND p.email IS NOT NULL
  UNION SELECT user_id FROM chat_reads WHERE poll_id = ?1
  UNION SELECT user_id FROM messages WHERE poll_id = ?1`;
// ?after=<iso>: only messages from then on (>=, the page drops ones it has). Without it: the newest CHAT_PAGE plus who wrote them.
async function listChat(request, env, url, id) {
  const { poll, user: me, owner } = await chatAccess(request, env, id, false);
  const user = me || CHAT_GUEST; // guests: nothing is theirs, no read mark, names only
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
  const out = { messages: msgs.map((m) => msgOut(m, user)), owner: poll.owner_id || null, canDeleteAll: owner, now: t0, me: me ? me.id : null }; // me: to spot my tags
  if (!me) { // guest: no members (no tagging), only the names of the people in these messages, no pictures or addresses
    if (!after) {
      const ids = new Set();
      for (const m of msgs) {
        ids.add(m.user_id); if (m.q_uid) ids.add(m.q_uid);
        for (const t of m.body.matchAll(/<@([A-Za-z0-9_]{4,40})>/g)) ids.add(t[1]);
        if (m.q_body) for (const t of m.q_body.matchAll(/<@([A-Za-z0-9_]{4,40})>/g)) ids.add(t[1]);
      }
      const { results: rr } = await env.DB.prepare("SELECT user_id, role FROM participants WHERE poll_id = ? AND user_id IS NOT NULL AND role != ''").bind(id).all();
      out.roles = Object.fromEntries(rr.filter((r) => POLL_ROLES.includes(r.role)).map((r) => [r.user_id, r.role]));
      out.people = await chatGuestNames(env, id, [...ids]);
    }
    return json(out);
  }
  // Who wrote them and who is in the chat (members can be tagged). Pictures only on the first load;
  // a later message from someone new makes the page reload once.
  if (!after) {
    // Members: account participants, accounts invited by email that haven't answered yet, and everyone who opened or wrote in the chat.
    const { results: mem } = await env.DB.prepare(CHAT_MEMBERS_SQL).bind(id).all();
    out.members = [...new Set([...(poll.owner_id ? [poll.owner_id] : []), ...mem.map((r) => r.user_id)])];
    const { results: rr } = await env.DB.prepare("SELECT user_id, role FROM participants WHERE poll_id = ? AND user_id IS NOT NULL AND role != ''").bind(id).all();
    out.roles = Object.fromEntries(rr.filter((r) => POLL_ROLES.includes(r.role)).map((r) => [r.user_id, r.role])); // tag next to names
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
const CHAT_GUEST = { id: '' };
// Names for guests reading the chat (uid -> { name }): the account's name, else its name in this poll. Never the email.
async function chatGuestNames(env, pollId, ids) {
  const out = {};
  for (let i = 0; i < ids.length; i += 90) { // D1 caps bound parameters per query
    const part = ids.slice(i, i + 90), q = part.map(() => '?').join(',');
    const { results } = await env.DB.prepare(`SELECT u.id, COALESCE(NULLIF(u.name, ''), (SELECT p.name FROM participants p WHERE p.poll_id = ? AND p.user_id = u.id LIMIT 1), '') AS name
      FROM users u WHERE u.id IN (${q})`).bind(pollId, ...part).all();
    for (const r of results) out[r.id] = { name: r.name || '?' };
  }
  return out;
}
// Body: { body }.
async function postChat(request, env, ctx, id) {
  const { poll, user } = await chatAccess(request, env, id);
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
  ctx.waitUntil(pushChat(env, poll, user, m).catch((e) => console.error(e)));
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
// ---------- push notifications (Web Push) ----------
// Each browser that turns on chat notifications stores its push address (push_subs). A new chat message is sent, end-to-end
// encrypted (RFC 8291 aes128gcm, VAPID RFC 8292), to the push service of every member's browsers, except the writer and people
// who muted that poll (chat_reads.muted). No dependencies: WebCrypto only. Without VAPID keys the feature is off (config push: null).
const PUSH_MAX = 30;        // subscriptions per message (Free plan: 50 subrequests and 10 ms CPU per request)
const PUSH_PER_USER = 10;   // devices per account (oldest dropped)
// Only real push services (the Worker POSTs to the endpoint, so no arbitrary hosts).
const PUSH_HOST_RE = /^(fcm\.googleapis\.com|android\.googleapis\.com|[a-z0-9.-]+\.push\.services\.mozilla\.com|updates\.push\.services\.mozilla\.com|[a-z0-9.-]*\.push\.apple\.com|[a-z0-9.-]+\.notify\.windows\.com)$/;
const unb64u = (s) => unb64(String(s).replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((String(s).length + 3) % 4));
const pushOn = (env) => !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY);
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; } return out; };
let VAPID = null; // { pub, key } cached per isolate
async function vapidKey(env) {
  if (VAPID && VAPID.pub === env.VAPID_PUBLIC_KEY) return VAPID.key;
  const raw = unb64u(env.VAPID_PUBLIC_KEY);
  // Forgive the usual paste slips: the whole "VAPID_PRIVATE_KEY=…" line, quotes, spaces, base64 instead of base64url.
  const d = String(env.VAPID_PRIVATE_KEY).trim().replace(/^VAPID_PRIVATE_KEY\s*=\s*/, '').replace(/^["']|["']$/g, '').trim()
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  let key;
  try {
    key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: b64url(raw.slice(1, 33)), y: b64url(raw.slice(33, 65)), d, ext: true },
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  } catch (e) {
    throw new Error(`VAPID_PRIVATE_KEY can't be read (${d.length} chars, expected the 43-char "d" from scripts/vapid-keys.mjs): ${e.message}`);
  }
  VAPID = { pub: env.VAPID_PUBLIC_KEY, key };
  return key;
}
async function vapidJwt(env, aud) {
  const part = (o) => b64url(enc.encode(JSON.stringify(o)));
  const sub = env.CONTACT_EMAIL ? 'mailto:' + env.CONTACT_EMAIL : env.SITE_URL || 'https://when-who.app';
  const unsigned = part({ typ: 'JWT', alg: 'ES256' }) + '.' + part({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub });
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, await vapidKey(env), enc.encode(unsigned)));
  return unsigned + '.' + b64url(sig);
}
const hkdf = async (salt, ikm, info, len) => new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info },
  await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']), len * 8));
// One ephemeral key pair per message (random salt per recipient).
async function pushEphemeral() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  return { kp, pub: new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)) };
}
async function pushEncrypt(eph, sub, payload) {
  const ua = unb64u(sub.p256dh), auth = unb64u(sub.auth);
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, eph.kp.privateKey, 256));
  const ikm = await hkdf(auth, shared, cat(enc.encode('WebPush: info\0'), ua, eph.pub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, cat(enc.encode(payload), new Uint8Array([2]))));
  const head = new Uint8Array(21); head.set(salt); new DataView(head.buffer).setUint32(16, 4096); head[20] = eph.pub.length;
  return cat(head, eph.pub, ct);
}
// Sends one payload (object, or a function of the subscription for per-language text) to subscriptions; drops dead ones.
async function pushSend(env, subs, payload, topic) {
  if (!pushOn(env) || !subs.length) return 0;
  const eph = await pushEphemeral(), jwts = new Map(), gone = [];
  let sent = 0;
  await Promise.all(subs.map(async (s) => {
    try {
      const aud = new URL(s.endpoint).origin;
      if (!jwts.has(aud)) jwts.set(aud, vapidJwt(env, aud));
      const data = JSON.stringify(typeof payload === 'function' ? payload(s) : payload);
      const res = await fetch(s.endpoint, { method: 'POST', body: await pushEncrypt(eph, s, data), headers: {
        authorization: `vapid t=${await jwts.get(aud)}, k=${env.VAPID_PUBLIC_KEY}`, 'content-encoding': 'aes128gcm',
        'content-type': 'application/octet-stream', ttl: '86400', urgency: 'normal', ...(topic ? { topic } : {}) } });
      if (res.status === 404 || res.status === 410) gone.push(s.id);
      else if (!res.ok) console.error('push', res.status, aud, (await res.text()).slice(0, 200));
      else sent++;
    } catch (e) { console.error('push', e); }
  }));
  if (gone.length) await env.DB.prepare(`DELETE FROM push_subs WHERE id IN (${gone.map(() => '?').join(',')})`).bind(...gone).run();
  return sent;
}
// A new chat message → notifyEvent (kind chat): members who want chat pushes ('all', or 'mentions' when tagged).
async function chatPlain(env, bodies, max) {
  const tagged = [...new Set(bodies.flatMap((b) => [...String(b).matchAll(/<@([A-Za-z0-9_]{4,40})>/g)].map((x) => x[1])))].slice(0, 90);
  const names = {};
  if (tagged.length) {
    const { results } = await env.DB.prepare(`SELECT id, email, name FROM users WHERE id IN (${tagged.map(() => '?').join(',')})`).bind(...tagged).all();
    for (const u of results) names[u.id] = personOut({ ...u, avatar: '', avatar_img: '' }).name;
  }
  // Tags as @name, attached meetings as ★.
  return bodies.map((b) => {
    const text = String(b).replace(/<@([A-Za-z0-9_]{4,40})>/g, (_, id) => '@' + (names[id] || '?')).replace(/<#m:[A-Za-z0-9_-]{1,24}>/g, '★').replace(/\s+/g, ' ').trim();
    return text.length > max ? text.slice(0, max - 1) + '…' : text;
  });
}
async function pushChat(env, poll, user, m) {
  const tagged = [...new Set([...m.body.matchAll(/<@([A-Za-z0-9_]{4,40})>/g)].map((x) => x[1]))];
  const [text] = await chatPlain(env, [m.body], 200);
  const name = personOut({ ...user, avatar: '', avatar_img: '' }).name.slice(0, 60);
  await notifyEvent(env, poll, { kind: 'chat', actor: user.id, name, ref: m.id, tagged,
    push: () => ({ name, body: text, url: `/?p=${poll.id}&chat=1`, at: m.created_at }) });
}
// Body: { endpoint, keys: { p256dh, auth } }.
async function savePushSub(request, env) {
  const user = requireUser(request);
  if (!pushOn(env)) throw new HttpError(503, 'Notifications aren’t set up on this site');
  const b = await body(request);
  const endpoint = typeof b.endpoint === 'string' ? b.endpoint : '';
  let u; try { u = new URL(endpoint); } catch { u = null; }
  if (!u || u.protocol !== 'https:' || endpoint.length > 1000 || !PUSH_HOST_RE.test(u.hostname)) throw new HttpError(400, 'This browser’s push service isn’t supported');
  const k = b.keys || {};
  let p, a; try { p = unb64u(k.p256dh); a = unb64u(k.auth); } catch { p = a = null; }
  if (!p || p.length !== 65 || p[0] !== 4 || !a || a.length !== 16) throw new HttpError(400, 'Invalid push keys');
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO push_subs (id, user_id, endpoint, p256dh, auth, lang, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth, lang = excluded.lang`)
      .bind(randomId(12), user.id, endpoint, b64url(p), b64url(a), reqLang(request), now()),
    env.DB.prepare(`DELETE FROM push_subs WHERE user_id = ?1 AND id NOT IN (SELECT id FROM push_subs WHERE user_id = ?1 ORDER BY created_at DESC LIMIT ${PUSH_PER_USER})`).bind(user.id),
  ]);
  return json({ ok: true });
}
// Body: { endpoint }. Works signed out too (the address is the secret), so signing out can switch it off.
async function deletePushSub(request, env) {
  const b = await body(request);
  if (typeof b.endpoint !== 'string' || !b.endpoint) throw new HttpError(400, 'Missing endpoint');
  await env.DB.prepare('DELETE FROM push_subs WHERE endpoint = ?').bind(b.endpoint).run();
  return json({ ok: true });
}
// Body: { endpoint? }: a test notification to this device (or all of the account's devices).
async function testPush(request, env) {
  const user = requireUser(request);
  if (!pushOn(env)) throw new HttpError(503, 'Notifications aren’t set up on this site');
  const b = await body(request);
  await checkThrottle(env, request, 'push-test', { key: 'u:' + user.id, max: 5, msg: `Too many test notifications. Try again in ${FAIL_WINDOW_MIN} minutes.` });
  await recordFail(env, request, 'push-test', 'u:' + user.id);
  const { results: subs } = await env.DB.prepare(`SELECT id, endpoint, p256dh, auth, lang FROM push_subs WHERE user_id = ?${typeof b.endpoint === 'string' ? ' AND endpoint = ?' : ''}`)
    .bind(...[user.id, ...(typeof b.endpoint === 'string' ? [b.endpoint] : [])]).all();
  if (!subs.length) throw new HttpError(404, 'Notifications aren’t on for this device');
  const sent = await pushSend(env, subs, (s) => s.lang === 'de'
    ? { kind: 'test', title: 'when-who', body: 'Benachrichtigungen sind an. So sehen neue Chat-Nachrichten aus.', url: '/?account', tag: 'test' }
    : { kind: 'test', title: 'when-who', body: 'Notifications are on. New chat messages will look like this.', url: '/?account', tag: 'test' });
  if (!sent) throw new HttpError(502, 'The push service didn’t accept the notification. Turn notifications off and on again.');
  return json({ ok: true, sent });
}
// Body: { muted }. Per person per poll, on the chat_reads row (a new row keeps read_at empty = nothing read yet).
async function muteChat(request, env, id) {
  const { poll, user } = await chatAccess(request, env, id);
  const b = await body(request);
  const cur = await ntFor(env, poll, user.id);
  const p = cleanPrefs({ chat: { p: b.muted ? 'off' : 'all' } }, cur.prefs);
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO answer_watch (poll_id, user_id, prefs, sent_at) VALUES (?, ?, ?, ?)
      ON CONFLICT (poll_id, user_id) DO UPDATE SET prefs = excluded.prefs`).bind(id, user.id, JSON.stringify(p), now()),
    env.DB.prepare(`INSERT INTO chat_reads (poll_id, user_id, read_at, muted) VALUES (?, ?, '', ?)
      ON CONFLICT (poll_id, user_id) DO UPDATE SET muted = excluded.muted`).bind(id, user.id, b.muted ? 1 : 0)]);
  return json({ ok: true, muted: !!b.muted, notify: ntOut(await ntFor(env, poll, user.id)) });
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
    env.DB.prepare('SELECT id, account_id, url, name, color, color_pick, icon, auto FROM user_calendars WHERE user_id = ? ORDER BY position, created_at').bind(user.id),
  ]);
  // iCal links are secrets: the page only learns which host they point at.
  return json({
    providers: calProviders(env),
    accounts: a.results.map((x) => ({ id: x.id, provider: x.provider, email: x.email, status: x.status, contacts: hasContacts(x) })),
    calendars: c.results.map((x) => ({ id: x.id, accountId: x.account_id || null, name: x.name, color: x.color_pick || x.color || '', colorOwn: !!x.color_pick, icon: x.icon || '', auto: !!x.auto, host: x.url ? icalHost(x.url) : '' })),
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
// Body: { name?, auto?, color? ('#rrggbb' picked by the person, '' = the provider's colour again), icon? (one emoji or '') }
async function updateCalendar(request, env, cid) {
  const user = requireUser(request);
  const c = await ownCalendar(env, user, cid);
  const b = await body(request);
  const name = b.name !== undefined ? str(b.name, 60, 'Name', true) : c.name;
  const auto = b.auto !== undefined ? (b.auto ? 1 : 0) : c.auto;
  let pick = c.color_pick || '';
  if (b.color !== undefined) { pick = b.color ? calColor(b.color) : ''; if (b.color && !pick) throw new HttpError(400, 'Colour: use #rrggbb'); }
  const icon = b.icon !== undefined ? emojiIcon(b.icon, 'Icon') : c.icon || '';
  await env.DB.prepare('UPDATE user_calendars SET name = ?, auto = ?, color_pick = ?, icon = ? WHERE id = ?').bind(name, auto, pick, icon, c.id).run();
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
// GET ?from=<ms>&to=<ms>[&all=1]. iCal: the raw feed. Google / Outlook: { events: [{ s, e, allDay, title }] },
// with s / e in ms (timed) or 'YYYY-MM-DD' (all-day, end exclusive). Cancelled events are left out, free ones too unless
// all=1 (the home calendar shows holidays and other free events; busy times don't).
async function calendarBusy(request, env, url, cid) {
  const user = requireUser(request);
  const c = await ownCalendar(env, user, cid);
  await calThrottle(env, request, user);
  if (c.url) return icsResponse(await fetchIcalText(c.url));
  const from = +url.searchParams.get('from'), to = +url.searchParams.get('to'), all = url.searchParams.get('all') === '1';
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
        if (x.status === 'cancelled' || (x.transparency === 'transparent' && !all) || !x.start || !x.end) continue;
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
        if (x.isCancelled || (x.showAs === 'free' && !all) || !x.start || !x.end) continue;
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
    `SELECT p.id, p.title, p.kind, p.icon, p.image_at, p.image IS NOT NULL AS has_image, pa.name, pa.role,
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
  // The newest message of every chat I'm in (Overview preview line).
  const { results: lm } = await env.DB.prepare(
    `SELECT poll_id, body, created_at, user_id, name, email, avatar, av_img, pname FROM (
       SELECT m.poll_id, m.body, m.created_at, m.user_id, u.name, u.email, u.avatar, LENGTH(u.avatar_img) AS av_img,
         (SELECT p.name FROM participants p WHERE p.poll_id = m.poll_id AND p.user_id = m.user_id LIMIT 1) AS pname,
         ROW_NUMBER() OVER (PARTITION BY m.poll_id ORDER BY m.created_at DESC) AS rn
       FROM messages m LEFT JOIN users u ON u.id = m.user_id
       WHERE m.poll_id IN (SELECT id FROM polls WHERE owner_id = ?1 UNION SELECT poll_id FROM participants WHERE user_id = ?1)
         AND m.poll_id IN (SELECT id FROM polls WHERE allow_comments = 1))
     WHERE rn = 1`).bind(user.id).all();
  const lmText = await chatPlain(env, lm.map((l) => l.body), 90);
  const lastMsg = Object.fromEntries(lm.map((l, i) => [l.poll_id, { name: l.name || (l.email || '').split('@')[0] || l.pname || '?',
    avatar: l.avatar || '', avatarImg: l.av_img ? `/api/users/${l.user_id}/avatar?v=${l.av_img}` : '', body: lmText[i], at: l.created_at, mine: l.user_id === user.id }]));
  const lastOf = (p) => (lastMsg[p.id] ? { last: lastMsg[p.id] } : {});
  const { results: hid } = await env.DB.prepare('SELECT poll_id FROM poll_hidden WHERE user_id = ?').bind(user.id).all();
  const hidden = new Set(hid.map((r) => r.poll_id)), hd = (p) => (hidden.has(p.id) ? { hidden: true } : {});
  const current = (p) => (p.start_date ? { startDate: p.start_date, endDate: p.end_date, deadline: p.deadline, answers: p.answers,
    status: effStatus({ status: p.status, end_date: p.end_date }) } : null);
  return json({
    polls: owned.map((p) => ({ id: p.id, title: p.title, kind: p.kind, icon: p.icon, image: pic(p), createdAt: p.created_at, unread: unread[p.id] || 0,
      current: current(p), ...lastOf(p), ...hd(p) })),
    answered: answered.map((p) => ({ id: p.id, title: p.title, kind: p.kind, icon: p.icon, image: pic(p), name: p.name, lastAnswered: p.last,
      ...(POLL_ROLES.includes(p.role) ? { role: p.role } : {}), unread: unread[p.id] || 0, current: current(p), ...lastOf(p), ...hd(p) })),
  });
}
// The meetings of one round (row.meetings) I'm in, one call per date in from..to (repeats expanded, all-day ranges per day):
// the owner is in all of them, others when the meeting is for everyone or lists their answer (mine = my response row).
// Proposals are skipped unless `proposed` (Upcoming lists them for voting). each(mt, { kind, mtitle, allDay, hs?, he?, date }).
function myMeetingOccs(row, mine, own, from, to, each, proposed = false) {
  for (const mt of jsonList(row.meetings)) {
    if (mt.proposed && !proposed) continue;
    if (!own && mt.participants !== 'all' && !(mine && Array.isArray(mt.participants) && mt.participants.some((x) => x.id === mine.id))) continue;
    const t = { kind: 'meeting', mtitle: mt.title || '', allDay: !!mt.allDay, ...(mt.allDay ? {} : { hs: mt.start, he: mt.end }) };
    if (mt.repeat && isDate(mt.repeat.from)) {
      for (let d = firstOnWeekday(mt.repeat.from, wdOf(mt.date)), i = 0; i < 520 && d <= to && (!mt.repeat.until || d <= mt.repeat.until); i++, d = addDays(d, 7 * (mt.repeat.every || 1)))
        if (d >= from) each(mt, { ...t, date: d });
    } else if (isDate(mt.date)) {
      const last = mt.allDay && mt.endDate ? mt.endDate : mt.date;
      for (let d = mt.date > from ? mt.date : from; d <= last && d <= to; d = addDays(d, 1)) each(mt, { ...t, date: d });
    }
  }
}
// GET /api/me/upcoming?from=&to= — the home page's Upcoming card: across my polls (not hidden from the overview), the meetings
// I'm in, proposals still up for a vote in open rounds (voted = my answer has a vote on it) and reply-by dates of open rounds
// (owners: replies close; others: only while they haven't answered). Read only, nothing stored. At most 60 days, 600 items.
async function upcoming(request, env, url) {
  const user = requireUser(request);
  const from = url.searchParams.get('from'), to = url.searchParams.get('to');
  if (!isDate(from) || !isDate(to) || to < from || daysBetween(from, to) > 60) throw new HttpError(400, 'Invalid dates');
  const { results: rows } = await env.DB.prepare(
    `SELECT p.id AS pid, p.title, p.icon, p.kind, p.owner_id, p.image_at, p.image IS NOT NULL AS has_image,
       i.id AS iid, i.start_date, i.end_date, i.status, i.deadline, i.meetings
     FROM polls p JOIN instances i ON i.poll_id = p.id
     WHERE (p.owner_id = ?1 OR p.id IN (SELECT poll_id FROM participants WHERE user_id = ?1))
       AND p.id NOT IN (SELECT poll_id FROM poll_hidden WHERE user_id = ?1)
       AND ((i.start_date <= ?3 AND i.end_date >= ?2) OR i.start_date = '${WEEK0}' OR i.meetings LIKE '%"repeat"%'
         OR (i.deadline >= ?2 AND i.deadline <= ?3))
     LIMIT 500`).bind(user.id, from, to).all();
  if (!rows.length) return json({ polls: [], items: [] });
  const { results: rs } = await env.DB.prepare(
    `SELECT r.id, r.instance_id, r.votes FROM responses r JOIN participants pa ON pa.id = r.participant_id WHERE pa.user_id = ?`).bind(user.id).all();
  const resp = new Map(rs.map((r) => [r.instance_id, r]));
  const items = [], used = new Map();
  const add = (row, it) => { items.push({ poll: row.pid, ...it }); used.set(row.pid, row); };
  for (const row of rows) {
    const mine = resp.get(row.iid), own = row.owner_id === user.id, open = effStatus(row) === 'open';
    let votes = []; try { votes = JSON.parse((mine && mine.votes) || '[]'); } catch {}
    if (!Array.isArray(votes)) votes = [];
    myMeetingOccs(row, mine, own, from, to, (mt, t) => {
      if (mt.proposed && !open) return;
      add(row, { ...t, kind: mt.proposed ? 'proposed' : 'meeting', mid: mt.id, ...(mt.location ? { location: mt.location } : {}),
        ...(mt.proposed ? { voted: votes.includes(mt.id) } : {}) });
    }, true);
    const dl = isDate(row.deadline) ? row.deadline : '';
    if (open && dl && dl >= from && dl <= to && (own || !mine)) add(row, { kind: 'deadline', date: dl, own });
  }
  const rank = { deadline: 0, meeting: 1, proposed: 2 };
  items.sort((a, b) => a.date.localeCompare(b.date) || (a.allDay ? 0 : 1) - (b.allDay ? 0 : 1) || (a.hs ?? -1) - (b.hs ?? -1) || rank[a.kind] - rank[b.kind]);
  const pic = (p) => (p.has_image ? p.image_at || '1' : '');
  return json({ polls: [...used.values()].map((r) => ({ id: r.pid, title: r.title, kind: r.kind, icon: r.icon || '', image: pic(r) })), items: items.slice(0, 600) });
}
// GET /api/me/todo — the home page's To do card: across polls I'm in (not my own, no role, not hidden from the overview), what's
// still open for me in the current round: availability not sent (avail), questions left empty (questions: n, req = required),
// vote groups without my vote (vote: n), and after-meeting questions open now (after: newest meeting, n), the last also from the
// round before. Same rules as the poll's own To do strip (todoList on the page). Read only.
async function myTodo(request, env) {
  const user = requireUser(request);
  const { results: rows } = await env.DB.prepare(
    `SELECT p.id AS pid, p.title, p.icon, p.kind, p.image_at, p.image IS NOT NULL AS has_image, pa.id AS part_id,
       i.id AS iid, i.seq, i.start_date, i.end_date, i.status, i.deadline, i.meetings, i.questions,
       (SELECT MAX(seq) FROM instances WHERE poll_id = p.id) AS top
     FROM participants pa JOIN polls p ON p.id = pa.poll_id JOIN instances i ON i.poll_id = p.id
     WHERE pa.user_id = ?1 AND (p.owner_id IS NULL OR p.owner_id != ?1) AND COALESCE(pa.role, '') = ''
       AND p.id NOT IN (SELECT poll_id FROM poll_hidden WHERE user_id = ?1)
       AND i.seq >= (SELECT MAX(seq) FROM instances WHERE poll_id = p.id) - 1
     ORDER BY p.id, i.seq DESC LIMIT 400`).bind(user.id).all();
  if (!rows.length) return json({ polls: [], items: [] });
  const iids = JSON.stringify([...new Set(rows.map((r) => r.iid))]), pids = JSON.stringify([...new Set(rows.map((r) => r.part_id))]);
  const { results: rs } = await env.DB.prepare(
    'SELECT instance_id, participant_id, votes FROM responses WHERE participant_id IN (SELECT value FROM json_each(?1)) AND instance_id IN (SELECT value FROM json_each(?2))').bind(pids, iids).all();
  const { results: fs } = await env.DB.prepare(
    'SELECT instance_id, extra FROM form_answers WHERE participant_id IN (SELECT value FROM json_each(?1)) AND instance_id IN (SELECT value FROM json_each(?2))').bind(pids, iids).all();
  const resp = new Map(rs.map((r) => [r.instance_id, r])), form = new Map(fs.map((f) => [f.instance_id, parseExtra(f.extra).a || {}]));
  const items = [], used = new Map(), at = Date.now();
  for (const row of rows) {
    const latest = row.seq === row.top, open = latest && effStatus(row) === 'open';
    const qs = questionsOf(row), meetings = jsonList(row.meetings), mine = resp.get(row.iid);
    if (!open && !qs.some(isAfter)) continue;
    const responses = qs.some((q) => q.who.mode === 'free')
      ? (await env.DB.prepare('SELECT participant_id, entries FROM responses WHERE instance_id = ?').bind(row.iid).all()).results : [];
    const part = { id: row.part_id }, dl = open && isDate(row.deadline) ? row.deadline : null;
    const add = (it) => { items.push({ poll: row.pid, iid: row.iid, ...(dl ? { deadline: dl } : {}), ...it }); used.set(row.pid, row); };
    if (open && !mine) add({ kind: 'avail' });
    const pq = qs.length ? pendingQuestions(qs, part, form.get(row.iid) || {}, meetings, responses, open, at) : { open: [], req: 0, after: [] };
    if (pq.open.length) add({ kind: 'questions', n: pq.open.length, req: pq.req });
    if (open && mine) {
      let votes = []; try { votes = JSON.parse(mine.votes || '[]'); } catch {}
      if (!Array.isArray(votes)) votes = [];
      const groups = new Map();
      for (const m of meetings) if (m.proposed) { const g = m.vote || ''; if (!groups.has(g)) groups.set(g, []); groups.get(g).push(m.id); }
      const n = [...groups.values()].filter((ids) => !ids.some((x) => votes.includes(x))).length;
      if (n) add({ kind: 'vote', n });
    }
    if (pq.after.length && !items.some((x) => x.poll === row.pid && x.kind === 'after')) {
      const o = pq.after[0];
      add({ kind: 'after', n: pq.after.length, mid: o.m.id, date: o.date, mtitle: String(o.m.title || '').slice(0, 80), before: isBefore(o.q) ? 1 : 0 });
    }
  }
  const rank = { avail: 0, questions: 1, vote: 2, after: 3 };
  items.sort((a, b) => (a.deadline || '9999').localeCompare(b.deadline || '9999') || a.poll.localeCompare(b.poll) || rank[a.kind] - rank[b.kind]);
  const pic = (p) => (p.has_image ? p.image_at || '1' : '');
  return json({ polls: [...used.values()].map((r) => ({ id: r.pid, title: r.title, kind: r.kind, icon: r.icon || '', image: pic(r) })), items: items.slice(0, 200) });
}
// GET /api/me/poll-busy?from=&to=&skip= — when I'm busy because of my other polls (Busy ▾ → Other polls on the answer page):
// confirmed meetings I'm in (any round), and hours I marked available / if needed in rounds that are still open
// (weekly polls' answers have no real dates, so only their meetings count). Read only, nothing stored.
// items: { poll, title, kind: 'meeting', date, allDay, hs?, he? } | { poll, title, kind: 'answer', date, hours }.
async function pollBusy(request, env, url) {
  const user = requireUser(request);
  const from = url.searchParams.get('from'), to = url.searchParams.get('to'), skip = url.searchParams.get('skip') || '';
  if (!isDate(from) || !isDate(to) || to < from || daysBetween(from, to) > 400) throw new HttpError(400, 'Invalid dates');
  const { results: rows } = await env.DB.prepare(
    `SELECT p.id AS pid, p.title, p.icon, p.kind, p.owner_id, p.answer_mode, p.hour_start, p.hour_end, p.day_pattern,
       i.id AS iid, i.start_date, i.end_date, i.status, i.meetings
     FROM polls p JOIN instances i ON i.poll_id = p.id
     WHERE p.id != ?2 AND (p.owner_id = ?1 OR p.id IN (SELECT poll_id FROM participants WHERE user_id = ?1))
       AND ((i.start_date <= ?4 AND i.end_date >= ?3) OR i.start_date = '${WEEK0}' OR i.meetings LIKE '%"repeat"%')
     LIMIT 500`).bind(user.id, skip, from, to).all();
  if (!rows.length) return json({ polls: [], items: [] });
  const { results: rs } = await env.DB.prepare(
    `SELECT r.id, r.instance_id, r.entries FROM responses r JOIN participants pa ON pa.id = r.participant_id WHERE pa.user_id = ?`).bind(user.id).all();
  const resp = new Map(rs.map((r) => [r.instance_id, r]));
  const items = [], used = new Map();
  const add = (row, it) => { if (items.length < 5000) { items.push({ poll: row.pid, title: row.title, ...it }); used.set(row.pid, row); } };
  for (const row of rows) {
    const mine = resp.get(row.iid), own = row.owner_id === user.id;
    myMeetingOccs(row, mine, own, from, to, (mt, t) => add(row, t));
    if (!mine || row.start_date === WEEK0 || effStatus(row) !== 'open') continue;
    let en = {}; try { en = JSON.parse(mine.entries || '{}') || {}; } catch (e) {}
    const pat = patternOf(row);
    for (const [d, v] of Object.entries(en)) {
      if (!isDate(d) || d < from || d > to) continue;
      const hours = v === 'y' || v === 'i' ? hoursOn(row, pat, d) : v && typeof v === 'object' ? [...(v.y || []), ...(v.i || [])].filter(Number.isInteger).sort((x, y) => x - y) : [];
      if (hours.length) add(row, { kind: 'answer', date: d, hours });
    }
  }
  return json({ polls: [...used.values()].map((r) => ({ id: r.pid, title: r.title, icon: r.icon || '' })), items });
}
// Hide a poll from (or show it again on) my overview. Only polls I own or am in; nothing else changes.
async function setPollHidden(request, env, id) {
  const user = requireUser(request);
  const b = await body(request);
  const mine = await env.DB.prepare('SELECT 1 FROM polls WHERE id = ?1 AND (owner_id = ?2 OR id IN (SELECT poll_id FROM participants WHERE user_id = ?2))')
    .bind(id, user.id).first();
  if (!mine) throw new HttpError(404, 'Poll not found');
  if (b.hidden) await env.DB.prepare('INSERT OR REPLACE INTO poll_hidden (user_id, poll_id, at) VALUES (?, ?, ?)').bind(user.id, id, new Date().toISOString()).run();
  else await env.DB.prepare('DELETE FROM poll_hidden WHERE user_id = ? AND poll_id = ?').bind(user.id, id).run();
  return json({ ok: true, hidden: !!b.hidden });
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
      if (p.unit === 'week' && p.every * 7 > MAX_RANGE_DAYS) throw new HttpError(400, 'A poll can cover at most 52 weeks');
      if (p.unit === 'month' && p.every > 12) throw new HttpError(400, 'A poll can cover at most 12 months');
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
      if (ps.length === 1) pat = ps[0].wd || ps[0].dom || pat.paused ? { wd: ps[0].wd, dom: ps[0].dom, ...(pat.paused ? { paused: pat.paused } : {}) } : null;
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
  if (has('remindQuestions')) p.remind_questions = b.remindQuestions ? 1 : 0; // only when sent: needs migration 0040
  if (!existing || has('icon')) p.icon = emojiIcon(b.icon, 'Icon');
  // Filled into the Meetings planner for every new meeting (same limits as a meeting's own fields).
  if (!existing || has('meetLocation')) p.meet_location = str(b.meetLocation, 200, 'Location');
  if (!existing || has('meetNote')) p.meet_note = str(b.meetNote, 1000, 'Description');
  if (has('meetQuestions')) { const l = meetQuestionTpls(b.meetQuestions); p.meet_questions = l.length ? JSON.stringify(l) : null; } // only when sent: needs migration 0033
  if (has('roundQuestions') && kind === 'series') { const l = roundQuestionTpls(b.roundQuestions); p.round_questions = l.length ? JSON.stringify(l) : null; } // only when sent: needs migration 0035
  if (has('autoMeetings')) p.auto_meetings = b.autoMeetings ? 1 : 0; // only when sent: needs migration 0036
  if (has('meetApply')) p.meet_apply = b.meetApply ? 1 : 0; // only when sent: needs migration 0039
  if (p.meet_apply && existing && p.meet_questions === undefined && jsonList(existing.meet_questions).some((x) => !x.id)) { // templates saved before they had ids
    const l = meetQuestionTpls(jsonList(existing.meet_questions)); p.meet_questions = l.length ? JSON.stringify(l) : null;
  }
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
  const qs = b.questions !== undefined ? presetQuestions(b.questions).map((q) => ({ ...q, at: t })) : []; // from a preset
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
  await insertInstance(env, p, seq, { ...(first || seriesFields(p, seq)), ...(qs.length ? { questions: JSON.stringify(qs) } : {}) }, true);
  return json({ id }, 201);
}

async function getPoll(request, env, ctx, url, id) {
  const poll = await loadPoll(env, id);
  const role = await roleOf(request, env, poll), caps = capsOf(role), admin = caps.see; // admin: organiser view (any role)
  if (!admin) await checkPassword(env, request, poll);
  // The owner opened a poll that was about to be deleted for being old: keep it (counts as activity).
  if (caps.own && poll.retention_warned_at) await env.DB.prepare('UPDATE polls SET retention_warned_at = NULL, updated_at = ? WHERE id = ?').bind(now(), id).run();
  if (caps.manage) await mergeEmailDupes(env, id, 3).catch((e) => console.error('dupes', e)); // one email = one person
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
    poll: publicPoll(poll, admin, caps.edit), isAdmin: admin, role, can: caps, emailEnabled: emailEnabled(env),
    instances: listed.map((i) => publicInstance(i, admin ? { responses: counts[i.id] || 0 } : {})),
    instance: publicInstance(sel), dates: datesOf(sel, poll),
  };
  // Answers the organiser put into a meeting's description (live; shown to everyone who sees the meeting, like the emails and .ics).
  await withAnswerTexts(env, poll, sel, out.instance);
  if (admin && poll.kind === 'series') {
    const n = Math.max(...all.map((i) => i.seq)) + 1;
    out.next = { startDate: periodStart(poll, n), endDate: periodEnd(poll, n), opens: openDate(poll, n) };
  }
  // Questions: options people suggested are always sent (labels only), so everyone can vote on them;
  // everyone's answers (form_answers) with the same visibility as the availability answers.
  const qs = questionsOf(sel), added = qs.length ? await addedOptions(env, sel.id) : new Map();
  if (qs.length) {
    out.form = { added: Object.fromEntries(added) };
    if (admin || !poll.hide_results) {
      const { results: fr } = await env.DB.prepare('SELECT f.id, f.participant_id, f.extra, f.updated_at, p.name FROM form_answers f JOIN participants p ON p.id = f.participant_id WHERE f.instance_id = ? ORDER BY f.created_at').bind(sel.id).all();
      out.form.rows = fr.map((r) => ({ id: r.id, pid: r.participant_id, name: r.name, extra: extraFor(r.extra, qs, added, admin), updatedAt: r.updated_at }));
    }
  }
  // The round before: its after-meeting questions about meetings that ended in the last 14 days (for the prompt on open).
  const prev = all.filter((i) => i.seq < sel.seq).pop();
  if (prev) {
    const pq = questionsOf(prev).filter(isAfter), pm = JSON.parse(prev.meetings || '[]'), since = Date.now() - 14 * 86400e3;
    const recent = pq.filter((q) => afterOccs(q, pm).some((o) => o.open >= since));
    if (recent.length) {
      const used = new Set(recent.flatMap((q) => afterOccs(q, pm).map((o) => o.m.id)));
      out.prevAfter = { iid: prev.id, seq: prev.seq, questions: recent, groups: groupsOf(prev).filter((g) => recent.some((q) => q.grp === g.id)),
        meetings: pm.filter((m) => used.has(m.id)) };
    }
  }
  if (admin || !poll.hide_results) {
    const { results } = await env.DB.prepare(`SELECT r.id, r.name, r.email, r.comment, r.entries, r.votes, r.updated_at, r.participant_id, ${AV_COLS} FROM responses r
      LEFT JOIN participants p ON p.id = r.participant_id LEFT JOIN users u ON u.id = p.user_id WHERE r.instance_id = ? ORDER BY r.created_at`).bind(sel.id).all();
    const props = proposedIds(sel), signedIn = !!userOf(request);
    out.responses = results.map((r) => ({ id: r.id, name: r.name, comment: r.comment, entries: JSON.parse(r.entries), updatedAt: r.updated_at,
      ...(caps.manage ? { email: r.email } : {}), ...(props.size ? { votes: parseVotes(r.votes, props) } : {}), ...avOut(r, signedIn) }));
    // My contact names for people (only where I may see their addresses anyway).
    if (caps.manage) { const cn = await contactNames(env, userOf(request), id, results); if (cn) out.cnames = cn; }
    // Names already used in this poll (any round), so people can pick themselves. Account answers are found by account instead.
    const { results: ps } = await env.DB.prepare('SELECT id, name FROM participants WHERE poll_id = ? AND user_id IS NULL ORDER BY name COLLATE NOCASE').bind(id).all();
    out.participants = ps;
    out.participantCount = await env.DB.prepare('SELECT COUNT(*) AS n FROM participants WHERE poll_id = ?').bind(id).first('n');
    if (!caps.edit) { // read-only People tab (everyone, and viewers): names, roles and whether they answered this round (no ids or emails)
      const { results: pp } = await env.DB.prepare(
        `SELECT p.name, p.user_id IS NOT NULL AS account, p.role, EXISTS (SELECT 1 FROM responses r WHERE r.participant_id = p.id AND r.instance_id = ?) AS answered,
           ${AV_COLS} FROM participants p LEFT JOIN users u ON u.id = p.user_id WHERE p.poll_id = ? ORDER BY p.name COLLATE NOCASE`).bind(sel.id, id).all();
      out.people = pp.map((p) => ({ name: p.name, account: !!p.account, answered: !!p.answered, ...(p.account && POLL_ROLES.includes(p.role) ? { role: p.role } : {}), ...avOut(p, signedIn) }));
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
  const person = user ? null : await personByKey(request, env, id);
  if (person) out.person = { pid: person.id, name: person.name, responseId: (await answerIn(env, person.id, sel.id)) || null };
  else if (!user && env.LINK_KEY && PKEY_RE.test(request.headers.get('x-person-key') || '')) { // old or wrong link
    const pid = request.headers.get('x-person-key').split('.')[0]; // that person has an account by now: they sign in instead
    out.person = (await env.DB.prepare('SELECT 1 FROM participants WHERE id = ? AND poll_id = ? AND user_id IS NOT NULL').bind(pid, id).first()) ? { signin: true } : { bad: true };
  }
  if (user) { // signed in: their answers are linked to the account
    const part = await accountParticipant(env, id, user.id);
    out.me = { name: part ? part.name : user.name, email: user.email, participantId: part ? part.id : null, shareBusy: !!(part && part.share_busy),
      responseId: part ? (await answerIn(env, part.id, sel.id)) || null : null };
    // Invited-only polls: in the poll as this account, or invited as a guest with this account's email (linked on first answer).
    if (poll.invited_only) out.me.invited = !!part || !!(await env.DB.prepare('SELECT 1 FROM participants WHERE poll_id = ? AND user_id IS NULL AND LOWER(email) = ? LIMIT 1').bind(id, user.email.toLowerCase()).first());
    const nt = await ntFor(env, poll, user.id); // notification settings for this poll (the bell)
    if (nt && nt.member) out.me.notify = ntOut(nt);
    const can = !!poll.allow_comments && (admin || !poll.invited_only || out.me.invited); // chat: everyone signed in, or the invited
    out.chat = { can, off: !poll.allow_comments, unread: can ? (await chatUnread(env, id, user.id)) || 0 : 0 };
    if (can && nt && nt.prefs.chat.p === 'off') out.chat.muted = true;
    if (out.chat.unread) out.chat.mentions = (await chatUnread(env, id, user.id, true)) || 0; // unread messages that tag me
    out.chat.read = can;
    if (can) Object.assign(out.chat, await chatPeekInfo(env, id, user));
  } else { // guests read along (invited-only polls: through their personal link); writing needs an account
    const read = await chatReadable(request, env, poll);
    out.chat = { can: false, read, off: !poll.allow_comments };
    if (read) Object.assign(out.chat, await chatPeekInfo(env, id, null));
  }
  return json(out);
}

// Header peek (newest message) and message counts per day / meeting thread. user = null for guests: no email-based name.
async function chatPeekInfo(env, id, user) {
  const [last, refs] = await env.DB.batch([
    env.DB.prepare(`SELECT m.body, m.created_at, m.user_id, u.name, u.email, (SELECT p.name FROM participants p WHERE p.poll_id = m.poll_id AND p.user_id = m.user_id LIMIT 1) AS pname
      FROM messages m LEFT JOIN users u ON u.id = m.user_id WHERE m.poll_id = ? ORDER BY m.created_at DESC LIMIT 1`).bind(id),
    env.DB.prepare('SELECT ref, COUNT(*) AS n FROM messages WHERE poll_id = ? AND ref IS NOT NULL GROUP BY ref').bind(id),
  ]);
  const out = { refs: Object.fromEntries(refs.results.map((r) => [r.ref, r.n])) }, l = last.results[0];
  if (l) out.last = { name: l.name || (user ? (l.email || '').split('@')[0] : l.pname) || '?', body: l.body.slice(0, 120), at: l.created_at, mine: !!user && l.user_id === user.id };
  return out;
}

async function updatePoll(request, env, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, env, poll, 'manage');
  const b = await body(request);
  const p = readPollSettings(b, poll);
  if (b.password !== undefined) p.password_hash = b.password ? await sha256(id + ':pw:' + str(b.password, 100, 'Password')) : null;
  if (request.headers.get('x-lang')) p.lang = reqLang(request);
  p.updated_at = now();
  const cols = Object.keys(p);
  await env.DB.prepare(`UPDATE polls SET ${cols.map((c) => c + ' = ?').join(', ')} WHERE id = ?`).bind(...cols.map((c) => p[c]), id).run();
  if (p.round_questions !== undefined) await addNewRoundQuestions(env, poll, p.round_questions);
  const np = { ...poll, ...p };
  const mOld = poll.meet_apply ? poll : { meet_location: '', meet_note: '' }; // just switched on: fill only meetings without their own
  if (np.auto_meetings && ['auto_meetings', 'hour_start', 'hour_end', 'day_pattern', 'answer_mode'].some((c) => p[c] !== undefined && p[c] !== poll[c])) await resyncAutoMeetings(env, np, mOld);
  else if (np.meet_apply && ['meet_apply', 'meet_location', 'meet_note', 'meet_questions'].some((c) => p[c] !== undefined && p[c] !== poll[c])) await syncMeetDefaults(env, np, mOld);
  return json({ ok: true });
}
// Auto meetings follow the poll's times in its open rounds (closed ones keep theirs).
async function resyncAutoMeetings(env, poll, old = poll) {
  const { results } = await env.DB.prepare('SELECT * FROM instances WHERE poll_id = ? ORDER BY seq DESC LIMIT 3').bind(poll.id).all();
  for (const inst of results || []) {
    if (effStatus(inst) !== 'open') continue;
    const m = JSON.stringify(syncAutoMeetings(poll, inst));
    if (m !== inst.meetings) await env.DB.prepare('UPDATE instances SET meetings = ? WHERE id = ? AND meetings = ?').bind(m, inst.id, inst.meetings).run();
    if (poll.meet_apply) await storeMeetDefaults(env, poll, old, { ...inst, meetings: m });
  }
}
// Every-round questions that were just added to the list are asked in the current round too, if it's open (edits count from the next round).
async function addNewRoundQuestions(env, poll, list) {
  const old = new Set(jsonList(poll.round_questions).map((x) => x.id)), fresh = jsonList(list).filter((x) => !old.has(x.id));
  if (!fresh.length) return;
  const inst = await env.DB.prepare('SELECT * FROM instances WHERE poll_id = ? ORDER BY seq DESC LIMIT 1').bind(poll.id).first();
  if (!inst || effStatus(inst) !== 'open') return;
  const items = itemsOf(inst), add = roundQuestionCopies(fresh, items);
  if (add.length) await env.DB.prepare('UPDATE instances SET questions = ? WHERE id = ? AND questions IS ?').bind(JSON.stringify([...items, ...add]), inst.id, inst.questions).run();
}

// The poll's picture. <img> can't send headers, so a password travels as ?pw= (like calendar.ics).
async function pollImage(request, env, url, id) {
  const poll = await env.DB.prepare('SELECT id, owner_id, password_hash, image FROM polls WHERE id = ?').bind(id).first();
  if (!poll || !poll.image) throw new HttpError(404, 'No picture');
  if (!(await isAdmin(request, env, poll)) && !(await guardedPasswordOk(env, request, poll, url.searchParams.get('pw')))) throw new HttpError(401, 'Password required');
  const m = poll.image.match(/^data:(image\/(?:webp|jpeg|png));base64,(.+)$/);
  if (!m) throw new HttpError(404, 'No picture');
  const bytes = Uint8Array.from(atob(m[2]), (c) => c.charCodeAt(0));
  return new Response(bytes, { headers: { 'content-type': m[1], 'cache-control': 'private, max-age=31536000, immutable' } });
}

async function deletePoll(request, env, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, env, poll, 'own');
  await env.DB.batch(pollDeleteStmts(env, id));
  return json({ ok: true });
}
// Everything stored for one poll (answers, people, rounds, chat, shared busy hours), poll row last.
const pollDeleteStmts = (env, id) => ['responses', 'form_answers', 'participants', 'instances', 'messages', 'chat_reads', 'shared_busy', 'poll_groups', 'answer_watch', 'poll_events', 'poll_hidden']
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
       AND NOT EXISTS (SELECT 1 FROM form_answers f WHERE f.poll_id = p.id AND f.updated_at >= ?1)
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
    html: emailHtml(mailBlocks({ title: subject, icon: poll.icon,
      intro: de ? `In deiner Umfrage „${poll.title}“ ist seit ${months} Monaten nichts mehr passiert. Damit keine alten Daten liegen bleiben, löschen wir sie am ${day} mit allen Antworten und Nachrichten.`
        : `Nothing has happened in your poll “${poll.title}” for ${months} months. So old data doesn't pile up, we'll delete it on ${day}, with all its answers and messages.`,
      after: de ? 'Willst du sie behalten? Öffne sie einfach, während du angemeldet bist. Wenn du nichts tust, wird sie gelöscht.'
        : "Want to keep it? Just open it while signed in. If you do nothing, it will be deleted.",
      button: { href: link, label: de ? 'Umfrage behalten' : 'Keep my poll' }, orLink: de ? 'Oder öffne diesen Link:' : 'Or open this link:' }),
      { preheader: subject, site, lang: langOf(poll.lang) }),
  });
}

// ---------- instances ----------
async function createNextInstance(request, env, ctx, url, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, env, poll, 'edit');
  if (poll.kind !== 'series') throw new HttpError(400, 'Only recurring series have a next poll');
  const last = await env.DB.prepare('SELECT MAX(seq) AS s FROM instances WHERE poll_id = ?').bind(id).first('s');
  const n = last == null ? currentSeq(poll) : last + 1;
  const inst = await insertInstance(env, poll, n, seriesFields(poll, n), false);
  if (!inst) throw new HttpError(409, 'That poll already exists');
  ctx.waitUntil(notifyOpened(env, poll, inst, url.origin).catch((e) => console.error(e)));
  return json({ ok: true, id: inst.id }, 201);
}

async function updateInstance(request, env, ctx, id, iid) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, env, poll, 'edit');
  const inst = await loadInstance(env, id, iid);
  const b = await body(request), u = {}, has = (k) => b[k] !== undefined;
  if (has('status')) { if (!['open', 'closed'].includes(b.status)) throw new HttpError(400, 'Invalid status'); u.status = b.status; }
  if (has('note')) u.note = str(b.note, 1000, 'Note');
  if (has('deadline')) { if (b.deadline && !isDate(b.deadline)) throw new HttpError(400, 'Invalid reply-by date'); u.deadline = b.deadline || null; u.reminded = 0; u.q_reminded = 0; }
  if ((has('startDate') || has('endDate')) && poll.kind !== 'weekly') {
    const s = b.startDate ?? inst.start_date, e = b.endDate ?? inst.end_date;
    checkRange(s, e); u.start_date = s; u.end_date = e;
  }
  if (has('meetings')) u.meetings = JSON.stringify(validateMeetings(b.meetings, poll, JSON.parse(inst.meetings || '[]')));
  if (has('questions')) {
    const { results: ps } = await env.DB.prepare('SELECT id FROM participants WHERE poll_id = ?').bind(id).all();
    const qs = validateQuestions(b.questions, u.meetings ? JSON.parse(u.meetings) : JSON.parse(inst.meetings || '[]'), itemsOf(inst), new Set(ps.map((p) => p.id)));
    u.questions = qs.length ? JSON.stringify(qs) : null;
  }
  const cols = Object.keys(u);
  if (cols.length) await env.DB.prepare(`UPDATE instances SET ${cols.map((c) => c + ' = ?').join(', ')} WHERE id = ?`).bind(...cols.map((c) => u[c]), iid).run();
  // Notifications: meetings set / proposed / changed / cancelled, questions added, the round closed or reopened.
  const actor = (userOf(request) || {}).id, evs = [];
  if (u.meetings) evs.push(...meetingEvents(JSON.parse(inst.meetings || '[]'), JSON.parse(u.meetings)));
  if (u.questions !== undefined) {
    const was = new Set(questionsOf(inst).map((q) => q.id)), added = (u.questions ? JSON.parse(u.questions) : []).filter((q) => q.type !== 'group' && !was.has(q.id));
    if (added.length) evs.push({ kind: 'question_added', name: added.slice(0, 3).map((q) => roundText(q.label, poll, inst)).join(' · ') + (added.length > 3 ? ' …' : '') });
  }
  if (u.status && u.status !== effStatus(inst)) evs.push({ kind: u.status === 'closed' ? 'poll_closed' : 'poll_reopened' });
  for (const ev of evs) fireEvent(ctx, env, poll, { ...ev, iid, actor });
  if (u.meetings && poll.meet_apply) await storeMeetDefaults(env, poll, poll, await loadInstance(env, id, iid)); // new meetings get the default questions
  const fresh = await loadInstance(env, id, iid);
  return json({ ok: true, instance: await withAnswerTexts(env, poll, fresh, publicInstance(fresh)) });
}

async function deleteInstance(request, env, id, iid) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, env, poll, 'manage');
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
function meetingToIcs(mt, poll, link, texts) {
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
  lines.push(`DESCRIPTION:${icsEscape(meetingDescText(poll, mt, texts && texts.get(mt.id), { link }))}`, 'END:VEVENT');
  return lines;
}
function buildIcs(poll, meetings, link, texts) {
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//when-who//EN', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
    `X-WR-CALNAME:${icsEscape(poll.title)}`, ...meetings.flatMap((mt) => meetingToIcs(mt, poll, link, texts)), 'END:VCALENDAR'];
  return lines.map(icsFold).join('\r\n') + '\r\n';
}
const whoText = (mt) => (mt.participants === 'all' ? 'Everyone' : mt.participants.map((p) => p.name).join(', '));
// Plain-text sections for meeting descriptions (.ics, emails): "📝 Description" header line, then the body.
const ANS_ICON = { y: '✅', i: '🟡', m: '🤔', n: '❌' };
const bullet = (x) => '• ' + String(x).replace(/\n/g, '\n  ');
const descSection = (icon, label, body) => (body ? `${icon} ${label}\n${body}` : '');
// The whole description of a meeting: poll description + meeting notes, participants, the answers (ans, from
// meetingAnswerText) and the poll link. pollDesc: false leaves the poll's description out (emails listing several meetings).
function meetingDescText(poll, mt, ans, { link, pollDesc = true } = {}) {
  const L = ANS_L[poll.lang === 'de' ? 'de' : 'en'];
  const desc = [pollDesc && poll.description, mt.note, mt.extra].map((x) => (x || '').trim()).filter(Boolean).join('\n\n');
  const who = mt.participants === 'all' ? `${L.who}\n• ${L.all}`
    : `${L.who} (${mt.participants.length})\n${mt.participants.map((p) => bullet(p.name)).join('\n')}`;
  return [descSection('📝', L.desc, desc), `👥 ${who}`, ans, link && `🔗 ${L.poll}: ${link}`].filter(Boolean).join('\n\n');
}
// The same description as mailBlocks sections ({ label, body }) for HTML emails; the poll link is left out (the email has a button).
function meetingSections(poll, mt, ans, { pollDesc = true } = {}) {
  const L = ANS_L[poll.lang === 'de' ? 'de' : 'en'];
  const desc = [pollDesc && poll.description, mt.note, mt.extra].map((x) => (x || '').trim()).filter(Boolean).join('\n\n');
  const who = mt.participants === 'all' ? { label: `👥 ${L.who}`, body: L.all }
    : { label: `👥 ${L.who} (${mt.participants.length})`, body: mt.participants.map((p) => p.name).join(', ') };
  const answers = (ans || '').split('\n\n').filter(Boolean).map((b) => { const i = b.indexOf('\n'); return i < 0 ? { body: b } : { label: b.slice(0, i), body: b.slice(i + 1) }; });
  return [desc && { label: `📝 ${L.desc}`, body: desc }, who, ...answers].filter(Boolean);
}
// ---- answers in a meeting's description (mt.inc), rendered live from the round's answers ----
// The data one round needs: availability answers and form answers (with names), options people added.
async function answerData(env, inst) {
  const [{ results: responses }, { results: forms }] = await Promise.all([
    env.DB.prepare('SELECT id, name, comment, entries FROM responses WHERE instance_id = ? ORDER BY created_at').bind(inst.id).all(),
    env.DB.prepare('SELECT f.extra, p.name FROM form_answers f JOIN participants p ON p.id = f.participant_id WHERE f.instance_id = ? ORDER BY f.created_at').bind(inst.id).all(),
  ]);
  const added = new Map();
  for (const f of forms) for (const [qid, list] of Object.entries(parseExtra(f.extra).add || {}))
    if (Array.isArray(list)) added.set(qid, [...(added.get(qid) || []), ...list.filter((o) => o && typeof o.id === 'string' && typeof o.label === 'string')]);
  return { responses: responses.map((r) => ({ ...r, entries: (() => { try { return JSON.parse(r.entries || '{}'); } catch { return {}; } })() })),
    forms: forms.map((f) => ({ name: f.name, a: parseExtra(f.extra).a || {} })), added };
}
const ANS_L = {
  en: { y: 'Coming', i: 'If needed', m: 'Maybe', n: 'Can’t', comments: 'Comments', yes: 'Yes', no: 'No', none: 'No answers yet',
    desc: 'Description', who: 'Participants', votes: 'Votes', all: 'Everyone', poll: 'Poll' },
  de: { y: 'Dabei', i: 'Wenn nötig', m: 'Vielleicht', n: 'Kann nicht', comments: 'Kommentare', yes: 'Ja', no: 'Nein', none: 'Noch keine Antworten',
    desc: 'Beschreibung', who: 'Teilnehmende', votes: 'Abstimmung', all: 'Alle', poll: 'Umfrage' },
};
// A person's state for the meeting: y / i / m / n (worst over its hours and days; nothing marked = n).
function meetState(entries, mt) {
  const rank = { n: 0, m: 1, i: 2, y: 3 }, days = [];
  for (let d = mt.date, k = 0; k < MAX_MEETING_DAYS && d <= (mt.endDate || mt.date); d = addDays(d, 1), k++) days.push(d);
  let worst = 'y';
  for (const d of days) {
    const v = entries[d];
    let st = 'n';
    if (typeof v === 'string') st = rank[v] != null ? v : 'n';
    else if (v && typeof v === 'object') {
      const at = (h) => (['y', 'i', 'm'].find((s) => (v[s] || []).includes(h)) || 'n');
      if (mt.allDay) st = ['y', 'i', 'm'].find((s) => (v[s] || []).length) || 'n';
      else { st = 'y'; for (let h = mt.start; h < mt.end; h++) { const x = at(h); if (rank[x] < rank[st]) st = x; } }
    }
    if (rank[st] < rank[worst]) worst = st;
  }
  return worst;
}
// The date whose answer a per-date question ({ "YYYY-MM-DD": value }) shows: the meeting's, or the next one of a repeating meeting.
function answerDate(vals) {
  const ks = Object.keys(vals || {}).filter(isDate).sort(), today = now().slice(0, 10);
  return ks.find((k) => k >= today) || ks[ks.length - 1];
}
function answerValueText(q, v, opts, L) {
  if (Q_CHOICE.has(q.type)) return (Array.isArray(v) ? v : []).map((o) => opts.get(o)).filter(Boolean).join(', ');
  if (q.type === 'rating') return `${v} / ${q.rating?.max || 5}`;
  if (q.type === 'yesno') return v && typeof v === 'object' ? (v.y ? L.yes : L.no) + (v.y && v.n != null ? ` (${v.n})` : '') : '';
  return typeof v === 'string' ? v : '';
}
// The text that mt.inc adds to the meeting's description ('' = nothing).
function meetingAnswerText(poll, inst, mt, data) {
  const inc = mt.inc;
  if (!inc || mt.proposed || !data) return '';
  const L = ANS_L[poll.lang === 'de' ? 'de' : 'en'], out = [];
  if (inc.who) {
    const rs = mt.participants === 'all' ? data.responses : data.responses.filter((r) => mt.participants.some((p) => p.id === r.id));
    const by = { y: [], i: [], m: [], n: [] };
    for (const r of rs) by[meetState(r.entries, mt)].push(r.name);
    const lines = ['y', 'i', 'm', 'n'].filter((s) => by[s].length).map((s) => `• ${ANS_ICON[s]} ${L[s]} (${by[s].length}): ${by[s].join(', ')}`);
    if (lines.length) out.push(descSection('🗳', L.votes, lines.join('\n')));
  }
  const qs = new Map(questionsOf(inst).map((q) => [q.id, q]));
  for (const pick of inc.qs || []) {
    const q = qs.get(pick.id);
    if (!q || isAfter(q)) continue;
    const opts = new Map([...(q.options || []), ...(data.added.get(q.id) || [])].map((o) => [o.id, o.label]));
    const vals = data.forms.map((f) => {
      let v = f.a[q.id];
      if (q.link.each && v && typeof v === 'object' && !Array.isArray(v) && !('y' in v)) v = v[answerDate(v)];
      return { name: f.name, v };
    }).filter((x) => x.v !== undefined && x.v !== null && x.v !== '' && !(Array.isArray(x.v) && !x.v.length));
    let body;
    if (!vals.length) body = [L.none];
    else if (pick.each) body = vals.map((x) => `${x.name}: ${answerValueText(q, x.v, opts, L)}`);
    else if (Q_CHOICE.has(q.type)) {
      const n = new Map();
      for (const x of vals) for (const o of Array.isArray(x.v) ? x.v : []) n.set(o, (n.get(o) || 0) + 1);
      body = [...opts].filter(([id]) => n.get(id)).sort((a, b) => n.get(b[0]) - n.get(a[0])).map(([id, label]) => `${label}: ${n.get(id)}`);
    } else if (q.type === 'rating') {
      const ns = vals.map((x) => +x.v).filter((x) => x > 0);
      body = [`Ø ${(ns.reduce((s, x) => s + x, 0) / ns.length).toFixed(1)} / ${q.rating?.max || 5} (${ns.length})`];
    } else if (q.type === 'yesno') {
      const yes = vals.filter((x) => x.v && x.v.y), sum = yes.reduce((s, x) => s + (+x.v.n || 0), 0);
      body = [`${L.yes}: ${yes.length}`, `${L.no}: ${vals.length - yes.length}`, q.count && sum ? `${q.count.label || '#'}: ${sum}` : ''];
    } else body = vals.map((x) => answerValueText(q, x.v, opts, L));
    out.push(descSection('❓', roundText(q.label, poll, inst).replace(/:$/, ''), body.filter(Boolean).map(bullet).join('\n')));
  }
  if (inc.comments) {
    const rs = mt.participants === 'all' ? data.responses : data.responses.filter((r) => mt.participants.some((p) => p.id === r.id));
    const cs = rs.filter((r) => (r.comment || '').trim());
    if (cs.length) out.push(descSection('💬', L.comments, cs.map((r) => bullet(`${r.name}: ${r.comment.trim()}`)).join('\n')));
  }
  const text = out.join('\n\n');
  return text.length > 4000 ? text.slice(0, 3999) + '…' : text;
}
// Adds answersText to the meetings of pub (= publicInstance(inst)) that include answers.
async function withAnswerTexts(env, poll, inst, pub) {
  if (!pub.meetings.some((m) => m.inc && !m.proposed)) return pub;
  const data = await answerData(env, inst);
  for (const m of pub.meetings) { const t = meetingAnswerText(poll, inst, m, data); if (t) m.answersText = t; }
  return pub;
}
// Map meeting id → answers text, for the confirmed meetings with inc in these instance rows (only those rounds are read).
async function meetingAnswerTexts(env, poll, insts) {
  const texts = new Map();
  for (const inst of insts) {
    const ms = JSON.parse(inst.meetings || '[]').filter((m) => m.inc && !m.proposed);
    if (!ms.length) continue;
    const data = await answerData(env, inst);
    for (const m of ms) { const t = meetingAnswerText(poll, inst, m, data); if (t) texts.set(m.id, t); }
  }
  return texts;
}
async function calendar(request, env, url, id) {
  const poll = await loadPoll(env, id);
  if (!(await guardedPasswordOk(env, request, poll, url.searchParams.get('pw')))) throw new HttpError(401, 'Password required');
  const { results } = await env.DB.prepare('SELECT id, meetings, questions FROM instances WHERE poll_id = ? ORDER BY seq').bind(id).all();
  let meetings = results.flatMap((i) => JSON.parse(i.meetings || '[]')).filter((mt) => !mt.proposed);
  const only = url.searchParams.get('m');
  if (only) meetings = meetings.filter((mt) => mt.id === only);
  const texts = await meetingAnswerTexts(env, poll, only ? results.filter((i) => JSON.parse(i.meetings || '[]').some((mt) => mt.id === only)) : results);
  const name = (only ? `${meetings[0]?.title || poll.title} ${meetings[0] ? meetingStart(meetings[0]) : ''}` : poll.title).replace(/[^\w\- ]+/g, '').trim() || 'meetings';
  return new Response(buildIcs(poll, meetings, `${url.origin}/?p=${poll.id}`, texts), {
    headers: { 'content-type': 'text/calendar; charset=utf-8', 'content-disposition': `${url.searchParams.get('download') ? 'attachment' : 'inline'}; filename="${name}.ics"`, 'cache-control': 'no-cache' },
  });
}

// ---------- email (optional: Resend, https://resend.com/docs/api-reference/emails/send-email) ----------
const emailEnabled = (env) => !!(env.RESEND_API_KEY && env.MAIL_FROM);
const headerSafe = (s) => String(s || '').replace(/[\r\n<>"\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60);
const b64 = (bytes) => { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(s); };
// One message: { fromName, to: [..], bcc?: [..], replyTo?, subject, text, html, attachments?: [{ content: Uint8Array, filename }] }
// Sender: "Anna via when-who" <MAIL_FROM>, so a person's name next to our address doesn't look like spoofing (spam filters, e.g. GMX).
const fromHeader = (env, name) => { const n = headerSafe(name); return `"${!n || n === 'when-who' ? 'when-who' : n + ' via when-who'}" <${env.MAIL_FROM}>`; };
// List-Unsubscribe (RFC 2369) for emails sent to many people (invites, reminders, digests): `unsub` = mailto address or https URL(s).
const unsubHeaders = (unsub) => {
  const v = [].concat(unsub || []).filter(Boolean).map((u) => /^https?:/.test(u) ? `<${u}>` : `<mailto:${u}?subject=unsubscribe>`);
  return v.length ? { headers: { 'List-Unsubscribe': v.join(', ').replace(/[\r\n]/g, '') } } : {};
};
async function sendEmail(env, m) {
  const payload = {
    from: fromHeader(env, m.fromName),
    to: m.to, subject: String(m.subject).replace(/[\r\n]+/g, ' ').slice(0, 200), text: m.text, html: m.html,
    ...(m.bcc && m.bcc.length ? { bcc: m.bcc } : {}),
    ...(m.replyTo ? { reply_to: m.replyTo } : {}),
    ...unsubHeaders(m.unsub),
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
// Several different messages in one Resend call (POST /emails/batch, max 100 each): one subrequest instead of one per person.
async function sendEmailBatch(env, msgs) {
  for (let i = 0; i < msgs.length; i += 100) {
    const payload = msgs.slice(i, i + 100).map((m) => ({
      from: fromHeader(env, m.fromName),
      to: m.to, subject: String(m.subject).replace(/[\r\n]+/g, ' ').slice(0, 200), text: m.text, html: m.html,
      ...(m.replyTo ? { reply_to: m.replyTo } : {}),
      ...unsubHeaders(m.unsub),
    }));
    const r = await fetch((env.RESEND_API_URL || 'https://api.resend.com') + '/emails/batch', {
      method: 'POST',
      headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (r.ok) continue;
    const detail = await r.text().catch(() => '');
    console.error('resend batch', r.status, detail.slice(0, 300));
    if (r.status === 429) throw new HttpError(503, 'The site’s email limit is reached for now. Try again later (or tomorrow).');
    throw new HttpError(502, 'The email couldn’t be sent. Try again later.');
  }
}
const escRe = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Personal links for the guest rows among `rows` (participantRows shape): Map email -> link. Empty without LINK_KEY.
async function personalLinks(env, poll, rows) {
  const out = new Map(), base = siteUrl(env, '');
  if (!env.LINK_KEY || !base) return out;
  for (const p of rows) {
    const e = (p.mail_to || '').toLowerCase();
    if (!p.user_id && EMAIL_RE.test(e) && !out.has(e)) out.set(e, await personalLink(env, base, poll.id, p));
  }
  return out;
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
// The designed email body (inside emailHtml's frame), the same look for every email. Everything is plain text and escaped here.
//   title (+ icon), intro (string or list of paragraphs), facts [[label, value, href?]], boxes [{ label, body, tone: 'note' | 'info' }],
//   sections [{ label, body }] (small heading + text), cards [{ title, facts, sections }] (one per meeting), after (paragraphs after
//   the cards), button { href, label } (+ orLink: "Or open this link:" with the address), foot (grey small print at the bottom).
const mailP = (s, extra = '') => `<p style="margin:0 0 16px;color:#334155${extra}">${linkify(escHtml(s))}</p>`;
function mailFacts(facts) {
  if (!facts || !facts.length) return '';
  return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 20px">${facts.map(([k, v, href]) =>
    `<tr><td style="padding:2px 12px 2px 0;color:#5B6578;white-space:nowrap;vertical-align:top">${escHtml(k)}</td><td style="padding:2px 0;font-weight:600;color:#0F172A">${
      href ? `<a href="${escHtml(href)}" style="color:#1F5EFF;text-decoration:none">${escHtml(v)}</a>` : escHtml(v)}</td></tr>`).join('')}</table>`;
}
const mailBox = (label, body, tone = 'info') => {
  const [bg, border] = tone === 'note' ? ['#F1F5F9', '#94A3B8'] : ['#E8EFFF', '#1F5EFF'];
  return `<div style="margin:0 0 20px;padding:14px 16px;background:${bg};border-left:3px solid ${border};border-radius:8px">
    ${label ? `<div style="margin:0 0 4px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.4px;color:#5B6578">${escHtml(label)}</div>` : ''}
    <div style="white-space:pre-wrap;color:#0F172A">${linkify(escHtml(body))}</div></div>`;
};
const mailSection = ({ label, body }) => body ? `<div style="margin:0 0 16px">
    ${label ? `<div style="margin:0 0 4px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.4px;color:#5B6578">${escHtml(label)}</div>` : ''}
    <div style="white-space:pre-wrap;color:#0F172A">${linkify(escHtml(body))}</div></div>` : '';
const mailButton = (b) => `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 12px"><tr><td style="border-radius:8px;background:#1F5EFF">
      <a href="${escHtml(b.href)}" style="display:inline-block;padding:12px 22px;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:8px">${escHtml(b.label)}</a></td></tr></table>`;
function mailBlocks({ title, icon, intro, facts, boxes, sections, cards, after, button, orLink, foot }) {
  // Paragraphs; an { label, body, tone } item is drawn as a box.
  const paras = (x) => (Array.isArray(x) ? x : [x]).filter(Boolean).map((s) => (typeof s === 'object' ? mailBox(s.label, s.body, s.tone) : mailP(s))).join('');
  const card = (c) => `<div style="margin:0 0 16px;padding:16px 18px;border:1px solid #E2E8F0;border-radius:10px">
    ${c.title ? `<div style="margin:0 0 8px;font-size:17px;font-weight:700;color:#0B1F3A">${c.href ? `<a href="${escHtml(c.href)}" style="color:#0B1F3A">${escHtml(c.title)}</a>` : escHtml(c.title)}</div>` : ''}
    ${mailFacts(c.facts).replace('margin:0 0 20px', 'margin:0 0 12px')}${(c.sections || []).map(mailSection).join('')}</div>`;
  return [
    title ? `<h1 style="margin:0 0 12px;font-size:22px;line-height:1.3;color:#0B1F3A">${icon ? escHtml(icon) + ' ' : ''}${escHtml(title)}</h1>` : '',
    intro ? paras(intro) : '',
    mailFacts(facts),
    (boxes || []).filter((b) => b && b.body).map((b) => mailBox(b.label, b.body, b.tone)).join(''),
    (sections || []).map(mailSection).join(''),
    (cards || []).map(card).join(''),
    after ? paras(after) : '',
    button ? mailButton(button) : '',
    button && orLink ? `<p style="margin:0 0 24px;font-size:13px;color:#5B6578">${escHtml(orLink)} ${linkify(escHtml(button.href))}</p>` : button ? '<div style="height:12px"></div>' : '',
    foot ? `<p style="margin:0;padding-top:16px;border-top:1px solid #E2E8F0;font-size:13px;color:#5B6578;white-space:pre-wrap">${linkify(escHtml(foot))}</p>` : '',
  ].join('\n');
}
// The footer text of a plain-text email ("\n\n—\n…") without its dash, for mailBlocks' foot.
const footOf = (s) => String(s || '').replace(/^\s*—\s*/, '');
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
// Question text may name the round: {month} (the round's first month) and {dates} (its period). German aliases {monat} / {zeitraum}.
// Stored raw, so a series copies the placeholders into every new round; filled in wherever the text is shown.
const ROUND_TOK_RE = /\{(month|monat|dates|zeitraum)\}/gi;
function roundText(s, poll, inst) {
  if (!s || !inst || !inst.start_date || !s.includes('{')) return s;
  return s.replace(ROUND_TOK_RE, (_, k) => (/^(month|monat)$/i.test(k)
    ? new Date(inst.start_date + 'T00:00:00Z').toLocaleDateString(LOCALE[langOf(poll.lang)], { month: 'long', timeZone: 'UTC' })
    : periodText(poll, inst)));
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
// `html` (optional): the email's own body HTML (already escaped); without it the text is shown with an Open poll button on top.
// `links` (optional, Map email -> personal link, see personalLinks): those people get a message of their own in which the
// poll's plain link (`${site}/?p=<id>`) is their personal one, sent in one Resend batch call; everyone gets a message of their own (BCC only with attachments).
async function sendMail(env, poll, { to, subject, text, html: bodyHtml, attachments, quota = false, fromName, replyTo, links }) {
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
  const pollLink = bodyHtml ? null : (text.match(/https?:\/\/[^\s]+\?p=[^\s]+/) || [])[0];
  const html = emailHtml(bodyHtml || `<div style="white-space:pre-wrap">${linkify(escHtml(text))}</div>`, {
    preheader: subject, button: pollLink ? { href: pollLink, label: poll.lang === 'de' ? 'Umfrage öffnen' : 'Open poll' } : null,
    site: siteUrl(env, ''), lang: langOf(poll.lang),
  });
  const unsub = reply || env.CONTACT_EMAIL || '';
  const base = { fromName: sender, subject, ...(reply ? { replyTo: reply } : {}), unsub };
  // Emails with an attachment (.ics) can't go through the batch API: those still go as BCC, max 50 recipients per message.
  if (attachments) {
    let sent = 0;
    for (let i = 0; i < list.length; i += 49) {
      const bcc = list.slice(i, i + 49);
      const to = (ownerMail || env.MAIL_FROM).toLowerCase();
      await sendEmail(env, { ...base, to: [to], bcc: bcc.filter((e) => e !== to), text, html, attachments });
      sent += bcc.length;
    }
    return sent;
  }
  // Everything else: one message per person (their own To, personal link when they have one) in Resend batch calls,
  // since mass BCC mail lands in spam more often. The organiser gets one copy with the plain link.
  const plain = new RegExp(escRe(`${siteUrl(env, '')}/?p=${poll.id}`) + '(?![\\w#&])', 'g');
  const html0 = links && links.size ? emailHtml(bodyHtml || `<div style="white-space:pre-wrap">${linkify(escHtml(text))}</div>`, {
    preheader: subject, button: pollLink ? { href: '\u0000', label: poll.lang === 'de' ? 'Umfrage öffnen' : 'Open poll' } : null,
    site: siteUrl(env, ''), lang: langOf(poll.lang),
  }) : null;
  const msgs = list.map((e) => {
    const link = links && links.get(e);
    if (!link) return { ...base, to: [e], text, html };
    const put = (x) => x.replace(plain, () => link);
    return { ...base, to: [e], text: put(text), html: put(html0).replace('\u0000', escHtml(link)) };
  });
  const om = ownerMail.toLowerCase();
  if (om && list.length && !list.includes(om)) msgs.push({ ...base, to: [om], text, html });
  if (msgs.length) await sendEmailBatch(env, msgs);
  return list.length;
}
const footer = (poll) => poll.lang === 'de'
  ? `\n\n—\nDu bekommst diese E-Mail, weil du in der Umfrage „${poll.title}“ deine E-Mail-Adresse angegeben hast. Um keine E-Mails mehr zu bekommen, öffne die Umfrage und entferne deine E-Mail-Adresse aus deiner Antwort.`
  : `\n\n—\nYou're getting this because you left your email address in the poll “${poll.title}”. To stop these emails, open the poll and remove your email from your answer.`;
const seriesFooter = (poll) => poll.lang === 'de'
  ? `\n\n—\nDu bekommst diese E-Mail, weil du an der Umfrage „${poll.title}“ teilnimmst. Um keine E-Mails mehr zu bekommen, entferne deine E-Mail-Adresse aus deiner Antwort in der Umfrage oder antworte auf diese E-Mail und bitte die Organisatorin oder den Organisator, dich von der Liste zu nehmen.`
  : `\n\n—\nYou're getting this because you're a participant in the poll “${poll.title}”. To stop these emails, remove your email from your answer in the poll, or reply to ask the organiser to take you off the list.`;

async function sendInvite(request, env, url, id, iid, mid) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, env, poll, 'manage');
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
  const ans = mt.inc ? meetingAnswerText(poll, inst, mt, await answerData(env, inst)) : '', texts = new Map(ans ? [[mt.id, ans]] : []);
  const text = [`${mt.title || poll.title}`, '', `${L.when}: ${when}`, mt.location ? `${L.where}: ${mt.location}\n${L.map}: https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(mt.location)}` : null,
    '', meetingDescText(poll, mt, ans, { link }), '', L.ics].filter((x) => x !== null).join('\n') + footer(poll);
  const mapUrl = (q) => `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(q)}`;
  const html = mailBlocks({ title: mt.title || poll.title, icon: poll.icon,
    facts: [[L.when, when], mt.location && [L.where, mt.location, mapUrl(mt.location)]].filter(Boolean),
    sections: meetingSections(poll, mt, ans), after: L.ics,
    button: { href: link, label: de ? 'Umfrage öffnen' : 'Open poll' }, foot: footOf(footer(poll)) });
  const ics = buildIcs(poll, [mt], link, texts);
  const sent = await sendMail(env, poll, { to: withMail.map((r) => r.email), subject: `${mt.title || poll.title}: ${when}`, text, html,
    attachments: [{ content: enc.encode(ics), filename: 'invite.ics', type: 'text/calendar', disposition: 'attachment' }], quota: true });
  mt.sentAt = now();
  await env.DB.prepare('UPDATE instances SET meetings = ? WHERE id = ?').bind(JSON.stringify(meetings), iid).run();
  return json({ ok: true, sent, missing: invited.filter((r) => !r.email).map((r) => r.name) });
}

// "Email all meetings": every meeting of the poll (all rounds) in one email to the people the owner picks,
// with the .ics of all of them attached and the subscription link. Body: { ids: [participantId], emails: [address], message? }.
async function sendAllMeetings(request, env, url, id) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, env, poll, 'manage');
  await adoptLang(request, env, poll);
  const b = await body(request);
  const message = str(b.message, 1000, 'Message');
  const ids = Array.isArray(b.ids) ? b.ids.filter((x) => typeof x === 'string' && ID_RE.test(x)) : [];
  const extra = Array.isArray(b.emails) ? b.emails.filter((x) => typeof x === 'string').map((x) => x.trim().toLowerCase()).filter(Boolean) : [];
  if (ids.length > 500 || extra.length > 50) throw new HttpError(400, 'Too many people');
  if (extra.some((e) => !EMAIL_RE.test(e))) throw new HttpError(400, 'Invalid email');
  const { results } = await env.DB.prepare('SELECT id, meetings, questions FROM instances WHERE poll_id = ? ORDER BY seq').bind(id).all();
  const meetings = results.flatMap((i) => JSON.parse(i.meetings || '[]')).filter((mt) => !mt.proposed);
  if (!meetings.length) throw new HttpError(400, 'There are no meetings yet');
  const texts = await meetingAnswerTexts(env, poll, results);
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
  const block = (mt) => [`▪ ${mt.title || poll.title}`, `  ${meetingWhen(mt, poll.lang)}`, mt.location ? `  ${L.where}: ${mt.location}` : null, '',
    '  ' + meetingDescText(poll, mt, texts.get(mt.id), { pollDesc: false }).replace(/\n/g, '\n  ').replace(/\n  \n/g, '\n\n')]
    .filter((x) => x !== null).join('\n');
  const text = [message || null, message ? '' : null, L.head(sorted.length), '', (upcoming.length ? upcoming : sorted).map(block).join('\n\n'),
    upcoming.length && past ? '\n' + L.past(past) : null, '', L.ics, '', L.sub, feed.replace(/^https?:/, 'webcal:'), `${L.google}: ${feed}`, '', `${L.poll}: ${link}`]
    .filter((x) => x !== null).join('\n') + L.footer;
  const shown = upcoming.length ? upcoming : sorted;
  const html = mailBlocks({ title: poll.title, icon: poll.icon, intro: L.head(sorted.length),
    boxes: [message && { label: de ? 'Nachricht' : 'Message', body: message, tone: 'note' }],
    cards: shown.map((mt) => ({ title: mt.title || poll.title,
      facts: [[de ? 'Wann' : 'When', meetingWhen(mt, poll.lang)],
        mt.location && [L.where, mt.location, `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(mt.location)}`]].filter(Boolean),
      sections: meetingSections(poll, mt, texts.get(mt.id), { pollDesc: false }) })),
    after: [upcoming.length && past ? L.past(past) : null, L.ics,
      { label: de ? 'Abonnieren' : 'Subscribe', body: `${L.sub}\n${feed.replace(/^https?:/, 'webcal:')}\n\n${L.google}:\n${feed}` }],
    button: { href: link, label: de ? 'Umfrage öffnen' : 'Open poll' }, foot: footOf(L.footer) });
  const name = poll.title.replace(/[^\w\- ]+/g, '').trim() || 'meetings';
  const sent = await sendMail(env, poll, { to, subject: L.subject, text, html, quota: true,
    attachments: [{ content: enc.encode(buildIcs(poll, sorted, link, texts)), filename: `${name}.ics` }] });
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
  await requireAdmin(request, env, poll, 'manage');
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
  const sent = await sendPollInvite(env, url, poll, userOf(request) || {}, emails, pids, { again, message });
  return json({ ok: true, sent, missing, ...(added || {}) });
}
// Invites participants `ids` of `poll` that have an email address (used when a linked group gains members).
async function inviteIds(env, url, poll, user, ids, opts) {
  const inst = await latestInstance(env, poll.id), want = new Set(ids);
  const rows = (await participantRows(env, poll.id, inst && inst.id)).filter((p) => want.has(p.id) && EMAIL_RE.test(p.mail_to));
  if (!rows.length) return 0;
  return sendPollInvite(env, url, poll, user, [...new Set(rows.map((p) => p.mail_to.toLowerCase()))], rows.map((p) => p.id), opts);
}
// The invite / reminder email for a poll: says who asks, what for, which dates, what to do and by when, the organiser's
// message and the poll's description, so it makes sense to someone who has never heard of when-who.
function inviteMail(poll, inst, name, { again = false, message = '', link }) {
  const de = poll.lang === 'de';
  const who = name || (de ? 'Jemand' : 'Someone');
  const title = poll.title;
  const dates = inst ? periodText(poll, inst) : '';
  const deadline = inst && inst.status === 'open' && inst.deadline ? fmtDay(inst.deadline.slice(0, 10), poll.lang) : '';
  const L = de ? {
    subject: again ? `Erinnerung: Wann hast du Zeit für „${title}“?` : `${who} lädt dich ein: Wann hast du Zeit für „${title}“?`,
    intro: `${who} plant „${title}“ und sucht einen Termin, der für alle passt.`
      + (again ? ' Du hast noch nicht geantwortet.' : '') + ' Bitte trag ein, an welchen Tagen und zu welchen Zeiten du Zeit hast. Das dauert etwa eine Minute.',
    dates: 'Zeitraum', by: 'Bitte antworte bis', msg: `Nachricht von ${who}`, about: 'Worum es geht',
    how: poll.invited_only ? 'Melde dich mit dieser E-Mail-Adresse an (wir schicken dir einen Code) und trag dann ein, wann du Zeit hast.'
      : 'Öffne den Link und tippe die Tage an, an denen du Zeit hast. Du brauchst kein Konto.',
    button: 'Eintragen, wann ich Zeit habe', orLink: 'Oder öffne diesen Link:',
    foot: `when-who ist ein kostenloses Werkzeug, um einen Termin zu finden, der für eine Gruppe passt. Du bekommst diese E-Mail, weil ${name || 'jemand'} deine Adresse zu dieser Umfrage hinzugefügt hat. Antworte auf diese E-Mail, um ${name ? who : 'die Organisatorin oder den Organisator'} zu erreichen. Wenn du nicht teilnehmen möchtest, ignoriere sie einfach.`,
  } : {
    subject: again ? `Reminder: when are you free for “${title}”?` : `${who} invites you: when are you free for “${title}”?`,
    intro: `${who} is planning “${title}” and wants to find a time that suits everyone.`
      + (again ? " You haven't answered yet." : '') + " Please mark the days and times you're free. It takes about a minute.",
    dates: 'Dates', by: 'Please answer by', msg: `Message from ${who}`, about: 'About this poll',
    how: poll.invited_only ? "Sign in with this email address (we'll email you a code), then mark when you're free."
      : "Open the link and tap the days you're free. You don't need an account.",
    button: "Mark when I'm free", orLink: 'Or open this link:',
    foot: `when-who is a free tool for finding a time that works for a group. You're getting this because ${name || 'someone'} added your address to this poll. Reply to this email to reach ${name ? who : 'the organiser'}. If you don't want to take part, just ignore it.`,
  };
  const facts = [dates && [L.dates, dates], deadline && [L.by, deadline]].filter(Boolean);
  const text = [
    L.intro, '',
    ...facts.map(([k, v]) => `${k}: ${v}`), facts.length ? '' : null,
    message ? `${L.msg}:\n${message}\n` : null,
    poll.description ? `${L.about}:\n${poll.description}\n` : null,
    L.how, link,
  ].filter((x) => x !== null).join('\n') + `\n\n—\n${L.foot}`;
  const html = mailBlocks({ title, icon: poll.icon, intro: L.intro, facts,
    boxes: [message && { label: L.msg, body: message, tone: 'note' }, poll.description && { label: L.about, body: poll.description }],
    after: L.how, button: { href: link, label: L.button }, orLink: L.orLink, foot: L.foot });
  return { subject: L.subject, text, html };
}
// Sends the invite (or reminder) email to `emails` and marks participants `pids` as invited.
async function sendPollInvite(env, url, poll, user, emails, pids, { again, message = '' }) {
  const inst = await latestInstance(env, poll.id);
  const link = `${siteUrl(env, url.origin)}/?p=${poll.id}`;
  const { subject, text, html } = inviteMail(poll, inst, user.name, { again, message, link });
  const want = new Set(pids);
  const links = pids.length && env.LINK_KEY ? await personalLinks(env, poll, (await participantRows(env, poll.id, null)).filter((p) => want.has(p.id))) : null;
  const sent = await sendMail(env, poll, { to: emails, subject, text, html, quota: true, links });
  if (pids.length) {
    const at = now();
    await env.DB.batch(pids.map((pid) => env.DB.prepare('UPDATE participants SET invited_at = ? WHERE id = ?').bind(at, pid)));
  }
  return sent;
}
// ---- reminders to answer the questions (Questions tab → Remind, and Settings → Email → Reminder with remindQuestions)
// Who: people in the poll (no admin / editor role, not the owner) with questions they may answer still empty (pendingQuestions;
// qid = only that question). Accounts (also guest rows whose address has an account) get a question_remind event, delivered by
// their notification settings (type questions: push now, email in the hourly digest). Guests with an address get an email
// with their personal link (Questions tab). Returns { pending, notified, emailed, missing: [names] }.
const QREMIND_GAP = 10 * 60000;
async function sendQuestionReminders(env, base, poll, inst, { qid = null, message = '', actor = null, name = '', quota = false }) {
  const all = questionsOf(inst), qs = qid ? all.filter((q) => q.id === qid) : all;
  if (!qs.length) throw new HttpError(400, qid ? 'Question not found' : 'This round has no questions');
  const meetings = jsonList(inst.meetings), roundOpen = effStatus(inst) === 'open';
  const rows = (await participantRows(env, poll.id, inst.id)).filter((p) => !['admin', 'editor'].includes(p.role) && !(p.user_id && p.user_id === poll.owner_id));
  const { results: fa } = await env.DB.prepare('SELECT participant_id, extra FROM form_answers WHERE instance_id = ?').bind(inst.id).all();
  const answers = new Map(fa.map((r) => [r.participant_id, parseExtra(r.extra).a || {}]));
  const responses = qs.some((q) => q.who.mode === 'free') ? (await env.DB.prepare('SELECT participant_id, entries FROM responses WHERE instance_id = ?').bind(inst.id).all()).results : [];
  const pending = rows.filter((p) => { const r = pendingQuestions(qs, p, answers.get(p.id) || {}, meetings, responses, roundOpen); return r.open.length + r.after.length > 0; });
  const out = { pending: pending.length, notified: 0, emailed: 0, missing: [] };
  if (!pending.length) return out;
  // Guest rows whose address belongs to an account: that account is the person.
  const guestMails = [...new Set(pending.filter((p) => !p.user_id && EMAIL_RE.test(p.mail_to)).map((p) => p.mail_to.toLowerCase()))];
  const acct = new Map();
  if (guestMails.length) {
    const { results } = await env.DB.prepare('SELECT id, email FROM users WHERE email IN (SELECT value FROM json_each(?))').bind(JSON.stringify(guestMails)).all();
    for (const u of results) acct.set(u.email.toLowerCase(), u.id);
  }
  const uids = new Set(), guests = [];
  for (const p of pending) {
    const uid = p.user_id || acct.get((p.mail_to || '').toLowerCase());
    if (uid) uids.add(uid);
    else if (EMAIL_RE.test(p.mail_to)) guests.push(p);
    else out.missing.push(p.name);
  }
  uids.delete(actor);
  if (uids.size) {
    const label = qid ? roundText(qs[0].label, poll, inst).slice(0, 120) : '';
    await notifyEvent(env, poll, { kind: 'question_remind', iid: inst.id, actor, name, tagged: [...uids].slice(0, 300), ref: JSON.stringify({ q: label, t: now() }) });
    out.notified = uids.size;
  }
  if (guests.length && emailEnabled(env) && base) {
    const link = `${base}/?p=${poll.id}`, tab = '&tab=questions';
    const { subject, text, html } = questionsMail(poll, inst, name, { message, q: qid ? roundText(qs[0].label, poll, inst) : '', link });
    const personal = await personalLinks(env, poll, guests), links = new Map();
    for (const p of guests) { const e = p.mail_to.toLowerCase(), pl = personal.get(e); links.set(e, pl ? pl.replace('#', tab + '#') : link + tab); }
    out.emailed = await sendMail(env, poll, { to: guests.map((p) => p.mail_to), subject, text, html, quota, links });
  } else out.missing.push(...guests.map((p) => p.name));
  return out;
}
// POST /api/polls/:id/instances/:iid/questions/remind { qid?, message? } — the organiser's Remind button (at most once per 10 minutes per poll).
async function remindQuestions(request, env, url, id, iid) {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, env, poll, 'manage');
  await adoptLang(request, env, poll);
  const b = await body(request);
  const message = str(b.message, 1000, 'Message');
  const qid = typeof b.qid === 'string' && QID_RE.test(b.qid) ? b.qid : null;
  const inst = await loadInstance(env, id, iid);
  const key = 'q:' + id;
  if (await env.DB.prepare("SELECT 1 FROM login_attempts WHERE ip = ? AND kind = 'qremind' AND at > ? LIMIT 1").bind(key, new Date(Date.now() - QREMIND_GAP).toISOString()).first())
    throw new HttpError(429, 'A reminder was just sent. Try again in a few minutes.');
  const user = userOf(request) || {};
  const r = await sendQuestionReminders(env, siteUrl(env, url.origin), poll, inst, { qid, message, actor: user.id || null, name: user.name || '', quota: true });
  if (!r.pending) throw new HttpError(400, 'Everyone has answered the questions');
  if (r.notified || r.emailed) await recordFail(env, request, 'qremind', key);
  return json({ ok: true, ...r });
}
// The question reminder email for guests: who asks, which poll, the question (one) or "the questions", by when, the message.
function questionsMail(poll, inst, name, { message = '', q = '', link }) {
  const de = poll.lang === 'de', title = poll.title;
  const who = name || (de ? 'Die Organisation' : 'The organiser');
  const deadline = inst && effStatus(inst) === 'open' && inst.deadline ? fmtDay(inst.deadline.slice(0, 10), poll.lang) : '';
  const L = de ? {
    subject: `Erinnerung: Bitte beantworte die Fragen zu „${title}“`,
    intro: `${who} bittet dich, ${q ? 'eine Frage' : 'die Fragen'} zu „${title}“ zu beantworten. Du hast noch nicht geantwortet.`,
    q: 'Frage', by: 'Bitte antworte bis', msg: `Nachricht von ${who}`, button: 'Fragen beantworten', orLink: 'Oder öffne diesen Link:',
    foot: `Du bekommst diese E-Mail, weil du bei dieser when-who-Umfrage dabei bist. Antworte auf diese E-Mail, um ${name || 'die Organisation'} zu erreichen.`,
  } : {
    subject: `Reminder: please answer the questions for “${title}”`,
    intro: `${who} asks you to answer ${q ? 'a question' : 'the questions'} for “${title}”. You haven't answered yet.`,
    q: 'Question', by: 'Please answer by', msg: `Message from ${who}`, button: 'Answer the questions', orLink: 'Or open this link:',
    foot: `You're getting this because you're in this when-who poll. Reply to this email to reach ${name || 'the organiser'}.`,
  };
  const facts = [q && [L.q, q], deadline && [L.by, deadline]].filter(Boolean);
  const text = [L.intro, '', ...facts.map(([k, v]) => `${k}: ${v}`), facts.length ? '' : null, message ? `${L.msg}:\n${message}\n` : null, link]
    .filter((x) => x !== null).join('\n') + `\n\n—\n${L.foot}`;
  const html = mailBlocks({ title, icon: poll.icon, intro: L.intro, facts, boxes: [message && { label: L.msg, body: message, tone: 'note' }],
    button: { href: link, label: L.button }, orLink: L.orLink, foot: L.foot });
  return { subject: L.subject, text, html };
}


// Who gets series emails: everyone in the poll's participant list who has an email address, not only last round's answers.
// Accounts: the account's email. Guests who answered: the email on their latest answer (removing it there stops the emails).
// ---------- notifications (answer_watch 0029, prefs + poll_events 0032) ----------
// What happens in a poll (an answer, a vote, a meeting set, questions added, a new round, a chat message) is logged in
// poll_events (notifyEvent) and pushed right away to the devices of people who want that type; the hourly cron sends one
// email per person with the types they want by email (notifyDigests). Preferences per type: { p: push, e: email };
// chat takes 'all' | 'mentions' | 'off'. Effective = the poll's override (answer_watch.prefs) ?? account defaults
// (users.notify) ?? built-in by role (organisers also get answers, votes and question answers). Answers, votes and
// question answers only go to people who can see the answers; chat only to chat members; guests (no account) get none.
const NT_TYPES = ['chat', 'answers', 'votes', 'qanswers', 'meetings', 'questions', 'rounds'];
const NT_SEE = new Set(['answers', 'votes', 'qanswers']); // need to see everyone's answers
const EV_TYPE = { chat: 'chat', answer: 'answers', answer_changed: 'answers', vote: 'votes', qanswer: 'qanswers',
  meeting_set: 'meetings', meeting_proposed: 'meetings', meeting_changed: 'meetings', meeting_cancelled: 'meetings',
  question_added: 'questions', question_open: 'questions', question_remind: 'questions', round_open: 'rounds', poll_closed: 'rounds', poll_reopened: 'rounds' };
const EV_QUIET = new Set(['answer_changed', 'vote', 'qanswer']); // same person again within EV_GAP: logged, not pushed again
const EV_GAP = 10 * 60000;
const EV_KEEP_DAYS = 3;
const DIGESTS_PER_RUN = 40;  // emails per hourly run (Resend free tier: 100 a day for the whole site)
const CHAT_LV = ['all', 'mentions', 'off'];
const ntBuiltin = (org) => ({ chat: { p: 'all', e: 'off' }, answers: { p: org ? 1 : 0, e: 0 }, votes: { p: org ? 1 : 0, e: 0 },
  qanswers: { p: org ? 1 : 0, e: 0 }, meetings: { p: 1, e: 0 }, questions: { p: 1, e: 0 }, rounds: { p: 1, e: 0 } });
const parseJ = (s) => { try { return s ? JSON.parse(s) : null; } catch { return null; } };
// Valid values from x laid over base (unknown keys and values ignored).
function cleanPrefs(x, base) {
  const out = JSON.parse(JSON.stringify(base));
  if (!x || typeof x !== 'object') return out;
  for (const k of NT_TYPES) {
    const v = x[k]; if (!v || typeof v !== 'object') continue;
    for (const c of ['p', 'e']) {
      if (v[c] === undefined) continue;
      if (k === 'chat') out.chat[c] = CHAT_LV.includes(v[c]) ? v[c] : v[c] === true || v[c] === 1 ? 'all' : v[c] === false || v[c] === 0 ? 'off' : out.chat[c];
      else out[k][c] = v[c] ? 1 : 0;
    }
  }
  return out;
}
// Account defaults: answers / votes / question answers apply only in polls the person organises.
function ntAccount(notify, org) {
  const b = ntBuiltin(org), acct = parseJ(notify);
  if (!acct) return b;
  const out = cleanPrefs(acct, b);
  if (!org) for (const k of NT_SEE) out[k] = b[k];
  return out;
}
// Columns per person: uid, email, notify, prefs, wem, wpu (legacy answer_watch), muted, role, inpoll.
const NT_COLS = (from) => `SELECT a.user_id AS uid, u.email, u.notify, w.prefs, w.email AS wem, w.push AS wpu, r.muted,
    (SELECT role FROM participants WHERE poll_id = ?1 AND user_id = a.user_id AND role != '' LIMIT 1) AS role,
    EXISTS (SELECT 1 FROM participants WHERE poll_id = ?1 AND (user_id = a.user_id OR (user_id IS NULL AND LOWER(email) = LOWER(u.email)))) AS inpoll
  FROM (${from}) a JOIN users u ON u.id = a.user_id
  LEFT JOIN answer_watch w ON w.poll_id = ?1 AND w.user_id = a.user_id
  LEFT JOIN chat_reads r ON r.poll_id = ?1 AND r.user_id = a.user_id`;
// One person's effective prefs and the types they may get in this poll.
function ntRow(poll, x) {
  const owner = !!poll.owner_id && poll.owner_id === x.uid, org = owner || POLL_ROLES.includes(x.role);
  const member = org || !poll.invited_only || !!x.inpoll;
  const see = org || (!poll.hide_results && member), chat = !!poll.allow_comments && member;
  const acct = ntAccount(x.notify, org), own = parseJ(x.prefs);
  let prefs;
  if (own) prefs = cleanPrefs(own, acct);
  else { // legacy switches: "notify me when someone answers" (0029) and the chat mute
    prefs = JSON.parse(JSON.stringify(acct));
    if (x.wem != null && (x.wem || x.wpu)) prefs.answers = { p: x.wpu ? 1 : 0, e: x.wem ? 1 : 0 };
    if (x.muted) prefs.chat.p = 'off';
  }
  const types = NT_TYPES.filter((k) => (k === 'chat' ? chat : NT_SEE.has(k) ? see : member));
  return { uid: x.uid, email: x.email, prefs, own: !!own, types, member };
}
// Everyone with an account connected to the poll (chat members, people in it, the owner, anyone with settings for it).
async function ntAudience(env, poll) {
  // (D1 allows only a few UNION terms per query, so one SELECT with ORs.)
  const { results } = await env.DB.prepare(NT_COLS(`SELECT u.id AS user_id FROM users u WHERE
      u.id IN (SELECT user_id FROM participants WHERE poll_id = ?1 AND user_id IS NOT NULL)
      OR u.email IN (SELECT LOWER(email) FROM participants WHERE poll_id = ?1 AND user_id IS NULL AND email IS NOT NULL AND email != '')
      OR u.id IN (SELECT user_id FROM chat_reads WHERE poll_id = ?1) OR u.id IN (SELECT user_id FROM messages WHERE poll_id = ?1)
      OR u.id IN (SELECT user_id FROM answer_watch WHERE poll_id = ?1) OR u.id = (SELECT owner_id FROM polls WHERE id = ?1)`) + ' LIMIT 300').bind(poll.id).all();
  return results.map((x) => ntRow(poll, x)).filter((a) => a.member);
}
async function ntFor(env, poll, uid) {
  const x = await env.DB.prepare(NT_COLS('SELECT ?2 AS user_id')).bind(poll.id, uid).first();
  return x ? ntRow(poll, x) : null;
}
const ntOut = (r) => ({ prefs: r.prefs, own: r.own, types: r.types });
const TAGGED_KINDS = new Set(['question_open', 'question_remind']); // tagged = the only accounts it is for (empty = everyone)
const wants = (a, type, ch, ev) => {
  if (!a.types.includes(type)) return false;
  if (TAGGED_KINDS.has(ev.kind) && (ev.tagged || []).length && !ev.tagged.includes(a.uid)) return false; // only people who may answer / were reminded
  const v = a.prefs[type][ch];
  return type === 'chat' ? v === 'all' || (v === 'mentions' && (ev.tagged || []).includes(a.uid)) : !!v;
};
// Event text in a language (push body and email line).
function evText(ev, poll, lang) {
  const de = langOf(lang) === 'de', n = ev.name || '?';
  const mt = (ev.kind || '').startsWith('meeting_') ? parseJ(ev.ref) : null;
  const when = mt ? meetingWhen(mt, lang) + (mt.title ? ` · ${mt.title}` : '') : '';
  switch (ev.kind) {
    case 'answer': return de ? `${n} hat geantwortet` : `${n} answered`;
    case 'answer_changed': return de ? `${n} hat die Antwort geändert` : `${n} changed their answer`;
    case 'vote': return de ? `${n} hat über die Terminvorschläge abgestimmt` : `${n} voted on the proposed times`;
    case 'qanswer': return de ? `${n} hat die Fragen beantwortet` : `${n} answered the questions`;
    case 'meeting_set': return (de ? 'Termin steht: ' : 'Meeting set: ') + when;
    case 'meeting_proposed': return (de ? 'Neuer Terminvorschlag zum Abstimmen: ' : 'New time to vote on: ') + when;
    case 'meeting_changed': return (de ? 'Termin geändert: ' : 'Meeting changed: ') + when;
    case 'meeting_cancelled': return (de ? 'Termin abgesagt: ' : 'Meeting cancelled: ') + when;
    case 'question_added': return (de ? 'Neue Fragen: ' : 'New questions: ') + n;
    case 'question_open': {
      const r = parseJ(ev.ref) || {}, at = r.t ? `${r.t}, ${fmtDay(r.d, lang)}` : fmtDay(r.d, lang);
      return (r.b ? (de ? `Fragen vor ${at}: ` : `Questions before ${at}: `) : (de ? `Fragen zu ${at}: ` : `Questions about ${at}: `)) + n;
    }
    case 'question_remind': {
      const r = parseJ(ev.ref) || {}, q = r.q ? `: ${r.q}` : '';
      return ev.name ? (de ? `${n} erinnert dich daran, die Fragen zu beantworten${q}` : `${n} reminds you to answer the questions${q}`)
        : (de ? `Erinnerung: Bitte beantworte die Fragen${q}` : `Reminder: please answer the questions${q}`);
    }
    case 'round_open': { const r = parseJ(ev.ref) || {}; return (de ? 'Neue Runde offen: ' : 'A new round is open: ') + periodText({ ...poll, lang }, { start_date: r.s, end_date: r.e }); }
    case 'poll_closed': return de ? 'Die Umfrage ist geschlossen' : 'The poll is closed';
    case 'poll_reopened': return de ? 'Die Umfrage ist wieder offen' : 'The poll is open again';
    case 'chat': return de ? `Nachricht von ${n}` : `Message from ${n}`;
  }
  return '';
}
const EV_TAB = { meetings: 'meetings', questions: 'questions', qanswers: 'questions' };
// Logs an event and pushes it. ev = { kind, iid?, actor?, name, ref?, tagged?: [uid], push?: (lang) => payload fields }.
async function notifyEvent(env, poll, ev) {
  const type = EV_TYPE[ev.kind]; if (!type) return;
  const at = now();
  let quiet = false;
  if (EV_QUIET.has(ev.kind) && ev.ref) {
    quiet = !!(await env.DB.prepare("SELECT 1 FROM poll_events WHERE poll_id = ? AND kind IN ('answer', 'answer_changed', ?) AND ref = ? AND at > ? LIMIT 1")
      .bind(poll.id, ev.kind, ev.ref, new Date(Date.now() - EV_GAP).toISOString()).first());
  }
  // Chat: the message itself is the record (no copy in the log); only mentions are kept for the email.
  await env.DB.prepare('INSERT INTO poll_events (poll_id, instance_id, kind, actor_id, name, ref, tagged, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(poll.id, ev.iid || null, ev.kind, ev.actor || null, String(ev.name || '').slice(0, 200), ev.kind === 'chat' ? '' : String(ev.ref || '').slice(0, 2000),
      (ev.tagged || []).join(','), at).run();
  if (quiet || !pushOn(env)) return;
  const to = (await ntAudience(env, poll)).filter((a) => a.uid !== ev.actor && wants(a, type, 'p', ev)).map((a) => a.uid);
  if (!to.length) return;
  const { results: subs } = await env.DB.prepare(`SELECT id, user_id, endpoint, p256dh, auth, lang FROM push_subs WHERE user_id IN (${to.map(() => '?').join(',')})
    ORDER BY created_at DESC LIMIT ?`).bind(...to, PUSH_MAX).all();
  if (!subs.length) return;
  const tag = (type === 'chat' ? 'chat' : ev.kind.replace(/_.*/, '')) + '-' + poll.id;
  const actor = ev.actor ? await env.DB.prepare('SELECT id, avatar, avatar_img FROM users WHERE id = ?').bind(ev.actor).first() : null;
  const who = actor ? { av: actor.avatar || '', icon: await avatarIcon(env, actor) } : {};
  const badge = type === 'chat' ? await unreadTotals(env, [...new Set(subs.map((x) => x.user_id))]) : null;
  await pushSend(env, subs, (s) => ({ kind: type === 'chat' ? 'chat' : ev.kind, title: String(poll.title || '').slice(0, 120), tag, poll: poll.id, at,
    url: `/?p=${poll.id}${EV_TAB[type] ? '&tab=' + EV_TAB[type] : ''}`, body: evText(ev, poll, s.lang).slice(0, 200), ...who,
    ...(badge ? { badge: badge[s.user_id] || 0 } : {}), ...(ev.push ? ev.push(s.lang) : {}) }), tag);
}
// Unread chat messages per account across its polls (same rule as myPolls), for the app icon badge.
async function unreadTotals(env, uids) {
  if (!uids.length) return {};
  const { results } = await env.DB.prepare(`WITH up AS (
      SELECT p.id AS poll_id, p.owner_id AS uid FROM polls p WHERE p.allow_comments = 1 AND p.owner_id IN (SELECT value FROM json_each(?1))
      UNION SELECT pa.poll_id, pa.user_id FROM participants pa JOIN polls p ON p.id = pa.poll_id AND p.allow_comments = 1
        WHERE pa.user_id IN (SELECT value FROM json_each(?1)))
    SELECT up.uid, COUNT(*) AS n FROM up JOIN messages m ON m.poll_id = up.poll_id AND m.user_id != up.uid
      LEFT JOIN chat_reads cr ON cr.poll_id = up.poll_id AND cr.user_id = up.uid
    WHERE m.created_at > COALESCE(cr.read_at, '') GROUP BY up.uid`).bind(JSON.stringify(uids)).all();
  return Object.fromEntries(results.map((r) => [r.uid, r.n]));
}
const fireEvent = (ctx, env, poll, ev) => ctx.waitUntil(notifyEvent(env, poll, ev).catch((e) => console.error('event', ev.kind, e)));
// Per-meeting questions that opened on their own in the last 3 hours (before / after a meeting, link.when / days):
// one question_open event per meeting date, to the accounts that may answer (in tagged; empty = everyone).
// Meeting times are read as UTC wall clock (no poll time zone is stored). poll_events (kept 3 days) is the dedupe.
const QOPEN_WINDOW = 3 * 3600e3;
async function notifyQuestionOpens(env) {
  const at = Date.now(), from = at - QOPEN_WINDOW;
  const { results: insts } = await env.DB.prepare(`SELECT i.id, i.poll_id, i.seq, i.start_date, i.end_date, i.questions, i.meetings FROM instances i
    WHERE i.questions LIKE '%"to":"after"%' AND (i.end_date >= ? OR i.meetings LIKE '%"repeat"%') LIMIT 200`)
    .bind(new Date(at - (MAX_Q_DAYS + 10) * 86400e3).toISOString().slice(0, 10)).all();
  let sent = 0;
  for (const inst of insts) {
    if (sent >= 30) break;
    const meetings = JSON.parse(inst.meetings || '[]'), byKey = new Map();
    for (const q of questionsOf(inst)) {
      if (!isAfter(q) || q.closed) continue;
      for (const o of afterOccs(q, meetings, at, true)) {
        if (o.open > at || o.open <= from || o.close <= at) continue;
        if (!byKey.has(o.key)) byKey.set(o.key, { o, qs: [] });
        byKey.get(o.key).qs.push(q);
      }
    }
    if (!byKey.size) continue;
    const poll = await env.DB.prepare('SELECT * FROM polls WHERE id = ?').bind(inst.poll_id).first();
    if (!poll) continue;
    const { results: old } = await env.DB.prepare("SELECT ref FROM poll_events WHERE poll_id = ? AND kind = 'question_open'").bind(poll.id).all();
    const done = new Set(old.flatMap((e) => { const r = parseJ(e.ref) || {}; return (r.q || []).map((id) => r.k + '|' + id); }));
    let parts = null, responses = null;
    for (const { o, qs: all } of byKey.values()) {
      const qs = all.filter((q) => !done.has(o.key + '|' + q.id));
      if (!qs.length || sent >= 30) continue;
      let tagged = [];
      if (qs.some((q) => (q.who || {}).mode !== 'all')) { // limited: the accounts that may answer at least one of them
        if (!parts) {
          parts = (await env.DB.prepare('SELECT id, user_id FROM participants WHERE poll_id = ? AND user_id IS NOT NULL').bind(poll.id).all()).results;
          responses = (await env.DB.prepare('SELECT participant_id, entries FROM responses WHERE instance_id = ?').bind(inst.id).all()).results;
        }
        if (qs.some((q) => (q.who || {}).mode === 'all')) tagged = [];
        else {
          tagged = [...new Set(parts.filter((p) => qs.some((q) => canAnswerAt(q, p, o.m, o.date, responses))).map((p) => p.user_id))];
          if (!tagged.length) continue;
        }
      }
      const name = qs.map((q) => roundText(q.label, poll, inst)).slice(0, 3).join(' · ') + (qs.length > 3 ? ' …' : '');
      await notifyEvent(env, poll, { kind: 'question_open', iid: inst.id, name, tagged: tagged.slice(0, 300),
        ref: JSON.stringify({ k: o.key, q: qs.map((q) => q.id), d: o.date, t: String(o.m.title || '').slice(0, 80), b: isBefore(qs[0]) ? 1 : 0 }) });
      sent++;
    }
  }
}
// Meetings saved: what's new, proposed, moved or gone (confirmed ones), at most 5 events per save.
function meetingEvents(oldList, newList) {
  const old = new Map(oldList.map((m) => [m.id, m])), evs = [];
  const brief = (m) => JSON.stringify({ date: m.date, endDate: m.endDate, start: m.start, end: m.end, allDay: m.allDay, repeat: m.repeat, title: m.title || '' });
  const timeOf = (m) => [m.date, m.endDate, m.start, m.end, m.allDay, JSON.stringify(m.repeat || null)].join('|');
  for (const m of newList) {
    const o = old.get(m.id);
    if (!o) evs.push({ kind: m.proposed ? 'meeting_proposed' : 'meeting_set', ref: brief(m) });
    else if (o.proposed && !m.proposed) evs.push({ kind: 'meeting_set', ref: brief(m) });
    else if (!m.proposed && timeOf(o) !== timeOf(m)) evs.push({ kind: 'meeting_changed', ref: brief(m) });
  }
  const ids = new Set(newList.map((m) => m.id));
  for (const o of oldList) if (!o.proposed && !ids.has(o.id)) evs.push({ kind: 'meeting_cancelled', ref: brief(o) });
  return evs.slice(0, 5);
}
// PUT /api/polls/:id/notify { prefs | null }: this poll's own settings (null = follow my defaults again).
async function setPollNotify(request, env, id) {
  const user = requireUser(request);
  const poll = await loadPoll(env, id);
  await checkPassword(env, request, poll);
  const b = await body(request);
  const cur = await ntFor(env, poll, user.id);
  if (b.prefs === null) {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM answer_watch WHERE poll_id = ? AND user_id = ?').bind(id, user.id),
      env.DB.prepare('UPDATE chat_reads SET muted = 0 WHERE poll_id = ? AND user_id = ?').bind(id, user.id)]);
  } else {
    if (!b.prefs || typeof b.prefs !== 'object') throw new HttpError(400, 'Invalid notification settings');
    const p = cleanPrefs(b.prefs, cur.prefs);
    await env.DB.prepare(`INSERT INTO answer_watch (poll_id, user_id, prefs, sent_at) VALUES (?, ?, ?, ?)
      ON CONFLICT (poll_id, user_id) DO UPDATE SET prefs = excluded.prefs`).bind(id, user.id, JSON.stringify(p), now()).run();
  }
  return json({ ok: true, notify: ntOut(await ntFor(env, poll, user.id)) });
}
// Old API (answer notifications only): { email, push } → the answers row of this poll's settings.
async function setWatch(request, env, id) {
  const user = requireUser(request);
  const poll = await loadPoll(env, id);
  await checkPassword(env, request, poll);
  const cur = await ntFor(env, poll, user.id);
  if (!cur.types.includes('answers')) throw new HttpError(403, 'Only people who can see the answers can get notified about them.');
  const b = await body(request);
  const p = cleanPrefs({ answers: { p: b.push ? 1 : 0, e: b.email ? 1 : 0 } }, cur.prefs);
  await env.DB.prepare(`INSERT INTO answer_watch (poll_id, user_id, prefs, sent_at) VALUES (?, ?, ?, ?)
    ON CONFLICT (poll_id, user_id) DO UPDATE SET prefs = excluded.prefs`).bind(id, user.id, JSON.stringify(p), now()).run();
  return json({ ok: true, watch: { email: !!p.answers.e, push: !!p.answers.p } });
}
// GET|PUT /api/me/notify { prefs | null }: account defaults (as for a poll you organise).
async function meNotify(request, env) {
  const user = requireUser(request);
  if (request.method === 'PUT') {
    const b = await body(request);
    if (b.prefs !== null && (!b.prefs || typeof b.prefs !== 'object')) throw new HttpError(400, 'Invalid notification settings');
    const was = await env.DB.prepare('SELECT notify FROM users WHERE id = ?').bind(user.id).first('notify');
    const v = b.prefs === null ? '' : JSON.stringify(cleanPrefs(b.prefs, ntAccount(was, true)));
    await env.DB.prepare('UPDATE users SET notify = ? WHERE id = ?').bind(v, user.id).run();
    user.notify = v;
  } else user.notify = await env.DB.prepare('SELECT notify FROM users WHERE id = ?').bind(user.id).first('notify');
  return json({ prefs: ntAccount(user.notify, true), own: !!user.notify, types: NT_TYPES });
}
// Hourly: one email per person with what happened (types they want by email) since the last run, all their polls together.
async function notifyDigests(env) {
  await env.DB.prepare('DELETE FROM poll_events WHERE at < ?').bind(new Date(Date.now() - EV_KEEP_DAYS * 86400000).toISOString()).run();
  const { results: evs } = await env.DB.prepare('SELECT * FROM poll_events WHERE digested = 0 ORDER BY id LIMIT 300').all();
  if (!evs.length) return;
  const maxId = evs[evs.length - 1].id;
  const base = siteUrl(env);
  if (emailEnabled(env) && base) {
    const byPoll = new Map();
    for (const e of evs) { if (!byPoll.has(e.poll_id)) byPoll.set(e.poll_id, []); byPoll.get(e.poll_id).push(e); }
    const people = new Map(); // uid -> { email, lang, polls: [{ poll, evs }] }
    for (const [pid, list] of byPoll) {
      const poll = await env.DB.prepare('SELECT * FROM polls WHERE id = ?').bind(pid).first();
      if (!poll) continue;
      for (const a of await ntAudience(env, poll)) {
        const mine = list.map((e) => ({ ...e, tagged: e.tagged ? e.tagged.split(',') : [] }))
          .filter((e) => e.actor_id !== a.uid && wants(a, EV_TYPE[e.kind] || '', 'e', e));
        if (!mine.length) continue;
        if (!people.has(a.uid)) people.set(a.uid, { email: a.email, lang: poll.lang, polls: [] });
        people.get(a.uid).polls.push({ poll, evs: mine });
      }
    }
    let sent = 0;
    for (const [, p] of people) {
      if (sent >= DIGESTS_PER_RUN) break;
      const de = p.lang === 'de', total = p.polls.reduce((n, x) => n + x.evs.length, 0);
      const sections = p.polls.map(({ poll, evs: list }) => {
        const lines = [], seen = new Set(), chat = list.filter((e) => e.kind === 'chat');
        // The same person's answer twice in an hour: one line (answered wins over changed).
        for (const e of [...list].reverse()) {
          if (e.kind === 'chat') continue;
          const key = EV_TYPE[e.kind] === 'answers' ? 'a:' + e.ref : ['vote', 'qanswer'].includes(e.kind) ? e.kind + ':' + e.ref : 'x:' + e.id;
          if (seen.has(key)) continue; seen.add(key);
          const first = EV_TYPE[e.kind] === 'answers' && list.some((x) => x.kind === 'answer' && x.ref === e.ref) ? { ...e, kind: 'answer' } : e;
          lines.unshift('• ' + evText(first, poll, p.lang));
        }
        if (chat.length) {
          const who = [...new Set(chat.map((e) => e.name))].slice(0, 4).join(', ');
          lines.push('• ' + (de ? `${chat.length === 1 ? 'Eine neue Chat-Nachricht' : chat.length + ' neue Chat-Nachrichten'} (${who})` : `${chat.length === 1 ? '1 new chat message' : chat.length + ' new chat messages'} (${who})`));
        }
        return { poll, lines };
      });
      const one = p.polls.length === 1 ? p.polls[0].poll : null;
      const subject = one ? `${one.title}: ${de ? (total === 1 ? 'eine Neuigkeit' : total + ' Neuigkeiten') : (total === 1 ? '1 update' : total + ' updates')}`
        : (de ? `Neuigkeiten in ${p.polls.length} Umfragen` : `Updates in ${p.polls.length} polls`);
      const foot = (de ? 'Du bekommst diese E-Mail, weil du diese Benachrichtigungen per E-Mail eingeschaltet hast. Ändern: die Glocke 🔔 oben in der Umfrage oder dein Konto → Benachrichtigungen.'
        : 'You’re getting this because you turned these notifications on by email. To change them, use the bell 🔔 at the top of the poll or Account → Notifications.');
      const text = sections.map((x) => `${x.poll.title}\n${x.lines.join('\n')}\n${base}/?p=${x.poll.id}`).join('\n\n') + '\n\n—\n' + foot;
      const html = emailHtml(mailBlocks({ title: one ? one.title : subject, icon: one && one.icon,
        cards: sections.map((x) => ({ title: one ? '' : (x.poll.icon ? x.poll.icon + ' ' : '') + x.poll.title, href: one ? null : `${base}/?p=${x.poll.id}`, sections: [{ body: x.lines.join('\n') }] })),
        button: one ? { href: `${base}/?p=${one.id}`, label: de ? 'Umfrage öffnen' : 'Open poll' } : null, foot }),
        { preheader: subject, site: base, lang: langOf(p.lang) });
      try { await sendEmail(env, { fromName: 'when-who', to: [p.email], subject, text, html, unsub: `${base}/?account` }); sent++; } catch (e) { console.error('digest', e); }
    }
  }
  await env.DB.prepare('UPDATE poll_events SET digested = 1 WHERE digested = 0 AND id <= ?').bind(maxId).run();
}

// Who gets round emails: everyone in the poll with an address (participantRows' mail_to) who hasn't answered `inst`.
const waitingRows = async (env, poll, inst) => (await participantRows(env, poll.id, inst.id)).filter((p) => !p.here && p.mail_to);
async function notifyOpened(env, poll, inst, origin) {
  // claim the notification so it is sent once even if the cron job and a visitor race
  const claim = await env.DB.prepare('UPDATE instances SET opened_notified = 1 WHERE id = ? AND opened_notified = 0').bind(inst.id).run();
  if (!claim.meta || !claim.meta.changes) return;
  if (poll.kind === 'series' && (await env.DB.prepare('SELECT 1 FROM instances WHERE poll_id = ? AND seq < ? LIMIT 1').bind(poll.id, inst.seq).first()))
    await notifyEvent(env, poll, { kind: 'round_open', iid: inst.id, ref: JSON.stringify({ s: inst.start_date, e: inst.end_date }) }).catch((e) => console.error('event', e));
  if (!poll.notify_open || !emailEnabled(env)) return;
  const rows = await waitingRows(env, poll, inst), to = rows.map((p) => p.mail_to), links = await personalLinks(env, poll, rows);
  if (!to.length) return;
  const base = siteUrl(env, origin); if (!base) return;
  const period = periodText(poll, inst), de = poll.lang === 'de', link = `${base}/?p=${poll.id}`;
  const by = inst.deadline ? fmtDay(inst.deadline.slice(0, 10), poll.lang) : '';
  const text = (de ? `Die Umfrage für ${period} ist offen.\n\nBitte trag ein, wann du Zeit hast${by ? ` (bis ${by})` : ''}:\n${link}`
    : `The poll for ${period} is open.\n\nPlease mark when you're available${by ? ` by ${by}` : ''}:\n${link}`) + seriesFooter(poll);
  const html = roundMail(poll, { intro: de ? `Die Umfrage für ${period} ist offen. Bitte trag ein, wann du Zeit hast.` : `The poll for ${period} is open. Please mark when you're available.`,
    period, by, link });
  await sendMail(env, poll, { to, subject: de ? `${poll.title}: Wann hast du Zeit (${period})?` : `${poll.title}: when are you free in ${period}?`, text, html, links });
}
// Body of the round-opened and reminder emails. The button has the plain poll link, so sendMail swaps in personal links.
function roundMail(poll, { intro, period, by, link }) {
  const de = poll.lang === 'de';
  return mailBlocks({ title: poll.title, icon: poll.icon, intro,
    facts: [[de ? 'Zeitraum' : 'Dates', period], by && [de ? 'Bitte antworte bis' : 'Please answer by', by]].filter(Boolean),
    button: { href: link, label: de ? 'Eintragen, wann ich Zeit habe' : "Mark when I'm free" }, orLink: de ? 'Oder öffne diesen Link:' : 'Or open this link:',
    foot: footOf(seriesFooter(poll)) });
}
async function remind(env, poll, inst) {
  const claim = await env.DB.prepare('UPDATE instances SET reminded = 1 WHERE id = ? AND reminded = 0').bind(inst.id).run();
  if (!claim.meta || !claim.meta.changes || !emailEnabled(env)) return;
  const base = siteUrl(env); if (!base) return;
  const rows = await waitingRows(env, poll, inst), to = rows.map((p) => p.mail_to), links = await personalLinks(env, poll, rows);
  if (!to.length) return;
  const period = periodText(poll, inst);
  const de = poll.lang === 'de';
  const intro = de ? `Erinnerung: Bitte trag bis ${fmtDay(inst.deadline, 'de')} ein, wann du für ${period} Zeit hast.`
    : `Reminder: please mark when you're available for ${period} by ${fmtDay(inst.deadline)}.`;
  const text = intro + `\n\n${base}/?p=${poll.id}` + seriesFooter(poll);
  const html = roundMail(poll, { intro, period, by: fmtDay(inst.deadline.slice(0, 10), poll.lang), link: `${base}/?p=${poll.id}` });
  await sendMail(env, poll, { to, subject: `${de ? 'Erinnerung' : 'Reminder'}: ${poll.title} (${period})`, text, html, links });
}
// Settings → Email → Reminder + "also the questions": on the reminder day, once per round (q_reminded), no mail quota (like remind).
async function remindQuestionsDue(env, poll, t) {
  const { results: due } = await env.DB.prepare(`SELECT * FROM instances WHERE poll_id = ? AND q_reminded = 0 AND deadline IS NOT NULL AND deadline >= ?
    AND questions IS NOT NULL AND questions NOT IN ('', '[]')`).bind(poll.id, t).all();
  for (const inst of due) {
    if (effStatus(inst) !== 'open' || addDays(inst.deadline, -poll.remind_days) > t || !questionsOf(inst).length) continue;
    const claim = await env.DB.prepare('UPDATE instances SET q_reminded = 1 WHERE id = ? AND q_reminded = 0').bind(inst.id).run();
    if (!claim.meta || !claim.meta.changes) continue;
    const owner = await ownerOf(env, poll);
    await sendQuestionReminders(env, siteUrl(env), poll, inst, { name: (owner && owner.name) || '' });
  }
}
async function runScheduled(env) {
  try {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now()),
      env.DB.prepare('DELETE FROM login_attempts WHERE at < ?').bind(new Date(Date.now() - 86400000).toISOString()),
      env.DB.prepare('DELETE FROM login_codes WHERE expires_at < ?').bind(now()),
      env.DB.prepare('DELETE FROM mail_log WHERE at < ?').bind(new Date(Date.now() - 2 * 86400000).toISOString()),
      env.DB.prepare('DELETE FROM oauth_states WHERE created_at < ?').bind(new Date(Date.now() - 3600000).toISOString()),
      env.DB.prepare('DELETE FROM mcp_requests WHERE created_at < ?').bind(new Date(Date.now() - MCP_CODE_MIN * 60000).toISOString()),
      env.DB.prepare('DELETE FROM mcp_grants WHERE refresh_exp < ?').bind(now()),
      env.DB.prepare('DELETE FROM mcp_clients WHERE created_at < ? AND id NOT IN (SELECT client_id FROM mcp_grants)').bind(new Date(Date.now() - 30 * 86400000).toISOString()),
    ]);
  } catch (e) { console.error('cleanup', e); }
  if (new Date().getUTCHours() === 3) { try { await deleteStalePolls(env); } catch (e) { console.error('retention', e); } }
  if (new Date().getUTCHours() === 4) { try { await mergeEmailDupesAll(env); } catch (e) { console.error('dupes', e); } }
  try { await notifyQuestionOpens(env); } catch (e) { console.error('qopen', e); }
  try { await notifyDigests(env); } catch (e) { console.error('digest', e); }
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
        if (poll.remind_questions) await remindQuestionsDue(env, poll, t).catch((e) => console.error('qremind', poll.id, e));
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
// Turns a guest row into the row of account u ({ id, email }). A statement, so callers can batch it.
const toAccountRow = (env, partId, u) => env.DB.prepare('UPDATE participants SET user_id = ?, name_key = ?, email = ? WHERE id = ? AND user_id IS NULL')
  .bind(u.id, acctKey(u.id), u.email, partId);
// Links a guest participant to the account with this email, unless the account is already someone in this poll.
async function linkGuestToAccount(env, pollId, partId, mail) {
  const acct = await accountByEmail(env, mail);
  if (!acct || !partId || await accountParticipant(env, pollId, acct.id)) return;
  await toAccountRow(env, partId, acct).run();
}
// Guest rows that are this account's person: added by the organiser with its email, or a guest who answered with it.
const guestRowsOf = (env, pollId, mail) => env.DB.prepare(
  `SELECT * FROM participants pa WHERE pa.poll_id = ? AND pa.user_id IS NULL AND (LOWER(TRIM(pa.email)) = ?
     OR EXISTS (SELECT 1 FROM responses r WHERE r.participant_id = pa.id AND LOWER(TRIM(r.email)) = ?)) ORDER BY pa.created_at`)
  .bind(pollId, mail, mail).all().then((r) => r.results);
// Guest rows of one address, the one to keep first: rows the organiser saved with it (participants.email), oldest first,
// then rows that only answered with it.
const guestRowsByEmail = async (env, pollId, mail) => (await guestRowsOf(env, pollId, mail.trim().toLowerCase()))
  .sort((a, b) => (a.email && a.email.trim().toLowerCase() === mail.trim().toLowerCase() ? 0 : 1) - (b.email && b.email.trim().toLowerCase() === mail.trim().toLowerCase() ? 0 : 1)
    || (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : 0));
// The signed-in account's person in this poll: its own row, else a guest row with its email (which becomes the
// account's). Guest rows with that email next to the account's row (duplicates from before) are merged into it.
// null = not in this poll yet.
async function accountRow(env, pollId, user) {
  let part = await accountParticipant(env, pollId, user.id);
  const guests = await guestRowsOf(env, pollId, user.email.toLowerCase());
  if (!part && guests.length) {
    part = guests.shift();
    await toAccountRow(env, part.id, user).run();
    Object.assign(part, { user_id: user.id, name_key: acctKey(user.id), email: user.email });
  }
  for (const g of guests) await mergeInto(env, g, part);
  return part;
}
// After sign-in (or a new account email): every poll's guest rows with this address become the account's person right away,
// so the polls show up in the account's list and nobody appears twice. One statement for polls where the account isn't
// anyone yet (the oldest guest row there becomes its row); leftover duplicates next to an account row are merged, a few
// per call (each merge costs queries; the Free plan allows 50 per request) and the rest when that poll is opened (accountRow).
const GUEST_MATCH = `pa.user_id IS NULL AND (LOWER(TRIM(pa.email)) = ?2
  OR EXISTS (SELECT 1 FROM responses r WHERE r.participant_id = pa.id AND LOWER(TRIM(r.email)) = ?2))`;
async function claimGuestRows(env, user) {
  const mail = user.email.toLowerCase();
  await env.DB.prepare(
    `UPDATE participants SET user_id = ?1, name_key = ?3, email = ?4 WHERE user_id IS NULL AND id IN (
       SELECT id FROM (SELECT pa.id, ROW_NUMBER() OVER (PARTITION BY pa.poll_id ORDER BY pa.created_at) AS n FROM participants pa
         WHERE ${GUEST_MATCH} AND NOT EXISTS (SELECT 1 FROM participants x WHERE x.poll_id = pa.poll_id AND x.user_id = ?1))
       WHERE n = 1)`).bind(user.id, mail, acctKey(user.id), user.email).run();
  const { results } = await env.DB.prepare(
    `SELECT pa.*, a.id AS dst_id, a.name AS dst_name FROM participants pa JOIN participants a ON a.poll_id = pa.poll_id AND a.user_id = ?1
     WHERE ${GUEST_MATCH} ORDER BY pa.created_at LIMIT 5`).bind(user.id, mail).all();
  for (const g of results) await mergeInto(env, g, { id: g.dst_id, name: g.dst_name });
}
// Name a signed-in person answers under: the profile name, else the typed one, else the name they already have in
// this poll (e.g. the one the organiser gave them), else the start of their email. Accounts made before sign-up asked
// for a name have none, so it's never required here.
const acctName = (user, typed, part) => user.name
  || (typeof typed === 'string' && typed.trim() ? personName(typed) : '')
  || (part && part.name) || user.email.split('@')[0].slice(0, 60);
// Invited-only polls: the answer must come from a signed-in account that the owner invited, either as that account
// or as a guest row with the account's email (that row then becomes the account's). The owner can always answer.
async function requireInvited(env, poll, user, admin, request) {
  if (!poll.invited_only || admin) return;
  if (!user && request && await personByKey(request, env, poll.id)) return; // their personal link
  if (!user) throw new HttpError(403, 'Only invited people can answer this poll. Sign in with the email address you were invited with.', { code: 'invite_only' });
  if (await accountParticipant(env, poll.id, user.id)) return;
  const g = await env.DB.prepare('SELECT id FROM participants WHERE poll_id = ? AND user_id IS NULL AND LOWER(email) = ? LIMIT 1').bind(poll.id, user.email.toLowerCase()).first();
  if (!g) throw new HttpError(403, 'Only invited people can answer this poll, and this account isn’t invited.', { code: 'not_invited' });
  await toAccountRow(env, g.id, user).run();
}
// ---------- personal links ----------
// A guest's own link to a poll: /?p=<poll>#k=<pid>.<token> (fragment: never in server logs). The token is an HMAC of
// poll, person and participants.link_ver with the LINK_KEY secret, so nothing secret is stored; "New link" bumps link_ver.
// Only guest rows have one: accounts sign in. The page sends it back as x-person-key; when signed in it's ignored.
const PKEY_RE = /^([\w-]{1,40})\.([\w-]{22})$/;
const PERSONS = new WeakMap(); // request -> participant row (or null), worked out once per request
async function linkToken(env, pollId, pid, ver) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.LINK_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(`plink:${pollId}:${pid}:${ver || 0}`));
  return b64url(new Uint8Array(sig)).slice(0, 22);
}
const personalLink = async (env, base, pollId, p) => `${base}/?p=${pollId}#k=${p.id}.${await linkToken(env, pollId, p.id, p.link_ver)}`;
async function personByKey(request, env, pollId) {
  if (PERSONS.has(request)) return PERSONS.get(request);
  PERSONS.set(request, null);
  const m = env.LINK_KEY && !userOf(request) && PKEY_RE.exec(request.headers.get('x-person-key') || '');
  if (!m) return null;
  await checkThrottle(env, request, 'name');
  const p = await env.DB.prepare('SELECT * FROM participants WHERE id = ? AND poll_id = ? AND user_id IS NULL').bind(m[1], pollId).first();
  if (p && safeEqual(await linkToken(env, pollId, p.id, p.link_ver), m[2])) { PERSONS.set(request, p); return p; }
  await recordFail(env, request, 'name');
  return null;
}
// ---------- shared busy hours ----------
// PUT /api/polls/:id/instances/:iid/busy { share, hours? }: the caller's account participant turns sharing on / off.
// hours = { "YYYY-MM-DD": [0..23] } for this round's dates, worked out in the sharer's browser from their own calendars.
// Turning it off deletes everything they shared with this poll.
const BUSY_PER_DAY = 300;
async function shareBusy(request, env, id, iid) {
  const user = requireUser(request);
  const poll = await loadPoll(env, id);
  const admin = await isAdmin(request, env, poll);
  if (!admin) await checkPassword(env, request, poll);
  const inst = await loadInstance(env, id, iid);
  await requireInvited(env, poll, user, admin, request);
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
// kind 'help' (the help assistant) has its own, larger cap.
async function aiQuota(request, env, user, kind = 'ai') {
  const help = kind === 'help';
  const key = user ? 'u:' + user.id : clientIp(request), max = Number(help ? env.HELP_PER_DAY : env.AI_PER_DAY) || (help ? HELP_PER_DAY : AI_PER_DAY);
  const since = new Date(Date.now() - 86400000).toISOString();
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND kind = ? AND at > ?').bind(key, kind, since).first('n');
  if (n >= max) throw new HttpError(429, help ? `You can ask the help assistant ${max} questions a day. Try again tomorrow.` : `You can fill from text ${max} times a day. Try again tomorrow.`);
  await recordFail(env, request, kind, key);
}
// Runs the model with a JSON schema and returns the parsed object (or null).
// text = the user's text, or a list of chat turns [{ role, content }].
async function aiJson(env, system, text, schema, maxTokens = 600, temperature = 0) {
  let out;
  try {
    out = await env.AI.run(env.AI_MODEL || AI_MODEL, {
      messages: [{ role: 'system', content: system }, ...(Array.isArray(text) ? text : [{ role: 'user', content: text }])],
      response_format: { type: 'json_schema', json_schema: schema },
      max_tokens: maxTokens, temperature,
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
  const admin = await isAdmin(request, env, poll);
  if (!admin) await checkPassword(env, request, poll);
  const inst = await loadInstance(env, id, iid);
  if (effStatus(inst) !== 'open' && !admin) throw new HttpError(409, 'This poll is closed');
  const b = await body(request);
  const text = str(b.text, 500, 'Text', true);
  const user = userOf(request);
  await requireInvited(env, poll, user, admin, request);
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
  await requireAdmin(request, env, poll, 'edit');
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

// ---------- Generate questions with AI (organiser, Questions tab) ----------
// The organiser describes what they want to ask; the model drafts questions in the page's question shape. Nothing is
// saved here: the page shows them for picking and saves the picked ones with the normal PATCH (validateQuestions).
// Only the text and the poll's title are sent.
const QGEN_MAX = 15;
const QGEN_SCHEMA = {
  type: 'object',
  properties: {
    title: { type: 'string' }, icon: { type: 'string' },
    questions: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          type: { type: 'string', enum: ['radio', 'check', 'select', 'rating', 'short', 'long', 'yesno'] }, label: { type: 'string' }, help: { type: 'string' },
          options: { type: 'array', items: { type: 'string' } },
          required: { type: 'boolean' }, private: { type: 'boolean' }, place: { type: 'boolean' }, add: { type: 'boolean' },
          rating_max: { type: 'integer' }, low: { type: 'string' }, high: { type: 'string' }, count_label: { type: 'string' },
          after: { type: 'string', enum: ['no', 'each', 'last'] },
        },
        required: ['type', 'label', 'help', 'options', 'required', 'private', 'place', 'add', 'rating_max', 'low', 'high', 'count_label', 'after'],
      },
    },
  },
  required: ['title', 'icon', 'questions'],
};
function qgenPrompt(poll, lang) {
  return [
    'You write a short form (questions) for the people of a scheduling poll, from the organiser\'s description.',
    `The poll is called: "${String(poll.title || '').slice(0, 120)}".`,
    'Question types: radio = pick one option; check = pick several; select = dropdown, pick one (long lists); rating = stars 1..rating_max;',
    'short = one line of text; long = a paragraph of text; yesno = yes / no, with an optional number asked after yes (count_label, e.g. "How many guests?").',
    'Use them like this: voting on a place or restaurant = radio with place true and add true (options = places named in the text, else empty);',
    'dietary or health needs = check (or long) with private true; bringing someone = yesno with count_label; feedback = rating (rating_max 5, low / high labels);',
    'choices of food, tasks, dates the text lists = radio or check with those options. Let people add options (add true) when the list is open-ended.',
    'Each question: label = the question, short and friendly; help = an optional short note ("" if none); options = choice labels (only for radio / check / select, else []);',
    'required = must be answered (default false); private = only the organiser sees the answers (default false); place = options are places (default false);',
    'rating_max = 5 unless said; low / high = rating labels ("" if none); count_label = "" unless yesno asks for a number.',
    'after = "no" normally; "each" for feedback asked after every meeting has happened ("how was each rehearsal"); "last" for feedback on only the latest meeting ("rate the last session").',
    'Write 2 to 8 questions unless the text asks for a number. Don\'t ask about dates or times: the poll already does that.',
    'title = a short name for the whole questionnaire (2-4 words); icon = one fitting emoji.',
    `Write everything in the language of the text (it may be ${lang === 'de' ? 'German or English' : 'English or German'}). Answer only with the JSON object.`,
  ].join('\n');
}
// Shared by Generate questions and Generate a poll: model output → questions in the page's shape (options as plain labels).
const aiLine = (v, n) => String(v ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, n);
const AI_PLACEHOLDER = /^(option|choice|auswahl|möglichkeit|wahl|game|spiel|place|ort)\s*[a-z]?\d*$/i; // "Option 1": made up, not from the text
const aiIcon = (v) => { try { return emojiIcon(aiLine(v, 16), 'Icon') || undefined; } catch { return undefined; } };
function aiQuestions(list) {
  const line = aiLine, out = [];
  for (const x of Array.isArray(list) ? list.slice(0, QGEN_MAX) : []) {
    if (!x || typeof x !== 'object' || !Q_TYPES.includes(x.type)) continue;
    const label = line(x.label, 200);
    if (!label) continue;
    const q = { type: x.type, label, help: line(x.help, 500) || undefined, req: x.required === true || undefined, vis: x.private === true ? 'owner' : 'all' };
    if (Q_CHOICE.has(q.type)) {
      const seen = new Set();
      q.options = (Array.isArray(x.options) ? x.options : []).map((o) => line(o, 120))
        .filter((o) => o && !AI_PLACEHOLDER.test(o) && !seen.has(o.toLowerCase()) && seen.add(o.toLowerCase())).slice(0, MAX_Q_OPTIONS);
      if (x.place === true) q.place = true;
      if (q.type !== 'select' && (x.add === true || !q.options.length)) q.add = true;
      if (q.type === 'select' && !q.options.length) q.type = 'radio', q.add = true;
    }
    if (q.type === 'rating') {
      const n = Math.round(Number(x.rating_max));
      q.rating = { max: Number.isFinite(n) ? Math.min(10, Math.max(3, n)) : 5, lo: line(x.low, 40) || undefined, hi: line(x.high, 40) || undefined };
    }
    if (q.type === 'yesno' && line(x.count_label, 60)) q.count = { label: line(x.count_label, 60), max: 20 };
    if (x.after === 'each' || x.after === 'last') { q.link = { to: 'after', ...(x.after === 'last' ? { last: true } : {}) }; q.who = { mode: 'meeting' }; }
    out.push(q);
  }
  return out;
}
async function questionsFromText(request, env, id, iid) {
  if (!env.AI) throw new HttpError(503, 'Filling from text isn’t available here');
  const poll = await loadPoll(env, id);
  await requireAdmin(request, env, poll, 'edit');
  await loadInstance(env, id, iid);
  const b = await body(request);
  const text = str(b.text, 500, 'Text', true);
  await aiQuota(request, env, userOf(request));
  const r = await aiJson(env, qgenPrompt(poll, reqLang(request)), text, QGEN_SCHEMA, 2000, 0.3);
  const out = aiQuestions(r && r.questions);
  if (!out.length) throw new HttpError(502, 'Couldn’t understand that. Try saying it differently.');
  const title = aiLine(r.title, 120);
  return json({ group: title ? { label: title, icon: aiIcon(r.icon) } : null, questions: out });
}

// ---------- Generate a poll with AI (New poll page) ----------
// The person describes the poll; the model drafts the New poll form (settings + questions) in a preset's data shape,
// checked by presetData (same checks as creating a poll). Nothing is saved: the page fills its form and the person
// creates the poll as usual. Only the text is sent.
const POLLGEN_SCHEMA = {
  type: 'object',
  properties: {
    title: { type: 'string' }, icon: { type: 'string' }, description: { type: 'string' },
    kind: { type: 'string', enum: ['single', 'series', 'weekly'] }, unit: { type: 'string', enum: ['week', 'month'] }, every: { type: 'integer' },
    start_date: { type: 'string' }, days: { type: 'integer' },
    answer_mode: { type: 'string', enum: ['days', 'slots', 'both'] }, weekdays: { type: 'array', items: { type: 'string' } },
    from: { type: 'integer' }, to: { type: 'integer' }, location: { type: 'string' },
    questionnaire_title: { type: 'string' }, questions: QGEN_SCHEMA.properties.questions,
  },
  required: ['title', 'icon', 'description', 'kind', 'unit', 'every', 'start_date', 'days', 'answer_mode', 'weekdays', 'from', 'to', 'location', 'questionnaire_title', 'questions'],
};
function pollGenPrompt(lang) {
  const t = today(), wd = (d) => FILL_WD[isoWd(d)];
  const wk = (n) => { const a = addDays(t, 7 * n - isoWd(t)); return `${a} to ${addDays(a, 6)}`; };
  return [
    'You set up a scheduling poll ("when is everyone free?") from the organiser\'s description. People mark the days or hours they are free.',
    `Today is ${t} (${wd(t)}). This week = ${wk(0)}, next week = ${wk(1)} (Monday to Sunday). Dates are always in the future: a month that has passed this year means next year.`,
    'title = short poll title (2-6 words); icon = one fitting emoji; description = one or two friendly sentences for the people answering ("" if nothing to add).',
    'kind: single = one date range to find a date in (a trip, a party, one meeting); series = a new poll every week or month for something that happens',
    'again and again (monthly club night, weekly training: unit week | month, every = 1 unless said); weekly = find a fixed regular weekly slot (a typical week, no dates).',
    'For single: start_date = first day of the range (YYYY-MM-DD, "" = today) and days = how many days the range covers (default 14; "next week" = next Monday, 7 days;',
    '"in March" = March 1st, 31 days; at most 365). For series and weekly: start_date "" and days 0.',
    'answer_mode: days = whole days (trips, day events, anything over several days); slots = hours (meetings, dinners, evenings, calls); both = days and hours.',
    'weekdays = which days are offered: "all", "weekdays", "weekend" or names (mon tue wed thu fri sat sun). "Not on Friday" = the other six.',
    'from / to = hours offered (24-hour clock, "to" exclusive, 0-24). "Morning" = 8-12, "afternoon" = 12-17, "evening" = 17-22, "lunch" = 12-14; default 8 to 24.',
    'location = where people meet, if the text names a place ("" otherwise).',
    'questions = a short form for the people (0 to 6), only for things the text asks or clearly needs, never about dates or times (the poll does that).',
    'Question types: radio = pick one; check = pick several; select = dropdown; rating = stars 1..rating_max; short / long = text; yesno = yes / no, optional number after yes (count_label).',
    'Voting on a place = radio with place true and add true; dietary needs = short with private true; bringing someone = yesno with count_label; feedback after meetings = rating with after "each" or "last".',
    'Each question: label = a full, friendly question ("Which game shall we play?"); help ("" if none); options = only choices the text names, never made-up ones like "Option 1"',
    '(else [] with add true, so people suggest them); required; private; place; add; rating_max (5); low; high;',
    'count_label = "" unless a number really fits after yes (e.g. "How many guests?"); after = "no" normally.',
    'questionnaire_title = a 2-4 word name for the questions if there are several, else "".',
    `Write everything in the language of the text (it may be ${lang === 'de' ? 'German or English' : 'English or German'}). Answer only with the JSON object.`,
  ].join('\n');
}
// ---------- help assistant (Workers AI) ----------
// "How do I …?" questions about the site, from the ? menu in the app bar. The page sends the last few turns and which
// page it's on; the model answers from HELP_DOC and may point at one place to open (show). Nothing is stored.
const HELP_PAGES = ['home', 'new', 'account', 'poll-answer', 'poll-edit', 'poll-manage', 'other'];
const HELP_SHOW = ['none', 'tour', 'new_poll', 'account', 'notifications', 'tab_answers', 'tab_meetings', 'tab_questions', 'tab_people', 'settings', 'chat', 'fill_ai'];
const HELP_SCHEMA = {
  type: 'object',
  properties: { answer: { type: 'string' }, show: { type: 'string', enum: HELP_SHOW } },
  required: ['answer', 'show'],
};
const HELP_DOC = `when-who is a free website for availability polls ("when is everyone free?") and for planning the meetings that follow.

POLLS. New poll (button on the home page). Which days and times: a list of rules that add up (e.g. weekdays 17–22 and weekends 10–22); Add puts a new empty rule in the list, click a rule to select it and change it (click again to unselect), the eye switches a rule off without deleting it. After Create poll, the browser's Back button goes back to the form to change the poll (same link). Kinds: One-off (one date range, e.g. a trip), Recurring (a new round every week or month, e.g. a monthly club night; earlier answers and the chat are kept together; rounds are listed in Settings → Rounds, others switch rounds with the round chip in the header) and Weekly schedule (a typical week, to find a regular weekly slot). People answer by whole days, by hours, or both. Start from: pick a ready-made preset (about 20 kinds, with fitting questions) or one of your own; "Describe it" lets AI fill the form from a sentence. Save as preset keeps settings for next time. Optional: reply-by date (deadline), poll password, Only invited people can answer, Hide answers from respondents, Chat on/off, an emoji or picture icon. You need to sign in to create and manage polls; answering works without an account.

SIGNING IN. Type your email, you get a 6-digit code by email (valid 10 minutes). There is no password.

ANSWERING (Availability tab → Mine). Paint days with the brush: Yes (green), If needed (amber), No (red). Tap or range: tap marks one day, range marks from one day to another. Open a day to fine-tune hours. Quick fill… sets rules like "weekdays 18–22". Fill with AI (✨): type "weekdays after 6, not Fridays" and it marks it for you. Undo ↶ / redo ↷ (also Cmd/Ctrl+Z). Then press Send/Save. Guests give a name (and optionally an email); they can come back with the same browser, or with a personal link the organiser sends. Group view: see everyone's answers and the best days/times.
Calendars (Account page): connect Google or Outlook, or paste an iCal link; your busy hours show greyed out while answering (Busy ▾ in My answer). You can share when you're busy with the poll's people (Share switch); only the busy hours are shared, never event titles. Busy ▾ → Other polls (signed in) also greys out meetings you're in and hours you marked available / if needed in your other open polls; only you see that. It is off at first: switch it on there or in Account → Calendars (Show my busy hours from other polls). The Busy ▾ menu can limit it to My answers or Meetings, and to certain polls.

MEETINGS tab. The organiser (and editors) plan meetings: Plan new, pick times from the answers, Quick Suggest (⚡) proposes the best times, Suggest with AI (✨) from a sentence like "2 evening meetings a week, not Fridays". Let people vote = propose several options and people vote. A meeting can have a place (place search), a note, repeat, and show answers from the poll. Everyone can add meetings to their calendar (.ics / subscribe), and the organiser can email everyone. At the top of the Meetings tab, "Get these meetings in your calendar" has one-tap buttons to subscribe in Apple Calendar (iPhone, iPad, Mac), Google Calendar or Outlook, Copy link for other apps, and Show me how (a short animated guide per app). A subscribed calendar updates by itself when meetings are added, changed or cancelled (calendar apps check every few hours). When the meetings already exist, Settings → Meetings → Create the meetings from these times makes one meeting per offered day for each run of hours without a break (also in every new round).

QUESTIONS tab. A small form for each round: choice, checkboxes, dropdown, rating, short/long text, yes/no, place vote; group them into questionnaires; Generate with AI (✨). Questions can be linked to meetings (shown on the meeting card) or asked per meeting, before or after it: in the question editor's "Applies to", pick Before each meeting or After each meeting and how many days before / after it opens (e.g. "What will you bring?" 2 days before, closing when the meeting starts; "Rate the evening" 1 day after). People who may answer get a notification when it opens. Results show bars and averages. Recurring polls: questions come back in every new round ("Ask again in new rounds" in the question editor or its ⋯ menu; "Only this round" stops it). Settings → Questions → Questions for every round (New poll: Questions, when Recurring) is a list that each new round gets fresh. "+ Month" / "+ Dates" put {month} / {dates} into a question, filled in per round (e.g. "What songs should we practice in {month}?"). Remind (🔔 in the Questions tab, or ⋯ on a question): people who haven't answered get a reminder, accounts by their notification settings (push / email), guests by email with their own link; at most every 10 minutes. Settings → Email → Reminder can also remind about unanswered questions automatically on the same day.

PEOPLE tab. Add people (by email, from your saved contacts or groups), send invites and reminders, copy each guest's personal link (⋯ menu). The owner can give accounts roles: Admin (manage settings, people, emails), Editor (meetings, questions, rounds), Viewer (see everything). Merge someone who answered under another name with "This is someone invited…". Save selected people as a group. Share: Copy link or Share invite in the header.

CHAT. The round button at the bottom right opens the poll's group chat (signed-in people write; guests can read along and see what happens in the poll). Tag people with @, reply, react, attach meetings, write in a day's or meeting's thread. 🔔 in the chat header mutes it.

NOTIFICATIONS. Push notifications on phones and computers (on iPhone only from the Home Screen app: Share → Add to Home Screen). "Show me how" buttons (Account → Notifications, the poll's 🔔, the chat) play a short animation of where to tap or click, for iPhone, Android, Chrome / Edge and Safari on a Mac; blocked notifications on a computer: it shows how to allow them again and optional email digests. Defaults in Account → Notifications; per poll with the 🔔 button in the poll header. After the first tour (and the first start of the Home Screen app) when-who offers to add it to the Home Screen and turn on notifications. Tapping a notification opens the poll's chat (or the tab it is about); the sender's name and picture show on Android and computers, and the installed app's icon shows the number of unread messages.

SETTINGS (organiser only): title, dates, answer mode, deadline, password, invited only, hide answers, chat, rounds of a recurring poll, defaults for new meetings (location, description, questions; the switch "Apply to all meetings" puts them on every meeting, also existing ones, and keeps them updated), delete the poll.

ACCOUNT page: name, avatar, email change, calendars, contacts (save people, ✎ edit name / email / a private note; when a contact goes by another name in your polls, pick Use theirs or Keep mine, which also shows your name for them in polls you manage) and groups, notifications, presets, Your data (download a copy, delete the account). Polls without activity for 12 months are deleted (the owner is emailed 14 days before).

OTHER: Guided tour = the ? button → Take the tour. Language and light/dark theme are in the top bar. when-who is free; there is no store app, but you can add it to the Home Screen on a phone or install it from Chrome / Edge (install icon in the address bar) or Safari on a Mac (File → Add to Dock); the account menu's Add to Home Screen / Install app shows how. Signed-in people now and then get a small card suggesting this or turning on notifications.

OVERVIEW CHATS. On the home page every poll card shows its chat's newest message (who wrote it, the start of it and when), in bold with a green count while unread; tap it to open the chat. Sort → Latest message puts polls with new messages first (the default).

UPCOMING. At the top of the home page (signed in), Upcoming shows the next two weeks across all your polls: a strip of days with dots, and below it a list by day of meetings you're in (time, place), meetings proposed for a vote (Vote / Voted) and reply-by dates (Reply by for polls you haven't answered yet, Replies close for your own polls). Tap a day to see only that day; tap a row to open the poll (meetings open its Meetings tab). Polls hidden from the overview are left out.
CALENDAR. The calendar button in the Upcoming card's header opens a full calendar (Month, Week or List; arrows move by a month or week, Today jumps back). It shows meetings you're in, meetings to vote on, reply-by dates, To do items, the hours you marked free in other polls' open rounds and the events of the calendars linked on your Account page (Google, Outlook or iCal links; read in your browser, never stored). Each poll and each linked calendar has its own colour; the small icon says what kind of item it is. The Filter button turns kinds, polls and calendars on or off and lets you pick a colour per poll (kept on this device) and a colour and emoji per linked calendar (also in Account, Calendars). Tap a poll item to open the poll; tap a calendar event to see its details.
TO DO. Above Upcoming (signed in), To do lists what's still open for you in polls you were invited to or answered: add your availability, questions left unanswered (how many are required), proposed times to vote on, and meetings to rate or answer questions about. The reply-by date shows on the right (amber when it's today or tomorrow). Tap a row to go straight there. Poll cards show a To do count too. Polls you organise aren't listed.`;
function helpPrompt(page, lang) {
  return [
    'You are the friendly help assistant of when-who. Answer the user\'s question about using when-who, using only the guide below.',
    'Rules: be short (at most 120 words), concrete, with the button / tab names from the guide in bold (**like this**). Use plain sentences or a few short numbered steps.',
    'If the guide doesn\'t cover it, say you\'re not sure and suggest the guided tour or contacting the site. Never invent features.',
    'Only help with when-who. Politely decline anything else. Never ask for passwords, sign-in codes or other personal data.',
    `Write in ${lang === 'de' ? 'German (use "du")' : 'English'}.`,
    `The user is on: ${{ home: 'the home page (their polls)', new: 'the New poll page', account: 'their Account page', 'poll-answer': 'a poll, as someone answering it', 'poll-edit': 'a poll, as an editor', 'poll-manage': 'a poll they organise', other: 'another page' }[page]}.`,
    `Set "show" to the one place that helps most (${HELP_SHOW.filter((x) => x !== 'none').join(', ')}; tab_* and settings, chat, fill_ai only on a poll page; settings only for organisers). Pick one whenever the answer is about a button, tab or page there (e.g. new_poll for making a poll, tab_meetings for picking a time); "none" only when nothing fits.`,
    '', 'GUIDE:', HELP_DOC,
  ].join('\n');
}
async function helpAsk(request, env) {
  if (!env.AI) throw new HttpError(503, 'The help assistant isn’t available here');
  const b = await body(request);
  const list = Array.isArray(b.messages) ? b.messages.slice(-8) : [];
  const msgs = list.map((x) => ({ role: x && x.role === 'assistant' ? 'assistant' : 'user', content: String((x && x.content) || '').trim().slice(0, 600) })).filter((x) => x.content);
  if (!msgs.length || msgs[msgs.length - 1].role !== 'user') throw new HttpError(400, 'Type a question');
  const page = HELP_PAGES.includes(b.page) ? b.page : 'other';
  await aiQuota(request, env, userOf(request), 'help');
  const r = await aiJson(env, helpPrompt(page, reqLang(request)), msgs, HELP_SCHEMA, 500, 0.2);
  const answer = r && typeof r.answer === 'string' ? r.answer.trim().slice(0, 2000) : '';
  if (!answer) throw new HttpError(502, 'Couldn’t understand that. Try saying it differently.');
  return json({ answer, show: HELP_SHOW.includes(r.show) && r.show !== 'none' ? r.show : null });
}

async function pollFromText(request, env) {
  if (!env.AI) throw new HttpError(503, 'Filling from text isn’t available here');
  const b = await body(request);
  const text = str(b.text, 500, 'Text', true);
  await aiQuota(request, env, userOf(request));
  const r = await aiJson(env, pollGenPrompt(reqLang(request)), text, POLLGEN_SCHEMA, 2500, 0.3);
  if (!r) throw new HttpError(502, 'Couldn’t understand that. Try saying it differently.');
  const num = (v, lo, hi, d) => { const n = Math.round(Number(v)); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d; };
  const kind = ['single', 'series', 'weekly'].includes(r.kind) ? r.kind : 'single';
  const d = { title: aiLine(r.title, 120) || aiLine(text, 60), description: aiLine(r.description, 1000), kind, icon: aiIcon(r.icon) || '',
    allowComments: true, meetLocation: aiLine(r.location, 200) };
  d.answerMode = ['days', 'slots', 'both'].includes(r.answer_mode) ? r.answer_mode : 'days';
  if (kind === 'weekly' && d.answerMode === 'days') d.answerMode = 'slots';
  if (kind === 'series') {
    d.unit = r.unit === 'week' ? 'week' : 'month';
    d.every = num(r.every, 1, d.unit === 'week' ? 12 : 3, 1);
    Object.assign(d, d.unit === 'week' ? { openDays: 6, deadlineDays: 2 } : { openDays: 11, deadlineDays: 4 });
  }
  let hs = num(r.from, 0, 23, 8), he = num(r.to, 1, 24, 24);
  if (d.answerMode === 'days' || he <= hs) { hs = 8; he = 24; }
  d.hourStart = hs; d.hourEnd = he;
  const wd = new Set();
  for (const x of Array.isArray(r.weekdays) ? r.weekdays.slice(0, 20) : []) {
    const v = String(x).toLowerCase().trim();
    if (v === 'all') [0, 1, 2, 3, 4, 5, 6].forEach((i) => wd.add(i)); else fillWds(v).forEach((i) => wd.add(i));
  }
  if (wd.size && wd.size < 7) d.dayPattern = { wd: [...wd].sort() };
  let startDate;
  if (kind === 'single') {
    d.days = num(r.days, 1, MAX_RANGE_DAYS, 14);
    let sd = String(r.start_date || '').trim();
    if (isDate(sd) && sd < today()) { const y = String(+sd.slice(0, 4) + 1) + sd.slice(4); if (isDate(y) && y >= today()) sd = y; } // "in July" in November = next July
    if (isDate(sd) && sd >= today() && sd <= addDays(today(), 400)) startDate = sd;
    // Make sure the range has at least one offered day (else the form can't be sent): widen it to a week.
    if (d.dayPattern && d.days < 7) {
      const s0 = startDate || today();
      let any = false; for (let i = 0; i < d.days; i++) if (wd.has(isoWd(addDays(s0, i)))) any = true;
      if (!any) d.days = 7;
    }
    d.remindDays = 2;
  }
  // Questions, in one questionnaire when the model named one (after-meeting questions keep their own link).
  let qs = aiQuestions(r.questions).slice(0, 8).map((q) => ({ ...q, options: q.options ? q.options.map((label) => ({ label })) : undefined }));
  const qt = aiLine(r.questionnaire_title, 120);
  if (qt && qs.length >= 2) qs = [{ id: 'grpAi1', type: 'group', label: qt, link: { to: 'poll' }, who: { mode: 'all' } },
    ...qs.map((q) => ({ ...q, grp: 'grpAi1', ...(q.link ? { own: true } : {}) }))];
  if (qs.length) d.questions = qs;
  let data;
  try { data = JSON.parse(presetData(d)); } catch (e) {
    console.log('AI poll rejected', e && e.message);
    delete d.questions; delete d.dayPattern;
    try { data = JSON.parse(presetData(d)); } catch { throw new HttpError(502, 'Couldn’t understand that. Try saying it differently.'); }
  }
  return json({ data, ...(startDate ? { startDate } : {}) });
}

async function createResponse(request, env, ctx, id, iid) {
  const poll = await loadPoll(env, id);
  const admin = await isAdmin(request, env, poll, 'manage');
  if (!(await isAdmin(request, env, poll))) await checkPassword(env, request, poll);
  const inst = await loadInstance(env, id, iid);
  if (effStatus(inst) !== 'open' && !admin) throw new HttpError(409, 'This poll is closed');
  const b = await body(request);
  const user = userOf(request);
  await requireInvited(env, poll, user, admin, request);
  // Signed in: the name shown to others is the account's profile name (typed name only while the profile has none).
  const mine = user ? await accountRow(env, id, user) : null;
  const linked = user ? null : await personByKey(request, env, id);
  const name = user ? acctName(user, b.name, mine) : linked ? linked.name : personName(b.name);
  const comment = poll.allow_comments ? str(b.comment, 500, 'Comment') : '';
  const mail = user ? user.email : (linked && linked.email) || email(b.email);
  if (poll.require_email && !mail && !admin) throw new HttpError(400, 'This poll asks for your email address');
  const entries = validateEntries(b.entries, poll, datesOf(inst, poll));
  const fill = parseFill(b.fill, poll, datesOf(inst, poll));
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM responses WHERE instance_id = ?').bind(iid).first('n');
  if (count >= MAX_RESPONSES) throw new HttpError(409, 'This poll has reached its maximum number of responses');
  let part;
  const person = user ? null : await personByKey(request, env, id);
  if (person) { // their personal link: this is that person, whatever name is typed
    part = person;
    const existing = await answerIn(env, part.id, iid);
    if (existing) throw new HttpError(409, 'You have already answered this poll', { code: 'own_answer', responseId: existing });
  } else if (user) { // signed in: one participant per account, whatever name they give
    part = mine;
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
      // One email = one person: a guest row with this address (added by the organiser, or an earlier answer) is this
      // person, under the name it already has here (the organiser's saved name wins over the typed one).
      const byMail = mail ? await guestRowsByEmail(env, id, mail) : [];
      part = byMail.shift() || null;
      if (part) for (const g of byMail.slice(0, 3)) await mergeInto(env, g, part); // duplicates from before
      else {
        // Same name as an existing guest: that's this person (e.g. the next round of a series), unless that row
        // has another email address (then it's someone else).
        part = await findParticipant(env, id, nameKey(name));
        if (part && mail && part.email && part.email.trim().toLowerCase() !== mail.toLowerCase())
          throw new HttpError(409, `“${part.name}” is already in this poll with another email address. Use that address, or add something to your name.`, { code: 'name_other_email' });
      }
      if (part) {
        const existing = await answerIn(env, part.id, iid);
        if (existing) throw nameTaken(part.name, part.id, existing);
        if (mail && !part.email) await env.DB.prepare("UPDATE participants SET email = ? WHERE id = ? AND COALESCE(email, '') = ''").bind(mail, part.id).run();
      } else part = await newParticipant(env, id, name, mail || '');
      if (acct && !ap) await linkGuestToAccount(env, id, part.id, mail);
    }
  }
  const rid = randomId(12), editKey = secret(), t = now();
  await env.DB.prepare('INSERT INTO responses (id, poll_id, instance_id, name, email, comment, entries, edit_hash, participant_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .bind(rid, id, iid, part.name, mail, comment, JSON.stringify(entries), await sha256('edit:' + editKey), part.id, t, t).run();
  if (fill) await env.DB.prepare('UPDATE responses SET fill = ? WHERE id = ?').bind(fill, rid).run(); // column from migration 0015
  fireEvent(ctx, env, poll, { kind: 'answer', iid, actor: user && user.id, name: part.name, ref: part.id });
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
  const person = r.participant_id ? await personByKey(request, env, r.poll_id) : null;
  if (person && person.id === r.participant_id) return true;
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
  if (!(await isAdmin(request, env, poll))) await checkPassword(env, request, poll);
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
  if (!(await isAdmin(request, env, poll, 'manage')) && !(await canEditResponse(request, env, r))) throw new HttpError(403, 'Not your response');
  return json({ id: r.id, instanceId: r.instance_id, name: r.name, email: r.email, comment: r.comment, entries: JSON.parse(r.entries),
    fill: r.fill ? JSON.parse(r.fill) : null, votes: parseVotes(r.votes, proposedIds(await loadInstance(env, id, r.instance_id))) });
}
// ---- votes on proposed meetings: responses.votes = JSON array of the meeting ids the person ticked.
const proposedIds = (inst) => new Set(JSON.parse(inst.meetings || '[]').filter((x) => x.proposed).map((x) => x.id));
function parseVotes(raw, props) { let v; try { v = JSON.parse(raw || '[]'); } catch { v = []; } return Array.isArray(v) ? v.filter((x) => props.has(x)) : []; }
// PUT /api/polls/:id/responses/:rid/votes { votes: [meetingId] } — by the answer's owner (same rule as editing it) or the organiser.
async function voteMeetings(request, env, ctx, id, rid) {
  const poll = await loadPoll(env, id);
  const r = await loadResponse(env, id, rid);
  const inst = await loadInstance(env, id, r.instance_id);
  const admin = await isAdmin(request, env, poll, 'manage');
  if (!admin && !(await canEditResponse(request, env, r))) throw new HttpError(403, 'Not your response');
  if (!(await isAdmin(request, env, poll))) await checkPassword(env, request, poll);
  const b = await body(request);
  const props = proposedIds(inst);
  if (!Array.isArray(b.votes) || b.votes.length > MAX_MEETINGS) throw new HttpError(400, 'Invalid votes');
  if (b.votes.some((x) => typeof x !== 'string' || !props.has(x))) throw new HttpError(400, 'That option is no longer up for a vote');
  // Pick-one votes keep only the last option the person sent for that vote (older picks may predate the switch).
  const grp = new Map(JSON.parse(inst.meetings || '[]').filter((x) => x.proposed && x.one).map((x) => [x.id, x.vote || '']));
  const seen = new Set();
  const votes = [...new Set(b.votes)].reverse().filter((x) => { if (!grp.has(x)) return true; const g = grp.get(x); if (seen.has(g)) return false; seen.add(g); return true; }).reverse();
  await env.DB.prepare('UPDATE responses SET votes = ? WHERE id = ?').bind(votes.length ? JSON.stringify(votes) : null, r.id).run();
  if (JSON.stringify(parseVotes(r.votes, props).sort()) !== JSON.stringify([...votes].sort()))
    fireEvent(ctx, env, poll, { kind: 'vote', iid: inst.id, actor: (userOf(request) || {}).id, name: r.name, ref: r.participant_id || r.id });
  return json({ ok: true, votes });
}
// ---- questions: a small form per round (instances.questions), answered apart from the availability (form_answers).
// Types: radio (one of), check (several), select (dropdown), rating (1..max), short / long text, yesno (+ optional count).
// link: { to: 'poll' } or { to: 'meetings', ids, each? } (each = one answer per date of a repeating meeting: { "YYYY-MM-DD": answer }).
// who: { mode: 'all' | 'people' (pids) | 'meeting' (people invited to the linked meetings) | 'free' (free at their time) }.
// form_answers.extra = { a: { qid: answer }, add: { qid: [{ id, label }] } }; add = options the person suggested (radio / check
// with add: true), kept in their own row so they go away with it.
const MAX_QUESTIONS = 30, MAX_Q_OPTIONS = 40, MAX_ADD_OPTIONS = 5;
const QID_RE = /^[A-Za-z0-9]{4,20}$/;
const Q_TYPES = ['radio', 'check', 'select', 'rating', 'short', 'long', 'yesno'];
const Q_CHOICE = new Set(['radio', 'check', 'select']);
const Q_WHO = ['all', 'people', 'meeting', 'free'];
// Questions saved by 0022 (type choice / text, meetings) in today's shape.
function normQ(q) {
  if (!q || typeof q !== 'object') return null;
  let x = { ...q };
  if (x.type === 'choice') x.type = x.multi ? 'check' : 'radio';
  else if (x.type === 'text') x.type = 'long';
  if (!x.link) x.link = Array.isArray(x.meetings) && x.meetings.length ? { to: 'meetings', ids: x.meetings } : { to: 'poll' };
  if (!x.who) x.who = { mode: 'all' };
  delete x.multi; delete x.meetings;
  return Q_TYPES.includes(x.type) ? x : null;
}
// Questionnaires (type 'group': label, icon, help, link, who) sit in the same list; a question joins one with grp.
function itemsOf(inst) { try { const q = JSON.parse(inst.questions || '[]'); return Array.isArray(q) ? q.filter((x) => x && typeof x === 'object') : []; } catch { return []; } }
const groupsOf = (inst) => itemsOf(inst).filter((x) => x.type === 'group');
// The questions, with link / who taken from their questionnaire unless they have their own (own: true).
function questionsOf(inst) {
  const items = itemsOf(inst), gs = new Map(items.filter((x) => x.type === 'group').map((g) => [g.id, g]));
  return items.filter((x) => x.type !== 'group').map(normQ).filter(Boolean).map((q) => {
    const g = q.grp && gs.get(q.grp);
    if (!g) { const { grp, ...x } = q; return x; }
    return q.own ? q : { ...q, link: g.link || { to: 'poll' }, who: g.who || { mode: 'all' } };
  });
}
function parseExtra(raw) { try { const x = JSON.parse(raw || 'null'); return x && typeof x === 'object' && !Array.isArray(x) ? x : {}; } catch { return {}; } }
const repeatsOf = (q, meetings) => (q.link.ids || []).map((id) => meetings.find((m) => m.id === id)).filter((m) => m && m.repeat);
// Is d one of the dates of a repeating meeting m?
function onRepeat(m, d) {
  if (!isDate(d) || d < m.repeat.from || (m.repeat.until && d > m.repeat.until)) return false;
  const first = firstOnWeekday(m.repeat.from, wdOf(m.date));
  const days = Math.round((Date.parse(d + 'T00:00:00Z') - Date.parse(first + 'T00:00:00Z')) / 86400000);
  return days >= 0 && days % (7 * m.repeat.every) === 0;
}
const MAX_QGROUPS = 15;
// Per-meeting questions (link.to 'after'): asked once per meeting date (each date of a repeating one) in its window (occWindow),
// answers { "<meeting id>:<YYYY-MM-DD>": value }. No ids = every confirmed meeting of the round.
// The Worker doesn't know the poll's time zone, so it allows 14 h either way; the page shows the exact ones.
// Timing (link.when / link.days): 'before' = opens `days` days before the meeting starts and closes when it starts;
// otherwise (after) opens `days` days after it ends and stays open.
const isAfter = (q) => !!(q && q.link && q.link.to === 'after');
const isBefore = (q) => isAfter(q) && q.link.when === 'before';
const MAX_Q_DAYS = 30;
// A per-meeting link as stored: ids / last / when / days kept.
const afterLink = (l, ids) => ({ to: 'after', ...((ids || l.ids || []).length ? { ids: ids || l.ids } : {}), ...(l.last ? { last: true } : {}),
  ...(l.when === 'before' ? { when: 'before' } : {}), ...(Number.isInteger(l.days) && l.days > 0 ? { days: Math.min(l.days, MAX_Q_DAYS) } : {}) });
const TZ_SLACK = 14 * 3600e3;
function meetEndMs(m, d) {
  const base = Date.parse(d + 'T00:00:00Z');
  if (m.allDay) return Date.parse((m.endDate && !m.repeat ? m.endDate : d) + 'T00:00:00Z') + 86400e3;
  return base + (m.end || 24) * 3600e3;
}
const meetStartMs = (m, d) => Date.parse(d + 'T00:00:00Z') + (m.allDay ? 0 : (m.start || 0) * 3600e3);
// When q opens / closes for meeting m on date d (meeting times read as UTC wall clock; close = Infinity for after-questions).
function occWindow(q, m, d) {
  const days = (q.link.days || 0) * 86400e3;
  if (isBefore(q)) { const s = meetStartMs(m, d); const d0 = Date.parse(d + 'T00:00:00Z'); return { open: days ? s - days : d0 < s ? d0 : s - 86400e3, close: s }; } // 0 days = on the day (all-day: the day before)
  return { open: meetEndMs(m, d) + days, close: Infinity };
}
// Occurrences that may be open now (newest opened first): [{ key, m, date, open, close, sure }] (sure = opened in every time zone).
// all: every occurrence, open or not (for the cron's opening notices).
function afterOccs(q, meetings, at = Date.now(), all = false) {
  const ids = q.link.ids && q.link.ids.length ? new Set(q.link.ids) : null, out = [];
  for (const m of meetings) {
    if (m.proposed || (ids && !ids.has(m.id))) continue;
    const dates = [];
    if (m.repeat) {
      for (let d = firstOnWeekday(m.repeat.from, wdOf(m.date)), i = 0; i < 520 && (!m.repeat.until || d <= m.repeat.until); i++, d = addDays(d, 7 * m.repeat.every)) {
        if (occWindow(q, m, d).open - TZ_SLACK > at) break;
        dates.push(d);
      }
    } else dates.push(m.date);
    for (const d of dates) {
      const w = occWindow(q, m, d);
      if (!all && (w.open - TZ_SLACK > at || w.close + TZ_SLACK <= at)) continue;
      out.push({ key: m.id + ':' + d, m, date: d, ...w, end: meetEndMs(m, d), sure: w.open + TZ_SLACK <= at });
    }
  }
  out.sort((a, b) => b.open - a.open);
  if (all) return out;
  if (!q.link.last) return out;
  const i = out.findIndex((o) => o.sure); // only the latest: nothing older than the newest one that has surely ended
  return i < 0 ? out : out.slice(0, i + 1);
}
// May participant part answer q for this one meeting date?
function canAnswerAt(q, part, m, d, responses) {
  const w = q.who || { mode: 'all' };
  if (w.mode === 'all') return true;
  if (!part) return false;
  if (w.mode === 'people') return (w.pids || []).includes(part.id);
  if (w.mode === 'meeting') return m.participants === 'all' || (Array.isArray(m.participants) && m.participants.some((p) => p.id === part.id));
  return freeAt(responses, part, m, d);
}
function freeAt(responses, part, m, d) {
  const r = responses.find((x) => x.participant_id === part.id);
  if (!r) return false;
  let e; try { e = JSON.parse(r.entries || '{}'); } catch { e = {}; }
  const v = e[d], ok = (x) => x === 'y' || x === 'i';
  if (typeof v === 'string') return ok(v);
  if (!v || typeof v !== 'object') return false;
  const hs = [...(v.y || []), ...(v.i || [])];
  return m.allDay ? hs.length > 0 : hs.includes(m.start);
}
// Occurrence keys of q this person may answer now.
const afterOpen = (q, part, meetings, responses, admin) => afterOccs(q, meetings).filter((o) => admin || canAnswerAt(q, part, o.m, o.date, responses)).map((o) => o.key);
// link / who of a question or questionnaire (meeting ids of this round, participant ids of this poll).
function linkWho(q, out, meetings, mids, pids) {
  const to = q.link && q.link.to;
  const ids = (to === 'meetings' || to === 'after') && Array.isArray(q.link.ids) ? [...new Set(q.link.ids.filter((x) => typeof x === 'string' && mids.has(x)))] : [];
  if (to === 'after') out.link = afterLink({ ...q.link, ids: [], days: q.link.days == null || q.link.days === '' ? 0 : int(q.link.days, 0, MAX_Q_DAYS, 'Days') }, ids);
  else out.link = ids.length ? { to: 'meetings', ids } : { to: 'poll' };
  if (to === 'meetings' && ids.length && q.link.each && repeatsOf(out, meetings).length) out.link.each = true;
  const mode = Q_WHO.includes(q.who && q.who.mode) ? q.who.mode : 'all';
  out.who = { mode };
  if (mode === 'people') {
    const ps = Array.isArray(q.who.pids) ? [...new Set(q.who.pids.filter((x) => typeof x === 'string' && pids.has(x)))] : [];
    if (!ps.length) throw new HttpError(400, 'Pick who can answer');
    out.who.pids = ps.slice(0, MAX_PARTICIPANTS);
  }
}
function validateQuestions(list, meetings, old = [], pids = new Set()) {
  if (!Array.isArray(list)) throw new HttpError(400, 'Invalid questions');
  const nq = list.filter((x) => x && x.type !== 'group').length, ng = list.length - nq;
  if (nq > MAX_QUESTIONS) throw new HttpError(400, `Up to ${MAX_QUESTIONS} questions per round`);
  if (ng > MAX_QGROUPS) throw new HttpError(400, `Up to ${MAX_QGROUPS} questionnaires per round`);
  const mids = new Set(meetings.map((m) => m.id)), prev = new Map(old.map((q) => [q.id, q])), seen = new Set();
  const newId = (x) => { const id = QID_RE.test(x || '') && !seen.has(x) ? x : randomId(8); seen.add(id); return id; };
  // Questionnaires first, so questions can refer to them.
  const gids = new Map();
  for (const g of list) if (g && g.type === 'group') gids.set(g, newId(g.id));
  const gset = new Set(gids.values());
  return list.map((q0) => {
    if (q0 && q0.type === 'group') {
      const id = gids.get(q0);
      const out = { id, type: 'group', label: str(q0.label, 120, 'Questionnaire', true), icon: emojiIcon(q0.icon, 'Icon') || undefined,
        help: str(q0.help, 500, 'Questionnaire note') || undefined, at: prev.get(id)?.at || now() };
      linkWho(q0, out, meetings, mids, pids);
      return out;
    }
    const q = normQ(q0);
    if (!q) throw new HttpError(400, 'Invalid question');
    const id = newId(q.id);
    const out = { id, type: q.type, label: str(q.label, 200, 'Question', true), help: str(q.help, 500, 'Question note') || undefined,
      icon: emojiIcon(q.icon, 'Icon') || undefined,
      req: q.req ? true : undefined, vis: q.vis === 'owner' ? 'owner' : 'all', closed: q.closed ? true : undefined,
      repeat: q.repeat === false ? false : undefined, at: prev.get(id)?.at || now() }; // at = when it was added
    if (typeof q.tpl === 'string' && QID_RE.test(q.tpl)) out.tpl = q.tpl; // a copy of the poll's every-round question q.tpl (round_questions)
    if (typeof q.mtpl === 'string' && QID_RE.test(q.mtpl)) { out.mtpl = q.mtpl; if (typeof q.mh === 'string' && q.mh.length <= 16) out.mh = q.mh; } // a copy of a meeting question template (meet_apply)
    if (typeof q.grp === 'string' && gset.has(q.grp)) { out.grp = q.grp; if (q.own) out.own = true; }
    linkWho(q, out, meetings, mids, pids);
    if (Q_CHOICE.has(q.type)) {
      const opts = Array.isArray(q.options) ? q.options : [];
      if (opts.length > MAX_Q_OPTIONS) throw new HttpError(400, `Up to ${MAX_Q_OPTIONS} options per question`);
      const os = new Set();
      out.options = opts.map((o) => {
        const oid = QID_RE.test(o?.id || '') && !os.has(o.id) ? o.id : randomId(8);
        os.add(oid);
        return { id: oid, label: str(o?.label, 120, 'Option', true) };
      });
      out.place = q.place ? true : undefined;
      if (q.type !== 'select') out.add = q.add ? true : undefined;
      if (!out.options.length && !out.add) throw new HttpError(400, 'Add an option, or let people add their own');
    }
    if (q.type === 'rating') {
      const r = q.rating || {};
      out.rating = { max: int(r.max ?? 5, 3, 10, 'Highest rating'), lo: str(r.lo, 40, 'Low label') || undefined, hi: str(r.hi, 40, 'High label') || undefined };
    }
    if (q.type === 'yesno' && q.count) out.count = { label: str(q.count.label, 60, 'Count label'), max: int(q.count.max ?? 20, 1, 99, 'Highest number') };
    return out;
  });
}
// May participant part (null = someone new) answer q? responses = the round's availability answers (for "free").
function canAnswer(q, part, meetings, responses) {
  const w = q.who || { mode: 'all' };
  if (w.mode === 'all') return true;
  if (!part) return false;
  if (w.mode === 'people') return (w.pids || []).includes(part.id);
  if (isAfter(q)) return true; // checked per meeting (afterOpen)
  const ms = (q.link.ids || []).map((id) => meetings.find((m) => m.id === id)).filter(Boolean);
  if (!ms.length) return true; // nothing linked: everyone
  if (w.mode === 'meeting') return ms.some((m) => m.participants === 'all' || (Array.isArray(m.participants) && m.participants.some((p) => p.id === part.id)));
  return ms.some((m) => freeAt(responses, part, m, m.date)); // free: marked available (or if needed) at the meeting's time
}
// What participant part still has to answer (overview To do, question reminders): a = their answers (form_answers.extra.a).
// open = questions of the round they may answer and left empty (only while the round is open; per-date ones while no date has
// an answer); after = after-meeting (or before-meeting) dates open for them now in every time zone, opened in the last 14 days, unanswered.
const qEmptyV = (v) => v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length);
const AFTER_TODO_MS = 14 * 86400e3;
function pendingQuestions(qs, part, a, meetings, responses, roundOpen, at = Date.now()) {
  const open = [], after = [];
  for (const q of qs) {
    if (q.closed || !canAnswer(q, part, meetings, responses)) continue;
    const v = a[q.id];
    if (isAfter(q)) {
      const got = v && typeof v === 'object' && !Array.isArray(v) ? v : {};
      for (const o of afterOccs(q, meetings, at))
        if (o.sure && o.open >= at - AFTER_TODO_MS && qEmptyV(got[o.key]) && canAnswerAt(q, part, o.m, o.date, responses))
          after.push({ q, key: o.key, m: o.m, date: o.date, open: o.open });
      continue;
    }
    if (!roundOpen) continue;
    if (q.link.each ? !(v && typeof v === 'object' && Object.values(v).some((x) => !qEmptyV(x))) : qEmptyV(v)) open.push(q);
  }
  after.sort((x, y) => y.open - x.open);
  return { open, req: open.filter((q) => q.req).length, after };
}
// Options people suggested in this round: Map question id → [{ id, label }] (from every form answer's `add`).
async function addedOptions(env, iid, skipId) {
  const { results } = await env.DB.prepare('SELECT id, extra FROM form_answers WHERE instance_id = ? AND extra IS NOT NULL').bind(iid).all();
  const out = new Map();
  for (const r of results) {
    if (r.id === skipId) continue;
    for (const [qid, list] of Object.entries(parseExtra(r.extra).add || {})) {
      if (!Array.isArray(list)) continue;
      if (!out.has(qid)) out.set(qid, []);
      out.get(qid).push(...list.filter((o) => o && typeof o.id === 'string' && typeof o.label === 'string'));
    }
  }
  return out;
}
const optionIds = (q, added) => new Set([...(q.options || []), ...(added.get(q.id) || [])].map((o) => o.id));
// One answer value of question q (or undefined when empty). valid = option ids it may pick.
function qValue(q, v, valid) {
  if (Q_CHOICE.has(q.type)) {
    v = Array.isArray(v) ? [...new Set(v.filter((o) => typeof o === 'string' && valid.has(o)))] : [];
    if (q.type !== 'check') v = v.slice(0, 1);
    return v.length ? v : undefined;
  }
  if (q.type === 'rating') return v == null || v === '' ? undefined : int(v, 1, q.rating.max, q.label);
  if (q.type === 'short' || q.type === 'long') return str(typeof v === 'string' ? v : '', q.type === 'short' ? 120 : 1000, q.label) || undefined;
  if (v && typeof v === 'object' && typeof v.y === 'boolean')
    return { y: v.y, ...(v.y && q.count && v.n != null && v.n !== '' ? { n: int(v.n, 0, q.count.max, q.count.label || 'Number') } : {}) };
  return undefined;
}
// Checks a person's answers to the round's questions. part = their participant (null = new), old = their saved answers.
// Questions they may not answer (closed, or not meant for them) keep the old value. needReq: required ones must be answered.
// onlyAfter: the round is closed, only after-meeting questions may still change.
async function validateExtra(env, raw, inst, { fid = null, part = null, admin = false, old = {}, needReq = true, onlyAfter = false } = {}) {
  const qs = questionsOf(inst);
  if (!qs.length) return null;
  if (raw != null && (typeof raw !== 'object' || Array.isArray(raw))) throw new HttpError(400, 'Invalid answers to questions');
  const x = raw || {}, a = x.a && typeof x.a === 'object' ? x.a : {}, addIn = x.add && typeof x.add === 'object' ? x.add : {};
  const meetings = JSON.parse(inst.meetings || '[]');
  const { results: responses } = qs.some((q) => q.who.mode === 'free')
    ? await env.DB.prepare('SELECT participant_id, entries FROM responses WHERE instance_id = ?').bind(inst.id).all() : { results: [] };
  const added = await addedOptions(env, inst.id, fid);
  const outA = {}, outAdd = {};
  for (const q of qs) {
    if ((q.closed || (onlyAfter && !isAfter(q)) || !canAnswer(q, part, meetings, responses)) && !admin) {
      if (old.a && old.a[q.id] !== undefined) outA[q.id] = old.a[q.id];
      if (old.add && old.add[q.id]) outAdd[q.id] = old.add[q.id];
      continue;
    }
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
    let v;
    if (isAfter(q)) { // per meeting date; ones that aren't open (any more) keep their old value
      const ok = new Set(afterOpen(q, part, meetings, responses, admin)), m = {};
      const obj = (o) => (o && typeof o === 'object' && !Array.isArray(o) ? o : {});
      for (const [k, pv] of Object.entries(obj(old.a && old.a[q.id]))) if (!ok.has(k)) m[k] = pv;
      for (const [k, dv] of Object.entries(obj(a[q.id])).slice(0, 200)) {
        if (!ok.has(k)) continue;
        const one = qValue(q, dv, valid);
        if (one !== undefined) m[k] = one;
      }
      v = Object.keys(m).length ? m : undefined;
    } else if (q.link.each) {
      const reps = repeatsOf(q, meetings), src = a[q.id] && typeof a[q.id] === 'object' && !Array.isArray(a[q.id]) ? a[q.id] : {}, m = {};
      for (const [d, dv] of Object.entries(src).slice(0, 60)) {
        if (!reps.some((r) => onRepeat(r, d))) continue;
        const one = qValue(q, dv, valid);
        if (one !== undefined) m[d] = one;
      }
      v = Object.keys(m).length ? m : undefined;
    } else v = qValue(q, a[q.id], valid);
    if (v !== undefined) outA[q.id] = v;
    if (needReq && q.req && !admin && !q.link.each && !isAfter(q) && v === undefined) throw new HttpError(400, `Please answer: ${roundText(q.label, {}, inst)}`, { code: 'question', question: q.id });
  }
  const out = { ...(Object.keys(outA).length ? { a: outA } : {}), ...(Object.keys(outAdd).length ? { add: outAdd } : {}) };
  return Object.keys(out).length ? JSON.stringify(out) : null;
}
// What the caller may see of someone's answers: the organiser everything, others only questions with vis 'all'.
function extraFor(raw, qs, added, full) {
  const x = parseExtra(raw), a = {};
  for (const q of qs) {
    let v = x.a && x.a[q.id];
    if (v === undefined || (!full && q.vis === 'owner')) continue;
    if (Q_CHOICE.has(q.type) && !q.link.each && !isAfter(q)) { const ok = optionIds(q, added); v = Array.isArray(v) ? v.filter((o) => ok.has(o)) : []; if (!v.length) continue; }
    a[q.id] = v;
  }
  return Object.keys(a).length ? a : undefined;
}
// The caller's form row and participant: signed in = their account in this poll; guests by the row's key (x-form-key),
// or by their availability answer (rid + the usual x-edit-key / x-edit-name).
async function formIdentity(request, env, id, iid, { fid, rid }) {
  const user = userOf(request);
  if (user) {
    const part = await accountRow(env, id, user);
    const row = part ? await env.DB.prepare('SELECT * FROM form_answers WHERE instance_id = ? AND participant_id = ?').bind(iid, part.id).first() : null;
    return { part, row, user };
  }
  const person = await personByKey(request, env, id);
  if (person) return { part: person, row: await env.DB.prepare('SELECT * FROM form_answers WHERE instance_id = ? AND participant_id = ?').bind(iid, person.id).first() };
  if (fid && ID_RE.test(fid)) {
    const row = await env.DB.prepare('SELECT * FROM form_answers WHERE id = ? AND instance_id = ?').bind(fid, iid).first();
    const key = request.headers.get('x-form-key');
    if (row && key && row.edit_hash && safeEqual(await sha256('edit:' + key), row.edit_hash))
      return { part: await env.DB.prepare('SELECT * FROM participants WHERE id = ?').bind(row.participant_id).first(), row };
  }
  if (rid && ID_RE.test(rid)) {
    const r = await env.DB.prepare('SELECT * FROM responses WHERE id = ? AND instance_id = ?').bind(rid, iid).first();
    if (r && r.participant_id && await canEditResponse(request, env, r)) {
      const part = await env.DB.prepare('SELECT * FROM participants WHERE id = ?').bind(r.participant_id).first();
      const row = await env.DB.prepare('SELECT * FROM form_answers WHERE instance_id = ? AND participant_id = ?').bind(iid, r.participant_id).first();
      return { part, row };
    }
  }
  return { part: null, row: null };
}
// GET /api/polls/:id/instances/:iid/form?fid=&rid= — my answers to the questions and which questions I may answer.
async function getForm(request, env, url, id, iid) {
  const poll = await loadPoll(env, id);
  const admin = await isAdmin(request, env, poll, 'manage');
  if (!(await isAdmin(request, env, poll))) await checkPassword(env, request, poll);
  const inst = await loadInstance(env, id, iid);
  const { part, row } = await formIdentity(request, env, id, iid, { fid: url.searchParams.get('fid'), rid: url.searchParams.get('rid') });
  const qs = questionsOf(inst), meetings = JSON.parse(inst.meetings || '[]');
  const { results: responses } = qs.some((q) => q.who.mode === 'free')
    ? await env.DB.prepare('SELECT participant_id, entries FROM responses WHERE instance_id = ?').bind(iid).all() : { results: [] };
  const occ = {}; // after-meeting questions: the meeting dates I may answer now
  for (const q of qs) if (isAfter(q) && (admin || canAnswer(q, part, meetings, responses))) occ[q.id] = afterOpen(q, part, meetings, responses, admin).slice(0, 60);
  return json({ id: row ? row.id : null, pid: part ? part.id : null, name: part ? part.name : null, extra: row ? parseExtra(row.extra) : {},
    can: qs.filter((q) => admin || canAnswer(q, part, meetings, responses)).map((q) => q.id), occ });
}
// PUT /api/polls/:id/instances/:iid/form { fid?, rid?, name?, email?, extra } — save my answers to the questions.
async function saveForm(request, env, ctx, url, id, iid) {
  const poll = await loadPoll(env, id);
  const admin = await isAdmin(request, env, poll, 'manage');
  if (!(await isAdmin(request, env, poll))) await checkPassword(env, request, poll);
  const inst = await loadInstance(env, id, iid);
  // A closed round still takes answers to its after-meeting questions ("How was the last rehearsal?").
  const onlyAfter = effStatus(inst) !== 'open' && !admin;
  if (onlyAfter && !questionsOf(inst).some(isAfter)) throw new HttpError(409, 'This poll is closed');
  if (!questionsOf(inst).length) throw new HttpError(400, 'This round has no questions');
  const b = await body(request);
  const user = userOf(request);
  await requireInvited(env, poll, user, admin, request);
  let { part, row } = await formIdentity(request, env, id, iid, { fid: b.fid, rid: b.rid });
  let editKey = null;
  if (!part) {
    if (user) part = await newParticipant(env, id, acctName(user, b.name, null), user.email, user.id);
    else {
      const name = personName(b.name), mail = email(b.email);
      if (poll.require_email && !mail && !admin) throw new HttpError(400, 'This poll asks for your email address');
      // Same name as a guest in this poll: that's this person, unless they already filled in this round's questions.
      part = await findParticipant(env, id, nameKey(name));
      if (part) {
        const has = await env.DB.prepare('SELECT id FROM form_answers WHERE instance_id = ? AND participant_id = ?').bind(iid, part.id).first('id');
        if (has) throw new HttpError(409, `“${part.name}” has already answered these questions. If that's you, open the poll on the device you used, or answer under another name.`, { code: 'form_taken' });
      } else part = await newParticipant(env, id, name, mail);
      if (mail) await linkGuestToAccount(env, id, part.id, mail);
    }
  }
  const extra = await validateExtra(env, b.extra, inst, { fid: row && row.id, part, admin, old: row ? parseExtra(row.extra) : {}, onlyAfter, needReq: !onlyAfter });
  const t = now();
  if (row) await env.DB.prepare('UPDATE form_answers SET extra = ?, updated_at = ? WHERE id = ?').bind(extra, t, row.id).run();
  else {
    const fid = randomId(12);
    if (!user) editKey = secret();
    await env.DB.prepare('INSERT INTO form_answers (id, poll_id, instance_id, participant_id, extra, edit_hash, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)')
      .bind(fid, id, iid, part.id, extra, editKey ? await sha256('edit:' + editKey) : null, t, t).run();
    row = { id: fid };
  }
  fireEvent(ctx, env, poll, { kind: 'qanswer', iid, actor: user && user.id, name: part.name, ref: part.id });
  return json({ ok: true, id: row.id, pid: part.id, name: part.name, extra: parseExtra(extra), ...(editKey ? { editKey } : {}) });
}
// DELETE /api/polls/:id/instances/:iid/form?fid=&rid= — remove my answers to the questions (the organiser: ?fid= of anyone's).
async function deleteForm(request, env, url, id, iid) {
  const poll = await loadPoll(env, id);
  const admin = await isAdmin(request, env, poll, 'manage');
  let { row } = await formIdentity(request, env, id, iid, { fid: url.searchParams.get('fid'), rid: url.searchParams.get('rid') });
  if (!row && admin && ID_RE.test(url.searchParams.get('fid') || '')) row = await env.DB.prepare('SELECT id FROM form_answers WHERE id = ? AND poll_id = ?').bind(url.searchParams.get('fid'), id).first();
  if (!row) throw new HttpError(404, 'Answers not found');
  await env.DB.prepare('DELETE FROM form_answers WHERE id = ?').bind(row.id).run();
  return json({ ok: true });
}
async function updateResponse(request, env, ctx, id, rid) {
  const poll = await loadPoll(env, id);
  const r = await loadResponse(env, id, rid);
  const inst = await loadInstance(env, id, r.instance_id);
  const admin = await isAdmin(request, env, poll, 'manage'), own = await canEditResponse(request, env, r);
  if (!own && !admin) throw new HttpError(403, 'Not your response');
  if (!admin) {
    await checkPassword(env, request, poll);
    if (effStatus(inst) !== 'open') throw new HttpError(409, 'This poll is closed');
  }
  await requireInvited(env, poll, userOf(request), admin, request);
  const b = await body(request);
  let name = b.name !== undefined ? personName(b.name) : r.name;
  let mail = b.email !== undefined ? email(b.email) : r.email;
  const comment = b.comment !== undefined && poll.allow_comments ? str(b.comment, 500, 'Comment') : r.comment;
  const entries = b.entries !== undefined ? JSON.stringify(validateEntries(b.entries, poll, datesOf(inst, poll))) : r.entries;
  const fill = b.fill !== undefined ? parseFill(b.fill, poll, datesOf(inst, poll)) : undefined;
  let partId = r.participant_id;
  const cur = partId ? await env.DB.prepare('SELECT * FROM participants WHERE id = ?').bind(partId).first() : null;
  const stmts = [];
  const user = userOf(request);
  // Their personal link: they are that person, so the organiser's name for them stays (no renaming into someone else).
  const person = cur && !admin ? await personByKey(request, env, id) : null;
  if (person && person.id === cur.id) { name = cur.name; if (!mail) mail = cur.email || ''; }
  // A guest who signs in and edits their own answer: link that person to the account (if it has none in this poll yet).
  if (user && own && cur && !cur.user_id && !(await accountParticipant(env, id, user.id))) {
    stmts.push(toAccountRow(env, cur.id, user));
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
  await env.DB.batch(stmts);
  if (mail && !(cur && cur.user_id)) await linkGuestToAccount(env, id, partId, mail);
  // A changed answer (pushed at most once per EV_GAP per person, see notifyEvent).
  if (entries !== r.entries || comment !== r.comment) fireEvent(ctx, env, poll, { kind: 'answer_changed', iid: inst.id, actor: user && user.id, name, ref: partId || r.id });
  return json({ ok: true, name });
}
async function deleteResponse(request, env, id, rid) {
  const poll = await loadPoll(env, id);
  const r = await loadResponse(env, id, rid);
  if (!(await isAdmin(request, env, poll, 'manage')) && !(await canEditResponse(request, env, r))) throw new HttpError(403, 'Not allowed');
  await env.DB.prepare('DELETE FROM responses WHERE id = ?').bind(rid).run();
  return json({ ok: true });
}

// ---------- participants (admin) ----------
async function adminPoll(request, env, id, cap = 'manage') {
  const poll = await loadPoll(env, id);
  await requireAdmin(request, env, poll, cap);
  return poll;
}
// Body: { role: 'admin' | 'editor' | 'viewer' | '' }. Owner only; only people in the poll as their account can hold a role.
async function setParticipantRole(request, env, id, pid) {
  const poll = await adminPoll(request, env, id, 'own');
  const p = await loadParticipant(env, id, pid);
  const b = await body(request), role = b.role == null ? '' : b.role;
  if (role !== '' && !POLL_ROLES.includes(role)) throw new HttpError(400, 'Invalid role');
  if (!p.user_id) throw new HttpError(400, 'Only people who answer with an account can get a role');
  if (p.user_id === poll.owner_id) throw new HttpError(400, 'The owner already has every right');
  await env.DB.prepare('UPDATE participants SET role = ? WHERE id = ?').bind(role, pid).run();
  return json({ ok: true, role });
}
// Only the owner may remove or merge away someone who holds a role.
async function guardRoleHolder(request, env, id, p) {
  if (p.role && POLL_ROLES.includes(p.role)) await adminPoll(request, env, id, 'own');
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
    `SELECT p.id, p.name, p.email, p.user_id, p.invited_at, p.group_id, p.role, p.link_ver, u.email AS ue, ${AV_COLS}, COUNT(r.id) AS rounds, MAX(r.updated_at) AS last,
       (SELECT r2.email FROM responses r2 WHERE r2.participant_id = p.id AND r2.email != '' ORDER BY r2.updated_at DESC LIMIT 1) AS answer_email,
       (SELECT r3.email FROM responses r3 WHERE r3.participant_id = p.id ORDER BY r3.updated_at DESC LIMIT 1) AS re,
       EXISTS (SELECT 1 FROM responses r4 WHERE r4.participant_id = p.id AND r4.instance_id = ?) AS here
     FROM participants p LEFT JOIN users u ON u.id = p.user_id LEFT JOIN responses r ON r.participant_id = p.id
     WHERE p.poll_id = ? GROUP BY p.id ORDER BY p.name COLLATE NOCASE`).bind(instId || '', pollId).all();
  return results.map((p) => ({ ...p, mail_to: (p.ue || (p.re !== null ? p.re : p.email) || '').trim() }));
}
// My names for people in a poll (saved contacts set to "keep my name"), for people whose address I may see anyway (manage).
// Keys: participant id, "r:<response id>" and "u:<user id>" (chat authors). Only names that differ from theirs.
async function contactNames(env, user, pollId, responses) {
  if (!user) return null;
  const { results } = await env.DB.prepare(
    `SELECT pa.id, pa.user_id, pa.name AS theirs, f.name FROM participants pa LEFT JOIN users u ON u.id = pa.user_id
     JOIN favourites f ON f.user_id = ? AND f.name_pref = 'mine' AND f.email = LOWER(TRIM(COALESCE(u.email, pa.email)))
     WHERE pa.poll_id = ?`).bind(user.id, pollId).all();
  if (!results.length) return null;
  const out = {}, byPid = new Map(results.map((r) => [r.id, r.name]));
  for (const r of results) {
    if (r.name !== r.theirs) out[r.id] = r.name;
    if (r.user_id) out['u:' + r.user_id] = r.name;
  }
  for (const r of responses || []) { const n = byPid.get(r.participant_id); if (n && n !== r.name) out['r:' + r.id] = n; }
  return Object.keys(out).length ? out : null;
}
async function listParticipants(request, env, id) {
  const poll = await adminPoll(request, env, id, 'see');
  const mails = await isAdmin(request, env, poll, 'manage'); // viewers and editors see the list without addresses
  if (mails) await mergeEmailDupes(env, id).catch((e) => console.error('dupes', e));
  const inst = await latestInstance(env, id);
  const rows = await participantRows(env, id, inst && inst.id);
  const { results: groups } = await env.DB.prepare('SELECT group_id AS id, name, icon FROM poll_groups WHERE poll_id = ? ORDER BY name COLLATE NOCASE').bind(id).all();
  const cnames = mails ? await contactNames(env, userOf(request), id) : null;
  return json({ groups, ...(cnames ? { cnames } : {}), participants: rows.map((p) => ({ id: p.id, name: p.name, email: mails ? p.email || p.answer_email || '' : '', account: !!p.user_id,
    role: p.user_id && POLL_ROLES.includes(p.role) ? p.role : '', isOwner: !!p.user_id && p.user_id === poll.owner_id,
    rounds: p.rounds, lastAnswered: p.last, invitedAt: p.invited_at || null, answeredNow: !!p.here, canMail: !!p.mail_to, groupId: p.group_id || null, ...avOut(p, true) })) });
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
// So is an email that has an account: one email = one person (a guest row with it becomes the account's row).
async function upsertPeople(env, id, people, me = null) {
  const added = [], updated = [], skipped = [], ids = [];
  const friends = people.some((x) => x.uid) ? new Map((me ? await friendRows(env, me.id) : []).map((u) => [u.id, u])) : null;
  const accts = new Map(), mails = [...new Set(people.filter((x) => !x.uid && x.email).map((x) => x.email.toLowerCase()))];
  for (let i = 0; i < mails.length; i += 90) {
    const part = mails.slice(i, i + 90);
    const { results } = await env.DB.prepare(`SELECT id, email FROM users WHERE LOWER(email) IN (${part.map(() => '?').join(',')})`).bind(...part).all();
    for (const u of results) accts.set(u.email.toLowerCase(), u);
  }
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
        await toAccountRow(env, p.id, f).run();
        updated.push(p.name); ids.push(p.id); continue;
      }
      p = await newParticipant(env, id, name, f.email, f.id);
      added.push(name); ids.push(p.id); continue;
    }
    const acct = x.email ? accts.get(x.email.toLowerCase()) : null;
    // The account's own row first, then a guest row with the address.
    let p = x.email ? await env.DB.prepare(
      `SELECT p.* FROM participants p LEFT JOIN users u ON u.id = p.user_id WHERE p.poll_id = ? AND (LOWER(p.email) = ? OR LOWER(u.email) = ?)
       ORDER BY p.user_id IS NULL LIMIT 1`).bind(id, x.email, x.email).first() : null;
    if (p && !p.user_id && acct) { await toAccountRow(env, p.id, acct).run(); updated.push(p.name); ids.push(p.id); continue; }
    if (!p) {
      p = await findParticipant(env, id, nameKey(x.name));
      if (p && x.email) {
        if (p.email && p.email.toLowerCase() !== x.email) { skipped.push(`${x.name} (already there with another email)`); ids.push(null); continue; }
        if (!p.email) {
          await (acct ? toAccountRow(env, p.id, acct) : env.DB.prepare('UPDATE participants SET email = ? WHERE id = ?').bind(x.email, p.id)).run();
          updated.push(x.name); ids.push(p.id); continue;
        }
      }
    }
    if (p) { skipped.push(p.name); ids.push(p.id); continue; }
    p = await newParticipant(env, id, x.name, acct ? acct.email : x.email, acct ? acct.id : null);
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
  await guardRoleHolder(request, env, id, await loadParticipant(env, id, pid));
  await env.DB.batch(removeParticipantStmts(env, pid, url.searchParams.get('answers') === '1'));
  return json({ ok: true });
}
const removeParticipantStmts = (env, pid, answers) => [
  answers
    ? env.DB.prepare('DELETE FROM responses WHERE participant_id = ?').bind(pid)
    : env.DB.prepare('UPDATE responses SET participant_id = NULL WHERE participant_id = ?').bind(pid),
  env.DB.prepare('DELETE FROM form_answers WHERE participant_id = ?').bind(pid), // answers to questions need a person
  env.DB.prepare('DELETE FROM shared_busy WHERE participant_id = ?').bind(pid),
  env.DB.prepare('DELETE FROM participants WHERE id = ?').bind(pid),
];
// Body: { into: participantId }. Moves all answers of :pid to `into`; where both answered the same round, the newer answer wins.
async function mergeParticipant(request, env, id, pid) {
  await adminPoll(request, env, id);
  const src = await loadParticipant(env, id, pid);
  await guardRoleHolder(request, env, id, src);
  const b = await body(request);
  if (typeof b.into !== 'string' || b.into === pid) throw new HttpError(400, 'Pick someone else to merge into');
  const dst = await loadParticipant(env, id, b.into);
  if (src.user_id && dst.user_id) throw new HttpError(409, 'Both are signed-in accounts, so they can’t be merged');
  return json({ ok: true, removedAnswers: await mergeInto(env, src, dst) });
}
// GET .../participants/:pid/link → { url }: a guest's personal link, for the organiser to send themselves.
// POST .../link/reset makes a new one (the old one stops working).
async function participantLink(request, env, id, pid, reset) {
  const poll = await adminPoll(request, env, id, 'manage');
  if (!env.LINK_KEY) throw new HttpError(404, 'Personal links aren’t set up on this site');
  const p = await loadParticipant(env, id, pid);
  if (p.user_id) throw new HttpError(400, 'This person has an account: they open the poll and sign in');
  if (reset) {
    await env.DB.prepare('UPDATE participants SET link_ver = link_ver + 1 WHERE id = ?').bind(p.id).run();
    p.link_ver = (p.link_ver || 0) + 1;
  }
  return json({ url: await personalLink(env, siteUrl(env, new URL(request.url).origin), poll.id, p) });
}
// Moves everything of participant src to dst and deletes src; where both answered the same round, the newer answer wins.
// Returns how many answers were dropped.
async function mergeInto(env, src, dst) {
  const { results } = await env.DB.prepare('SELECT id, instance_id, participant_id, updated_at FROM responses WHERE participant_id IN (?, ?)').bind(src.id, dst.id).all();
  const byRound = {}, drop = [];
  for (const r of results) {
    const keep = byRound[r.instance_id];
    if (!keep) { byRound[r.instance_id] = r; continue; }
    if (r.updated_at > keep.updated_at) { drop.push(keep.id); byRound[r.instance_id] = r; } else drop.push(r.id);
  }
  // Answers to questions: the merged person's round answers move over where the other has none.
  const { results: fa } = await env.DB.prepare('SELECT id, instance_id, participant_id, updated_at FROM form_answers WHERE participant_id IN (?, ?)').bind(src.id, dst.id).all();
  const fBy = {}, fDrop = [];
  for (const r of fa) { const k = fBy[r.instance_id]; if (!k) { fBy[r.instance_id] = r; continue; } if (r.updated_at > k.updated_at) { fDrop.push(k.id); fBy[r.instance_id] = r; } else fDrop.push(r.id); }
  await env.DB.batch([
    ...drop.map((rid) => env.DB.prepare('DELETE FROM responses WHERE id = ?').bind(rid)),
    ...fDrop.map((fid) => env.DB.prepare('DELETE FROM form_answers WHERE id = ?').bind(fid)),
    env.DB.prepare('UPDATE form_answers SET participant_id = ? WHERE participant_id = ?').bind(dst.id, src.id),
    env.DB.prepare('UPDATE responses SET participant_id = ?, name = ? WHERE participant_id IN (?, ?)').bind(dst.id, dst.name, src.id, dst.id),
    env.DB.prepare('DELETE FROM participants WHERE id = ?').bind(src.id),
    env.DB.prepare('DELETE FROM shared_busy WHERE participant_id IN (?, ?)').bind(src.id, dst.id), // re-shared on their next visit
    // If the merged one was an account, the remaining person now belongs to that account.
    src.user_id
      ? env.DB.prepare('UPDATE participants SET user_id = ?, name_key = ?, email = ? WHERE id = ?').bind(src.user_id, src.name_key, src.email, dst.id)
      : env.DB.prepare("UPDATE participants SET email = CASE WHEN email = '' THEN ? ELSE email END WHERE id = ?").bind(src.email, dst.id),
    env.DB.prepare('UPDATE participants SET invited_at = ? WHERE id = ? AND (invited_at IS NULL OR invited_at < ?)').bind(src.invited_at, dst.id, src.invited_at),
    env.DB.prepare('UPDATE participants SET group_id = COALESCE(group_id, ?) WHERE id = ?').bind(src.group_id || null, dst.id),
  ]);
  return drop.length;
}

// One email = one person, for data from before guests were matched by email: people in a poll who share an address
// (the account's own, a guest row's saved one, or else the address of its latest answer) become one. The account's
// row wins, then the row the organiser saved with that address (its name stays), then the oldest. At most `limit` merges
// per call (each costs a few queries; the Free plan allows 50 per request), the rest on the next call.
const EMAIL_OF_ROW = `LOWER(TRIM(COALESCE(u.email, NULLIF(TRIM(pa.email), ''),
  (SELECT r.email FROM responses r WHERE r.participant_id = pa.id AND r.email != '' ORDER BY r.updated_at DESC LIMIT 1), '')))`;
async function mergeEmailDupes(env, pollId, limit = 5) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM (SELECT pa.*, ${EMAIL_OF_ROW} AS em, NULLIF(TRIM(pa.email), '') IS NOT NULL AS saved
       FROM participants pa LEFT JOIN users u ON u.id = pa.user_id WHERE pa.poll_id = ?)
     WHERE em != '' AND em IN (SELECT em FROM (SELECT ${EMAIL_OF_ROW} AS em FROM participants pa LEFT JOIN users u ON u.id = pa.user_id
       WHERE pa.poll_id = ?) GROUP BY em HAVING COUNT(*) > 1)
     ORDER BY em, user_id IS NULL, saved DESC, created_at`).bind(pollId, pollId).all();
  let n = 0, keep = null;
  for (const r of results) {
    if (!keep || keep.em !== r.em) { keep = r; continue; }
    if (r.user_id) continue; // two accounts never merge
    if (n++ >= limit) break;
    await mergeInto(env, r, keep);
  }
  return n;
}
// Daily: polls that still have people split in two by address (polls nobody opens get cleaned too).
async function mergeEmailDupesAll(env) {
  const { results } = await env.DB.prepare(
    `SELECT DISTINCT poll_id FROM (SELECT pa.poll_id, ${EMAIL_OF_ROW} AS em FROM participants pa LEFT JOIN users u ON u.id = pa.user_id)
     WHERE em != '' GROUP BY poll_id, em HAVING COUNT(*) > 1 LIMIT 8`).all();
  for (const r of results) await mergeEmailDupes(env, r.poll_id, 4);
}

// ---------- MCP: AI assistants (Claude, ChatGPT, …) use an account through the Model Context Protocol ----------
// when-who is its own OAuth 2.1 authorization server (RFC 8414 metadata, RFC 7591 dynamic registration of public clients,
// PKCE S256 only) and protected resource (RFC 9728). Paths live outside /api/ (clients expect them at the site root):
//   /.well-known/oauth-protected-resource[/mcp], /.well-known/oauth-authorization-server, /oauth/register, /oauth/authorize,
//   /oauth/token, /oauth/revoke, and the MCP endpoint POST /mcp (Streamable HTTP, stateless, JSON replies, no SSE).
// /oauth/authorize sends the person to the page (?connect=<request id>), which signs them in with the emailed code and
// asks Allow / Deny (GET|POST /api/connect/:id). Tokens are stored only as hashes (mcp_grants); access 1 h, refresh 60 days (rotated).
// Tools call the normal API handlers through callApi() (an INTERNAL request with the grant's user preset), so every check,
// role, cap and rate limit applies unchanged. Auth is a bearer header only (no cookies), so CORS is open on these paths.
const MCP_CODE_MIN = 10;        // an authorization request / code is valid this long
const MCP_ACCESS_SEC = 3600;    // access token lifetime
const MCP_REFRESH_DAYS = 60;    // refresh token lifetime (renewed on every refresh)
const MCP_MAX_GRANTS = 20;      // connected apps per account
const MCP_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26'];
const INTERNAL = new WeakSet(); // requests made by callApi(): route() keeps the preset user instead of reading cookies
const MCP_CORS = { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, mcp-protocol-version, mcp-session-id, last-event-id',
  'access-control-expose-headers': 'www-authenticate, mcp-protocol-version', 'access-control-max-age': '86400' };
const isMcpPath = (p) => p === '/mcp' || p.startsWith('/.well-known/oauth-') || p.startsWith('/oauth/');
const mcpHash = (token) => sha256('mcp:' + token);
const oauthErr = (status, code, msg) => new HttpError(status, msg, { oauth: code });

async function mcpEntry(request, env, ctx, url) {
  let res;
  try { res = await mcpRoute(request, env, ctx, url); } catch (e) {
    if (!(e instanceof HttpError)) console.error(e);
    res = e instanceof HttpError ? json({ error: e.extra.oauth || (e.status === 429 ? 'slow_down' : 'invalid_request'), error_description: e.message }, e.status)
      : json({ error: 'server_error', error_description: 'Something went wrong on the server.' }, 500);
  }
  res = secure(res, url);
  if (url.pathname !== '/oauth/authorize') for (const [k, v] of Object.entries(MCP_CORS)) res.headers.set(k, v);
  return res;
}
async function mcpRoute(request, env, ctx, url) {
  const p = url.pathname, m = request.method, base = siteUrl(env, url.origin);
  if (m === 'OPTIONS') return new Response(null, { status: 204 });
  if (p.startsWith('/.well-known/oauth-protected-resource') && m === 'GET')
    return json({ resource: base + '/mcp', resource_name: 'when-who', authorization_servers: [base], bearer_methods_supported: ['header'], scopes_supported: ['polls'] });
  if (p === '/.well-known/oauth-authorization-server' && m === 'GET')
    return json({ issuer: base, authorization_endpoint: base + '/oauth/authorize', token_endpoint: base + '/oauth/token',
      registration_endpoint: base + '/oauth/register', revocation_endpoint: base + '/oauth/revoke', scopes_supported: ['polls'],
      response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'],
      revocation_endpoint_auth_methods_supported: ['none'], authorization_response_iss_parameter_supported: true });
  if (p === '/oauth/authorize' && m === 'GET') return mcpAuthorize(request, env, url);
  if (p === '/mcp' && m !== 'POST') return json({ error: 'Use POST' }, 405, { allow: 'POST, OPTIONS' });
  if (m !== 'POST') throw new HttpError(404, 'Not found');
  if (p === '/mcp') return mcpPost(request, env, ctx, url);
  if (env.RL_WRITE && !(await env.RL_WRITE.limit({ key: clientIp(request) })).success) throw oauthErr(429, 'slow_down', 'Too many requests. Wait a minute and try again.');
  if (p === '/oauth/register') return mcpRegister(request, env);
  if (p === '/oauth/token') return mcpToken(request, env);
  if (p === '/oauth/revoke') return mcpRevoke(request, env);
  throw new HttpError(404, 'Not found');
}

// Return addresses: https, http on this machine (desktop apps), or an app's own scheme (cursor://, vscode://).
const BAD_SCHEMES = new Set(['javascript:', 'data:', 'file:', 'vbscript:', 'blob:', 'about:', 'ftp:', 'ws:', 'wss:', 'mailto:', 'tel:', 'sms:']);
function okRedirect(u) {
  if (typeof u !== 'string' || u.length > 500) return false;
  let x; try { x = new URL(u); } catch { return false; }
  if (x.hash || x.username || x.password) return false;
  if (x.protocol === 'https:') return true;
  if (x.protocol === 'http:') return ['localhost', '127.0.0.1', '[::1]'].includes(x.hostname);
  return /^[a-z][a-z0-9+.-]*:$/.test(x.protocol) && !BAD_SCHEMES.has(x.protocol);
}
const hostOf = (u) => { try { const x = new URL(u); return x.host || x.protocol.replace(/:$/, ''); } catch { return ''; } };
async function mcpClient(env, id) {
  if (typeof id !== 'string' || !/^[A-Za-z0-9]{16,40}$/.test(id)) return null;
  const c = await env.DB.prepare('SELECT * FROM mcp_clients WHERE id = ?').bind(id).first();
  return c ? { ...c, uris: JSON.parse(c.redirect_uris) } : null;
}
async function mcpRegister(request, env) {
  await checkThrottle(env, request, 'mcpreg', { max: 60, msg: 'Too many app registrations. Try again later.' });
  await recordFail(env, request, 'mcpreg');
  const b = await body(request);
  const uris = Array.isArray(b.redirect_uris) ? [...new Set(b.redirect_uris)] : [];
  if (!uris.length || uris.length > 10 || !uris.every(okRedirect)) throw oauthErr(400, 'invalid_redirect_uri', 'redirect_uris must be 1 to 10 https (or local http) addresses');
  if (b.grant_types && (!Array.isArray(b.grant_types) || b.grant_types.some((g) => !['authorization_code', 'refresh_token'].includes(g))))
    throw oauthErr(400, 'invalid_client_metadata', 'Only authorization_code and refresh_token are supported');
  const name = (typeof b.client_name === 'string' ? b.client_name.replace(/[\u0000-\u001f\u007f]/g, '').trim() : '').slice(0, 80) || hostOf(uris[0]) || 'App';
  const id = randomId(24), t = now();
  await env.DB.prepare('INSERT INTO mcp_clients (id, name, redirect_uris, created_at) VALUES (?, ?, ?, ?)').bind(id, name, JSON.stringify(uris), t).run();
  return json({ client_id: id, client_id_issued_at: Math.floor(Date.now() / 1000), client_name: name, redirect_uris: uris,
    grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none', scope: 'polls' }, 201);
}
const plainPage = (status, text) => new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>when-who</title><p style="font:16px system-ui;margin:2em">${text}</p>`,
  { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
function backTo(redirectUri, params, base) {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) if (v) u.searchParams.set(k, v);
  u.searchParams.set('iss', base); // RFC 9207
  return u.toString();
}
async function mcpAuthorize(request, env, url) {
  const q = url.searchParams, base = siteUrl(env, url.origin);
  const client = await mcpClient(env, q.get('client_id'));
  const ru = q.get('redirect_uri') || (client && client.uris.length === 1 ? client.uris[0] : '');
  // Never send anyone to an address the app didn't register.
  if (!client || !client.uris.includes(ru)) return plainPage(400, 'This connection link isn’t valid (unknown app or return address). Start connecting again from the app.');
  const state = (q.get('state') || '').slice(0, 500);
  const fail = (error, desc) => new Response(null, { status: 302, headers: { location: backTo(ru, { error, error_description: desc, state }, base) } });
  if (q.get('response_type') !== 'code') return fail('unsupported_response_type', 'Only response_type=code is supported');
  const ch = q.get('code_challenge') || '';
  if (q.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(ch)) return fail('invalid_request', 'PKCE with S256 is required');
  const resource = q.get('resource');
  if (resource && ![base, base + '/', base + '/mcp', base + '/mcp/'].includes(resource)) return fail('invalid_target', 'Unknown resource');
  await checkThrottle(env, request, 'mcpauth', { max: 60, msg: 'Too many tries. Try again later.' });
  await recordFail(env, request, 'mcpauth');
  const id = randomId(20);
  await env.DB.prepare('INSERT INTO mcp_requests (id, client_id, redirect_uri, state, code_challenge, resource, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, client.id, ru, state || null, ch, resource || null, now()).run();
  return new Response(null, { status: 302, headers: { location: `${base}/?connect=${id}`, 'cache-control': 'no-store' } });
}
async function mcpPending(env, rid) {
  const since = new Date(Date.now() - MCP_CODE_MIN * 60000).toISOString();
  const r = /^[A-Za-z0-9]{20}$/.test(rid || '') ? await env.DB.prepare('SELECT * FROM mcp_requests WHERE id = ? AND code_hash IS NULL AND created_at > ?').bind(rid, since).first() : null;
  const c = r && await mcpClient(env, r.client_id);
  if (!r || !c) throw new HttpError(404, 'This connection request has expired. Start connecting again from the app.');
  return { r, c };
}
// GET /api/connect/:id: what the consent screen shows. POST { allow }: the answer; the page then goes to `redirect`.
async function connectInfo(request, env, rid) {
  requireUser(request);
  const { r, c } = await mcpPending(env, rid);
  return json({ name: c.name, host: hostOf(r.redirect_uri), local: /^http:/.test(r.redirect_uri), registered: c.created_at });
}
async function connectAnswer(request, env, url, rid) {
  const user = requireUser(request);
  const { r } = await mcpPending(env, rid);
  const b = await body(request), base = siteUrl(env, url.origin);
  if (b.allow !== true) {
    await env.DB.prepare('DELETE FROM mcp_requests WHERE id = ?').bind(rid).run();
    return json({ redirect: backTo(r.redirect_uri, { error: 'access_denied', state: r.state }, base) });
  }
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM mcp_grants WHERE user_id = ?').bind(user.id).first('n');
  if (n >= MCP_MAX_GRANTS) throw new HttpError(409, `You have ${MCP_MAX_GRANTS} connected apps. Disconnect one on your Account page first.`);
  const code = secret() + secret();
  const ok = await env.DB.prepare('UPDATE mcp_requests SET user_id = ?, code_hash = ? WHERE id = ? AND code_hash IS NULL').bind(user.id, await mcpHash('code:' + code), rid).run();
  if (!ok.meta.changes) throw new HttpError(409, 'This connection request was already answered.');
  return json({ redirect: backTo(r.redirect_uri, { code, state: r.state }, base) });
}
async function mcpIssue(env, uid, client, grantId) {
  const access = 'wwa_' + secret() + secret(), refresh = 'wwr_' + secret() + secret(), t = now();
  const aExp = new Date(Date.now() + MCP_ACCESS_SEC * 1000).toISOString(), rExp = new Date(Date.now() + MCP_REFRESH_DAYS * 86400000).toISOString();
  const [ah, rh] = [await mcpHash(access), await mcpHash(refresh)];
  if (grantId) await env.DB.prepare('UPDATE mcp_grants SET access_hash = ?, access_exp = ?, refresh_hash = ?, refresh_exp = ?, used_at = ? WHERE id = ?').bind(ah, aExp, rh, rExp, t, grantId).run();
  else await env.DB.prepare('INSERT INTO mcp_grants (id, user_id, client_id, client_name, access_hash, access_exp, refresh_hash, refresh_exp, created_at, used_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .bind(randomId(12), uid, client.id, client.name, ah, aExp, rh, rExp, t, t).run();
  if (!grantId) await env.DB.prepare('UPDATE mcp_clients SET used_at = ? WHERE id = ?').bind(t, client.id).run();
  return json({ access_token: access, token_type: 'Bearer', expires_in: MCP_ACCESS_SEC, refresh_token: refresh, scope: 'polls' }, 200, { pragma: 'no-cache' });
}
async function oauthBody(request) {
  if ((request.headers.get('content-type') || '').includes('application/json')) return body(request);
  const text = await request.text();
  if (text.length > 20000) throw oauthErr(413, 'invalid_request', 'Request too large');
  return Object.fromEntries(new URLSearchParams(text));
}
async function mcpToken(request, env) {
  await checkThrottle(env, request, 'mcptok', { max: 100, msg: 'Too many failed attempts. Try again later.' });
  const b = await oauthBody(request);
  const bad = async (msg) => { await recordFail(env, request, 'mcptok'); return oauthErr(400, 'invalid_grant', msg); };
  if (b.grant_type === 'authorization_code') {
    const code = typeof b.code === 'string' && b.code.length <= 200 ? b.code : '';
    const r = code ? await env.DB.prepare('SELECT * FROM mcp_requests WHERE code_hash = ?').bind(await mcpHash('code:' + code)).first() : null;
    if (!r) throw await bad('Unknown or used code');
    await env.DB.prepare('DELETE FROM mcp_requests WHERE id = ?').bind(r.id).run(); // single use
    if (r.created_at < new Date(Date.now() - MCP_CODE_MIN * 60000).toISOString()) throw await bad('The code has expired');
    if ((b.client_id && b.client_id !== r.client_id) || b.redirect_uri !== r.redirect_uri) throw await bad('client_id or redirect_uri does not match');
    const v = typeof b.code_verifier === 'string' ? b.code_verifier : '';
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(v)) throw await bad('code_verifier missing or invalid');
    const ch = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(v))));
    if (!safeEqual(ch, r.code_challenge)) throw await bad('code_verifier does not match');
    const client = await mcpClient(env, r.client_id);
    if (!client || !(await env.DB.prepare('SELECT 1 FROM users WHERE id = ?').bind(r.user_id).first())) throw await bad('Unknown app or account');
    return mcpIssue(env, r.user_id, client, null);
  }
  if (b.grant_type === 'refresh_token') {
    const rt = typeof b.refresh_token === 'string' && b.refresh_token.length <= 200 ? b.refresh_token : '';
    const g = rt ? await env.DB.prepare('SELECT * FROM mcp_grants WHERE refresh_hash = ? AND refresh_exp > ?').bind(await mcpHash(rt), now()).first() : null;
    if (!g || (b.client_id && b.client_id !== g.client_id)) throw await bad('Unknown or expired refresh token');
    return mcpIssue(env, g.user_id, { id: g.client_id, name: g.client_name }, g.id);
  }
  throw oauthErr(400, 'unsupported_grant_type', 'Use authorization_code or refresh_token');
}
// RFC 7009: forget the grant behind either token. Always 200 (no probing).
async function mcpRevoke(request, env) {
  const b = await oauthBody(request);
  if (typeof b.token === 'string' && b.token.length <= 200) {
    const h = await mcpHash(b.token);
    await env.DB.prepare('DELETE FROM mcp_grants WHERE access_hash = ? OR refresh_hash = ?').bind(h, h).run();
  }
  return new Response(null, { status: 200 });
}
// Account page: connected apps.
async function listConnections(request, env) {
  const user = requireUser(request);
  const { results } = await env.DB.prepare('SELECT id, client_name, created_at, used_at FROM mcp_grants WHERE user_id = ? ORDER BY created_at DESC').bind(user.id).all();
  return json({ connections: results.map((g) => ({ id: g.id, name: g.client_name, createdAt: g.created_at, usedAt: g.used_at })) });
}
async function deleteConnection(request, env, gid) {
  const user = requireUser(request);
  await env.DB.prepare('DELETE FROM mcp_grants WHERE id = ? AND user_id = ?').bind(gid, user.id).run();
  return json({ ok: true });
}

// ---- the MCP endpoint (JSON-RPC 2.0) ----
async function mcpAuth(env, request) {
  const m = /^Bearer\s+([A-Za-z0-9_-]{20,200})$/i.exec(request.headers.get('authorization') || '');
  if (!m) return null;
  const g = await env.DB.prepare('SELECT id, user_id, used_at FROM mcp_grants WHERE access_hash = ? AND access_exp > ?').bind(await mcpHash(m[1]), now()).first();
  if (!g) return null;
  const u = await env.DB.prepare('SELECT id, email, name, avatar, bio, created_at, avatar_img IS NOT NULL AS has_img FROM users WHERE id = ?').bind(g.user_id).first();
  if (!u) return null;
  if (!g.used_at || g.used_at < new Date(Date.now() - 3600000).toISOString()) await env.DB.prepare('UPDATE mcp_grants SET used_at = ? WHERE id = ?').bind(now(), g.id).run();
  return { grant: g.id, user: { id: u.id, email: u.email, name: u.name || '', avatar: u.avatar || '', bio: u.bio || '', hasImg: !!u.has_img, created: u.created_at } };
}
const rpcOk = (id, result) => ({ jsonrpc: '2.0', id, result });
const rpcErr = (id, code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
async function mcpPost(request, env, ctx, url) {
  const base = siteUrl(env, url.origin);
  const auth = await mcpAuth(env, request);
  if (!auth) return json({ error: 'invalid_token', error_description: 'Connect when-who again (sign in).' }, 401, {
    'www-authenticate': `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"${request.headers.get('authorization') ? ', error="invalid_token"' : ''}` });
  // Shared egress IPs (an assistant's servers talk for many people): limit per connected app instead of per IP.
  const key = 'mcp:' + auth.grant;
  if (env.RL_WRITE && !(await env.RL_WRITE.limit({ key })).success) return json(rpcErr(null, -32000, 'Too many requests. Wait a minute and try again.'), 429);
  const text = await request.text();
  if (text.length > 200_000) return json(rpcErr(null, -32600, 'Request too large'), 413);
  let msg; try { msg = JSON.parse(text); } catch { return json(rpcErr(null, -32700, 'Parse error'), 400); }
  const call = { env, ctx, user: auth.user, key, origin: url.origin, base };
  const list = Array.isArray(msg) ? msg.slice(0, 20) : [msg];
  const out = [];
  for (const m of list) { const r = await mcpHandle(call, m); if (r) out.push(r); }
  if (!out.length) return new Response(null, { status: 202 });
  return json(Array.isArray(msg) ? out : out[0]);
}
const MCP_INSTRUCTIONS = `when-who finds when a group of people is free. A poll covers a range of dates (one round; a recurring series gets a new round each period).
Each person marks per date: "y" available, "i" if needed, "m" maybe, "n" not available, or per hour as {"y":[18,19],"i":[],"m":[20]} (hour 18 = 18:00-19:00, within the poll's hours).
Start with list_polls, then get_poll for dates, answers and the best times. Always give the person the poll link.
Ask before inviting people by email, setting meetings or sending chat messages: they reach other people.`;
async function mcpHandle(call, m) {
  if (!m || typeof m !== 'object' || m.jsonrpc !== '2.0' || typeof m.method !== 'string') return rpcErr(m && m.id, -32600, 'Invalid request');
  const isNote = m.id === undefined, p = m.params && typeof m.params === 'object' ? m.params : {};
  if (m.method.startsWith('notifications/')) return null;
  if (m.method === 'initialize') {
    const v = MCP_VERSIONS.includes(p.protocolVersion) ? p.protocolVersion : MCP_VERSIONS[0];
    return rpcOk(m.id, { protocolVersion: v, capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'when-who', title: 'when-who', version: '1.0.0', websiteUrl: call.base }, instructions: MCP_INSTRUCTIONS });
  }
  if (m.method === 'ping') return rpcOk(m.id, {});
  if (m.method === 'tools/list') return rpcOk(m.id, { tools: MCP_TOOLS.map(({ run, ...t }) => t) });
  if (m.method === 'tools/call') {
    const tool = MCP_TOOLS.find((t) => t.name === p.name);
    if (!tool) return rpcErr(m.id, -32602, 'Unknown tool: ' + String(p.name).slice(0, 60));
    const args = p.arguments && typeof p.arguments === 'object' && !Array.isArray(p.arguments) ? p.arguments : {};
    try {
      const out = await tool.run(call, args);
      return rpcOk(m.id, { content: [{ type: 'text', text: typeof out === 'string' ? out : JSON.stringify(out) }] });
    } catch (e) {
      if (!(e instanceof HttpError)) { console.error('mcp tool', p.name, e); return rpcOk(m.id, { content: [{ type: 'text', text: 'Something went wrong on the server.' }], isError: true }); }
      return rpcOk(m.id, { content: [{ type: 'text', text: e.message }], isError: true });
    }
  }
  return isNote ? null : rpcErr(m.id, -32601, 'Method not found');
}
// Runs one API call as the connected account: the same handlers, checks and limits as the page.
async function callApi(call, method, path, data, headers = {}) {
  const u = new URL('/api' + path, call.origin);
  const req = new Request(u, { method, body: data === undefined ? undefined : JSON.stringify(data),
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': call.key, ...headers } });
  INTERNAL.add(req); USERS.set(req, call.user);
  const res = await route(req, call.env, call.ctx, u);
  const out = await res.json().catch(() => ({}));
  if (!res.ok) throw new HttpError(res.status, out.error || 'Request failed');
  return out;
}
// Tool arguments (the Worker validates again; these only give clear messages).
const argId = (v, what = 'poll_id') => { if (typeof v !== 'string' || !ID_RE.test(v)) throw new HttpError(400, `${what} is missing or invalid`); return v; };
const pwHeader = (a) => (typeof a.password === 'string' && a.password ? { 'x-poll-password': a.password.slice(0, 100) } : {});
const pollLink = (call, id) => `${call.base}/?p=${id}`;
const WD_SHORT = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const mcpWd = (d) => WD_SHORT[(new Date(d + 'T00:00:00Z').getUTCDay() + 6) % 7];
const hourText = (h) => pad(h % 24) + ':00';

// Who is free when, worked out like the page's group view: per date the hours with the most people free
// (available + if needed), then the fewest "if needed", then the most "maybe"; the longest run of those hours.
function availabilitySummary(poll, dates, responses) {
  const H = []; for (let h = poll.hourStart; h < poll.hourEnd; h++) H.push(h);
  const daysOnly = poll.answerMode === 'days';
  const states = (v) => {
    const mp = new Map();
    if (v === 'y' || v === 'i' || v === 'm') H.forEach((h) => mp.set(h, v));
    else if (v && typeof v === 'object') ['m', 'i', 'y'].forEach((s) => (v[s] || []).forEach((h) => mp.set(h, s)));
    return mp;
  };
  const days = [];
  for (const d of dates) {
    const per = H.map((h) => ({ h, free: [], ifn: [], maybe: [] }));
    const allDay = [];
    for (const r of responses) {
      const v = (r.entries || {})[d], st = states(v);
      if (v === 'y') allDay.push(r.name);
      for (const x of per) { const s = st.get(x.h); if (s === 'y') x.free.push(r.name); else if (s === 'i') x.ifn.push(r.name); else if (s === 'm') x.maybe.push(r.name); }
    }
    const score = (x) => (x.free.length + x.ifn.length) * 10000 - x.ifn.length * 100 + x.maybe.length;
    const peak = Math.max(0, ...per.map(score));
    if (!peak) continue;
    let best = null, cur = null;
    for (const x of per) {
      if (score(x) === peak) { cur = cur && cur.to === x.h ? { ...cur, to: x.h + 1 } : { from: x.h, to: x.h + 1, x }; if (!best || cur.to - cur.from > best.to - best.from) best = cur; }
      else cur = null;
    }
    const b = best.x;
    days.push({ date: d, weekday: mcpWd(d), ...(daysOnly ? {} : { from: hourText(best.from), to: hourText(best.to) }),
      free: b.free.length + b.ifn.length, of: responses.length, available: b.free, if_needed: b.ifn, maybe: b.maybe,
      ...(daysOnly ? {} : { available_all_day: allDay }), _s: peak, _len: best.to - best.from });
  }
  const best_times = days.filter((x) => x.free).sort((a, b) => b._s - a._s || b._len - a._len || a.date.localeCompare(b.date)).slice(0, 5)
    .map(({ date, weekday, from, to, free, of, if_needed }) => ({ date, weekday, from, to, free, of, if_needed: if_needed.length }));
  return { people_answered: responses.length, best_times, days: days.map(({ _s, _len, ...x }) => x) };
}
const meetingOut = (mt) => ({ id: mt.id, date: mt.date, ...(mt.endDate ? { end_date: mt.endDate } : {}), weekday: mcpWd(mt.date),
  ...(mt.allDay ? { all_day: true } : { from: hourText(mt.start), to: hourText(mt.end) }), title: mt.title || undefined,
  location: mt.location || undefined, note: mt.note || undefined, from_answers: mt.answersText || undefined, ...(mt.proposed ? { proposed: true, vote: mt.vote } : {}),
  ...(mt.repeat ? { repeat: mt.repeat } : {}) });
const loadPollFor = (call, a) => callApi(call, 'GET', `/polls/${argId(a.poll_id)}${a.round_id ? '?i=' + argId(a.round_id, 'round_id') : ''}`, undefined, pwHeader(a));
const pollIdProp = { poll_id: { type: 'string', description: 'Poll id (from list_polls or a poll link ?p=<id>)' } };
const roundProp = { round_id: { type: 'string', description: 'Round id (series only; default = the current round)' } };
const pwProp = { password: { type: 'string', description: 'The poll password, only for password-protected polls you don’t manage' } };
const ENTRY_DOC = 'Map of date (YYYY-MM-DD, one of the poll dates) to "y" available / "i" if needed / "m" maybe / "n" not available for the whole day, or per hour {"y":[hours],"i":[hours],"m":[hours]} (hour 18 = 18:00-19:00; other hours = not available). null removes a date.';

const MCP_TOOLS = [
  { name: 'whoami', title: 'Who am I', description: 'The when-who account this connection uses.',
    inputSchema: { type: 'object', properties: {} }, annotations: { readOnlyHint: true, openWorldHint: false },
    run: async (call) => ({ name: call.user.name || null, email: call.user.email, site: call.base }) },
  { name: 'list_polls', title: 'List my polls', description: 'Polls I own and polls I answered or have a role in, with their current round (dates, open/closed, number of answers).',
    inputSchema: { type: 'object', properties: {} }, annotations: { readOnlyHint: true, openWorldHint: false },
    run: async (call) => {
      const r = await callApi(call, 'GET', '/me/polls');
      const cur = (c) => (c ? { dates: c.startDate === WEEK0 ? 'weekly schedule' : `${c.startDate} to ${c.endDate}`, status: c.status, answers: c.answers, reply_by: c.deadline || undefined } : null);
      return {
        owned: r.polls.map((p) => ({ id: p.id, title: p.title, kind: p.kind, link: pollLink(call, p.id), current_round: cur(p.current), unread_chat: p.unread || undefined })),
        answered: r.answered.map((p) => ({ id: p.id, title: p.title, kind: p.kind, link: pollLink(call, p.id), my_name: p.name, role: p.role, last_answered: p.lastAnswered, current_round: cur(p.current), unread_chat: p.unread || undefined })),
      };
    } },
  { name: 'get_poll', title: 'Show a poll', description: 'A poll\'s dates and hours, my answer, everyone\'s answers (when visible to me), the best times (who is free when) and its meetings.',
    inputSchema: { type: 'object', properties: { ...pollIdProp, ...roundProp, ...pwProp }, required: ['poll_id'] }, annotations: { readOnlyHint: true, openWorldHint: false },
    run: async (call, a) => {
      const g = await loadPollFor(call, a), P = g.poll, I = g.instance;
      const rs = g.responses || null, mine = g.me && g.me.responseId && rs ? rs.find((r) => r.id === g.me.responseId) : null;
      let myEntries = mine ? mine.entries : null;
      if (!myEntries && g.me && g.me.responseId) myEntries = (await callApi(call, 'GET', `/polls/${P.id}/responses/${g.me.responseId}`, undefined, pwHeader(a))).entries;
      return {
        id: P.id, title: P.title, description: P.description || undefined, link: pollLink(call, P.id), kind: P.kind,
        answer_type: P.answerMode === 'days' ? 'whole days only' : P.answerMode === 'slots' ? 'hours' : 'whole days or hours',
        hours: P.answerMode === 'days' ? undefined : `${hourText(P.hourStart)}-${hourText(P.hourEnd)}`,
        my_role: g.role || (g.me && g.me.participantId ? 'participant' : 'none'), password_protected: P.hasPassword || undefined,
        round: { id: I.id, status: I.status, dates: g.dates, reply_by: I.deadline || undefined, note: I.note || undefined },
        other_rounds: g.instances.length > 1 ? g.instances.filter((i) => i.id !== I.id).map((i) => ({ id: i.id, from: i.startDate, to: i.endDate, status: i.status })) : undefined,
        my_answer: myEntries || null,
        answers: rs ? (rs.length <= 60 ? rs.map((r) => ({ name: r.name, comment: r.comment || undefined, entries: r.entries })) : `${rs.length} answers (too many to list; see availability)`) : 'hidden by the organiser',
        availability: rs ? availabilitySummary(P, g.dates, rs) : undefined,
        meetings: (I.meetings || []).map(meetingOut),
        people: g.people ? g.people.map((p) => ({ name: p.name, answered: p.answered, role: p.role })) : undefined,
        questions: (I.questions || []).length ? `${I.questions.length} questions: answer them in the app (Questions tab)` : undefined,
        chat: g.chat && g.chat.can ? { unread: g.chat.unread || 0 } : undefined,
      };
    } },
  { name: 'answer_poll', title: 'Answer a poll', description: 'Save my availability in a poll (creates my answer or updates it). By default the given dates are merged into my existing answer; replace=true sends the whole answer.',
    inputSchema: { type: 'object', properties: { ...pollIdProp, ...roundProp,
      entries: { type: 'object', description: ENTRY_DOC, additionalProperties: { anyOf: [{ type: 'string', enum: ['y', 'i', 'm', 'n'] }, { type: 'object' }, { type: 'null' }] } },
      replace: { type: 'boolean', description: 'Replace my whole answer instead of merging (default false)' },
      comment: { type: 'string', description: 'Optional comment shown with my answer (polls without chat only)' }, ...pwProp }, required: ['poll_id', 'entries'] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    run: async (call, a) => {
      if (!a.entries || typeof a.entries !== 'object' || Array.isArray(a.entries)) throw new HttpError(400, 'entries must be an object of date → answer');
      const g = await loadPollFor(call, a), id = g.poll.id, rid = g.me && g.me.responseId;
      const dates = new Set(g.dates), wrong = Object.keys(a.entries).filter((d) => !dates.has(d));
      if (wrong.length) throw new HttpError(400, `Not dates of this round: ${wrong.slice(0, 5).join(', ')}. The round's dates are ${g.dates[0]} to ${g.dates[g.dates.length - 1]} (see get_poll).`);
      const old = rid && !a.replace ? (await callApi(call, 'GET', `/polls/${id}/responses/${rid}`, undefined, pwHeader(a))).entries : {};
      const entries = { ...old, ...a.entries };
      for (const [d, v] of Object.entries(entries)) if (v == null) delete entries[d];
      const b = { entries, ...(typeof a.comment === 'string' ? { comment: a.comment } : {}) };
      if (rid) await callApi(call, 'PUT', `/polls/${id}/responses/${rid}`, b, pwHeader(a));
      else await callApi(call, 'POST', `/polls/${id}/instances/${g.instance.id}/responses`, { ...b, name: call.user.name || undefined }, pwHeader(a));
      return { ok: true, saved: rid ? 'updated my answer' : 'added my answer', days_marked: Object.keys(entries).length, link: pollLink(call, id) };
    } },
  { name: 'create_poll', title: 'Create a poll', description: 'Create a one-off availability poll for a date range (owned by my account). Returns its id and link to share.',
    inputSchema: { type: 'object', properties: {
      title: { type: 'string', description: 'Title, max 120 characters' }, description: { type: 'string', description: 'Optional description, max 1000 characters' },
      start_date: { type: 'string', description: 'First date, YYYY-MM-DD' }, end_date: { type: 'string', description: 'Last date, YYYY-MM-DD (at most 365 days after start)' },
      weekdays: { type: 'array', items: { type: 'integer', minimum: 0, maximum: 6 }, description: 'Only these weekdays (0 = Monday … 6 = Sunday); default all' },
      answer_type: { type: 'string', enum: ['days', 'slots', 'both'], description: 'days = whole days only, slots = hours, both (default)' },
      hour_start: { type: 'integer', minimum: 0, maximum: 23, description: 'First hour people can pick (default 8)' },
      hour_end: { type: 'integer', minimum: 1, maximum: 24, description: 'End of the last hour (default 24)' },
      reply_by: { type: 'string', description: 'Optional reply-by date, YYYY-MM-DD' },
      hide_results: { type: 'boolean', description: 'Hide answers from people who answer (default false)' },
      invited_only: { type: 'boolean', description: 'Only invited, signed-in people may answer (default false)' },
      language: { type: 'string', enum: ['en', 'de'], description: 'Language of emails sent for this poll (default en)' } }, required: ['title', 'start_date', 'end_date'] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    run: async (call, a) => {
      const b = { kind: 'single', title: a.title, description: a.description, startDate: a.start_date, endDate: a.end_date, deadline: a.reply_by || null,
        answerMode: a.answer_type || 'both', hourStart: a.hour_start, hourEnd: a.hour_end, hideResults: !!a.hide_results, invitedOnly: !!a.invited_only,
        dayPattern: Array.isArray(a.weekdays) && a.weekdays.length ? { wd: a.weekdays } : null };
      const r = await callApi(call, 'POST', '/polls', b, a.language === 'de' ? { 'x-lang': 'de' } : {});
      return { ok: true, id: r.id, link: pollLink(call, r.id), next: 'Share the link, or add_people with invite=true to email people.' };
    } },
  { name: 'add_people', title: 'Add people to a poll', description: 'Add people (name + email) to a poll I manage. With invite=true each gets an email with the poll link (counts toward the daily email limit). Ask the person first.',
    inputSchema: { type: 'object', properties: { ...pollIdProp,
      people: { type: 'array', maxItems: 200, items: { type: 'object', properties: { name: { type: 'string' }, email: { type: 'string' } }, required: ['name', 'email'] } },
      invite: { type: 'boolean', description: 'Email them an invitation now (default false)' },
      message: { type: 'string', description: 'Optional personal message in the invitation, max 1000 characters' } }, required: ['poll_id', 'people'] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    run: async (call, a) => {
      const id = argId(a.poll_id), people = Array.isArray(a.people) ? a.people.map((p) => ({ name: p && p.name, email: p && p.email })) : [];
      const r = a.invite ? await callApi(call, 'POST', `/polls/${id}/invite`, { people, message: a.message || '' })
        : await callApi(call, 'POST', `/polls/${id}/participants`, { people });
      return { ok: true, added: r.added, updated: r.updated, skipped: r.skipped || undefined, invited: a.invite ? r.sent : 0, without_email: r.missing && r.missing.length ? r.missing : undefined };
    } },
  { name: 'schedule_meeting', title: 'Schedule a meeting', description: 'Add a meeting to a poll\'s round (organisers and editors). propose=true puts it up for a vote instead of setting it; proposals with the same vote id are options of one vote. Ask the person first.',
    inputSchema: { type: 'object', properties: { ...pollIdProp, ...roundProp,
      date: { type: 'string', description: 'YYYY-MM-DD' }, all_day: { type: 'boolean' },
      start_hour: { type: 'integer', minimum: 0, maximum: 23 }, end_hour: { type: 'integer', minimum: 1, maximum: 24, description: 'e.g. 18 to 20 = 18:00-20:00' },
      title: { type: 'string' }, location: { type: 'string' }, note: { type: 'string' },
      propose: { type: 'boolean', description: 'Put it up for a vote instead of setting it (default false)' },
      vote: { type: 'string', description: 'Vote id from an earlier proposal, to add another option to the same vote' } }, required: ['poll_id', 'date'] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    run: async (call, a) => {
      const g = await loadPollFor(call, a), P = g.poll, I = g.instance;
      if (P.kind === 'weekly') throw new HttpError(400, 'Meetings of weekly schedule polls repeat: set them in the app.');
      if (!g.can || !g.can.edit) throw new HttpError(403, 'Only the organiser (or an editor) can schedule meetings.');
      if (!a.all_day && (!Number.isInteger(a.start_hour) || !Number.isInteger(a.end_hour))) throw new HttpError(400, 'Give start_hour and end_hour, or all_day=true');
      const vote = a.propose ? (typeof a.vote === 'string' && /^[A-Za-z0-9]{4,20}$/.test(a.vote) ? a.vote : randomId(8)) : undefined;
      const mt = { id: randomId(8), date: a.date, allDay: !!a.all_day, start: a.all_day ? undefined : a.start_hour, end: a.all_day ? undefined : a.end_hour,
        title: a.title || '', location: a.location || P.meetLocation || '', note: a.note || P.meetNote || '', participants: 'all',
        ...(a.propose ? { proposed: true, vote } : {}) };
      await callApi(call, 'PATCH', `/polls/${P.id}/instances/${I.id}`, { meetings: [...(I.meetings || []), mt] });
      return { ok: true, meeting: meetingOut({ ...mt, proposed: mt.proposed, vote }), link: pollLink(call, P.id),
        next: a.propose ? 'People vote on it in the poll.' : 'People see it in the poll and can add it to their calendar. Calendar invitations by email are sent from the app (Meetings tab).' };
    } },
  { name: 'send_message', title: 'Send a chat message', description: 'Post a message in a poll\'s group chat as me. Everyone in the poll can read it and may get a notification. Ask the person first.',
    inputSchema: { type: 'object', properties: { ...pollIdProp, text: { type: 'string', description: 'The message' } }, required: ['poll_id', 'text'] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    run: async (call, a) => {
      const id = argId(a.poll_id);
      await callApi(call, 'POST', `/polls/${id}/chat`, { body: a.text });
      return { ok: true, link: pollLink(call, id) + '&chat=1' };
    } },
];
