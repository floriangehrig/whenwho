# when-who

Availability polls ("when is everyone free?") with recurring poll series, meeting scheduling,
.ics calendar export, sign-in by emailed code and optional emails (Resend). Runs on Cloudflare Workers + D1. No framework and no build step.

## Layout
- `src/worker.js`: the API (`/api/*`), the hourly cron job (`scheduled`) and email sending. Plain JS module.
- `public/index.html`: the whole web app (HTML + CSS + vanilla JS in one file), served via the `ASSETS` binding.
- `migrations/`: D1 schema migrations, numbered `NNNN_description.sql`.
- `wrangler.toml`: Worker name `whenwho`, D1 binding `DB` (database `whenwho`), cron trigger, optional email config.

## Data model (see migrations/0001_initial.sql)
- `polls`: one row per poll or series (kind `single` | `series`), with settings, owner (`owner_id`), optional password, and an icon
  (`icon` emoji, or `image` = small data URL served by `GET /api/polls/:id/image`). `admin_hash` is legacy: old admin keys only work to claim a poll.
- `instances`: one row per round of a poll (a series gets a new one each period). Holds dates, deadline, status and meetings (JSON).
- `participants`: one per person per poll, shared across all instances of a series. `responses.participant_id` links to it.
  Guests are unique by name (`name_key` = lower-cased name). Signed-in people are unique by account (`user_id`; `name_key` = "\u0001" + user id), so names may repeat.
- `users`: accounts, one per (lower-cased) email, with profile `name` and `avatar` (emoji) / `avatar_img` (data URL).
  `ical_url` (optional) is the person's secret iCal feed: the page never gets it back (`GET /api/me` returns only its host);
  `POST /api/me/calendar` fetches it (or a pasted link) and the page parses it to pre-fill free hours.
- `user_calendars` / `calendar_accounts` (0009): an account's calendars. Each is an iCal link (`url`, secret, never sent to the page)
  or a calendar inside a Google / Outlook account signed in with OAuth (`calendar_accounts`, tokens AES-GCM encrypted with `CAL_TOKEN_KEY`).
  `auto` = grey out the owner's busy hours on polls they answer (fetched via `GET /api/me/calendars/:id/busy`; event titles are never stored).
  `users.ical_url` is legacy (copied into `user_calendars`). `oauth_states` holds sign-ins in progress.
  Sign-in is a 6-digit code emailed to the address (`login_codes`, hashed, 10 min, 5 tries). There is no password login.
  Only the owning account can manage a poll.
- `polls.invited_only` (0014): only invited people may answer. They must be signed in, as an account in the poll's `participants`
  or with the email of a guest row the owner added (that row then becomes the account's). The owner can always answer.
  Adding people (`POST .../participants`, invites) requires an email address, except friends picked by `uid`.
- `sessions` / `login_attempts`: sessions (cookie `ww_session`, `user_id` = `users.id`) and rate limiting. `polls.owner_id` = owning user.
- `mail_log`: recipients of person-started emails, for the daily cap (`MAIL_PER_DAY`).
- `friends` (0010): friend requests between accounts. A request goes to an email (`to_email`; `to_id` once that address has an account),
  `status` `pending` → `ok` when the other person accepts on their Account page. `POST /api/me/friends` answers the same whether or not
  the address has an account (no probing). Picking a friend in a poll's People tab adds them as their account (`people: [{ uid }]`).
  `contacts` in `GET /api/me/friends` = guests the owner added to their polls by email (from `participants`, not stored separately).
  The page no longer shows friend requests (API kept): the Account page's **Contacts** card and the Add-people popup share one
  contacts engine (`contactGroups` / `contactListHtml`): favourites (`favourites`, 0013; the card shows only these until Show all),
  people from your polls (`contacts` + accepted `friends`) and contacts imported in the browser (never stored unless starred).
- `messages` / `chat_reads` (0012): one group chat per poll (a series shares it), `GET|POST /api/polls/:id/chat`, `DELETE .../chat/:mid`.
  Only the owner and participants with an account (`participants.user_id`) may read or write; guests can't. The page polls
  `?after=` every 15 s while the chat is on screen (no WebSockets, no emails). `chat_reads.read_at` drives unread counts
  (`chat.unread` in `GET /api/polls/:id`, `unread` in `GET /api/me/polls`).
- `responses`: one row per person per instance. `entries` JSON: `{ "YYYY-MM-DD": "y"|"m"|"n"|{y:[h],m:[h],n:[h]} }`.
  `fill` (0015) = the Quick fill rules behind it plus the hand-made layer (`{ rules, base }`), so "Clear all" can keep the
  Quick fill marks; only returned by `GET .../responses/:rid` (the answer's owner or the organiser).

## Commands
- `npm install` once.
- `npm run db:migrate:local` then `npm run dev`: local site at http://localhost:8787 with a local database.
- `npm run db:migrate:remote`: apply new migrations to the production database.
- Deploys happen automatically when `main` is pushed to GitHub (Cloudflare Workers Builds).
  Other branches get a preview URL. `npx wrangler deploy` deploys by hand.

## Rules
- **Schema changes:** add a new migration file (`npx wrangler d1 migrations create whenwho <name>`). Never edit or delete an applied migration.
  Apply it to production (`npm run db:migrate:remote`) **before** pushing code that depends on it, and keep changes backwards compatible
  (add columns with defaults, don't rename or drop in the same release).
- Production config (custom domain, `MAIL_FROM`, `SITE_URL`, `TURNSTILE_SITE_KEY`) is in `wrangler.toml`; `RESEND_API_KEY` and `TURNSTILE_SECRET` are secrets.
  Calendar sign-in (optional): secrets `CAL_TOKEN_KEY` plus `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` and/or `MS_CLIENT_ID`/`MS_CLIENT_SECRET`;
  redirect URI `<site>/api/oauth/{google|microsoft}/callback`. Without them the Connect buttons are hidden and only iCal links work.
  Email is sent through the Resend HTTP API (`sendEmail` in the Worker). Without `RESEND_API_KEY`, sign-in codes are printed to the `npm run dev` log.
- Cost guard: the site is meant to run on the Workers Free plan (hard limits, no usage billing) + Resend free tier.
- Secrets (API tokens, email settings) never go in the repo. Use `wrangler secret put` or the dashboard, and `.dev.vars` locally (git-ignored).
- Keep the app dependency-free: one HTML file, inline CSS/JS. Escape all user content with `esc()` in the page and validate all input in the Worker.
- **Languages (English + German):** every user-visible string in the page goes through `t('English text',{vars})`, with its German text
  added to `germanText()` at the end of the script (missing entries fall back to English). Dates use `LOC`. The EN/DE switch is in the app bar
  (saved as `lang` in localStorage; default = browser language). Server error messages stay English and are translated in `api()` via `tErr()`.
  The page sends `x-lang`; the Worker stores it as `polls.lang` when the owner creates, edits or invites, and writes that poll's emails in it.
- Secrets in requests: respondent edit key in `x-edit-key`, poll password in `x-poll-password` (`?pw=` for calendar and image URLs).
  `x-admin-key` is only accepted by `POST /api/polls/:id/claim` (moving an old admin-link poll into an account).
- Before committing, test the changed flow locally with `npm run dev` (create a poll, answer it in a private window, check the group overview).
- Commit messages: short imperative summary ("Add reminder emails"), with a body if it isn't obvious.
