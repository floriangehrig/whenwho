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
  Changing the account email (`POST /api/me/email`, then `.../email/verify`) sends a code to the new address, stored in
  `login_codes` as `change:<user id>:<address>` (so it can't sign anyone in); on success it updates `users.email` and the copies
  in `participants` / `responses` (the account's), owned polls' legacy `admin_email` and `friends.to_email`, and notifies the old address.
  Only the owning account can manage a poll.
  Everyone gets the organiser's tab row minus Settings: Answers · Meetings · Rounds (series with 2+ visible rounds) · People.
  For non-organisers People is read-only from `people` in `GET /api/polls/:id` (names + answered this round, no emails;
  not sent when answers are hidden, so the tab disappears).
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
- `contact_groups` (0019): private named sets of people per account (`name`, `icon` emoji, `members` JSON `[{name,email}]`; max 50 groups,
  100 people each), sent as `groups` in `GET /api/me/friends`, managed via `POST /api/me/groups`, `PATCH|DELETE /api/me/groups/:id`.
  The Contacts card shows them as a rail of tiles (editor dialog `grpOpen`; 👥 on a contact row = its Groups sheet); the Add-people popup
  lists them first (`pdGroupsHtml`: "Add N" = members not in the poll, ⌄ = one by one; search matches group and member names).
  People tab: select people → Save as group. Adding a group uses the normal `POST .../participants`.
- `messages` / `chat_reads` (0012): one group chat per poll (a series shares it), `GET|POST /api/polls/:id/chat`, `DELETE .../chat/:mid`.
  Everyone signed in may read and write (invited-only polls: the owner and invited people); guests can't.
  `polls.allow_comments` is the poll's **Chat** switch (Answering in Settings): off = no chat (403, dock hidden) and no guest Comment field. The page polls
  `?after=` while the chat is open (15 s, slowing to 60 s when quiet; no WebSockets, no emails). `chat_reads.read_at` drives unread counts
  (`chat.unread` in `GET /api/polls/:id`, `unread` in `GET /api/me/polls`). 0016: `messages.ref` puts a message in a day / meeting
  thread (`d:YYYY-MM-DD` / `m:<meeting id>`), `reactions` (JSON emoji → user ids, sent as counts) via `POST .../chat/:mid/react`,
  `updated_at` makes `?after=` return changed reactions. `GET /api/polls/:id` adds `chat.last` (header peek) and `chat.refs` (thread counts).
  The page shows the chat in one drawer (round button bottom-right; bottom sheet on phones) instead of a card or tab. It is one
  timeline: messages plus events worked out on the page (answers, grouped when close together; meetings by their `at` stamp; rounds by
  `createdAt`). Guests see only the events. Dates of the poll written in a message become chips that jump to that day.
  People who can chat don't get the Comment field under My answer.
  Tags and attachments are inline tokens in `messages.body`: `<@user id>` (a chat member: owner, account participants, accounts invited by email, anyone who opened
  or wrote in the chat; listed as `members` in the full `GET .../chat`, with `me` = caller's id) and `<#m:meeting id>` (proposed or set). The composer shows readable
  labels (typed `@` list or the 📎 list) and turns them into tokens on send; max 20 tokens per message. 0018: `messages.reply_to`
  quotes another message (`re` / `rq` in the API; `rq` null once the original is deleted). `chat.mentions` in `GET /api/polls/:id` =
  unread messages that tag me (the dock's `@` badge). Hold (touch), right-click or ⌄ opens the message menu (react, reply, copy, delete);
  swipe right replies. Search and filters (tagged me, meetings, replies to me, person; everything / messages / events) run on the page
  over the loaded messages (`CHAT_KEEP`).
- `shared_busy` / `participants.share_busy` (0020): opt-in per person per poll to show the poll's people when they're busy.
  The sharer's page works out their busy hours (picked auto calendars) for the round's dates and uploads only `{ "YYYY-MM-DD": [h] }`
  via `PUT /api/polls/:id/instances/:iid/busy` `{ share, hours }` (when changed, or every 6 h; off deletes all their rows).
  `GET /api/polls/:id` sends `busy: [{ pid, name, hours, updatedAt }]` (same visibility as answers, caller left out) and `me.shareBusy`.
  The Busy ▾ in My answer has two sections: **Own** (my auto calendars + the Share switch) and **Others** (people who share; All / None /
  one by one, picks in localStorage `busyPplOff:<poll>`, `"*"` = None so later sharers stay hidden too); their hours
  show with accent stripes the other way (`obusy` / `.obm`).
- `responses`: one row per person per instance. `entries` JSON: `{ "YYYY-MM-DD": "y"|"m"|"n"|{y:[h],m:[h],n:[h]} }`.
  `fill` (0015) = the Quick fill rules behind it plus the hand-made layer (`{ rules, base }`), so "Clear all" can keep the
  Quick fill marks; only returned by `GET .../responses/:rid` (the answer's owner or the organiser).
- **Fill with AI** (✨ in My answer): `POST /api/polls/:id/instances/:iid/fill-text` `{ text }` sends the text to
  Workers AI (binding `AI`, model `AI_MODEL`), which returns rules; the Worker expands them to `{ rules: [{ dates, hs, he, st }] }`
  and the page paints them onto the answer as a hand edit (Undo). Nothing is stored. Voice = the keyboard's own dictation
  (no mic button of our own). Same access checks as answering; `AI_PER_DAY` fills per account / IP per day (`login_attempts`, kind `ai`).
  Without the `AI` binding `GET /api/config` says `aiFill: false` and the button is hidden.
- **Place search** (location fields of meetings): the page asks `GET /api/places?q=&lang=`, which forwards the text to Photon
  (photon.komoot.io, OpenStreetMap) and caches the trimmed answer for a day. It runs before the session lookup (one call per keystroke).
  Server-side first (direct browser requests get blocked on phones: content blockers, shared mobile IPs); when `/api/places`
  fails (Photon refuses the Worker from some Cloudflare locations, e.g. a phone on a VPN served in Helsinki) the page asks Photon directly.
- **Suggest** (⚡ in the Meetings planner): settings `sugopt` in localStorage. Off by default, **Options** (`step`, hours apart) turns it
  from "best time per day" into every start time in the picked hours (e.g. 2 h meetings every hour, overlapping) as separate drafts,
  capped by How many and the 100-meeting limit, with Let people vote switched on so they're proposed for a vote.
- **Suggest with AI** (✨ in the Meetings planner, organiser only): `POST /api/polls/:id/instances/:iid/suggest-text` `{ text, people }`
  turns "2 evening meetings a week, not Fridays" into the planner's Suggest settings (`{ s, wd, hs, he, dates }`); the page runs the
  normal Suggest with them (Undo restores settings and drafts). Only the text and the number of selected people are sent, no answers.
  Shares the `AI_PER_DAY` cap with Fill with AI.

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
  added to `germanText()` at the end of the script (missing entries fall back to English). Dates use `LOC`. The language picker (System default / English / Deutsch) is in the app bar
  (saved as `lang` in localStorage; default = browser language). Server error messages stay English and are translated in `api()` via `tErr()`.
  The page sends `x-lang`; the Worker stores it as `polls.lang` when the owner creates, edits or invites, and writes that poll's emails in it.
- Secrets in requests: respondent edit key in `x-edit-key`, poll password in `x-poll-password` (`?pw=` for calendar and image URLs).
  `x-admin-key` is only accepted by `POST /api/polls/:id/claim` (moving an old admin-link poll into an account).
- Before committing, test the changed flow locally with `npm run dev` (create a poll, answer it in a private window, check the group overview).
- Commit messages: short imperative summary ("Add reminder emails"), with a body if it isn't obvious.
