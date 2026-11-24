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
- `users`: accounts, one per (lower-cased) email, with profile `name`, `bio` (0024, one line, shown only to the person in the Account banner) and `avatar` (emoji) / `avatar_img` (data URL).
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
  Only the owning account can manage a poll, unless it gives people **roles** (0026, `participants.role` = `admin` | `editor` | `viewer`,
  accounts only, set by the owner in the People tab's role menu via `PUT /api/polls/:id/participants/:pid/role`). The Worker checks
  capabilities, not ownership: `roleOf` / `isAdmin(request, env, poll, cap)` / `requireAdmin(…, cap)` / `adminPoll(…, cap)` with
  `see` (viewer: hidden answers, all rounds, owner-only questions, people without emails; no poll password needed) ‹ `edit` (editor: meetings,
  questions, round dates / status, next round, AI suggest) ‹ `manage` (admin: settings, people, emails, others' answers, chat deletes) ‹ `own`
  (owner: delete poll, roles; role holders can only be removed by the owner). `GET /api/polls/:id` sends `role` and `can`; the page's
  `normRole` sets `isAdmin` = `can.edit` (organiser view) and uses `canSee()` / `canManage()` / `isOwnerP()` for the rest.
  Emails sent by admins count toward the owner's daily cap.
  Everyone gets the organiser's tab row minus Settings: Availability · Meetings · Questions · People. A series' rounds are managed in
  Settings → **Rounds** (list + schedule for new rounds, `roundsSection` / `renderSeries`); others switch rounds with the header's round chip.
  For non-organisers People is read-only from `people` in `GET /api/polls/:id` (names + answered this round, no emails;
  not sent when answers are hidden, so the tab disappears).
- `polls.invited_only` (0014): only invited people may answer. They must be signed in, as an account in the poll's `participants`
  or with the email of a guest row the owner added (that row then becomes the account's). The owner can always answer.
  Adding people (`POST .../participants`, invites) requires an email address, except friends picked by `uid`.
- **Overview** (home page, signed in): Your polls / Polls you answered each get a toolbar (`homeTools`: title search, All / Open / Closed / Hidden,
  kind, sort; `HOME_V`, kept in localStorage `hpv` without the search) and a ⋯ menu per card (Copy share link, Hide from overview).
  Hidden polls are per account in `poll_hidden` (0034), set by `PUT /api/me/polls/:id/hidden { hidden }`; `GET /api/me/polls` marks them `hidden: true`.
- `sessions` / `login_attempts`: sessions (cookie `ww_session`, `user_id` = `users.id`) and rate limiting. `polls.owner_id` = owning user.
- `mail_log`: recipients of person-started emails, for the daily cap (`MAIL_PER_DAY`).
- `friends` (0010): friend requests between accounts. A request goes to an email (`to_email`; `to_id` once that address has an account),
  `status` `pending` → `ok` when the other person accepts on their Account page. `POST /api/me/friends` answers the same whether or not
  the address has an account (no probing). Picking a friend in a poll's People tab adds them as their account (`people: [{ uid }]`).
  `contacts` in `GET /api/me/friends` = people in the owner's polls with an address, guests and accounts (from `participants`, not stored separately).
  **One email = one person:** adding someone by an email that has an account adds the account (`upsertPeople`); signing in or changing the
  account email claims that address's guest rows in every poll (`claimGuestRows`, a few merges per call, the rest lazily in `accountRow`);
  the page shows each address once across contact sections (`cgDedup`).
  Someone who answered without an email (plain link, other name) can be merged into an invited person by the organiser:
  People tab ⋯ → **This is someone invited…** (`pmPick`, banner `pmSuggest` for one clear name match) → `POST .../participants/:pid/merge` (`mergeInto`).
  Guests too: a guest answering with an address already in the poll becomes that row under its saved name (`guestRowsByEmail` in
  `createResponse`; a name match with another address is refused, `name_other_email`); new guest rows keep their address.
  Old splits are merged by `mergeEmailDupes` (People tab, managers opening the poll, daily 04:00 UTC sweep `mergeEmailDupesAll`).
  Signed-in callers get account avatars on people and answers (`avOut`: People tab, `people`, `responses`; the day panel shows them too).
- **Personal links** (0031, needs secret `LINK_KEY`; without it `GET /api/config` sends `personalLinks: false` and nothing changes): a guest row's
  own link `/?p=<poll>#k=<pid>.<token>`, token = HMAC(`LINK_KEY`, poll:pid:`participants.link_ver`) (`linkToken` / `personalLink`), so nothing
  secret is stored; `POST .../participants/:pid/link/reset` bumps `link_ver` (old link dead), `GET .../link` returns it (People ⋯ menu, manage).
  The page keeps it as `plink:<poll>` and sends `x-person-key` (never when signed in; accounts sign in). `personByKey` then makes that row the
  answerer in `createResponse` / `updateResponse` (name locked) / `canEditResponse` / `formIdentity`, passes `requireInvited` (invited-only polls
  need no sign-in through it) and `GET /api/polls/:id` sends `person = { pid, name, responseId }` ("Answering as …", `personMe()`), or `{ bad }`.
  Invites, reminders and round-opened emails give each guest with an email their own message via `sendMail({ links })` →
  `sendEmailBatch` (Resend `/emails/batch`, one subrequest per 100); accounts and the rest get the BCC copy as before.
  The page no longer shows friend requests (API kept): the Account page's **Contacts** card and the Add-people popup share one
  contacts engine (`contactGroups` / `contactListHtml`): favourites (`favourites`, 0013; the card shows only these until Show all),
  people from your polls (`contacts` + accepted `friends`) and contacts imported in the browser (never stored unless starred).
- `contact_groups` (0019): private named sets of people per account (`name`, `icon` emoji, `members` JSON `[{name,email}]`; max 50 groups,
  100 people each), sent as `groups` in `GET /api/me/friends`, managed via `POST /api/me/groups`, `PATCH|DELETE /api/me/groups/:id`.
  The Contacts card shows them as a rail of tiles (editor dialog `grpOpen`; 👥 on a contact row = its Groups sheet); the Add-people popup
  lists them first (`pdGroupsHtml`: "Add N" = members not in the poll, ⌄ = one by one; search matches group and member names).
  People tab: select people → Save as group. A group added from the Add-people popup is **linked** (0024): `POST /api/polls/:id/groups { groupId }`
  stores `poll_groups` (copy of name + icon) and marks its people `participants.group_id`; `updateGroup` runs `syncGroup` for every linked poll
  (new members added, and invited when the group's people there were; removed ones deleted unless they answered, then just ungrouped).
  `DELETE /api/polls/:id/groups/:gid[?people=1]` unlinks; deleting the group ungroups. The People tab shows linked groups as collapsible
  headers (`pgShut`, localStorage `pgrp:<poll>`); `GET .../participants` sends `groups` and each person's `groupId`.
  Contacts whose address has an account carry that account's `avatar` / `avatarImg` (`accountsByEmail`; pictures via `GET /api/users/:uid/avatar`,
  signed-in only); imported ones are looked up with `POST /api/me/contacts/lookup`. Your own address is never a contact (`isMe`, server checks).
- `messages` / `chat_reads` (0012): one group chat per poll (a series shares it), `GET|POST /api/polls/:id/chat`, `DELETE .../chat/:mid`.
  Everyone signed in may read and write (invited-only polls: the owner and invited people). Guests (no account) may **read** when they can
  open the poll (invited-only polls: only through their personal link, `chatReadable`): `GET .../chat` (`chatAccess(…, write = false)`) gives them
  no `members`, `me: null`, and `people` as names only (`chatGuestNames`: account name or poll name, never email-based, no avatars); no read mark.
  `GET /api/polls/:id` sends `chat.read` (can read) next to `chat.can` (can write); page `chatRead()` vs `chatCan()`. Guests' "new message"
  peek / ring compares `chat.last.at` with localStorage `chatSeen:<poll>`; writing, reacting, replying, deleting and muting need an account.
  `polls.allow_comments` is the poll's **Chat** switch (Answering in Settings): off = no chat (403, dock hidden) and no guest Comment field. The page polls
  `?after=` while the chat is open (15 s, slowing to 60 s when quiet; no WebSockets, no emails; see **Push notifications**). `chat_reads.read_at` drives unread counts
  (`chat.unread` in `GET /api/polls/:id`, `unread` in `GET /api/me/polls`). 0016: `messages.ref` puts a message in a day / meeting
  thread (`d:YYYY-MM-DD` / `m:<meeting id>`), `reactions` (JSON emoji → user ids, sent as counts) via `POST .../chat/:mid/react`,
  `updated_at` makes `?after=` return changed reactions. `GET /api/polls/:id` adds `chat.last` (header peek) and `chat.refs` (thread counts).
  The page shows the chat in one drawer (round button bottom-right; bottom sheet on phones) instead of a card or tab. The button pops in, peeks out as a pill ("Chat" or the newest unread message, `chatPeek`) on opening a poll (once per tab, `sessionStorage peek:<poll>`) and when a message comes in, and a ring pulses while there are unread messages (`.ping`). It is one
  timeline: messages plus events worked out on the page (answers, grouped when close together; meetings by their `at` stamp; rounds by
  `createdAt`). Guests who can't read the chat see only the events. Dates of the poll written in a message become chips that jump to that day.
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
- **Push notifications** (0028, Web Push): `push_subs` = one row per browser that turned on chat notifications (endpoint + p256dh / auth keys,
  `lang`; max 10 per account). `POST|DELETE /api/me/push`, `POST /api/me/push/test`. Endpoints must be on a known push host (`PUSH_HOST_RE`,
  the Worker POSTs to them). `postChat` runs `pushChat` in `waitUntil`: every chat member's devices (`CHAT_MEMBERS_SQL` + owner) except the writer
  and people who muted the poll (`chat_reads.muted`, `PUT /api/polls/:id/chat/mute`, `chat.muted` in `GET /api/polls/:id`), at most `PUSH_MAX`
  (30) per message (Free plan limits). Payload `{ kind, title, name, body, url, tag, poll, at }`, encrypted with WebCrypto only (RFC 8291 aes128gcm,
  VAPID RFC 8292); 404/410 deletes the sub. Keys: `VAPID_PUBLIC_KEY` (var) + `VAPID_PRIVATE_KEY` (secret), made by `node scripts/vapid-keys.mjs`;
  without them `GET /api/config` sends `push: null` and the UI is hidden. Page: `public/sw.js` (service worker, the one extra script file: shows the
  notification unless a focused tab is on that poll, tap opens `?p=<id>&chat=1`) and `public/manifest.webmanifest` (iPhone: push only from the
  Home Screen app). `pushEnable` / `pushDisable` / `pushResync` (daily), ask bar at the top of the chat (`pushAskHtml`, ✕ = `pushAsk`, 30 days),
  🔔/🔕 mute in the chat header (`chatMuteBtn`), Account → Summary → Notifications (`pushSecDraw`, Send a test). Signing out unsubscribes.
  **Add to Home Screen guide** (`hsOpen(os)`, dialog `#hsdlg`, classes `hs-*`): an animated drawn phone (iPhone Safari / Android Chrome, picked by UA, switchable)
  where a fake finger taps each step; autoplays (not with reduced motion), tap the phone / ‹ › / dots to step. Opened by `data-hsopen` buttons: Show me how
  next to the homescreen hints (chat ask bar, `ntDevice`, `pushSecDraw`), the account menu on phones not running it standalone (`hsCan`), and a `home` tour step.
  Android also gets Install now when Chrome fired `beforeinstallprompt` (`HS.bip`).
- **Notifications** (0029 `answer_watch`, 0032 prefs + `poll_events`): what people are told about, per type: `chat` (`'all'|'mentions'|'off'`),
  `answers`, `votes`, `qanswers` (these three only for people who can see the answers), `meetings`, `questions`, `rounds`, each `{ p: push, e: email }`.
  Effective prefs (`ntRow`): the poll's override (`answer_watch.prefs`, set with the 🔔 button in the poll header, dialog `ntOpen`, `PUT /api/polls/:id/notify
  { prefs | null }`) ?? account defaults (`users.notify`, Account → Notifications, `GET|PUT /api/me/notify`) ?? built-in by role (`ntBuiltin`: everyone push
  for chat / meetings / questions / rounds, organisers also answers / votes / question answers; email off). Legacy `answer_watch.email/push` and
  `chat_reads.muted` still count when there is no override; the chat header 🔔/🔕 sets `chat.p`. Audience (`ntAudience`) = accounts connected to the poll
  (chat members, people in it, owner, anyone with settings); guests get none. Events are logged by `notifyEvent` (from answers, votes, question answers,
  `updateInstance` meeting / question / status diffs (`meetingEvents`), `notifyOpened` for later series rounds, `postChat`) into `poll_events` (kept 3 days)
  and pushed right away (`kind` = event, `tag` per type; same person's changed answer / vote / form within 10 min is logged but not pushed).
  The hourly cron's `notifyDigests` emails each person once with the events they want by email, across polls, then marks them `digested`.
  `GET /api/polls/:id` sends `me.notify = { prefs, own, types }`. Push URLs may carry `&tab=meetings|questions`.
- `responses`: one row per person per instance. `entries` JSON: `{ "YYYY-MM-DD": "y"|"m"|"n"|{y:[h],m:[h],n:[h]} }`.
  `fill` (0015) = the Quick fill rules behind it plus the hand-made layer (`{ rules, base }`), so "Clear all" can keep the
  Quick fill marks; only returned by `GET .../responses/:rid` (the answer's owner or the organiser).
- **Questions** (0022, 0023): a small form per round. `instances.questions` = the organiser's questions (`validateQuestions`, order = list order):
  `type` `radio` | `check` | `select` | `rating` (`rating.max/lo/hi`) | `short` | `long` | `yesno` (`count`); choice types have `options`,
  `place` (place search, map links, **Use as place** sets the linked meetings' location), `add` (people suggest options); `req`, `vis`
  (`all` | `owner`), `closed`, `repeat` (series: copy into new rounds, default on). `link` = `{ to: 'poll' }` or `{ to: 'meetings', ids, each? }`
  (meetings incl. proposed options; `each` = per date of a repeating meeting, answers `{ "YYYY-MM-DD": value }`). `who` = `{ mode: all |
  people (pids) | meeting (invited to the linked meetings) | free (marked y / if needed at their time) }`, enforced by `canAnswer`.
  Answers live in `form_answers` (0023; one row per person per round, `extra = { a, add }`, guests have their own `edit_hash`), apart from the
  availability: `GET|PUT|DELETE /api/polls/:id/instances/:iid/form` (`fid` + `x-form-key`, or `rid` of their availability answer; accounts by
  session). `GET /api/polls/:id` sends `form = { added, rows }` (rows filtered by `extraFor`, same visibility as answers). Old 0022 shapes are
  normalised by `normQ`; `responses.extra` is no longer used.
  Page: the **Questions** tab only (`renderQuestions`): **Fill in** (own Send bar, guests give a name) and **Results** (bars, rating averages,
  text lists, compact view), organiser editor inline (`qEditor`, popup fields `qDd` for type / applies to / who; `qeRead` then `qeRerender`),
  ⋯ menu and drag (`data-qgrip`) to reorder.
  **Questionnaires**: items `{ type: 'group', label, icon, help, link, who }` in the same list; a question joins one with `grp` and takes its
  `link` / `who` (resolved in `questionsOf`) unless `own: true`. `GET` sends `instance.groups`; the page saves `[...groups, ...questions]`
  (`saveQuestions(list, gs)`), shows them as collapsible cards (`qGroupCard`, collapsed ones in `qgc:<poll>`), drag or ⋯ Move to between them.
  **Generate with AI** (✨ in the Ask ▾ menu / empty state, organiser only): `POST /api/polls/:id/instances/:iid/questions-text` `{ text }`
  sends the text and the poll title to Workers AI and returns draft questions in the page's shape (`{ group: {label, icon} | null, questions }`,
  no ids, nothing stored). The page (`qAiPanel`) lists them to pick, optionally as a new questionnaire, and saves with `saveQuestions` (Undo).
  Shares the `AI_PER_DAY` cap.
  **After-meeting questions**: `link = { to: 'after', ids?, last? }` (no ids = every confirmed meeting of the round) are asked once per
  meeting that has ended (each date of a repeating one); answers `{ "<meeting id>:<YYYY-MM-DD>": value }`. `last` = only the newest one
  can be answered (older ones close). The Worker doesn't know the time zone, so `afterOccs` allows 14 h either way (`TZ_SLACK`) and the page
  shows the exact ones (`qOccs`); `GET .../form` sends `occ` (the dates I may answer, checked per meeting by `canAnswerAt`). They stay
  answerable in a closed round (`saveForm` `onlyAfter`); series copies keep them as after-questions. On open, `qAfterPrompt` asks the newest
  unanswered one of the last 14 days in a sheet (Skip = localStorage `qskip:<poll>`); `GET /api/polls/:id` sends `prevAfter` (the round
  before) so a meeting there opens that round. Ended meetings get a Rate chip; rating results show the average per meeting.
  Questions and questionnaires have an optional `icon` (one emoji, `emojiIcon`; picker `qIconDd` with defaults `Q_ICONS`). The Answers tab is called **Availability** (key `answers`).
  **Questions in meetings**: questions linked to a meeting are embedded in its card and in vote option rows (`qMeetBlock`, wrapper
  `[data-mqx]`, one line per question there until tapped, `P.mqopen`): people answer there with the counts showing (`qBody(q, true, px, live)`,
  `px` = id prefix so the tab and the card don't share ids) and Send (`qSend`); guests with no name yet get Answer → Questions tab.
  The organiser's **Ask ▾** on a card (`qMeetAsk`: place vote, choice, yes/no, text, rating, from a preset linked to it via `qPresetAdd(pr, mid)`)
  and ✎ open the editor inside the card (`qOpenEditor(q, mid)` → `P.qedit.inMeet`). `renderQuestions` draws the tab (`renderQuestionsTab`,
  without the editor when it's in a card) and then `qMeetRefresh` (only the `[data-mqx]` blocks, focus kept by `keepFocus`).
  **Questions for new meetings** (0033 `polls.meet_questions`, like `meet_location` / `meet_note`): up to 5 templates (questions without
  id / link / who, `meetQuestionTpls` in the Worker, sent as `meetQuestions`, editors only; also in presets). Edited with one small engine
  (`mqtBox` / `mqtDraw`, live list `MQT[pre]`, `data-mqt*`) in Settings / New poll → Meetings (`meetDefRows`) and Plan new → Details
  (`#dm_qs`, `P.dmeta.qs`, pre-filled from the poll). `saveDrafts` checks the 30-per-round limit first, then adds one question per template
  for each new meeting, or one linked to all of them with **One question for all** (`dm.qOne`) (`mqtQuestions`).
  **Questions in every round** (series): a question with `repeat !== false` is copied into the next round (`insertInstance`; editor switch
  `qe_rep` at the top, ⋯ Ask in every round / Only this round, 🔁 Every round tag `qEvery`). 0035 `polls.round_questions` = up to 10 templates
  with stable ids (`roundQuestionTpls`, sent as `roundQuestions`, editors of a series; presets too), edited in Settings → Questions and New poll → Questions
  (Recurring) with the same mqt engine (prefix `r` / `nr`, `roundQsRows`). Every new round gets fresh copies marked `tpl` = template id
  (`roundQuestionCopies`, skips ones the round has by `tpl` or same label); `tpl` copies aren't repeat-copied, so changing or deleting one
  round's copy doesn't change later rounds. Saving the list adds new templates to the current open round too (`addNewRoundQuestions`).
  ⋯ Add to every-round list (`qToRoundList`) moves a question into the list. **Placeholders** `{month}` / `{dates}` (also `{monat}` /
  `{zeitraum}`) in a question's label / help are stored raw and filled in per round: page `qTokData` in `api()` keeps `_raw` and shows
  `qTx(...)`; `qRawOf` puts the raw text back before saving / editing / presets. Worker `roundText` (event names, meeting descriptions).
  Editor chips ＋ Month / ＋ Dates (`qTokChips`, `data-qtok`, inserted into the last focused field of `[data-qtokscope]`) with a preview.
- **Answers in a meeting** (meeting field `inc`, no table): the meeting editor's (✎ on a card, also holds the location; ＋ Add place opens it) and
  Plan new → Details' (`#dm_inc`, `P.dmeta.inc`, set on every new meeting) **From the answers** (`incPicker` / `incRead(box)`) picks
  `{ who, comments, qs: [{ id, each }] }` (who's coming at its time, answer comments, questions as summary or per person; not after-meeting ones).
  The Worker renders it live (`meetingAnswerText`, data from `answerData`, `meetingAnswerTexts` for several rounds) into the .ics DESCRIPTION,
  the invite / Email all emails and `answersText` on meetings in `GET /api/polls/:id` (card block, `descOf` for copy/share, MCP `from_answers`).
  Shown to everyone who gets the meeting, even when answers are hidden (the editor warns).
- **Fill with AI** (✨ in My answer): `POST /api/polls/:id/instances/:iid/fill-text` `{ text }` sends the text to
  Workers AI (binding `AI`, model `AI_MODEL`), which returns rules; the Worker expands them to `{ rules: [{ dates, hs, he, st }] }`
  and the page paints them onto the answer as a hand edit (Undo). Nothing is stored. Voice = the keyboard's own dictation
  (no mic button of our own). Same access checks as answering; `AI_PER_DAY` fills per account / IP per day (`login_attempts`, kind `ai`).
  Without the `AI` binding `GET /api/config` says `aiFill: false` and the button is hidden.
- **Generate a poll with AI** (✨ Describe it next to Start from on the New poll page, `CONFIG.aiFill`): `POST /api/polls/generate-text` `{ text }`
  (signed out too, by IP) sends only the text to Workers AI (`pollFromText`, `POLLGEN_SCHEMA`) and returns `{ data, startDate? }`, `data` in a
  preset's shape (checked by `presetData`; questions via the shared `aiQuestions`, in one questionnaire when the model names one). The page fills
  the form with `applyPreset` (Undo restores the snapshot); nothing is created or stored. Shares the `AI_PER_DAY` cap.
- **Help assistant** (page + Worker, nothing stored): the app bar's ? (`tourButton`) is a menu **Ask for help** · **Take the tour** (just one when only
  one applies; also in the account menu). `helpOpen` (dialog `#helpdlg`, classes `hx-*`, history in sessionStorage `help`) sends the last 8 turns and
  the page kind (`helpPage`) to `POST /api/help`; the Worker answers from `HELP_DOC` (a plain-words guide to the site: **update it when you add a
  main feature**) via Workers AI and may name one place to open (`show`, `HELP_SHOW`; the page's **Show me** button, `helpShow` / `helpCan`).
  Own daily cap `HELP_PER_DAY` (40, `login_attempts` kind `help`). `GET /api/config` sends `help`.
- **Presets** (`poll_presets`, 0025): saved starting points for new polls, per account (max 50): `data` = the New poll body without
  dates or password (`days` = length of a one-off range) plus `questions` (links reset by `presetQuestions`: meetings → whole poll,
  after-meeting ones kept, `people` → everyone). `GET|POST /api/me/presets` (POST with a name you already use replaces it),
  `PATCH|DELETE /api/me/presets/:id` (PATCH `{ folder }` moves one to another group). `POST /api/polls` takes `questions` for the first round.
  Built-in presets: `builtinPresets()` (about 20, each with fitting questions; built with the `QB` helpers), grouped by `PRESET_CATS`;
  my own are grouped by `data.folder` (empty = My presets). The New poll page shows a **Start from** field that opens the picker
  (`prsOpen`, dialog `#psdlg`, classes `ps-*`: search, group chips, collapsible groups in localStorage `prsc`, tap a row to preview its
  questions, Use / double-click / Enter; ⋯ Rename / Move to group / Delete on mine) and **Save as preset** (name + group); Settings has a
  Save as preset row (`presetFromPoll`).
  The Save dialog has an **Include questions** switch (off = settings only); the picker's **Without questions** uses a preset's settings only.
  **Question presets**: same table, `data = { scope: 'questions', questions, icon?, folder? }` (no settings; `presetData` validates only
  the questions). Saved from a questionnaire's or question's ⋯ menu or Ask ▾ → Save all as preset (`qPresetData`); Ask ▾ → From a preset
  opens the picker with `ctx.mode = 'questions'` (every preset with questions, built-in too) and `qPresetAdd` adds them with fresh ids
  (`qFromPreset`). In poll mode the picker hides question presets.
- **Your data** (Account page, GDPR rights): `GET /api/me/export` = JSON copy of everything about the account (secret columns
  like `*_hash` / tokens stripped; owned polls in full, polls answered by title); `POST /api/me/delete` emails a code (`login_codes` key
  `delete:<user id>`, can't sign in), `POST /api/me/delete/verify` `{ code }` deletes the account, its owned polls (with everyone's answers
  and chat), its answers / messages / reactions / shared busy hours in other polls, calendars (Google grant revoked), contacts and groups,
  then emails a confirmation. Both are driven by **`USER_DATA`** in the Worker: every table with its export SQL and delete SQL (or `skip`
  with a reason), in deletion order. Restriction / objection requests go by email (`CONTACT_EMAIL`, mailto on the card).
- **Retention** (GDPR storage limitation): once a day (03:17 UTC cron run) `deleteStalePolls` deletes up to 25 polls with no activity
  for `RETAIN_MONTHS` (default 12, `"0"` = off): no poll change, answer, chat message or chat read since, and (single polls, or series
  rounds with meetings) the last day has passed. 14 days before (`RETAIN_WARN_DAYS`) the owner is emailed (`retentionWarning`,
  `polls.retention_warned_at`, 0021); only polls warned in the current quiet spell are deleted, and the owner opening the poll
  (`getPoll`) clears the mark and keeps it. Uses `pollDeleteStmts` (same as deleting a poll). Stated in `renderPrivacy`.
- **Place search** (location fields of meetings): the page asks `GET /api/places?q=&lang=`, which forwards the text to Photon
  (photon.komoot.io, OpenStreetMap) and caches the trimmed answer for a day. It runs before the session lookup (one call per keystroke).
  Server-side first (direct browser requests get blocked on phones: content blockers, shared mobile IPs); when `/api/places`
  fails (Photon refuses the Worker from some Cloudflare locations, e.g. a phone on a VPN served in Helsinki) the page asks Photon directly.
- **Quick Suggest** (⚡ in the Meetings planner): settings `sugopt` in localStorage. Days are picked **By weekday** or as
  **Pick dates** (chips for the round's dates, `sugMode()` / `P.sugDates`, in memory per poll, part of the planner undo; Suggest with AI fills them).
  Off by default, **Options** (`step`, hours apart) turns it
  from "best time per day" into every start time in the picked hours (e.g. 2 h meetings every hour, overlapping) as separate drafts,
  capped by How many and the 100-meeting limit, with Let people vote switched on so they're proposed for a vote.
- **Suggest with AI** (✨ in the Meetings planner, organiser only): `POST /api/polls/:id/instances/:iid/suggest-text` `{ text, people }`
  turns "2 evening meetings a week, not Fridays" into the planner's Suggest settings (`{ s, wd, hs, he, dates }`); the page runs the
  normal Suggest with them (Undo restores settings and drafts). Only the text and the number of selected people are sent, no answers.
  Shares the `AI_PER_DAY` cap with Fill with AI.
- **Guided tour** (page only): spotlight walkthrough (`tourStart` / `tourShow` / `tourSteps(key)`, classes `tour-*`). Tours by page and role:
  `home`, `new`, `account`, and on a poll `answer` (people answering, viewers) ‹ `edit` (+ planner, questions editor, dates) ‹ `manage`
  (+ share, People, roles for the owner, Settings). Steps are `{ sel, title, body, go, when }`: `go()` opens the tab first, steps whose
  element isn't visible are skipped (so no AI / chat / closed round just shortens it). Shown once per tour (localStorage `tour`, a higher
  level marks the lower ones seen), started by `tourAuto()` after the page is drawn; replay with the ? button in the app bar (`tourButton`)
  or Take the tour in the account menu. When you add a main feature, add a step for it.
  Demo steps (`demo`, people who can answer): a fake finger (`tourPtr`, `demoKit`) paints days (`demoDays`), shows tap vs range
  (`demoRange`) and fine-tunes hours (`demoHours`) on My answer; `tourDemoSnap` / `tourDemoRestore` put the answer, mode, brush and
  undo history back when the demo steps end, nothing is saved. The answer brush always starts in tap mode (range isn't remembered).
- **To do** (page only, people answering; not organisers): `todoList()` works out what's still open for me in this round from page state
  (availability not sent, required questions empty `qReqOpen`, vote groups without my vote, after-meeting questions via `qPromptPick(true)`).
  `todoSync()` draws the `#todo` strip under the header chips (amber when the deadline is today / tomorrow) and the `.tdot` dots on the tabs;
  it runs from `renderBody`, `renderMeetings`, `renderQuestions` and `renderHeader`. Tapping a chip (`data-todo`) opens the tab and flashes the spot.
- **Undo / redo** (page only): two histories in `HIST`, `ans` (My answer: marks + Quick fill layers) and `plan` (planner drafts + Suggest dates).
  `histTick()` runs at the start of every `renderBody()` and pushes the last snapshot when the state changed, so any edit path is covered
  without hooks (one drag = one step; name/comment typing isn't tracked). ↶ / ↷ in one small grey box (`histSeg`, `.hseg`; My answer adds its ✕ Clear there) and ⌘Z / ⌘⇧Z / Ctrl+Y
  (not in text fields, dialogs or the chat). Reset when the round or the loaded answer changes (`histReset`). Max 50 steps.

## Commands
- `npm install` once.
- `npm run db:migrate:local` then `npm run dev`: local site at http://localhost:8787 with a local database.
- `npm run db:migrate:remote`: apply new migrations to the production database.
- Deploys happen automatically when `main` is pushed to GitHub (Cloudflare Workers Builds).
  Other branches get a preview URL. `npx wrangler deploy` deploys by hand.

## Rules
- **Schema changes:** add a new migration file (`npx wrangler d1 migrations create whenwho <name>`). Never edit or delete an applied migration.
  **Personal data stays covered:** with every new migration, add its tables to `USER_DATA` (export + delete, or `skip` with a reason),
  check new columns are exported / deleted with their table, then set `USER_DATA_REVIEWED` to the migration's number. If it stores a new kind
  of personal data, describe it in the privacy policy (`renderPrivacy`) and bump `PRIVACY_UPDATED`. `npm run check` fails until this is done:
  run it before committing.
  Apply it to production (`npm run db:migrate:remote`) **before** pushing code that depends on it, and keep changes backwards compatible
  (add columns with defaults, don't rename or drop in the same release).
- **Legal pages** (required in Germany): `?imprint` (Impressum, § 5 DDG), `?privacy` and `?rules` (DSA: content rules, how to report illegal content),
  linked in `siteFoot()` on every page and in the email footer. Their data comes from `OPERATOR_NAME` / `OPERATOR_ADDRESS` / `OPERATOR_PHONE` /
  `CONTACT_EMAIL` / `DPA_NAME` in `wrangler.toml` (via `/api/config`). When a feature sends data somewhere new or stores something new, update the
  privacy policy (`renderPrivacy`, bump `PRIVACY_UPDATED`): that includes any new outside service (a `fetch` to a new host, a new CSP entry,
  a new email or AI use). Load nothing from third parties on page load (the Inter font is self-hosted in `public/fonts/`).
- Production config (custom domain, `MAIL_FROM`, `SITE_URL`, `TURNSTILE_SITE_KEY`) is in `wrangler.toml`; `RESEND_API_KEY` and `TURNSTILE_SECRET` are secrets.
  Personal invite links (optional): secret `LINK_KEY` (any long random string; changing it kills all personal links).
  Calendar sign-in (optional): secrets `CAL_TOKEN_KEY` plus `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` and/or `MS_CLIENT_ID`/`MS_CLIENT_SECRET`;
  redirect URI `<site>/api/oauth/{google|microsoft}/callback`. Without them the Connect buttons are hidden and only iCal links work.
  Email is sent through the Resend HTTP API (`sendEmail` in the Worker). Without `RESEND_API_KEY`, sign-in codes are printed to the `npm run dev` log.
- Cost guard: the site is meant to run on the Workers Free plan (hard limits, no usage billing) + Resend free tier.
- Secrets (API tokens, email settings) never go in the repo. Use `wrangler secret put` or the dashboard, and `.dev.vars` locally (git-ignored).
- **CSP:** the page's two inline `<script>` blocks are allowed by sha256 hash (no `'unsafe-inline'`), so after editing either one run
  `node scripts/check-csp.mjs --fix` (updates `CSP` in the Worker and `public/_headers`; `npm run check` fails until then). No inline
  `on…=` handlers in HTML or templates: use `addEventListener`. Poll passwords are throttled per IP and per poll (`guardedPasswordOk`);
  `RL_WRITE` / `RL_PLACES` (Rate Limiting bindings in `wrangler.toml`) cap changes and place lookups per IP per minute.
- Keep the app dependency-free: one HTML file, inline CSS/JS. Escape all user content with `esc()` in the page and validate all input in the Worker.
- **Languages (English + German):** every user-visible string in the page goes through `t('English text',{vars})`, with its German text
  added to `germanText()` at the end of the script (missing entries fall back to English). Dates use `LOC`. The language picker (System default / English / Deutsch) is in the app bar
  (saved as `lang` in localStorage; default = browser language). Server error messages stay English and are translated in `api()` via `tErr()`.
  The page sends `x-lang`; the Worker stores it as `polls.lang` when the owner creates, edits or invites, and writes that poll's emails in it.
- Secrets in requests: respondent edit key in `x-edit-key`, poll password in `x-poll-password` (`?pw=` for calendar and image URLs).
  `x-admin-key` is only accepted by `POST /api/polls/:id/claim` (moving an old admin-link poll into an account).
- Before committing, test the changed flow locally with `npm run dev` (create a poll, answer it in a private window, check the group overview).
- Commit messages: short imperative summary ("Add reminder emails"), with a body if it isn't obvious.
