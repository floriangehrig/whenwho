# whenwho

Find out when everyone's free, and who can make it. A small website for availability polls. Respondents don't need an account. It runs free on Cloudflare Workers + D1.

- **Recurring series** (e.g. monthly rehearsals): a new poll opens automatically for each period (every N weeks or months), a set number of days before the period starts. The share link always shows the newest open poll. You can manage each poll in the series: view, close or reopen, edit dates or reply-by date, add a note, delete, or open the next one early.
- **One-off polls** (e.g. a vacation): one date range.
- People answer with **whole days**, **time slots** or **both**: available, maybe or not available.
- **Scheduling:** pick a day in the group overview and schedule a meeting, for everyone or only some people. The best time and the people who are free are filled in for you.
- **Calendar:** "Add to calendar" (.ics) per meeting, plus a subscribable calendar feed for the whole series.
- **Email (optional, via Resend):** send meeting invites with the calendar file attached, notify people when a new poll in a series opens, and remind people before the reply-by date. Without it, "Email invite" opens your own email app.

## Files
- `src/worker.js`: API, hourly cron job, emails
- `public/index.html`: the web app
- `migrations/`: database schema (D1 migrations)
- `wrangler.toml`: Cloudflare configuration
- `CLAUDE.md`: project notes for Claude Code

## Setup
See the step-by-step setup guide: Cloudflare + GitHub + Claude Code.
Short version:
```
npm install
npx wrangler login
npx wrangler d1 create whenwho        # put the database_id into wrangler.toml
npm run db:migrate:remote
npx wrangler deploy
```
Anyone can sign in with their email (top right: **Sign in**, a 6-digit code is emailed) and create polls. Answering never needs an account.
Each account has a profile page (name and avatar: an emoji or a picture) under the avatar menu → **Account & profile**.
Then connect the GitHub repo in Cloudflare (Worker → Settings → Builds) so every push to `main` deploys.

### Email (Resend)
Needed for sign-in codes in production. Resend's free plan (100 emails/day, 3,000/month) is plenty for a small group,
and it simply stops sending at the limit, so it can't run up a bill.
1. Create a Resend account and add your domain (**Domains → Add domain**). If the domain is on Cloudflare,
   Resend can add the DNS records for you; otherwise copy them into **Cloudflare → DNS** (DKIM TXT, plus MX and SPF TXT on the `send` subdomain).
   Also add DMARC: TXT `_dmarc` = `v=DMARC1; p=quarantine`.
2. **API Keys → Create**: permission "Sending access", limited to that domain. Then `npx wrangler secret put RESEND_API_KEY`.
3. In `wrangler.toml` set `MAIL_FROM` (e.g. `noreply@your-domain.com`) and `SITE_URL`.
4. Deploy. Sign in, and in a poll's **Settings** add your email and press **Send test email**.

Without `RESEND_API_KEY` (e.g. locally), sign-in codes are printed in the `npm run dev` output instead of being emailed.

Who gets what:
- **Meeting invite:** everyone invited to the meeting who left an email address, sent as BCC. You get a copy, and replies go to you.
- **New poll opened:** people who answered the previous poll in the series and left an email, if that's turned on for the series.
- **Reminder:** people who answered last time but not yet this time, N days before the reply-by date, if turned on.

## Notes
- Each poll has a **share link** for respondents. Only the account that created a poll can change or delete it. Polls get an emoji icon or a picture (resized in the browser and stored in D1).
  Old admin links (`?admin=…`) no longer manage a poll: opening one while signed in moves that poll into your account.
- **People who answer while signed in** are identified by their account's email, so their answer follows them to every device and their name doesn't have to be unique.
- **Guests (no account): names are unique within a poll** and stay the same across all rounds of a series. Typing the same name again (on any device) brings back that person's answer. Anyone who knows a name can change that answer, so this suits groups that trust each other. If a guest later signs in and edits their answer, it moves into their account. The owner manages people under **Participants** (edit, merge duplicates, remove, add people in advance).
- Meeting times are floating local times (18:00 shows as 18:00 for everyone), which is fine for a group in one time zone.
- Failed sign-in codes and name lookups are limited to 10 per 15 minutes per IP.
# whenwho
