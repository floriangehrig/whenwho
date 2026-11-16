# whenwho

Find out when everyone's free, and who can make it. A small website for availability polls. Respondents don't need an account. It runs free on Cloudflare Workers + D1.

- **Recurring series** (e.g. monthly rehearsals): a new poll opens automatically for each period (every N weeks or months), a set number of days before the period starts. The share link always shows the newest open poll. You can manage each poll in the series: view, close or reopen, edit dates or reply-by date, add a note, delete, or open the next one early.
- **One-off polls** (e.g. a vacation): one date range.
- People answer with **whole days**, **time slots** or **both**: available, maybe or not available.
- **Scheduling:** pick a day in the group overview and schedule a meeting, for everyone or only some people. The best time and the people who are free are filled in for you.
- **Calendar:** "Add to calendar" (.ics) per meeting, plus a subscribable calendar feed for the whole series.
- **Email (optional, Cloudflare Email Service):** send meeting invites with the calendar file attached, notify people when a new poll in a series opens, and remind people before the reply-by date. Without it, "Email invite" opens your own email app.

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
Then connect the GitHub repo in Cloudflare (Worker → Settings → Builds) so every push to `main` deploys.

### Optional: email (Cloudflare Email Service)
Needs the **Workers Paid plan** and a **domain of your own** added to Cloudflare.
1. In the dashboard, open **Email Service** and onboard your domain for sending. Follow Cloudflare's steps, which include adding DNS records.
2. Uncomment `[[send_email]]` in `wrangler.toml` (or Worker → **Settings → Bindings → Add → Send email**), name `EMAIL`.
3. Worker → **Settings → Variables and Secrets** → add:
   - `MAIL_FROM` = an address on that domain, e.g. `whenwho@your-domain.com`
   - `SITE_URL` = your site's address, e.g. `https://whenwho.your-subdomain.workers.dev`
4. Deploy. In a poll's **Settings**, add your email and press **Send test email**.

Who gets what:
- **Meeting invite:** everyone invited to the meeting who left an email address, sent as BCC. You get a copy, and replies go to you.
- **New poll opened:** people who answered the previous poll in the series and left an email, if that's turned on for the series.
- **Reminder:** people who answered last time but not yet this time, N days before the reply-by date, if turned on.

## Notes
- Each poll has a **share link** (for respondents) and an **admin link** (keep it private: it can change or delete the poll).
- People's "edit my answer" key lives in their browser. In another browser, they'd answer again.
- Meeting times are floating local times (18:00 shows as 18:00 for everyone), which is fine for a group in one time zone.
- There's no rate limiting. That's fine for small groups, but don't post links publicly.
# whenwho
