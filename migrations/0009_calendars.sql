-- whenwho: several calendars per account (iCal links, and Google / Outlook accounts signed in with OAuth).
-- Each calendar can grey out the owner's busy hours on polls they answer (auto = 1).
-- Additive only: users.ical_url stays (older code still reads it); its value is copied in below.

-- A signed-in Google or Outlook account. Tokens are encrypted with the CAL_TOKEN_KEY secret.
CREATE TABLE calendar_accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL,              -- 'google' | 'microsoft'
  email TEXT NOT NULL DEFAULT '',
  refresh_token TEXT NOT NULL,
  access_token TEXT,
  expires_at INTEGER,                  -- ms since epoch
  status TEXT NOT NULL DEFAULT 'ok',   -- 'ok' | 'expired' (needs reconnecting)
  created_at TEXT NOT NULL
);
CREATE INDEX idx_calendar_accounts_user ON calendar_accounts (user_id);

-- One calendar: an iCal link (url, secret) or a calendar inside a calendar account (account_id + ext_id).
CREATE TABLE user_calendars (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  account_id TEXT,
  ext_id TEXT,
  url TEXT,
  name TEXT NOT NULL DEFAULT '',
  color TEXT NOT NULL DEFAULT '',
  auto INTEGER NOT NULL DEFAULT 1,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_user_calendars_user ON user_calendars (user_id);

-- OAuth sign-ins in progress (state + PKCE verifier), deleted after use or by the hourly cleanup.
CREATE TABLE oauth_states (
  state TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  verifier TEXT NOT NULL,
  created_at TEXT NOT NULL
);

INSERT INTO user_calendars (id, user_id, url, name, auto, created_at)
  SELECT 'c' || lower(hex(randomblob(6))), id, ical_url, 'Calendar', 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  FROM users WHERE ical_url IS NOT NULL AND ical_url <> '';
