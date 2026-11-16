-- whenwho: accounts that sign in with a one-time code sent by email.
-- Additive only: the built-in 'admin' account (sessions.user_id = 'admin') keeps working.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,   -- lower-cased
  created_at    TEXT NOT NULL,
  last_login_at TEXT
);

-- At most one live sign-in code per email address. Only a hash of the code is stored.
CREATE TABLE IF NOT EXISTS login_codes (
  email      TEXT PRIMARY KEY,          -- lower-cased
  code_hash  TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

-- Emails sent per account (invites, test emails) to cap sending. Cleaned up by the cron job.
CREATE TABLE IF NOT EXISTS mail_log (
  user_id TEXT NOT NULL,
  n       INTEGER NOT NULL,
  at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_log_user ON mail_log (user_id, at);
