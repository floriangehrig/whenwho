-- whenwho: admin login sessions and poll-wide participant names.
-- Additive only: the code from before this migration keeps working.

-- Login sessions. Only a hash of the cookie token is stored. user_id is 'admin' for the built-in account.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);

-- Failed admin logins and name lookups, to slow down guessing. Cleaned up by the cron job.
CREATE TABLE IF NOT EXISTS login_attempts (
  ip   TEXT NOT NULL,
  kind TEXT NOT NULL,   -- 'login' | 'name'
  at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS login_attempts_ip ON login_attempts (ip, kind, at);

-- A participant is a name that is unique within a poll (case-insensitive) and stays the same across
-- all rounds of a series. Typing the name again recalls that person's answer.
CREATE TABLE IF NOT EXISTS participants (
  id         TEXT PRIMARY KEY,
  poll_id    TEXT NOT NULL,
  name       TEXT NOT NULL,
  name_key   TEXT NOT NULL,             -- lower-cased, trimmed name
  email      TEXT NOT NULL DEFAULT '',  -- optional, added by the admin
  created_at TEXT NOT NULL,
  UNIQUE (poll_id, name_key)
);

ALTER TABLE polls ADD COLUMN owner_id TEXT;            -- user who owns the poll (NULL = only the admin link)
ALTER TABLE responses ADD COLUMN participant_id TEXT;  -- participants.id (NULL = not linked)

CREATE INDEX IF NOT EXISTS polls_owner ON polls (owner_id);
CREATE INDEX IF NOT EXISTS responses_participant ON responses (participant_id);

-- Backfill: one participant per distinct name in each poll, then link the existing answers.
INSERT OR IGNORE INTO participants (id, poll_id, name, name_key, email, created_at)
  SELECT lower(hex(randomblob(8))), poll_id, MIN(TRIM(name)), LOWER(TRIM(name)), '', MIN(created_at)
  FROM responses GROUP BY poll_id, LOWER(TRIM(name));
UPDATE responses SET participant_id = (
  SELECT p.id FROM participants p WHERE p.poll_id = responses.poll_id AND p.name_key = LOWER(TRIM(responses.name))
) WHERE participant_id IS NULL;
