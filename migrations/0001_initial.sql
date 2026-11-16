-- whenwho: initial database schema (Cloudflare D1 / SQLite)
-- Never edit a migration that has been applied. Add a new numbered file instead.

CREATE TABLE IF NOT EXISTS polls (
  id             TEXT PRIMARY KEY,
  admin_hash     TEXT NOT NULL,
  title          TEXT NOT NULL,
  description    TEXT NOT NULL DEFAULT '',
  kind           TEXT NOT NULL,               -- 'single' (one poll) | 'series' (recurring)
  unit           TEXT,                        -- series: 'week' | 'month'
  every          INTEGER,                     -- series: repeat every N units
  anchor         TEXT,                        -- series: start date of the first period (YYYY-MM-DD)
  open_days      INTEGER,                     -- series: open each new poll N days before its period starts
  deadline_days  INTEGER,                     -- series: reply-by N days before the period starts (NULL = none)
  answer_mode    TEXT NOT NULL DEFAULT 'both',-- 'days' | 'slots' | 'both'
  hour_start     INTEGER NOT NULL DEFAULT 8,
  hour_end       INTEGER NOT NULL DEFAULT 24,
  hide_results   INTEGER NOT NULL DEFAULT 0,
  allow_comments INTEGER NOT NULL DEFAULT 1,
  password_hash  TEXT,
  admin_email    TEXT NOT NULL DEFAULT '',    -- optional: organiser's email (reply-to, copies)
  notify_open    INTEGER NOT NULL DEFAULT 0,  -- email previous respondents when a new poll in the series opens
  remind_days    INTEGER,                     -- email a reminder N days before the deadline (NULL = off)
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);

-- Each poll has one or more instances (one per period of a series; exactly one for a single poll).
CREATE TABLE IF NOT EXISTS instances (
  id              TEXT PRIMARY KEY,
  poll_id         TEXT NOT NULL,
  seq             INTEGER NOT NULL,
  start_date      TEXT NOT NULL,
  end_date        TEXT NOT NULL,
  deadline        TEXT,
  status          TEXT NOT NULL DEFAULT 'open', -- 'open' | 'closed' (also closed automatically after end_date)
  note            TEXT NOT NULL DEFAULT '',
  meetings        TEXT NOT NULL DEFAULT '[]',   -- JSON array of scheduled meetings
  opened_notified INTEGER NOT NULL DEFAULT 0,
  reminded        INTEGER NOT NULL DEFAULT 0,
  created_at      TEXT NOT NULL,
  UNIQUE (poll_id, seq)
);

CREATE TABLE IF NOT EXISTS responses (
  id          TEXT PRIMARY KEY,
  poll_id     TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  name        TEXT NOT NULL,
  email       TEXT NOT NULL DEFAULT '',       -- optional, only shown to the admin
  comment     TEXT NOT NULL DEFAULT '',
  entries     TEXT NOT NULL DEFAULT '{}',     -- JSON: { "YYYY-MM-DD": "y"|"m"|"n"|{y:[h],m:[h],n:[h]} }
  edit_hash   TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS instances_poll ON instances (poll_id, seq);
CREATE INDEX IF NOT EXISTS responses_instance ON responses (instance_id);
CREATE INDEX IF NOT EXISTS responses_poll ON responses (poll_id);
