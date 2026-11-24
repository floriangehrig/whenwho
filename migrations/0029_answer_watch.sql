-- "Notify me when someone answers": per person per poll. email = hourly digest, push = Web Push right away.
-- sent_at = digest cutoff (answers updated after it go in the next email). No row = off.
CREATE TABLE answer_watch (
  poll_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  email INTEGER NOT NULL DEFAULT 0,
  push INTEGER NOT NULL DEFAULT 0,
  sent_at TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (poll_id, user_id)
);
CREATE INDEX answer_watch_user ON answer_watch (user_id);
