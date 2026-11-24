-- Notification preferences per event type: account defaults (users.notify) and per-poll overrides (answer_watch.prefs),
-- both JSON { chat: { p, e }, answers, votes, qanswers, meetings, questions, rounds } ('' = built-in / follow defaults).
ALTER TABLE users ADD COLUMN notify TEXT NOT NULL DEFAULT '';
ALTER TABLE answer_watch ADD COLUMN prefs TEXT NOT NULL DEFAULT '';
-- Short log of what happened in a poll (answers, votes, meetings, questions, rounds, chat), for push and the hourly email.
-- name = who did it, or a meeting / question label; ref = participant id, message id or meeting JSON; tagged = @mentioned user ids.
-- Deleted after 3 days.
CREATE TABLE poll_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  poll_id TEXT NOT NULL,
  instance_id TEXT,
  kind TEXT NOT NULL,
  actor_id TEXT,
  name TEXT NOT NULL DEFAULT '',
  ref TEXT NOT NULL DEFAULT '',
  tagged TEXT NOT NULL DEFAULT '',
  at TEXT NOT NULL,
  digested INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX poll_events_poll ON poll_events (poll_id, at);
CREATE INDEX poll_events_digest ON poll_events (digested, id);
