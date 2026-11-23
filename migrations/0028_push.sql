-- Web Push: one row per browser / device that turned on chat notifications (endpoint = the browser's push address).
CREATE TABLE push_subs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  lang TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX push_subs_user ON push_subs (user_id);
-- Per person per poll: 1 = no push notifications for this poll's chat.
ALTER TABLE chat_reads ADD COLUMN muted INTEGER NOT NULL DEFAULT 0;
