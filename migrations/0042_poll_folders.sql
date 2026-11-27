-- Poll groups (Account page): a person's own named sets of polls (a poll may be in several). Each has a secret live
-- calendar link (/api/feeds/<feed_token>.ics) that bundles the meetings the person is in across those polls.
-- Called "folders" in code because poll_groups already links contact groups to polls.
CREATE TABLE poll_folders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT '',
  polls TEXT NOT NULL DEFAULT '[]',
  feed_token TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_poll_folders_user ON poll_folders(user_id);
CREATE UNIQUE INDEX idx_poll_folders_token ON poll_folders(feed_token);
