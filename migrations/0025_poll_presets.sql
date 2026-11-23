-- Poll presets: an account's saved starting points for new polls (title, settings and questions; no dates, people or passwords).
CREATE TABLE poll_presets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT '',
  data TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_poll_presets_user ON poll_presets (user_id);
