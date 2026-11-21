-- whenwho: contact groups = named, private sets of people (name + email) on an account, added to a poll in one go.
-- members = JSON [{ "name": "...", "email": "..." }], emails lower-cased and unique within the group.
-- Additive only: older code ignores the table.
CREATE TABLE contact_groups (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT '',
  members TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_contact_groups_user ON contact_groups (user_id);
