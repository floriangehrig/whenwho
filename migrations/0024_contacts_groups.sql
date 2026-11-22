-- Profile description (shown only on the person's own Account page).
ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT '';
-- Contact groups linked to a poll: the poll's people stay in sync with the group (one group per person; first wins).
ALTER TABLE participants ADD COLUMN group_id TEXT;
CREATE INDEX idx_participants_group ON participants (poll_id, group_id);
CREATE TABLE poll_groups (
  poll_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  name TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  PRIMARY KEY (poll_id, group_id)
);
CREATE INDEX idx_poll_groups_group ON poll_groups (group_id);
