-- whenwho: people can share the hours they're busy in their calendars with a poll (opt-in per person per poll).
-- The sharer's browser uploads only busy hours per date of the round ({ "YYYY-MM-DD": [h, ...] }), no event titles or times.
-- Additive only: older code ignores the column and the table.
ALTER TABLE participants ADD COLUMN share_busy INTEGER NOT NULL DEFAULT 0;

CREATE TABLE shared_busy (
  instance_id TEXT NOT NULL,
  participant_id TEXT NOT NULL,
  poll_id TEXT NOT NULL,
  hours TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (instance_id, participant_id)
);
CREATE INDEX idx_shared_busy_poll ON shared_busy (poll_id);
