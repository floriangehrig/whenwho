-- whenwho: polls a person hid from their overview (Your polls / Polls you answered). Only changes what the home page shows.
-- Additive only: older code ignores the table.
CREATE TABLE poll_hidden (
  user_id TEXT NOT NULL,
  poll_id TEXT NOT NULL,
  at TEXT NOT NULL,
  PRIMARY KEY (user_id, poll_id)
);
CREATE INDEX idx_poll_hidden_poll ON poll_hidden (poll_id);
