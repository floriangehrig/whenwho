-- whenwho: one group chat per poll (a series shares one), for the owner and participants with an account.
-- chat_reads remembers when each person last read a poll's chat (for unread badges).
-- Additive only: older code ignores both tables.
CREATE TABLE messages (
  id TEXT PRIMARY KEY,
  poll_id TEXT NOT NULL,
  user_id TEXT NOT NULL,      -- users.id of the author
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_messages_poll ON messages (poll_id, created_at);
CREATE TABLE chat_reads (
  poll_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  read_at TEXT NOT NULL,
  PRIMARY KEY (poll_id, user_id)
);
