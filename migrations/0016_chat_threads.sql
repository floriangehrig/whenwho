-- whenwho: chat messages can belong to a day or meeting thread and carry emoji reactions.
-- ref: NULL = general chat, 'd:YYYY-MM-DD' = a day of the poll, 'm:<meeting id>' = a scheduled meeting.
-- reactions: JSON { "👍": [user id, …] }. updated_at: set when reactions change, so polling picks the change up.
-- Additive only: older code ignores the new columns.
ALTER TABLE messages ADD COLUMN ref TEXT;
ALTER TABLE messages ADD COLUMN reactions TEXT NOT NULL DEFAULT '{}';
ALTER TABLE messages ADD COLUMN updated_at TEXT;
CREATE INDEX idx_messages_poll_upd ON messages (poll_id, updated_at);
