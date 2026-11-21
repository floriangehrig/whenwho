-- whenwho: a chat message can quote another one (reply). NULL = not a reply.
-- Tags (<@user id>) and attached meetings (<#m:meeting id>) live inline in messages.body, so they need no column.
-- Additive only: older code ignores the new column.
ALTER TABLE messages ADD COLUMN reply_to TEXT;
