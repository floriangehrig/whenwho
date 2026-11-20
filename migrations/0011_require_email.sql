-- whenwho: the organiser can require guests to give an email address (as well as their name) to answer.
-- Additive only: older code ignores the column and keeps email optional.
ALTER TABLE polls ADD COLUMN require_email INTEGER NOT NULL DEFAULT 0;
