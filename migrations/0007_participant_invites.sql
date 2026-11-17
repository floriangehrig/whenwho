-- whenwho: when the site last emailed a participant an invite or reminder from the People tab (NULL = never).
-- Additive only: older code ignores the column.
ALTER TABLE participants ADD COLUMN invited_at TEXT;
