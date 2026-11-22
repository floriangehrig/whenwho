-- whenwho: polls with no activity for RETAIN_MONTHS are deleted; the owner is emailed RETAIN_WARN_DAYS before.
-- retention_warned_at = when that warning went out (NULL = not warned, or the owner opened the poll since).
-- Additive only: older code ignores the column.
ALTER TABLE polls ADD COLUMN retention_warned_at TEXT;
