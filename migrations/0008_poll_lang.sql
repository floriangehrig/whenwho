-- whenwho: language of a poll's emails ('en' | 'de'), set from the organiser's page language.
-- Additive only: older code ignores the column.
ALTER TABLE polls ADD COLUMN lang TEXT NOT NULL DEFAULT 'en';
