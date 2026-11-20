-- whenwho: the owner can let only invited people answer (they sign in with the invited email address).
-- Additive only: older code ignores the column and lets anyone answer.
ALTER TABLE polls ADD COLUMN invited_only INTEGER NOT NULL DEFAULT 0;
