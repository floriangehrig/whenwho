-- whenwho: the Quick fill rules behind an answer, kept apart from the hand-made marks so "Clear all" can keep them.
-- JSON { rules: [{ pat, hs, he, st }], base: {entries} } ('' = none). Only the answer's owner (or the organiser) gets it back.
-- Additive only: older code ignores the column.
ALTER TABLE responses ADD COLUMN fill TEXT NOT NULL DEFAULT '';
