-- whenwho: votes on proposed meetings (meetings with `proposed: true` in instances.meetings).
-- JSON array of the meeting ids this person ticked (approval voting); NULL = no votes.
-- Additive only: older code ignores the column.
ALTER TABLE responses ADD COLUMN votes TEXT;
