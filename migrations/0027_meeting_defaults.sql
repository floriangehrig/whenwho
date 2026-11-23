-- Default location and description for new meetings (filled into the Meetings planner).
ALTER TABLE polls ADD COLUMN meet_location TEXT NOT NULL DEFAULT '';
ALTER TABLE polls ADD COLUMN meet_note TEXT NOT NULL DEFAULT '';
