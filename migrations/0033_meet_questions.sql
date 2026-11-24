-- Questions filled into the Meetings planner for every new meeting (like meet_location / meet_note):
-- JSON list of question templates without ids, links or who; NULL = none.
ALTER TABLE polls ADD COLUMN meet_questions TEXT;
