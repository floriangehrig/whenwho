-- Settings / New poll → Meetings: apply the default location, description and questions to every meeting (existing and auto-made too)
-- and keep them in sync when the defaults change. Off by default (= only new meetings made in the planner get them).
ALTER TABLE polls ADD COLUMN meet_apply INTEGER NOT NULL DEFAULT 0;
