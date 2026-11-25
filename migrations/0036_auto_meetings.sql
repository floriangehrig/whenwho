-- Create the meetings from the poll's offered times (each run of hours without a gap = one meeting), in every round.
ALTER TABLE polls ADD COLUMN auto_meetings INTEGER NOT NULL DEFAULT 0;
