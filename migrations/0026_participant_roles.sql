-- Poll roles: an account in a poll's participants can be made admin, editor or viewer by the poll's owner ('' = none).
ALTER TABLE participants ADD COLUMN role TEXT NOT NULL DEFAULT '';
