-- whenwho: an account's iCal feed URL, used to pre-fill availability from the person's own calendar.
-- It is a secret (Google/Outlook "secret address"): the Worker fetches it and never returns it to the page.
-- Additive only: older code ignores the column.
ALTER TABLE users ADD COLUMN ical_url TEXT;
