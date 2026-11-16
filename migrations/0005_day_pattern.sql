-- whenwho: limit which days a poll offers, e.g. "Fridays" or "1st-20th of the month".
-- day_pattern: JSON {"wd":[0..6]|null,"dom":[from,to]|null} (wd 0 = Monday). NULL = every day.
-- Additive only: older code ignores the column and offers every day.
ALTER TABLE polls ADD COLUMN day_pattern TEXT;
