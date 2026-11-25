-- Account setting: grey out my busy hours from my other polls while answering (Account → Calendars, Busy ▾ → Other polls). Off by default.
ALTER TABLE users ADD COLUMN busy_polls INTEGER NOT NULL DEFAULT 0;
