-- Calendar view on the home page: a linked calendar's own icon (one emoji) and the colour the person picked for it
-- (empty = the provider's colour in `color`, which Google / Outlook resyncs keep updating).
ALTER TABLE user_calendars ADD COLUMN icon TEXT NOT NULL DEFAULT '';
ALTER TABLE user_calendars ADD COLUMN color_pick TEXT NOT NULL DEFAULT '';
