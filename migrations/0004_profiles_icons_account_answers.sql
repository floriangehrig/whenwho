-- whenwho: account profiles (name + avatar), poll icons / pictures, and answers linked to accounts.
-- Additive only: the code from before this migration keeps working (it ignores the new columns).

-- Profile shown in the app bar and the account page. avatar: '' = initial on a colour, otherwise an emoji.
-- avatar_img: optional uploaded picture as a small data URL (resized in the browser), shown instead of the emoji.
ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN avatar_img TEXT;

-- Poll icon: '' = first letter of the title, otherwise an emoji. image: optional picture (data URL), image_at: its version.
ALTER TABLE polls ADD COLUMN icon TEXT NOT NULL DEFAULT '';
ALTER TABLE polls ADD COLUMN image TEXT;
ALTER TABLE polls ADD COLUMN image_at TEXT;

-- A participant who answered while signed in is identified by their account (email), not by their name.
-- Their name_key is "\u0001" + user id, so it never clashes with a typed name and names can repeat.
ALTER TABLE participants ADD COLUMN user_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS participants_user ON participants (poll_id, user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS participants_user_any ON participants (user_id);

-- The built-in "admin" account is gone: end its sessions.
DELETE FROM sessions WHERE user_id = 'admin';
