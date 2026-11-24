-- Personal invite links: a guest's link is an HMAC of poll, person and this version (secret LINK_KEY).
-- "New link" bumps it, so the old link stops working. Nothing secret is stored.
ALTER TABLE participants ADD COLUMN link_ver INTEGER NOT NULL DEFAULT 0;
