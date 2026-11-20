-- whenwho: favourites = a private starred list of people (name + email) on an account, shown first when adding people to a poll.
-- calendar_accounts.scope = the scopes the provider granted (to know whether contacts may be read).
-- oauth_states.ret = poll to go back to after a contacts sign-in.
-- Additive only: older code ignores the table and columns.
CREATE TABLE favourites (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,         -- lower-cased
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_favourites_user_email ON favourites (user_id, email);
ALTER TABLE calendar_accounts ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_states ADD COLUMN ret TEXT;
