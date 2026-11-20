-- whenwho: friends between accounts. A request goes to an email address (so nobody can tell whether it has an account);
-- the other person accepts it on their Account page. to_id is filled in once the address has an account.
-- Additive only: older code ignores the table.
CREATE TABLE friends (
  id TEXT PRIMARY KEY,
  from_id TEXT NOT NULL,                  -- users.id of the person who asked
  to_email TEXT NOT NULL,                 -- lower-cased address the request went to
  to_id TEXT,                             -- users.id of that address, once known
  status TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'ok'
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_friends_pair ON friends (from_id, to_email);
CREATE INDEX idx_friends_to ON friends (to_id);
CREATE INDEX idx_friends_email ON friends (to_email);
