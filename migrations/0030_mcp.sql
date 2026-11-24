-- MCP (Model Context Protocol): AI assistants connect to an account with OAuth 2.1.
-- mcp_clients = apps that registered themselves (dynamic client registration, public clients, no secret).
CREATE TABLE mcp_clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,          -- JSON list
  created_at TEXT NOT NULL,
  used_at TEXT
);
-- An authorization in progress: created by /oauth/authorize, gets user_id + code_hash when the person allows it.
-- Single use, valid 10 minutes.
CREATE TABLE mcp_requests (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  state TEXT,
  code_challenge TEXT NOT NULL,
  resource TEXT,
  user_id TEXT,
  code_hash TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX mcp_requests_code ON mcp_requests (code_hash);
-- A connected app: one per sign-in. Tokens are stored only as hashes.
CREATE TABLE mcp_grants (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_name TEXT NOT NULL,
  access_hash TEXT NOT NULL,
  access_exp TEXT NOT NULL,
  refresh_hash TEXT NOT NULL,
  refresh_exp TEXT NOT NULL,
  created_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX mcp_grants_user ON mcp_grants (user_id);
CREATE UNIQUE INDEX mcp_grants_access ON mcp_grants (access_hash);
CREATE UNIQUE INDEX mcp_grants_refresh ON mcp_grants (refresh_hash);
