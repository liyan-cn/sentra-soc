CREATE TABLE IF NOT EXISTS api_tokens(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK(role IN ('viewer','reviewer','operator','admin')),
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_enabled ON api_tokens(enabled, expires_at);

