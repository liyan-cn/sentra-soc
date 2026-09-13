CREATE TABLE discovered_devices(
  id TEXT PRIMARY KEY,
  source_ip TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','observing','active','ignored','error')),
  parser TEXT,
  source TEXT,
  confidence REAL NOT NULL DEFAULT 0,
  sample_count INTEGER NOT NULL DEFAULT 0,
  candidate_count INTEGER NOT NULL DEFAULT 0,
  parsed_count INTEGER NOT NULL DEFAULT 0,
  parse_success_rate REAL NOT NULL DEFAULT 0,
  field_completeness REAL NOT NULL DEFAULT 0,
  log_glob TEXT NOT NULL,
  config_json TEXT NOT NULL DEFAULT '{}',
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  confirmed_by TEXT,
  confirmed_at TEXT,
  promoted_at TEXT,
  last_error TEXT
);
CREATE INDEX idx_discovered_devices_status ON discovered_devices(status,last_seen_at);

