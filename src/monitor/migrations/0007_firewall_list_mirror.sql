CREATE TABLE firewall_list_entries(
  id TEXT PRIMARY KEY,
  list_type TEXT NOT NULL CHECK(list_type IN ('blacklist','whitelist')),
  direction TEXT NOT NULL CHECK(direction IN ('src','dst')),
  ip TEXT NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'any',
  reason TEXT NOT NULL DEFAULT '',
  inserted_at TEXT,
  age_time TEXT NOT NULL DEFAULT 'Permanent',
  expires_at TEXT,
  permanent INTEGER NOT NULL DEFAULT 1,
  hit_count INTEGER NOT NULL DEFAULT 0,
  description TEXT NOT NULL DEFAULT '',
  synced_at TEXT NOT NULL,
  UNIQUE(list_type,direction,ip,protocol)
);
CREATE INDEX idx_firewall_list_type ON firewall_list_entries(list_type,direction,ip);
