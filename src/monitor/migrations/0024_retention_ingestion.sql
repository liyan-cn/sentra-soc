CREATE TABLE IF NOT EXISTS runtime_settings(
  name TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingestion_hourly_stats(
  hour TEXT NOT NULL, device_id TEXT NOT NULL, line_count INTEGER NOT NULL DEFAULT 0,
  last_seen_at TEXT NOT NULL, PRIMARY KEY(hour,device_id)
);
