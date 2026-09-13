ALTER TABLE hosts ADD COLUMN consecutive_successes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN outage_started_at TEXT;
ALTER TABLE hosts ADD COLUMN outage_notified_at TEXT;
ALTER TABLE hosts ADD COLUMN last_probe_json TEXT NOT NULL DEFAULT '{}';
