CREATE TABLE IF NOT EXISTS asset_discovery_jobs(
 id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,actor TEXT NOT NULL,
 status TEXT NOT NULL,request_json TEXT NOT NULL,result_json TEXT NOT NULL DEFAULT '{}',
 progress INTEGER NOT NULL DEFAULT 0,total INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_workspace ON asset_discovery_jobs(workspace_id,created_at);
