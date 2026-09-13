CREATE INDEX IF NOT EXISTS idx_soc_alerts_workspace_time_title
  ON soc_alerts(workspace_id, occurred_at, title);
