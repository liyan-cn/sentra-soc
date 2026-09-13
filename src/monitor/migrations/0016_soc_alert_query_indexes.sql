CREATE INDEX IF NOT EXISTS idx_soc_alerts_workspace_time
  ON soc_alerts(workspace_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_soc_alerts_time
  ON soc_alerts(occurred_at DESC);
