CREATE INDEX IF NOT EXISTS idx_policy_decisions_event_created
  ON policy_decisions(event_id,created_at DESC);
