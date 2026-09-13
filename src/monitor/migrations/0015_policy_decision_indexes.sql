CREATE INDEX IF NOT EXISTS idx_policy_decisions_event_decision
  ON policy_decisions(event_id, decision);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_created
  ON policy_decisions(created_at);
