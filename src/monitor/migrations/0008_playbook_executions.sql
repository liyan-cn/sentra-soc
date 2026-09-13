CREATE TABLE playbook_executions(
  id TEXT PRIMARY KEY,
  playbook_id TEXT NOT NULL,
  playbook_version TEXT NOT NULL,
  event_id TEXT NOT NULL REFERENCES security_events(id),
  review_id TEXT REFERENCES review_cases(id),
  action_type TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE INDEX idx_playbook_executions_time ON playbook_executions(created_at,playbook_id);
