CREATE TABLE notification_channels(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  provider TEXT NOT NULL CHECK(provider IN ('wechat','smtp','sms_webhook')),
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  config_json TEXT NOT NULL DEFAULT '{}',
  secret_encrypted TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id,provider)
);
CREATE INDEX idx_notification_channels_enabled ON notification_channels(workspace_id,enabled,provider);
