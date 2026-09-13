ALTER TABLE vpn_sessions ADD COLUMN last_seen_at TEXT;
ALTER TABLE vpn_sessions ADD COLUMN session_origin TEXT NOT NULL DEFAULT 'login';
UPDATE vpn_sessions SET last_seen_at=COALESCE(logout_at,login_at) WHERE last_seen_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_vpn_status_seen ON vpn_sessions(status,last_seen_at);
