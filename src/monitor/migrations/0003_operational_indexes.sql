CREATE INDEX IF NOT EXISTS idx_reviews_ip_status ON review_cases(ip, status);
CREATE INDEX IF NOT EXISTS idx_vpn_status_login ON vpn_sessions(status, login_at);
CREATE INDEX IF NOT EXISTS idx_heartbeat_updated ON service_heartbeats(updated_at);

