import json

RETENTION_DEFAULTS = {
    'security_events_days': 180, 'parse_failures_days': 30, 'host_checks_days': 30,
    'vpn_sessions_days': 180, 'notification_logs_days': 90, 'audit_logs_days': 365,
}


def effective_retention(settings, conn):
    result = {**RETENTION_DEFAULTS, **settings.section('retention')}
    row = conn.execute("SELECT value_json FROM runtime_settings WHERE name='retention'").fetchone()
    if row:
        result.update(json.loads(row['value_json']))
    return result
