-- Historical DPTECH URL classification records were telemetry, not confirmed attacks.
-- Preserve them for audit but exclude them from attack totals, trends and review workflows.
UPDATE policy_decisions
SET decision='IGNORE', rule_id='migration-dptech-url-telemetry',
    reason='DPTECH url_class is traffic telemetry; no local attack rule was available at ingestion time'
WHERE event_id IN (
  SELECT id FROM security_events WHERE source='DPTECH_IPS' AND category='URL_SCAN'
);

UPDATE review_cases
SET status='closed', resolution='historical DPTECH URL classification telemetry',
    updated_at=CURRENT_TIMESTAMP
WHERE event_id IN (
  SELECT id FROM security_events WHERE source='DPTECH_IPS' AND category='URL_SCAN'
) AND status IN ('open','claimed');

DELETE FROM soc_alerts
WHERE event_id IN (
  SELECT id FROM security_events WHERE source='DPTECH_IPS' AND category='URL_SCAN'
);
