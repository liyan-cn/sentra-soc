CREATE TABLE source_alert_hourly_stats(
  hour TEXT NOT NULL,
  device_id TEXT NOT NULL,
  source TEXT NOT NULL,
  src_ip TEXT NOT NULL DEFAULT '',
  event_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(hour,device_id,source,src_ip)
);

INSERT INTO source_alert_hourly_stats(hour,device_id,source,src_ip,event_count)
SELECT substr(a.occurred_at,1,13),e.device_id,a.source,COALESCE(a.src_ip,''),COUNT(*)
FROM soc_alerts a
JOIN security_events e ON e.id=a.event_id
WHERE a.occurred_at>=strftime('%Y-%m-%dT%H:%M:%S','now','-48 hours')
GROUP BY substr(a.occurred_at,1,13),e.device_id,a.source,COALESCE(a.src_ip,'');

CREATE TRIGGER trg_soc_alert_hourly_stats AFTER INSERT ON soc_alerts
BEGIN
  INSERT INTO source_alert_hourly_stats(hour,device_id,source,src_ip,event_count)
  SELECT substr(NEW.occurred_at,1,13),e.device_id,NEW.source,COALESCE(NEW.src_ip,''),1
  FROM security_events e WHERE e.id=NEW.event_id
  ON CONFLICT(hour,device_id,source,src_ip)
  DO UPDATE SET event_count=event_count+1;
END;
