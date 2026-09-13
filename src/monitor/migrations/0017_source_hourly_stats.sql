CREATE TABLE IF NOT EXISTS source_hourly_stats(
  hour TEXT NOT NULL,
  device_id TEXT NOT NULL,
  source TEXT NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(hour,device_id,source)
);

INSERT INTO source_hourly_stats(hour,device_id,source,event_count)
SELECT substr(occurred_at,1,13),device_id,source,COUNT(*)
FROM security_events
WHERE occurred_at>=datetime('now','-48 hours')
GROUP BY substr(occurred_at,1,13),device_id,source
ON CONFLICT(hour,device_id,source) DO UPDATE SET event_count=excluded.event_count;

CREATE TRIGGER IF NOT EXISTS trg_security_event_hourly_stats
AFTER INSERT ON security_events
BEGIN
  INSERT INTO source_hourly_stats(hour,device_id,source,event_count)
  VALUES(substr(NEW.occurred_at,1,13),NEW.device_id,NEW.source,1)
  ON CONFLICT(hour,device_id,source) DO UPDATE SET event_count=event_count+1;
END;
