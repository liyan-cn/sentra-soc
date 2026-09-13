import logging
from datetime import datetime, timezone

from monitor.domain.models import SecurityEvent
from monitor.workers.collector_worker import enrich_event


class FailingProvider:
    def __init__(self, message):
        self.message = message
    def lookup(self, _ip):
        raise RuntimeError(self.message)


def test_enrichment_failures_degrade_without_losing_event_or_leaking_message():
    event = SecurityEvent(source="TEST", device_id="d1", event_type="attack",
                          occurred_at=datetime.now(timezone.utc), src_ip="8.8.8.8", raw_line="x")
    location, threat = enrich_event(
        event, FailingProvider("private geo credential"), FailingProvider("private intel credential"),
        logging.getLogger("test"),
    )
    assert location == "UNKNOWN"
    assert threat == {}
    assert event.attributes["threat_intel"] == {}
    assert event.attributes["enrichment_errors"] == [
        "threat_intelligence:RuntimeError", "geolocation:RuntimeError",
    ]
    assert "credential" not in str(event.attributes)


def test_successful_enrichment_is_attached_to_event():
    class Provider:
        def __init__(self, value): self.value = value
        def lookup(self, _ip): return self.value

    event = SecurityEvent(source="TEST", device_id="d1", event_type="attack",
                          occurred_at=datetime.now(timezone.utc), src_ip="8.8.8.8", raw_line="x")
    location, threat = enrich_event(event, Provider("US/CA"), Provider({"tags": ["scanner"]}),
                                    logging.getLogger("test"))
    assert location == "US/CA"
    assert threat == {"tags": ["scanner"]}
    assert "enrichment_errors" not in event.attributes
