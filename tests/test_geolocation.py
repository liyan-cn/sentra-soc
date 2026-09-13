import requests

from monitor.infrastructure.database import Database
from monitor.infrastructure.geolocation import GeoLocationService


def test_private_address_never_calls_external_service(tmp_path, monkeypatch):
    db = Database(tmp_path / "geo.db"); db.initialize()
    monkeypatch.setattr(requests, "get", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()))
    assert GeoLocationService(db).lookup("10.0.0.1") == "INTERNAL"


def test_outage_opens_circuit_and_failures_are_cached(tmp_path, monkeypatch):
    db = Database(tmp_path / "geo.db"); db.initialize()
    calls = []

    def unavailable(url, **_kwargs):
        calls.append(url)
        raise requests.Timeout("provider unavailable")

    monkeypatch.setattr(requests, "get", unavailable)
    service = GeoLocationService(db, failure_threshold=2, circuit_breaker_seconds=3600,
                                 failure_ttl_minutes=10)
    assert service.lookup("8.8.8.8") == "UNKNOWN"
    assert service.lookup("1.1.1.1") == "UNKNOWN"
    assert service.lookup("9.9.9.9") == "UNKNOWN"
    assert service.lookup("8.8.8.8") == "UNKNOWN"
    assert len(calls) == 2
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM ip_geo_cache WHERE status='error'").fetchone()[0] == 2


def test_successful_lookup_is_cached(tmp_path, monkeypatch):
    db = Database(tmp_path / "geo.db"); db.initialize()
    calls = []

    class Response:
        def raise_for_status(self):
            return None
        def json(self):
            return {"status": "success", "country": "US", "regionName": "CA", "city": "LA"}

    monkeypatch.setattr(requests, "get", lambda url, **_kwargs: calls.append(url) or Response())
    service = GeoLocationService(db)
    assert service.lookup("8.8.4.4") == "US/CA/LA"
    assert service.lookup("8.8.4.4") == "US/CA/LA"
    assert len(calls) == 1
