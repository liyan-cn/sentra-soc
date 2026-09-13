from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from monitor.domain.models import DecisionType, SecurityEvent
from monitor.infrastructure.database import Database
from monitor.services.event_service import EventService


def event(line: str):
    return SecurityEvent(source="TEST", device_id="dev", event_type="attack",
                         occurred_at=datetime.now(timezone.utc), src_ip="8.8.8.8",
                         dst_ip="192.0.2.1", category="scan", raw_line=line)


def test_block_is_atomic_and_idempotent(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize()
    service = EventService(db, {"defaults": {"window_seconds": 60, "warn_threshold": 1,
                                              "block_threshold": 1, "block_minutes": 10}})
    decision = service.submit(event("one"), "美国/加州")
    assert decision.decision == DecisionType.BLOCK
    assert service.submit(event("one"), "美国/加州") is None
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM blacklist_entries").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM action_outbox").fetchone()[0] == 1


def test_unknown_location_requires_review(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize()
    service = EventService(db, {"defaults": {"warn_threshold": 1, "block_threshold": 1}})
    assert service.submit(event("two"), "UNKNOWN").decision == DecisionType.MANUAL_REVIEW


def test_whitelist_cidr_overrides_block_policy(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize()
    with db.transaction() as conn:
        conn.execute("INSERT INTO whitelist_entries(network,reason,created_at) VALUES(?,?,?)",
                     ("8.8.8.0/24", "trusted scanner", datetime.now(timezone.utc).isoformat()))
    service = EventService(db, {"defaults": {"warn_threshold": 1, "block_threshold": 1}})
    decision = service.submit(event("trusted"), "美国")
    assert decision.decision == DecisionType.IGNORE
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM action_outbox").fetchone()[0] == 0


def test_concurrent_duplicate_events_create_one_decision_and_action(tmp_path):
    db = Database(tmp_path / "concurrent-events.db", busy_timeout_ms=5000); db.initialize()
    service = EventService(db, {"defaults": {"window_seconds": 60, "warn_threshold": 1,
                                              "block_threshold": 1, "block_minutes": 10}})

    def submit(_index):
        return service.submit(event("same raw vendor record"), "US")

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(submit, range(40)))

    assert sum(result is not None for result in results) == 1
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM policy_decisions").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM blacklist_entries").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM action_outbox").fetchone()[0] == 1
