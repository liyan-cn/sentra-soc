import json
import uuid

from monitor.domain.models import utc_now
from monitor.infrastructure.database import Database
from monitor.workers.action_worker import claim, enqueue_notification, finish, notification_suppressed


def add_action(db, action_type="BLOCK"):
    now = utc_now().isoformat()
    aggregate_id = str(uuid.uuid4())
    with db.transaction() as conn:
        conn.execute(
            """INSERT INTO blacklist_entries(id,ip,desired_state,actual_state,first_seen_at,last_seen_at,
            desired_expires_at,hit_count,category,source) VALUES(?,?,'pending_block','unknown',?,?,?,?,?,?)""",
            (aggregate_id, "8.8.4.4", now, now, now, 1, "scan", "TEST"),
        )
        conn.execute(
            """INSERT INTO action_outbox(id,action_type,aggregate_type,aggregate_id,payload_json,
            idempotency_key,status,available_at,created_at,updated_at) VALUES(?,?, 'blacklist',?,?,?,'pending',?,?,?)""",
            (str(uuid.uuid4()), action_type, aggregate_id, json.dumps({"ip": "8.8.4.4"}),
             str(uuid.uuid4()), now, now, now),
        )
    return aggregate_id


def test_disabled_mode_does_not_claim_firewall_action(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize(); add_action(db)
    assert claim(db, "worker", 60, "disabled") is None


def test_dry_run_is_not_reported_as_applied(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize(); entry_id = add_action(db)
    action = claim(db, "worker", 60, "dry_run")
    finish(db, action, True, simulated=True)
    with db.connect() as conn:
        row = conn.execute("SELECT desired_state,actual_state FROM blacklist_entries WHERE id=?", (entry_id,)).fetchone()
    assert tuple(row) == ("pending_block", "simulated")


def test_notification_is_separate_and_idempotent(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize(); add_action(db)
    action = claim(db, "worker", 60, "live")
    finish(db, action, True)
    enqueue_notification(db, action, "blocked")
    enqueue_notification(db, action, "blocked")
    with db.connect() as conn:
        actions = conn.execute("SELECT action_type,status FROM action_outbox ORDER BY created_at").fetchall()
    assert [(row["action_type"], row["status"]) for row in actions] == [
        ("BLOCK", "succeeded"), ("NOTIFY", "pending")
    ]


def test_notification_delivery_is_audited(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize(); add_action(db)
    block = claim(db, "worker", 60, "live")
    finish(db, block, True); enqueue_notification(db, block, "blocked")
    notification = claim(db, "worker", 60, "live")
    finish(db, notification, False, "channel unavailable")
    with db.connect() as conn:
        row = conn.execute("SELECT status,error FROM notification_logs WHERE id=?", (notification["id"],)).fetchone()
    assert row["status"] == "retry"
    assert "unavailable" in row["error"]


def test_successful_notification_can_suppress_same_key(tmp_path):
    db = Database(tmp_path / "test.db"); db.initialize(); add_action(db)
    block = claim(db, "worker", 60, "live"); finish(db, block, True); enqueue_notification(db, block, "blocked")
    notification = claim(db, "worker", 60, "live"); finish(db, notification, True)
    assert notification_suppressed(db, block["aggregate_id"], 3600)
