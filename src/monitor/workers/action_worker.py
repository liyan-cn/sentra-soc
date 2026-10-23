from __future__ import annotations

import json
import logging
import os
import socket
import uuid
from datetime import timedelta

from monitor.common.logging import configure_logging
from monitor.domain.models import utc_now
from monitor.plugins.builtins import create_registry
from monitor.infrastructure.notification_settings import database_notifier
from .runtime import build_runtime, heartbeat, install_shutdown_handlers


def claim(db, worker_id: str, lease_seconds: int, firewall_mode: str = "disabled"):
    now = utc_now()
    locked_until = now + timedelta(seconds=lease_seconds)
    with db.transaction(immediate=True) as conn:
        # A worker can exit after claiming work. Requeue expired leases in bounded
        # batches; a completed action cannot be overwritten by its former owner.
        expired=conn.execute("""SELECT id,attempts,max_attempts FROM action_outbox
            WHERE status='running' AND locked_until IS NOT NULL AND locked_until<? LIMIT 50""",
            (now.isoformat(),)).fetchall()
        for item in expired:
            exhausted=int(item['attempts'])>=int(item['max_attempts'])
            conn.execute("""UPDATE action_outbox SET status=?,locked_by=NULL,locked_until=NULL,
                available_at=?,updated_at=?,last_error=? WHERE id=?""",
                ('dead' if exhausted else 'retry',now.isoformat(),now.isoformat(),
                 'worker lease expired; retry limit reached' if exhausted else 'worker lease expired; queued for retry',item['id']))
        firewall_filter = "" if firewall_mode != "disabled" else "AND action_type NOT IN ('BLOCK','REFRESH_BLOCK','UNBLOCK')"
        row = conn.execute(
            f"""SELECT * FROM action_outbox WHERE status IN ('pending','retry')
            AND available_at<=? AND (locked_until IS NULL OR locked_until<?)
            {firewall_filter}
            ORDER BY priority DESC,created_at ASC LIMIT 1""", (now.isoformat(), now.isoformat())  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
        ).fetchone()
        if not row:
            return None
        conn.execute(
            """UPDATE action_outbox SET status='running',locked_by=?,locked_until=?,attempts=attempts+1,updated_at=?
            WHERE id=?""", (worker_id, locked_until.isoformat(), now.isoformat(), row["id"]),
        )
        return {**dict(row),'locked_by':worker_id,'locked_until':locked_until.isoformat()}


def finish(db, action, success: bool, error: str = "", simulated: bool = False, notification_status: str | None = None):
    now = utc_now()
    attempts = int(action["attempts"]) + 1
    status = "succeeded" if success else ("dead" if attempts >= int(action["max_attempts"]) else "retry")
    available = now + timedelta(seconds=min(300, 2 ** min(attempts, 8)))
    with db.transaction(immediate=True) as conn:
        changed=conn.execute(
            """UPDATE action_outbox SET status=?,available_at=?,locked_by=NULL,locked_until=NULL,last_error=?,updated_at=?
            WHERE id=? AND status='running' AND locked_by=? AND locked_until=?""",
            (status, available.isoformat(), error[:2000] or None, now.isoformat(), action["id"],
             action['locked_by'],action['locked_until']),
        )
        if not changed.rowcount:return False
        if action["action_type"] == "NOTIFY":
            payload = json.loads(action["payload_json"])
            dedup_key = str(payload.get("dedup_key", action["aggregate_id"]))
            conn.execute(
                """INSERT INTO notification_logs(id,dedup_key,channel,status,error,created_at)
                VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,error=excluded.error""",
                (action["id"], dedup_key, "configured",
                 notification_status or ("succeeded" if success else status), error[:2000] or None, now.isoformat()),
            )
        if action["aggregate_type"] == "blacklist":
            actual = "simulated" if simulated else ("unblocked" if action["action_type"] == "UNBLOCK" else "blocked")
            desired = (("pending_unblock" if action["action_type"] == "UNBLOCK" else "pending_block") if simulated
                       else ("unblocked" if action["action_type"] == "UNBLOCK" else "blocked"))
            conn.execute(
                """UPDATE blacklist_entries SET actual_state=?,desired_state=?,last_error=?,confirmed_expires_at=CASE WHEN ? THEN desired_expires_at ELSE confirmed_expires_at END WHERE id=?""",
                (actual if success else "error", desired if success else ("pending_unblock" if action["action_type"] == "UNBLOCK" else "pending_block"),
                 error[:2000] or None, 1 if success else 0, action["aggregate_id"]),
            )
    return True


def enqueue_notification(db, action: dict, content: str) -> None:
    """Create a separate idempotent task after the enforcement state commits."""
    now = utc_now().isoformat()
    with db.transaction() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO action_outbox
            (id,action_type,aggregate_type,aggregate_id,payload_json,idempotency_key,status,
             priority,available_at,created_at,updated_at)
            VALUES(?,'NOTIFY','notification',?,?,?,'pending',10,?,?,?)""",
            (str(uuid.uuid4()), action["id"], json.dumps({"content": content, "dedup_key": action["aggregate_id"]}, ensure_ascii=False),
             f"notify:{action['id']}", now, now, now),
        )


def safe_enqueue_notification(db, action: dict, content: str, logger: logging.Logger) -> None:
    try:
        enqueue_notification(db, action, content)
    except Exception:
        # Enforcement is already committed. Never roll it back or repeat it just
        # because creation of its informational notification failed.
        logger.exception("failed to enqueue post-action notification", extra={"action_id": action["id"]})


def notification_suppressed(db, dedup_key: str, interval_seconds: int) -> bool:
    if interval_seconds <= 0:
        return False
    cutoff = (utc_now() - timedelta(seconds=interval_seconds)).isoformat()
    with db.connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM notification_logs WHERE dedup_key=? AND status='succeeded' AND created_at>=? LIMIT 1",
            (dedup_key, cutoff),
        ).fetchone()
    return row is not None


def run():
    settings, db, _ = build_runtime()
    stopping = install_shutdown_handlers()
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    worker_cfg = settings.section("workers")
    firewall_cfg = settings.section("firewall")
    firewall_mode = str(firewall_cfg.get("mode", "disabled")).lower()
    if firewall_mode not in {"disabled", "dry_run", "live"}:
        raise ValueError("firewall.mode must be disabled, dry_run, or live")
    notify_cfg = settings.section("notification")
    registry = create_registry()
    action_factory = registry.load("actions", str(firewall_cfg.get("provider", "huawei_ssh")))
    firewall = action_factory(firewall_cfg, password=settings.firewall_password)
    logger = logging.getLogger("action-worker")
    processed = 0
    failed = 0
    while not stopping.is_set():
        action = claim(db, worker_id, int(worker_cfg.get("lease_seconds", 60)), firewall_mode)
        if not action:
            heartbeat(db, "action-worker", details={"processed": processed, "failed": failed,
                                                      "firewall_mode": firewall_mode})
            stopping.wait(float(worker_cfg.get("poll_seconds", 2)))
            continue
        try:
            payload = json.loads(action["payload_json"])
            simulated = False
            suppressed = False
            if action["action_type"] in ("BLOCK", "REFRESH_BLOCK"):
                if firewall_mode == "live":
                    firewall.apply(payload)
                else:
                    simulated = True
            elif action["action_type"] == "UNBLOCK":
                if firewall_mode == "live":
                    firewall.revoke(payload)
                else:
                    simulated = True
            elif action["action_type"] == "NOTIFY":
                dedup_key = str(payload.get("dedup_key", action["aggregate_id"]))
                suppressed = notification_suppressed(
                    db, dedup_key, int(notify_cfg.get("min_interval_seconds", 0)))
                if not suppressed:
                    # Web-managed notification changes become effective on the
                    # next message and do not require restarting the worker.
                    database_notifier(db, settings, registry).send(payload["content"])
            else:
                raise ValueError(f"unsupported action: {action['action_type']}")
            if not finish(db, action, True, simulated=simulated,
                          notification_status="suppressed" if suppressed else None):
                logger.warning('ignored completion from expired action lease',extra={'action_id':action['id']})
                continue
            if action["action_type"] in ("BLOCK", "REFRESH_BLOCK"):
                safe_enqueue_notification(
                    db, action,
                    f"Monitor 3.0 {'模拟封禁' if simulated else '封禁成功'}\n"
                    f"IP: {payload['ip']}\n类别: {payload.get('category','Unknown')}",
                    logger,
                )
            elif action["action_type"] == "UNBLOCK":
                safe_enqueue_notification(
                    db, action,
                    f"Monitor 3.0 {'模拟解封' if simulated else '解封成功'}\nIP: {payload['ip']}",
                    logger,
                )
            processed += 1
            heartbeat(db, "action-worker", details={"processed": processed, "failed": failed,
                                                      "firewall_mode": firewall_mode})
        except Exception as exc:
            logger.exception("action failed", extra={"action_id": action["id"]})
            finish(db, action, False, str(exc))
            failed += 1
            heartbeat(db, "action-worker", status="degraded",
                      details={"processed": processed, "failed": failed, "last_error": str(exc)[:500],
                               "firewall_mode": firewall_mode})


def main():
    configure_logging()
    run()


if __name__ == "__main__":
    main()
