from __future__ import annotations

import json
import os
import signal
import socket
import threading
from monitor.common.config import load_settings
from monitor.common.rules import RuleLoader
from monitor.infrastructure.storage_factory import create_storage


def build_runtime():
    settings = load_settings()
    db = create_storage(settings)
    # Production upgrades are performed by ``monitor3 migrate`` before
    # services are restarted.  Avoid all workers contending for a migration
    # write lock during normal startup; a fresh database is still initialized
    # completely by Database.initialize itself.
    db.initialize(migrate=False)
    return settings, db, RuleLoader(settings).load()


HEALTHY_STATUSES = frozenset({"ok", "running", "ready"})


def install_shutdown_handlers() -> threading.Event:
    """Return an event set by SIGINT/SIGTERM so workers can finish their current unit of work."""
    stopping = threading.Event()

    def request_stop(_signum, _frame):
        stopping.set()

    signal.signal(signal.SIGINT, request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_stop)
    return stopping


def heartbeat(db, service: str, status: str = "ok", details: dict | None = None) -> bool:
    from monitor.domain.models import utc_now
    instance = f"{socket.gethostname()}:{os.getpid()}"
    try:
        with db.transaction(retries=8) as conn:
            conn.execute(
                """INSERT INTO service_heartbeats(service,instance_id,status,details_json,updated_at)
                VALUES(?,?,?,?,?) ON CONFLICT(service) DO UPDATE SET instance_id=excluded.instance_id,
                status=excluded.status,details_json=excluded.details_json,updated_at=excluded.updated_at""",
                (service, instance, status, json.dumps(details or {}, ensure_ascii=False), utc_now().isoformat()),
            )
        return True
    except Exception:
        # A heartbeat must never terminate a collector.  The next periodic
        # cycle will repair the heartbeat once a competing writer is finished.
        return False
