from __future__ import annotations

import logging

from monitor.common.logging import configure_logging
from monitor.domain.models import utc_now
from monitor.infrastructure.firewall import HuaweiFirewallClient
from .runtime import build_runtime, heartbeat, install_shutdown_handlers


def sync_once(db, firewall: HuaweiFirewallClient) -> dict:
    now = utc_now().isoformat()
    snapshots = {
        list_type: firewall.list_items(list_type)
        for list_type in ("blacklist", "whitelist")
    }
    with db.transaction(immediate=True) as conn:
        for list_type, items in snapshots.items():
            seen = []
            for item in items:
                entry_id = f"fw:{list_type}:{item['direction']}:{item['ip']}:{item['protocol']}"
                seen.append(entry_id)
                conn.execute(
                    """INSERT INTO firewall_list_entries(
                       id,list_type,direction,ip,protocol,reason,inserted_at,age_time,expires_at,
                       permanent,hit_count,description,synced_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(id) DO UPDATE SET reason=excluded.reason,
                       inserted_at=excluded.inserted_at,age_time=excluded.age_time,
                       expires_at=excluded.expires_at,permanent=excluded.permanent,
                       hit_count=excluded.hit_count,description=excluded.description,synced_at=excluded.synced_at""",
                    (entry_id, list_type, item["direction"], item["ip"], item["protocol"],
                     item["reason"], item["inserted_at"], item["age_time"], item["expires_at"],
                     int(item["permanent"]), item["hit_count"], item["description"], now),
                )
            if seen:
                placeholders = ",".join("?" for _ in seen)
                conn.execute(
                    f"DELETE FROM firewall_list_entries WHERE list_type=? AND id NOT IN ({placeholders})",
                    (list_type, *seen),
                )
            else:
                conn.execute("DELETE FROM firewall_list_entries WHERE list_type=?", (list_type,))
    return {key: len(value) for key, value in snapshots.items()}


def run():
    settings, db, _ = build_runtime()
    stopping = install_shutdown_handlers()
    cfg = settings.section("firewall")
    firewall = HuaweiFirewallClient(cfg, settings.firewall_password)
    interval = max(5, int(cfg.get("sync_interval_seconds", 15)))
    logger = logging.getLogger("firewall-sync-worker")
    while not stopping.is_set():
        try:
            counts = sync_once(db, firewall)
            heartbeat(db, "firewall-sync", details=counts)
        except Exception as exc:
            logger.exception("firewall list pull failed")
            heartbeat(db, "firewall-sync", status="degraded",
                      details={"error": str(exc)[:500]})
        stopping.wait(interval)


def main():
    configure_logging()
    run()


if __name__ == "__main__":
    main()
