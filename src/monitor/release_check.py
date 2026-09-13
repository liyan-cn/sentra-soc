from __future__ import annotations

import shutil
from datetime import datetime, timezone
from importlib import resources

from monitor.common.rules import RuleLoader
from monitor.common.health import service_max_age
from monitor.infrastructure.backups import verify_backup
from monitor.workers.runtime import HEALTHY_STATUSES


def run_release_checks(settings, db, validation_errors: list[str], require_backup: bool = False) -> list[dict]:
    checks: list[dict] = [{"name": "configuration", "ok": not validation_errors,
                           "errors": validation_errors}]
    try:
        loader = RuleLoader(settings)
        rules = loader.load()
        checks.append({"name": "policy-rules", "ok": True, "version": loader.version,
                       "policies": len(rules.get("policies", []))})
    except Exception as exc:
        checks.append({"name": "policy-rules", "ok": False, "error": str(exc)})

    try:
        with db.connect() as conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = conn.execute("PRAGMA foreign_key_check").fetchall()
            journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
            versions = [row[0] for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version")]
        checks.append({"name": "database-integrity",
                       "ok": integrity == "ok" and not foreign_keys and str(journal).lower() == "wal",
                       "integrity": integrity, "foreign_key_errors": len(foreign_keys),
                       "journal_mode": journal, "schema_versions": versions})
    except Exception as exc:
        checks.append({"name": "database-integrity", "ok": False, "error": str(exc)})

    minimum_mb = int(settings.section("operations").get("min_free_disk_mb", 512))
    disk = shutil.disk_usage(db.path.parent)
    free_mb = disk.free // (1024 * 1024)
    checks.append({"name": "disk-space", "ok": free_mb >= minimum_mb,
                   "free_mb": free_mb, "minimum_mb": minimum_mb})

    required_assets = ("base.yaml", "rules.yaml", "dashboard.html", "dashboard.css", "dashboard.js")
    package = resources.files("monitor.resources")
    missing = [name for name in required_assets if not package.joinpath(name).is_file()]
    checks.append({"name": "packaged-assets", "ok": not missing, "missing": missing})

    health = settings.section("health")
    required_services = list(health.get("required_services", []))
    unhealthy = []
    if required_services:
        with db.connect() as conn:
            rows = {row["service"]: row for row in conn.execute(
                "SELECT service,status,updated_at FROM service_heartbeats WHERE service IN (%s)"
                % ",".join("?" for _ in required_services), required_services)}
        now = datetime.now(timezone.utc)
        for service in required_services:
            maximum_age = service_max_age(settings, service)
            row = rows.get(service)
            if row is None:
                unhealthy.append({"service": service, "reason": "missing"})
                continue
            updated = datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00"))
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
            age = (now - updated).total_seconds()
            if row["status"] not in HEALTHY_STATUSES or age > maximum_age:
                unhealthy.append({"service": service, "status": row["status"], "age_seconds": round(age)})
    checks.append({"name": "required-workers", "ok": not unhealthy,
                   "required": required_services, "unhealthy": unhealthy})

    backup_directory = db.path.parent / "backups"
    backups = sorted(backup_directory.glob("monitor3-*.db"), key=lambda path: path.stat().st_mtime_ns,
                     reverse=True) if backup_directory.exists() else []
    if backups:
        try:
            verified = verify_backup(backups[0])
            age_hours = (datetime.now(timezone.utc).timestamp() - backups[0].stat().st_mtime) / 3600
            maximum_hours = int(settings.section("backup").get("max_age_hours", 30))
            checks.append({"name": "recent-backup", "ok": age_hours <= maximum_hours,
                           "path": verified["path"], "age_hours": round(age_hours, 2),
                           "maximum_hours": maximum_hours, "integrity": verified["integrity"]})
        except Exception as exc:
            checks.append({"name": "recent-backup", "ok": False, "error": str(exc)})
    else:
        checks.append({"name": "recent-backup", "ok": not require_backup,
                       "required": require_backup, "message": "no automatic backup found"})
    return checks
