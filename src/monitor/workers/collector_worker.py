from __future__ import annotations

import argparse
import hashlib
import logging
import sqlite3
import time

from monitor.common.errors import IgnoredLog
from monitor.common.logging import configure_logging
from monitor.common.rules import RuleLoader
from monitor.common.playbooks import PlaybookLoader
from monitor.domain.models import utc_now
from monitor.plugins.builtins import create_registry
from monitor.parsers import get_parser
from monitor.services.event_service import EventService
from monitor.sources import FileTailSource
from .runtime import build_runtime, heartbeat, install_shutdown_handlers


def enrich_event(event, geo, intel, logger) -> tuple[str, dict]:
    """Treat enrichment plugins as optional; never lose a parsed security event."""
    errors = []
    try:
        threat = intel.lookup(event.src_ip) or {}
    except Exception as exc:
        logger.warning("threat intelligence lookup failed", exc_info=exc,
                       extra={"event_id": event.id, "ip": event.src_ip})
        threat = {}
        errors.append("threat_intelligence:" + type(exc).__name__)
    try:
        location = geo.lookup(event.src_ip) or "UNKNOWN"
    except Exception as exc:
        logger.warning("geolocation lookup failed", exc_info=exc,
                       extra={"event_id": event.id, "ip": event.src_ip})
        location = "UNKNOWN"
        errors.append("geolocation:" + type(exc).__name__)
    event.attributes["threat_intel"] = threat
    if errors:
        event.attributes["enrichment_errors"] = errors
    return location, threat


def record_failure(db, device_id: str, line: str, exc: Exception) -> bool:
    raw_hash = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
    now = utc_now().isoformat()
    try:
        with db.transaction(immediate=True, retries=2) as conn:
            conn.execute(
                """INSERT INTO parse_failures(device_id,raw_hash,sample,error,first_seen_at,last_seen_at)
                VALUES(?,?,?,?,?,?) ON CONFLICT(device_id,raw_hash) DO UPDATE SET
                count=count+1,last_seen_at=excluded.last_seen_at,error=excluded.error""",
                (device_id, raw_hash, line[:1000], str(exc)[:1000], now, now),
            )
        return True
    except sqlite3.OperationalError as db_exc:
        if "locked" not in str(db_exc).lower():
            raise
        return False


def run(device_id: str):
    settings, db, _ = build_runtime()
    stopping = install_shutdown_handlers()
    rule_loader = RuleLoader(settings)
    rules = rule_loader.load()
    playbook_loader = PlaybookLoader(settings, database=db)
    playbooks = playbook_loader.load()
    device = settings.device(device_id)
    parser = get_parser(device["parser"])
    service = EventService(db, rules, settings.section("policy").get("local_region", ""),
                           playbooks, playbook_loader.version)
    geo_cfg = settings.section("geolocation")
    geo = create_registry().load("geolocation", str(geo_cfg.get("provider", "ip_api")))(geo_cfg, database=db)
    intel_cfg = settings.section("threat_intelligence")
    intel = create_registry().load("threat_intel", str(intel_cfg.get("provider", "static")))(intel_cfg)
    source = FileTailSource(db, device_id, device["log_glob"], bool(device.get("start_at_end", False)))
    logger = logging.getLogger(f"collector.{device_id}")
    heartbeat_interval = max(5, int(settings.section("workers").get("heartbeat_seconds", 30)))
    last_heartbeat = time.monotonic()
    while not stopping.is_set():
        changed, latest_rules = rule_loader.reload_if_changed()
        playbooks_changed, latest_playbooks = playbook_loader.reload_if_changed()
        if changed or playbooks_changed:
            service = EventService(db, latest_rules, settings.section("policy").get("local_region", ""),
                                   latest_playbooks, playbook_loader.version)
            logger.info("policy or playbook rules reloaded", extra={"device": device_id})
        records = source.poll(int(device.get("batch_size", 100)))
        if not records:
            heartbeat(db, f"collector:{device_id}", source.health()["status"], {
                **source.health(), "rules_version": rule_loader.version, "rules_error": rule_loader.last_error,
                "playbooks_version": playbook_loader.version, "playbooks_error": playbook_loader.last_error})
            last_heartbeat = time.monotonic()
            stopping.wait(float(device.get("poll_seconds", 1)))
            continue
        last_checkpoint = None
        for index, record in enumerate(records, 1):
            retry_record = False
            try:
                if record.checkpoint.get('unterminated_tail'):
                    raise ValueError('Archived log has an unterminated final fragment; preserved for inspection')
                event = parser.parse(record.data, device_id)
                location, threat = enrich_event(event, geo, intel, logger)
                decision = service.submit(event, location, threat)
                if decision:
                    logger.info("event processed", extra={"event_id": event.id, "device": device_id})
            except IgnoredLog:
                pass
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower():
                    raise
                retry_record = True
                logger.warning("database busy; retaining collector checkpoint for retry",
                               extra={"device": device_id})
            except Exception as exc:
                if not record_failure(db, device_id, record.data, exc):
                    retry_record = True
            if retry_record:
                break
            # Checkpoint once per batch. Replaying a few already-deduped lines
            # after a crash is safe; taking a write lock per line is not.
            last_checkpoint = record.checkpoint
            now = time.monotonic()
            if now - last_heartbeat >= heartbeat_interval:
                heartbeat(db, f"collector:{device_id}", "running", {
                    **source.health(), "batch_processed": index, "batch_size": len(records),
                    "rules_version": rule_loader.version, "rules_error": rule_loader.last_error,
                    "playbooks_version": playbook_loader.version,
                    "playbooks_error": playbook_loader.last_error})
                last_heartbeat = now
        if last_checkpoint:
            try:
                source.commit(last_checkpoint)
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower():
                    raise
                logger.warning("database busy; collector checkpoint will retry",
                               extra={"device": device_id})
        heartbeat(db, f"collector:{device_id}", details={
            **source.health(), "rules_version": rule_loader.version, "rules_error": rule_loader.last_error,
            "playbooks_version": playbook_loader.version, "playbooks_error": playbook_loader.last_error})
        last_heartbeat = time.monotonic()


def main():
    configure_logging()
    cli = argparse.ArgumentParser()
    cli.add_argument("--device", required=True)
    run(cli.parse_args().device)


if __name__ == "__main__":
    main()
