from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import uuid
from pathlib import Path

from monitor.common.logging import configure_logging
from monitor.common.playbooks import PlaybookLoader
from monitor.common.rules import RuleLoader
from monitor.discovery import PARSER_SOURCES, discover_source_dirs, fingerprint, tail_samples
from monitor.parsers import get_parser
from monitor.plugins.builtins import create_registry
from monitor.services.event_service import EventService
from monitor.sources import FileTailSource
from monitor.domain.models import utc_now
from monitor.workers.collector_worker import enrich_event, record_failure
from .runtime import build_runtime, heartbeat, install_shutdown_handlers


def configured_source_ips(settings) -> set[str]:
    result = set()
    for device in settings.raw.get("devices", []):
        glob = str(device.get("log_glob", ""))
        for part in Path(glob).parts:
            if part.count(".") == 3:
                result.add(part)
    return result


def scan(settings, db) -> dict[str, int]:
    cfg = settings.section("discovery")
    root = Path(cfg.get("syslog_root", "/home/syslog"))
    high_confidence = float(cfg.get("auto_observe_confidence", 0.9))
    minimum_candidates = int(cfg.get("minimum_candidate_lines", 3))
    known = configured_source_ips(settings)
    created = updated = 0
    now = utc_now().isoformat()
    for source_ip, directory in discover_source_dirs(root):
        if source_ip in known:
            continue
        samples = tail_samples(directory, int(cfg.get("sample_lines", 300)),
                               int(cfg.get("sample_max_bytes", 2_000_000)))
        result = fingerprint(samples, "auto-" + source_ip.replace(".", "-"))
        status = ("observing" if result.parser and result.confidence >= high_confidence
                  and result.candidate_count >= minimum_candidates else "pending")
        log_glob = str(directory / "*.log")
        generated = json.dumps({"id": "auto-" + source_ip.replace(".", "-"), "source_ip": source_ip,
                                "parser": result.parser, "source": result.source,
                                "log_glob": log_glob, "managed_by": "discovery-worker"}, ensure_ascii=False)
        try:
            # Discovery metadata is advisory.  Use a deferred transaction and
            # skip a cycle when collectors own the single SQLite writer lock.
            # The next scan will retry; ingestion must always win.
            with db.transaction(immediate=False, retries=2) as conn:
                row = conn.execute("SELECT id,status,parser,confirmed_at FROM discovered_devices WHERE source_ip=?", (source_ip,)).fetchone()
                if row is None:
                    conn.execute(
                        """INSERT INTO discovered_devices
                        (id,source_ip,status,parser,source,confidence,sample_count,candidate_count,parsed_count,
                         parse_success_rate,field_completeness,log_glob,config_json,first_seen_at,last_seen_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (str(uuid.uuid4()), source_ip, status, result.parser, result.source, result.confidence,
                         result.sample_count, result.candidate_count, result.parsed_count, result.parse_success_rate,
                         result.field_completeness, log_glob, generated, now, now),
                    )
                    created += 1
                else:
                    # Never overwrite an operator-confirmed parser or change active lifecycle state.
                    # During observation, automatic fingerprints may be corrected as
                    # more samples arrive (for example H3C traffic telemetry versus
                    # H3C WAF attacks).  Once an operator confirms the type, freeze it.
                    h3c_legacy_misclassification = (
                        row["status"] == "observing" and row["parser"] == "h3c_waf"
                        and result.parser == "h3c_security" and result.confidence >= 0.9
                        and result.parse_success_rate >= 0.9
                    )
                    parser = result.parser if (
                        row["status"] in ("pending", "observing", "error") and not row["confirmed_at"]
                    ) or h3c_legacy_misclassification else (row["parser"] or result.parser)
                    source = PARSER_SOURCES.get(parser) if parser else result.source
                    persisted_config = json.loads(generated)
                    persisted_config.update({"parser": parser, "source": source})
                    next_status = status if row["status"] in ("pending", "error") and not row["parser"] else row["status"]
                    conn.execute(
                        """UPDATE discovered_devices SET status=?,parser=?,source=?,confidence=?,sample_count=?,
                        candidate_count=?,parsed_count=?,parse_success_rate=?,field_completeness=?,log_glob=?,
                        config_json=?,last_seen_at=?,last_error=NULL WHERE id=?""",
                        (next_status, parser, source, result.confidence, result.sample_count, result.candidate_count,
                         result.parsed_count, result.parse_success_rate, result.field_completeness, log_glob,
                         json.dumps(persisted_config, ensure_ascii=False), now, row["id"]),
                    )
                    updated += 1
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower():
                raise
    return {"created": created, "updated": updated}


def collect_once(settings, db, rules, playbooks, playbook_version, geo, intel, logger) -> int:
    from monitor.common.errors import IgnoredLog
    processed = 0
    with db.connect() as conn:
        devices = [dict(row) for row in conn.execute(
            "SELECT * FROM discovered_devices WHERE status IN ('observing','active') AND parser IS NOT NULL")]
    for device in devices:
        try:
            device_id = "auto-" + device["source_ip"].replace(".", "-")
            parser = get_parser(device["parser"])
            discovery = settings.section("discovery")
            source = FileTailSource(
                db, device_id, device["log_glob"], False,
                max_checkpoint_lag_seconds=int(discovery.get("max_checkpoint_lag_seconds", 3600)),
                max_checkpoint_lag_bytes=int(discovery.get("max_checkpoint_lag_bytes", 4 * 1024 * 1024)),
            )
            service = EventService(db, rules, settings.section("policy").get("local_region", ""),
                                   playbooks, playbook_version, observation_only=device["status"] != "active")
            last_checkpoint = None
            for record in source.poll(int(discovery.get("batch_size", 200))):
                try:
                    event = parser.parse(record.data, device_id)
                    location, threat = enrich_event(event, geo, intel, logger)
                    service.submit(event, location, threat)
                    processed += 1
                except IgnoredLog:
                    pass
                except sqlite3.OperationalError:
                    logger.warning("database unavailable; retaining discovery checkpoint for retry",
                                   extra={"device": device_id})
                    break
                except Exception as exc:
                    try:
                        if not record_failure(db, device_id, record.data, exc):
                            break
                    except Exception:
                        logger.warning("failed to persist parse failure", exc_info=True, extra={"device": device_id})
                        break
                last_checkpoint = record.checkpoint
            if last_checkpoint:
                source.commit(last_checkpoint)
        except Exception:
            # One busy or malformed source must not prevent other newly
            # discovered devices from being scanned and heartbeated.
            logger.warning("dynamic device collection failed", exc_info=True,
                           extra={"device": device.get("source_ip", "unknown")})
    return processed


def run(once: bool = False):
    settings, db, _ = build_runtime()
    stopping = install_shutdown_handlers()
    logger = logging.getLogger("discovery-worker")
    rules_loader, playbook_loader = RuleLoader(settings), PlaybookLoader(settings, database=db)
    registry = create_registry()
    geo_cfg = settings.section("geolocation")
    geo = registry.load("geolocation", str(geo_cfg.get("provider", "ip_api")))(geo_cfg, database=db)
    intel_cfg = settings.section("threat_intelligence")
    intel = registry.load("threat_intel", str(intel_cfg.get("provider", "static")))(intel_cfg)
    totals = {"discovered": 0, "processed": 0}
    while not stopping.is_set():
        try:
            report = scan(settings, db)
            totals["discovered"] += report["created"]
            rules, playbooks = rules_loader.load(), playbook_loader.load()
            totals["processed"] += collect_once(settings, db, rules, playbooks, playbook_loader.version,
                                                 geo, intel, logger)
            heartbeat(db, "discovery-worker", details={**totals, **report})
        except Exception as exc:
            logger.exception("device discovery cycle failed")
            heartbeat(db, "discovery-worker", "degraded", {**totals, "last_error": str(exc)[:500]})
        if once:
            return
        stopping.wait(float(settings.section("discovery").get("scan_interval_seconds", 15)))


def main():
    configure_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    run(parser.parse_args().once)


if __name__ == "__main__":
    main()
