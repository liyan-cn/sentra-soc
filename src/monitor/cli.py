from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import secrets
import uuid
from datetime import timedelta
from pathlib import Path

from monitor.common.config import ConfigError, load_settings
from monitor.infrastructure.storage_factory import create_storage
from monitor.plugins.builtins import create_registry
from monitor.api.auth import ROLES, token_hash
from monitor.domain.models import utc_now
from monitor.common.rules import RuleLoader
from monitor.simulation import print_report, replay, simulate
from monitor.infrastructure.backups import create_backup, prune_backups, rehearse_restore, restore_backup, verify_backup
from monitor.release_check import run_release_checks


def validate(settings) -> list[str]:
    errors: list[str] = []
    registry = create_registry()

    def integer(section: str, field: str, default: int, minimum: int, maximum: int) -> None:
        try:
            value = int(settings.section(section).get(field, default))
            if not minimum <= value <= maximum:
                errors.append(f"{section}.{field} must be between {minimum} and {maximum}")
        except (TypeError, ValueError):
            errors.append(f"{section}.{field} must be an integer")

    def number(section: str, field: str, default: float, minimum: float, maximum: float) -> None:
        try:
            value = float(settings.section(section).get(field, default))
            if not minimum <= value <= maximum:
                errors.append(f"{section}.{field} must be between {minimum} and {maximum}")
        except (TypeError, ValueError):
            errors.append(f"{section}.{field} must be numeric")

    def plugin(section: str, field: str, kind: str, default: str) -> None:
        name = str(settings.section(section).get(field, default))
        if name not in registry.names(kind):
            errors.append(f"{section}.{field} plugin not found: {name}")

    ids: set[str] = set()
    for index, device in enumerate(settings.raw.get("devices", [])):
        label = f"devices[{index}]"
        device_id = str(device.get("id", ""))
        if not device_id:
            errors.append(f"{label}.id is required")
        elif device_id in ids:
            errors.append(f"duplicate device id: {device_id}")
        ids.add(device_id)
        parser = str(device.get("parser", ""))
        is_vpn_activity = str(device.get("source", "")).upper().endswith("_VPN")
        if not is_vpn_activity and parser not in registry.names("parsers"):
            errors.append(f"{label}.parser plugin not found: {parser}")
        if not device.get("log_glob"):
            errors.append(f"{label}.log_glob is required")
    firewall = settings.section("firewall")
    plugin("firewall", "provider", "actions", "huawei_ssh")
    integer("firewall", "timeout_minutes", 10000, 1, 525600)
    number("firewall", "command_timeout_seconds", 10, 1, 60)
    mode = str(firewall.get("mode", "disabled"))
    if mode not in {"disabled", "dry_run", "live"}:
        errors.append("firewall.mode must be disabled, dry_run, or live")
    if mode == "live":
        for field in ("host", "username", "known_hosts"):
            if not firewall.get(field):
                errors.append(f"firewall.{field} is required in live mode")
        if not settings.firewall_password:
            errors.append("MONITOR_FIREWALL_PASSWORD is required in live mode")
        known_hosts = firewall.get("known_hosts")
        if known_hosts and not Path(known_hosts).expanduser().exists():
            errors.append(f"firewall.known_hosts does not exist: {known_hosts}")
    integer("api", "port", 5001, 1, 65535)
    integer("api", "max_request_bytes", 1048576, 1024, 100 * 1024 * 1024)
    integer("api", "auth_rate_limit_per_minute", 120, 0, 100000)
    integer("api", "token_usage_update_seconds", 300, 0, 86400)
    integer("api", "trusted_proxy_hops", 0, 0, 5)
    integer("database", "busy_timeout_ms", 10000, 100, 300000)
    integer("backup", "keep_last", 14, 1, 3650)
    integer("backup", "max_age_hours", 30, 1, 8760)
    integer("operations", "min_free_disk_mb", 512, 1, 1048576)
    number("workers", "poll_seconds", 2, 0.05, 3600)
    integer("workers", "lease_seconds", 60, 5, 86400)
    integer("workers", "heartbeat_seconds", 30, 1, 3600)
    integer("health", "heartbeat_max_age_seconds", 180, 5, 86400)
    number("discovery", "auto_observe_confidence", .9, 0, 1)
    integer("discovery", "minimum_candidate_lines", 3, 1, 10000)
    integer("discovery", "sample_lines", 300, 10, 10000)
    integer("discovery", "sample_max_bytes", 2000000, 1024, 100 * 1024 * 1024)
    integer("discovery", "promote_min_parsed", 20, 1, 1000000)
    number("discovery", "promote_min_success_rate", .9, 0, 1)
    number("discovery", "promote_min_field_completeness", .75, 0, 1)
    for field, default in (
        ("security_events_days", 180), ("parse_failures_days", 30),
        ("host_checks_days", 30), ("vpn_sessions_days", 180),
        ("notification_logs_days", 90), ("audit_logs_days", 365),
    ):
        integer("retention", field, default, 1, 36500)
    integer("retention", "batch_size", 1000, 10, 100000)
    integer("retention", "aggregate_days", 2, 1, 31)
    integer("retention", "interval_seconds", 300, 60, 86400)
    integer("geolocation", "ttl_days", 7, 1, 3650)
    number("geolocation", "timeout_seconds", 3, 0.1, 60)
    integer("geolocation", "failure_ttl_minutes", 60, 1, 1440)
    integer("geolocation", "failure_threshold", 5, 1, 1000)
    integer("geolocation", "circuit_breaker_seconds", 60, 1, 3600)
    plugin("notification", "provider", "notifiers", "wechat")
    plugin("geolocation", "provider", "geolocation", "ip_api")
    plugin("threat_intelligence", "provider", "threat_intel", "static")

    required = settings.section("health").get("required_services", [])
    if not isinstance(required, list) or any(not isinstance(item, str) or not item.strip() for item in required):
        errors.append("health.required_services must be a list of non-empty service names")
    elif len(required) != len(set(required)):
        errors.append("health.required_services must not contain duplicates")

    notification = settings.section("notification")
    notification_provider = str(notification.get("provider", "wechat"))
    if notification.get("enabled"):
        if notification_provider == "wechat" and not settings.webhook:
            errors.append("notification is enabled but MONITOR_WECHAT_WEBHOOK is empty")
        elif notification_provider == "webhook" and not settings.generic_webhook_url:
            errors.append("notification is enabled but MONITOR_WEBHOOK_URL is empty")
        elif notification_provider == "smtp":
            missing = [field for field in ("host", "from", "to") if not notification.get(field)]
            if missing:
                errors.append("notification SMTP fields missing: " + ", ".join(missing))
            if notification.get("username") and not settings.smtp_password:
                errors.append("notification SMTP username is set but MONITOR_SMTP_PASSWORD is empty")
    if notification_provider == "fanout":
        channels = notification.get("channels", [])
        if not isinstance(channels, list) or not channels:
            errors.append("notification.channels must be a non-empty list for fanout")
        else:
            for index, channel in enumerate(channels):
                provider = channel.get("provider") if isinstance(channel, dict) else None
                if provider == "fanout" or provider not in registry.names("notifiers"):
                    errors.append(f"notification.channels[{index}].provider is invalid: {provider}")

    secret_fields = (
        ("api", "admin_token", "MONITOR_ADMIN_TOKEN"),
        ("firewall", "password", "MONITOR_FIREWALL_PASSWORD"),
        ("notification", "webhook", "MONITOR_WECHAT_WEBHOOK"),
        ("notification", "password", "MONITOR_SMTP_PASSWORD"),
        ("notification", "secret", "MONITOR_WEBHOOK_SECRET"),
    )
    for section, field, environment in secret_fields:
        if settings.section(section).get(field):
            errors.append(f"{section}.{field} must not contain a secret; use {environment}")
    return errors


def doctor(as_json: bool = False) -> int:
    checks = []
    try:
        settings = load_settings()
        checks.append({"name": "configuration", "ok": True})
    except Exception as exc:
        checks.append({"name": "configuration", "ok": False, "error": str(exc)})
        settings = None
    if settings:
        errors = validate(settings)
        checks.append({"name": "validation", "ok": not errors, "errors": errors})
        try:
            loader = RuleLoader(settings)
            loader.load()
            checks.append({"name": "policy-rules", "ok": True, "version": loader.version})
        except Exception as exc:
            checks.append({"name": "policy-rules", "ok": False, "error": str(exc)})
        try:
            db = create_storage(settings)
            # Deployments perform migrations before services are started.
            # Doctor is a read-only live health check and must not contend
            # with collectors for a migration/DDL write lock.
            db.initialize(migrate=False)
            with db.connect() as conn:
                versions = [row[0] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
            checks.append({"name": "database", "ok": True, "versions": versions})
        except Exception as exc:
            checks.append({"name": "database", "ok": False, "error": str(exc)})
    for package in ("flask", "yaml", "requests"):
        try:
            importlib.metadata.version("PyYAML" if package == "yaml" else package)
            checks.append({"name": f"dependency:{package}", "ok": True})
        except importlib.metadata.PackageNotFoundError:
            checks.append({"name": f"dependency:{package}", "ok": False})
    if as_json:
        print(json.dumps({"checks": checks}, ensure_ascii=False, indent=2))
    else:
        for check in checks:
            print(f"[{'OK' if check['ok'] else 'FAIL'}] {check['name']}")
            for error in check.get("errors", []):
                print(f"  - {error}")
            if check.get("error"):
                print(f"  - {check['error']}")
    return 0 if all(item["ok"] for item in checks) else 1


def main():
    cli = argparse.ArgumentParser(prog="monitor3")
    sub = cli.add_subparsers(dest="command", required=True)
    doctor_cmd = sub.add_parser("doctor", help="validate configuration, database, and dependencies")
    doctor_cmd.add_argument("--json", action="store_true")
    release_cmd = sub.add_parser("release-check", help="run production release acceptance checks")
    release_cmd.add_argument("--json", action="store_true")
    release_cmd.add_argument("--require-backup", action="store_true")
    plugins = sub.add_parser("plugins", help="list available plugins")
    plugins.add_argument("kind", choices=["sources", "parsers", "actions", "notifiers", "geolocation", "threat_intel"], nargs="?")
    sub.add_parser("migrate", help="initialize or upgrade the database")
    token = sub.add_parser("token", help="manage hashed API tokens")
    token_sub = token.add_subparsers(dest="token_command", required=True)
    create = token_sub.add_parser("create")
    create.add_argument("name")
    create.add_argument("--role", choices=sorted(ROLES, key=ROLES.get), default="viewer")
    create.add_argument("--expires-days", type=int)
    revoke = token_sub.add_parser("revoke")
    revoke.add_argument("name")
    token_sub.add_parser("list")
    simulator = sub.add_parser("simulate", help="evaluate one synthetic event without side effects")
    simulator.add_argument("--source", required=True)
    simulator.add_argument("--category", required=True)
    simulator.add_argument("--src-ip", required=True)
    simulator.add_argument("--count", type=int, default=1)
    simulator.add_argument("--location", default="UNKNOWN")
    simulator.add_argument("--severity", default="high")
    simulator.add_argument("--threat-tag", action="append", default=[])
    simulator.add_argument("--threat-confidence", type=int, default=0)
    replay_cmd = sub.add_parser("replay", help="analyze a historical log file without database or actions")
    replay_cmd.add_argument("--device", required=True)
    replay_cmd.add_argument("--file", required=True)
    replay_cmd.add_argument("--limit", type=int, default=10000)
    backup = sub.add_parser("backup", help="create, verify, or restore SQLite backups")
    backup_sub = backup.add_subparsers(dest="backup_command", required=True)
    backup_create = backup_sub.add_parser("create")
    backup_create.add_argument("--output")
    backup_create.add_argument("--keep-last", type=int,
                               help="retain this many automatic monitor3-*.db backups")
    backup_verify = backup_sub.add_parser("verify")
    backup_verify.add_argument("--input", required=True)
    backup_rehearse = backup_sub.add_parser("rehearse")
    backup_rehearse.add_argument("--input", required=True)
    backup_restore = backup_sub.add_parser("restore")
    backup_restore.add_argument("--input", required=True)
    backup_restore.add_argument("--confirm", action="store_true",
                                help="confirm services are stopped and replace the live database")
    sub.add_parser("maintenance", help="run retention, aggregation, and SQLite maintenance once")
    args = cli.parse_args()
    if args.command == "doctor":
        raise SystemExit(doctor(args.json))
    if args.command == "plugins":
        registry = create_registry()
        kinds = [args.kind] if args.kind else ["sources", "parsers", "actions", "notifiers", "geolocation", "threat_intel"]
        for kind in kinds:
            print(f"{kind}: {', '.join(registry.names(kind)) or '-'}")
        return
    settings = load_settings()
    if args.command in {"simulate", "replay"}:
        rules = RuleLoader(settings).load()
        local_region = str(settings.section("policy").get("local_region", ""))
        if args.command == "simulate":
            print_report(simulate(
                rules, source=args.source, category=args.category, src_ip=args.src_ip,
                count=args.count, location=args.location, severity=args.severity,
                threat_tags=args.threat_tag, threat_confidence=args.threat_confidence,
                local_region=local_region,
            ))
        else:
            device = settings.device(args.device)
            print_report(replay(rules, device["parser"], args.device, args.file, args.limit, local_region))
        return
    db = create_storage(settings)
    db.initialize()
    if args.command == "release-check":
        checks = run_release_checks(settings, db, validate(settings), args.require_backup)
        if args.json:
            print(json.dumps({"checks": checks}, ensure_ascii=False, indent=2))
        else:
            for check in checks:
                print(f"[{'OK' if check['ok'] else 'FAIL'}] {check['name']}")
        raise SystemExit(0 if all(check["ok"] for check in checks) else 1)
    if args.command == "maintenance":
        from monitor.workers.maintenance_worker import run_once
        print_report(run_once(settings, db))
        return
    if args.command == "backup":
        if args.backup_command == "create":
            report = create_backup(db, args.output)
            keep = args.keep_last
            if keep is None:
                keep = int(settings.section("backup").get("keep_last", 14))
            report["retention"] = prune_backups(Path(report["path"]).parent, keep)
            print_report(report)
            return
        if args.backup_command == "verify":
            print_report(verify_backup(args.input))
            return
        if args.backup_command == "rehearse":
            print_report(rehearse_restore(args.input))
            return
        if not args.confirm:
            raise SystemExit("restore refused: stop all Monitor 3.0 services and pass --confirm")
        print_report(restore_backup(db, args.input))
        return
    if args.command == "token":
        if args.token_command == "create":  # CLI subcommand name, not a credential.  # nosec B105
            raw_token = "m3_" + secrets.token_urlsafe(32)
            now = utc_now()
            expires = now + timedelta(days=args.expires_days) if args.expires_days else None
            with db.transaction() as conn:
                conn.execute(
                    "INSERT INTO api_tokens(id,name,token_hash,role,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                    (str(uuid.uuid4()), args.name, token_hash(raw_token), args.role, now.isoformat(),
                     expires.isoformat() if expires else None),
                )
            print(f"token created for {args.name} ({args.role}); copy it now, it will not be shown again:")
            print(raw_token)
            return
        if args.token_command == "revoke":  # CLI subcommand name, not a credential.  # nosec B105
            with db.transaction() as conn:
                changed = conn.execute("UPDATE api_tokens SET enabled=0 WHERE name=?", (args.name,)).rowcount
            if not changed:
                raise SystemExit(f"token not found: {args.name}")
            print(f"token revoked: {args.name}")
            return
        with db.connect() as conn:
            rows = conn.execute("SELECT name,role,enabled,created_at,expires_at,last_used_at FROM api_tokens ORDER BY name")
            for row in rows:
                print(f"{row['name']} role={row['role']} enabled={bool(row['enabled'])} expires={row['expires_at'] or '-'} last_used={row['last_used_at'] or '-'}")
        return
    print(f"database upgraded: {settings.database_path}")


if __name__ == "__main__":
    main()
