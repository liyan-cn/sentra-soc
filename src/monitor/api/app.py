from __future__ import annotations

import json
import os
import platform
from importlib import resources
import uuid
import ipaddress
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, Response, g, jsonify, request, send_file
from werkzeug.middleware.proxy_fix import ProxyFix

from monitor.common.logging import configure_logging
from monitor.common.health import service_max_age
from monitor.domain.models import utc_now
from monitor.services.event_service import EventService
from monitor.services.whitelist_service import find_whitelist_match
from monitor.workers.runtime import HEALTHY_STATUSES, build_runtime
from monitor.api.auth import TokenAuthenticator
from monitor.api.rate_limit import SlidingWindowLimiter
from monitor.common.rules import RuleLoader
from monitor.common.playbooks import PlaybookLoader
from monitor.discovery import PARSER_SOURCES
from monitor.domain.playbook_engine import PlaybookContext, PlaybookEngine
from monitor.domain.models import SecurityEvent
from monitor.simulation import simulate as simulate_policy
from monitor.api.soc_features import register_soc_features


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _source_summaries(conn, settings, cutoff: str) -> list[dict]:
    """Merge configured and auto-discovered devices using hourly ingestion rollups.

    The raw event table can contain millions of flow records per day.  Dashboard
    reads must never regroup that table.  ``source_hourly_stats`` is maintained
    incrementally by SQLite and keeps this read bounded to a few dozen rows.
    """
    raw_counts = {
        row["device_id"]: dict(row)
        for row in conn.execute(
            """SELECT device_id,source,SUM(event_count) AS raw_events
            FROM source_hourly_stats WHERE hour>=substr(?,1,13)
            GROUP BY device_id,source""",
            (cutoff,),
        )
    }
    for row in conn.execute(
        """SELECT device_id,source,SUM(event_count) AS events,
        COUNT(DISTINCT CASE WHEN src_ip<>'' THEN src_ip END) AS unique_sources
        FROM source_alert_hourly_stats WHERE hour>=substr(?,1,13)
        GROUP BY device_id,source""",
        (cutoff,),
    ):
        counts = raw_counts.setdefault(row["device_id"], {
            "device_id": row["device_id"], "source": "", "raw_events": 0,
        })
        counts.update({"events": row["events"], "unique_sources": row["unique_sources"]})

    configured_devices = [
        item for item in getattr(settings, "raw", {}).get("devices", [])
        if item.get("enabled", True) and item.get("parser")
    ]
    sources: list[dict] = []
    for device in configured_devices:
        counts = raw_counts.pop(device.get("id"), {})
        log_glob = str(device.get("log_glob", ""))
        parts = log_glob.replace("\\", "/").split("/")
        device_ip = next((part for part in parts if _is_ip(part)), "")
        device_name = str(device.get("name") or device.get("source") or device.get("id"))
        sources.append({
            "device_id": device.get("id", ""), "device_ip": device_ip,
            "device_name": device_name,
            "display_name": f"{device_ip} · {device_name}" if device_ip else device_name,
            "source": device.get("source", counts.get("source", "")),
            "raw_events": int(counts.get("raw_events") or 0),
            "events": int(counts.get("events") or 0),
            "unique_sources": int(counts.get("unique_sources") or 0),
        })
    for device_id, counts in raw_counts.items():
        source = counts.get("source") or "UNKNOWN"
        sources.append({
            "device_id": device_id, "device_ip": "", "device_name": source,
            "display_name": f"{device_id} · {source}", "source": source,
            "raw_events": int(counts.get("raw_events") or 0),
            "events": int(counts.get("events") or 0),
            "unique_sources": int(counts.get("unique_sources") or 0),
        })

    known_device_ids = {item["device_id"] for item in sources}
    discovered = [dict(row) for row in conn.execute(
        """SELECT source_ip,name,status,parser,source,parsed_count,
        parse_success_rate,field_completeness,last_seen_at
        FROM discovered_devices WHERE status IN ('observing','active')
        ORDER BY last_seen_at DESC"""
    )]
    for device in discovered:
        device_id = "auto-" + device["source_ip"].replace(".", "-")
        device_name = str(device["name"] or device["source"] or device["parser"] or "待识别设备")
        if device_id in known_device_ids:
            current = next(item for item in sources if item["device_id"] == device_id)
            current.update({
                "device_ip": device["source_ip"], "device_name": device_name,
                "display_name": f"{device['source_ip']} · {device_name}",
                "lifecycle": device["status"],
                "sample_events": int(device["parsed_count"] or 0),
                "parse_success_rate": float(device["parse_success_rate"] or 0),
                "field_completeness": float(device["field_completeness"] or 0),
            })
            continue
        sources.append({
            "device_id": device_id, "device_ip": device["source_ip"],
            "device_name": device_name,
            "display_name": f"{device['source_ip']} · {device_name}",
            "source": device["source"] or "DISCOVERED", "raw_events": 0,
            "events": 0, "unique_sources": 0,
            "sample_events": int(device["parsed_count"] or 0),
            "lifecycle": device["status"],
            "parse_success_rate": float(device["parse_success_rate"] or 0),
            "field_completeness": float(device["field_completeness"] or 0),
        })
    ingestion = {r['device_id']: dict(r) for r in conn.execute(
        """SELECT device_id,SUM(line_count) AS processed_lines,MAX(last_seen_at) AS last_ingested_at
        FROM ingestion_hourly_stats WHERE hour>=substr(?,1,13) GROUP BY device_id""", (cutoff,))}
    for item in sources:
        item.update(ingestion.get(item['device_id'], {'processed_lines': 0, 'last_ingested_at': None}))
        last = item.get('last_ingested_at')
        item['data_age_seconds'] = max(0,int((utc_now()-datetime.fromisoformat(last)).total_seconds())) if last else None
        item['ingestion_state'] = 'unknown' if last is None else 'delayed' if item['data_age_seconds']>900 else 'recent'
    sources.sort(key=lambda item: (item["processed_lines"], item["raw_events"], item["events"], item.get("sample_events", 0)),
                 reverse=True)
    return sources


def _limit_source_summaries(sources: list[dict], limit: int) -> list[dict]:
    """Keep discovered live sensors visible even when historical sources are busier."""
    selected = list(sources[:limit])
    discovered = [item for item in sources if item.get("lifecycle") in ("observing", "active")]
    for item in discovered:
        if item in selected:
            continue
        replace = next((index for index in range(len(selected) - 1, -1, -1)
                        if not selected[index].get("lifecycle")), None)
        if replace is None:
            break
        selected[replace] = item
    return selected


def _service_max_age(settings, service: str) -> int:
    """Return a cadence-aware heartbeat threshold for one service."""
    return service_max_age(settings, service)


def _vpn_active_cutoff(settings) -> str:
    timeouts = [
        max(60, int(device.get("activity_timeout_seconds", 600)))
        for device in getattr(settings, "raw", {}).get("devices", [])
        if str(device.get("source", "")).upper().endswith("VPN")
    ]
    return (utc_now() - timedelta(seconds=max(timeouts or [600]))).isoformat()


def create_app(settings=None, db=None) -> Flask:
    if settings is None or db is None:
        settings, db, _ = build_runtime()
    app = Flask(__name__)
    api_config = settings.section("api")
    app.config["MAX_CONTENT_LENGTH"] = max(1024, int(api_config.get("max_request_bytes", 1048576)))
    proxy_hops = max(0, min(int(api_config.get("trusted_proxy_hops", 0)), 5))
    if proxy_hops:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxy_hops, x_proto=proxy_hops, x_host=proxy_hops)
    app.config["SETTINGS"] = settings
    app.config["DB"] = db
    authenticator = TokenAuthenticator(
        db, settings.admin_token, int(api_config.get("token_usage_update_seconds", 300))
    )
    auth_limiter = SlidingWindowLimiter(int(api_config.get("auth_rate_limit_per_minute", 120)))

    @app.before_request
    def request_context():
        supplied = request.headers.get("X-Request-ID", "").strip()
        g.request_id = supplied[:128] if supplied and all(31 < ord(char) < 127 for char in supplied) else str(uuid.uuid4())

    @app.after_request
    def security_headers(response):
        response.headers["X-Request-ID"] = g.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; object-src 'none'"
        if request.path.startswith("/api/") or request.path.startswith("/health"):
            response.headers["Cache-Control"] = "no-store"
        elif request.path.endswith((".css", ".js")):
            # UI assets contain no user data. A short public cache removes the
            # largest part of repeat-navigation latency while ETags still
            # allow safe revalidation after deployment.
            response.headers["Cache-Control"] = "public, max-age=3600, must-revalidate"
        else:
            response.headers["Cache-Control"] = "no-cache"
        return response

    @app.errorhandler(404)
    def route_not_found(_error):
        return jsonify({"error": {"code": "NOT_FOUND", "message": "resource not found"},
                        "meta": {"request_id": g.request_id}}), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify({"error": {"code": "METHOD_NOT_ALLOWED", "message": "method not allowed"},
                        "meta": {"request_id": g.request_id}}), 405

    @app.errorhandler(Exception)
    def unhandled_error(error):
        if isinstance(error, sqlite3.OperationalError) and any(
                word in str(error).lower() for word in ('locked', 'busy')):
            return jsonify({"error": {"code": "DATABASE_BUSY",
                "message": "数据库暂忙，本次操作未完成，请稍后重试"},
                "meta": {"request_id": g.request_id}}), 503, {"Retry-After": "3"}
        app.logger.exception("unhandled API error", extra={"request_id": g.request_id})
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": "internal server error"},
                        "meta": {"request_id": g.request_id}}), 500

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": {"code": "PAYLOAD_TOO_LARGE", "message": "request body too large"},
                        "meta": {"request_id": getattr(g, "request_id", "")}}), 413

    def ok(data=None, **meta):
        return jsonify({"data": data, "meta": {"request_id": g.request_id, **meta}})

    def require_role(role):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if not auth_limiter.allow(request.remote_addr or "unknown"):
                    response = jsonify({"error": {"code": "RATE_LIMITED", "message": "too many authenticated requests"},
                                        "meta": {"request_id": g.request_id}})
                    response.headers["Retry-After"] = "60"
                    return response, 429
                supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
                identity = authenticator.authenticate(supplied)
                if not identity:
                    return jsonify({"error": {"code": "UNAUTHORIZED", "message": "需要身份认证"},
                                    "meta": {"request_id": g.request_id}}), 401
                if not identity.permits(role):
                    return jsonify({"error": {"code": "FORBIDDEN", "message": "权限不足"},
                                    "meta": {"request_id": g.request_id}}), 403
                g.identity = identity
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    @app.get("/health/live")
    def live():
        return ok({"status": "alive"})

    @app.get("/")
    def dashboard():
        return send_file(resources.files("monitor.resources").joinpath("dashboard.html"))

    @app.get("/dashboard.css")
    def dashboard_css():
        return send_file(resources.files("monitor.resources").joinpath("dashboard.css"), mimetype="text/css")

    @app.get("/dashboard-batch.css")
    def dashboard_batch_css():
        return send_file(resources.files("monitor.resources").joinpath("dashboard-batch.css"), mimetype="text/css")

    @app.get("/dashboard.js")
    def dashboard_js():
        return send_file(resources.files("monitor.resources").joinpath("dashboard.js"), mimetype="application/javascript")

    @app.get("/dashboard-batch.js")
    def dashboard_batch_js():
        return send_file(resources.files("monitor.resources").joinpath("dashboard-batch.js"), mimetype="application/javascript")

    @app.get("/automation.css")
    def automation_css():
        return send_file(resources.files("monitor.resources").joinpath("automation.css"), mimetype="text/css")

    @app.get("/automation.js")
    def automation_js():
        return send_file(resources.files("monitor.resources").joinpath("automation.js"), mimetype="application/javascript")

    @app.get("/soc-features.css")
    def soc_features_css():
        return send_file(resources.files("monitor.resources").joinpath("soc-features.css"), mimetype="text/css")

    @app.get("/soc-features.js")
    def soc_features_js():
        return send_file(resources.files("monitor.resources").joinpath("soc-features.js"), mimetype="application/javascript")

    @app.get("/display")
    @app.get("/screen")
    def display():
        return send_file(resources.files("monitor.resources").joinpath("display.html"))

    @app.get("/display.css")
    def display_css():
        return send_file(resources.files("monitor.resources").joinpath("display.css"), mimetype="text/css")

    @app.get("/display-fix.css")
    def display_fix_css():
        return send_file(resources.files("monitor.resources").joinpath("display-fix.css"), mimetype="text/css")

    @app.get("/display.js")
    def display_js():
        return send_file(resources.files("monitor.resources").joinpath("display-wall.js"), mimetype="application/javascript")

    @app.get("/display-ui-fix.js")
    def display_ui_fix_js():
        return send_file(resources.files("monitor.resources").joinpath("display-ui-fix.js"), mimetype="application/javascript")

    @app.get("/health/ready")
    def ready():
        try:
            with db.connect() as conn:
                conn.execute("SELECT 1").fetchone()
                health = settings.section("health")
                required = list(health.get("required_services", []))
                rows = {row["service"]: row for row in conn.execute(
                    "SELECT service,status,updated_at FROM service_heartbeats WHERE service IN (%s)"
                    % ",".join("?" for _ in required), required
                )} if required else {}
            now = utc_now()
            unhealthy = []
            for service in required:
                row = rows.get(service)
                if row is None:
                    unhealthy.append({"service": service, "reason": "missing"})
                    continue
                updated = datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00"))
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=timezone.utc)
                age = max(0, (now - updated).total_seconds())
                maximum_age = _service_max_age(settings, service)
                if row["status"] not in HEALTHY_STATUSES or age > maximum_age:
                    unhealthy.append({"service": service, "reason": "stale_or_unhealthy", "age_seconds": round(age)})
            if unhealthy:
                return jsonify({"error": {"code": "NOT_READY", "message": "required services unavailable",
                                           "services": unhealthy},
                                "meta": {"request_id": g.request_id}}), 503
            return ok({"status": "ready", "required_services": required})
        except Exception as exc:
            app.logger.warning("readiness check failed", exc_info=exc, extra={"request_id": g.request_id})
            return jsonify({"error": {"code": "NOT_READY", "message": "service dependencies unavailable"},
                            "meta": {"request_id": g.request_id}}), 503

    @app.get("/metrics")
    def metrics():
        now = utc_now()
        with db.connect() as conn:
            oldest_action = conn.execute(
                "SELECT MIN(created_at) FROM action_outbox WHERE status IN ('pending','retry','running')"
            ).fetchone()[0]
            heartbeats = conn.execute("SELECT service,status,updated_at FROM service_heartbeats").fetchall()
            values = {
                "monitor3_events_total": conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0],
                "monitor3_blacklist_active": conn.execute("SELECT COUNT(*) FROM blacklist_entries WHERE desired_state IN ('pending_block','blocked')").fetchone()[0],
                "monitor3_reviews_open": conn.execute("SELECT COUNT(*) FROM review_cases WHERE status IN ('open','claimed')").fetchone()[0],
                "monitor3_actions_pending": conn.execute("SELECT COUNT(*) FROM action_outbox WHERE status IN ('pending','retry','running')").fetchone()[0],
                "monitor3_actions_dead": conn.execute("SELECT COUNT(*) FROM action_outbox WHERE status='dead'").fetchone()[0],
                "monitor3_parse_failures_total": conn.execute("SELECT COALESCE(SUM(count),0) FROM parse_failures").fetchone()[0],
                "monitor3_hosts_offline": conn.execute("SELECT COUNT(*) FROM hosts WHERE status='offline'").fetchone()[0],
                "monitor3_vpn_active": conn.execute("SELECT COUNT(*) FROM vpn_sessions WHERE status='active'").fetchone()[0],
            }
        heartbeat_ages = []
        unhealthy = 0
        for row in heartbeats:
            updated = datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00"))
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
            age = max(0, (now - updated).total_seconds())
            heartbeat_ages.append((row["service"], age))
            if row["status"] not in HEALTHY_STATUSES or age > _service_max_age(settings, row["service"]):
                unhealthy += 1
        values["monitor3_services_unhealthy"] = unhealthy
        values["monitor3_actions_oldest_age_seconds"] = 0
        if oldest_action:
            created = datetime.fromisoformat(oldest_action.replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            values["monitor3_actions_oldest_age_seconds"] = max(0, (now - created).total_seconds())
        if getattr(db, "dialect", "") == "sqlite":
            values["monitor3_database_bytes"] = db.path.stat().st_size if db.path.exists() else 0
        lines = ["# TYPE " + name + " gauge\n" + name + " " + str(value) for name, value in values.items()]
        lines.append("# TYPE monitor3_service_heartbeat_age_seconds gauge")
        for service, age in heartbeat_ages:
            safe_service = service.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            lines.append(f'monitor3_service_heartbeat_age_seconds{{service="{safe_service}"}} {age}')
        return Response("\n".join(lines) + "\n", mimetype="text/plain")

    @app.get("/api/v1/overview")
    @require_role("viewer")
    def overview():
        today = utc_now().date().isoformat()
        with db.connect() as conn:
            data = {
                "active_blacklist": conn.execute("SELECT COUNT(*) FROM blacklist_entries WHERE desired_state IN ('pending_block','blocked')").fetchone()[0],
                "pending_actions": conn.execute("SELECT COUNT(*) FROM action_outbox WHERE status IN ('pending','retry','running')").fetchone()[0],
                "open_reviews": conn.execute("SELECT COUNT(*) FROM review_cases WHERE status IN ('open','claimed')").fetchone()[0],
                "today_events": conn.execute(
                    """SELECT COUNT(*) FROM security_events e WHERE e.occurred_at>=?
                    AND EXISTS (SELECT 1 FROM policy_decisions d
                                WHERE d.event_id=e.id AND d.decision<>'IGNORE')""", (today,)
                ).fetchone()[0],
                "offline_hosts": conn.execute("SELECT COUNT(*) FROM hosts WHERE status='offline'").fetchone()[0],
                "active_vpn": conn.execute("SELECT COUNT(*) FROM vpn_sessions WHERE status='active'").fetchone()[0],
            }
        return ok(data)

    def paged_query(sql: str, params=()):
        try:
            size = min(max(int(request.args.get("page_size", 50)), 1), 200)
            page = max(int(request.args.get("page", 1)), 1)
        except (TypeError, ValueError):
            return jsonify({"error": {"code": "VALIDATION_ERROR",
                                      "message": "page and page_size must be integers"},
                            "meta": {"request_id": g.request_id}}), 400
        offset = (page - 1) * size
        if offset > 10_000_000:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "page is too large"},
                            "meta": {"request_id": g.request_id}}), 400
        with db.connect() as conn:
            fetched = conn.execute(sql + " LIMIT ? OFFSET ?", (*params, size + 1, offset)).fetchall()
        rows = [dict(row) for row in fetched[:size]]
        return ok(rows, page=page, page_size=size, has_more=len(fetched) > size)

    def paged_rows(rows: list[dict]):
        try:
            size = min(max(int(request.args.get("page_size", 50)), 1), 200)
            page = max(int(request.args.get("page", 1)), 1)
        except (TypeError, ValueError):
            return jsonify({"error": {"code": "VALIDATION_ERROR",
                                      "message": "page and page_size must be integers"},
                            "meta": {"request_id": g.request_id}}), 400
        offset = (page - 1) * size
        return ok(rows[offset:offset + size], page=page, page_size=size,
                  has_more=len(rows) > offset + size)

    def query_text(name: str) -> str:
        return str(request.args.get(name, "")).strip()

    def add_exact_filter(clauses: list[str], params: list, column: str, arg_name: str):
        value = query_text(arg_name)
        if value:
            clauses.append(f"{column}=?")
            params.append(value)

    def add_like_filter(clauses: list[str], params: list, column: str, arg_name: str):
        value = query_text(arg_name)
        if value:
            clauses.append(f"{column} LIKE ?")
            params.append(f"%{value}%")

    def add_text_search(clauses: list[str], params: list, columns: tuple[str, ...]):
        value = query_text("q")
        if value:
            clauses.append("(" + " OR ".join(f"{column} LIKE ?" for column in columns) + ")")
            params.extend([f"%{value}%"] * len(columns))

    def add_time_filters(clauses: list[str], params: list, column: str):
        start = query_text("date_from") or query_text("start")
        end = query_text("date_to") or query_text("end")
        if start:
            clauses.append(f"{column}>=?")
            params.append(start)
        if end:
            clauses.append(f"{column}<=?")
            params.append(end + "T23:59:59" if len(end) == 10 else end)

    def where_clause(clauses: list[str]) -> str:
        return (" WHERE " + " AND ".join(clauses)) if clauses else ""

    def filter_memory_rows(rows: list[dict], *, text_fields=(), exact_fields=None, date_field: str = "") -> list[dict]:
        exact_fields = exact_fields or {}
        q = query_text("q").casefold()
        if q:
            rows = [
                row for row in rows
                if any(q in str(row.get(field, "")).casefold() for field in text_fields)
            ]
        for arg_name, fields in exact_fields.items():
            value = query_text(arg_name)
            if not value:
                continue
            wanted = value.casefold()
            rows = [
                row for row in rows
                if any(str(row.get(field, "")).casefold() == wanted for field in fields)
            ]
        start = query_text("date_from") or query_text("start")
        end = query_text("date_to") or query_text("end")
        if date_field and (start or end):
            end_value = end + "T23:59:59" if end and len(end) == 10 else end
            rows = [
                row for row in rows
                if (not start or str(row.get(date_field, "")) >= start)
                and (not end_value or str(row.get(date_field, "")) <= end_value)
            ]
        return rows

    @app.get("/api/v1/events")
    @require_role("viewer")
    def events():
        clauses, params = [], []
        add_time_filters(clauses, params, "e.occurred_at")
        add_like_filter(clauses, params, "e.src_ip", "src_ip")
        add_like_filter(clauses, params, "e.dst_ip", "dst_ip")
        add_like_filter(clauses, params, "e.source", "source")
        add_like_filter(clauses, params, "e.category", "category")
        add_exact_filter(clauses, params, "e.severity", "severity")
        add_like_filter(clauses, params, "e.device_id", "device_id")
        add_text_search(clauses, params, ("e.src_ip", "e.dst_ip", "e.source", "e.category", "e.device_id"))
        return paged_query(
            """SELECT e.*,
            COALESCE(
              NULLIF(json_extract(e.attributes_json,'$.source_location'),''),
              NULLIF(json_extract(e.attributes_json,'$.src_location'),''),
              NULLIF((SELECT d.location FROM policy_decisions d
                      WHERE d.event_id=e.id ORDER BY d.created_at DESC LIMIT 1),''),
              'UNKNOWN') AS source_location
            FROM security_events e""" + where_clause(clauses) + " ORDER BY e.occurred_at DESC",
            tuple(params),
        )

    @app.get("/api/v1/events/<event_id>")
    @require_role("viewer")
    def event_detail(event_id):
        with db.connect() as conn:
            event = conn.execute("SELECT * FROM security_events WHERE id=?", (event_id,)).fetchone()
            if not event:
                return jsonify({"error": {"code": "NOT_FOUND", "message": "事件不存在"}}), 404
            decisions = [dict(x) for x in conn.execute("SELECT * FROM policy_decisions WHERE event_id=?", (event_id,))]
        return ok({"event": dict(event), "decisions": decisions})

    @app.get("/api/v1/blacklist")
    @require_role("viewer")
    def blacklist():
        with db.connect() as conn:
            firewall_rows = [dict(row) for row in conn.execute(
                """SELECT id,ip,'FIREWALL' AS source,direction AS category,
                'blocked' AS desired_state,'blocked' AS actual_state,
                expires_at AS desired_expires_at,description,hit_count,inserted_at,
                age_time,direction,protocol,'firewall' AS origin,synced_at
                FROM firewall_list_entries WHERE list_type='blacklist'
                ORDER BY inserted_at DESC,direction,ip"""
            )]
            mirrored = {(row["ip"], row["direction"]) for row in firewall_rows}
            local_rows = [dict(row) | {"origin": "local", "direction": "src"}
                          for row in conn.execute("SELECT * FROM blacklist_entries ORDER BY last_seen_at DESC")
                          if (row["ip"], "src") not in mirrored]
        rows = filter_memory_rows(
            firewall_rows + local_rows,
            text_fields=("ip", "description", "category", "source", "origin", "desired_state", "actual_state"),
            exact_fields={
                "direction": ("direction",),
                "status": ("actual_state", "desired_state"),
                "source": ("source", "origin"),
            },
            date_field="inserted_at",
        )
        ip_value = query_text("ip")
        if ip_value:
            rows = [row for row in rows if ip_value in str(row.get("ip", ""))]
        return paged_rows(rows)

    @app.post("/api/v1/blacklist")
    @require_role("operator")
    def blacklist_create():
        body = request.get_json(silent=True) or {}
        try:
            ip = str(ipaddress.ip_address(str(body.get("ip", "")).strip()))
            minutes = min(max(int(body.get("minutes", 1440)), 1), 525600)
        except (ValueError, TypeError):
            return jsonify({"error": {"code": "VALIDATION_ERROR",
                                      "message": "ip 或 minutes 无效"}}), 400
        reason = str(body.get("reason", "")).strip()
        if not reason:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "必须填写 reason"}}), 400
        now = utc_now(); expires = now + timedelta(minutes=minutes)
        with db.transaction(immediate=True) as conn:
            allowed = find_whitelist_match(conn, ip, now.isoformat())
            if allowed:
                return jsonify({"error": {"code": "WHITELIST_CONFLICT",
                                          "message": f"该 IP 命中白名单 {allowed['network']}"}}), 409
            existing = conn.execute("SELECT * FROM blacklist_entries WHERE ip=?", (ip,)).fetchone()
            entry_id = existing["id"] if existing else str(uuid.uuid4())
            conn.execute(
                """INSERT INTO blacklist_entries(id,ip,desired_state,actual_state,first_seen_at,last_seen_at,
                desired_expires_at,hit_count,category,source,location)
                VALUES(?,?,'pending_block','unknown',?,?,?,1,'MANUAL','MANUAL','MANUAL')
                ON CONFLICT(ip) DO UPDATE SET desired_state='pending_block',version=version+1,
                last_seen_at=excluded.last_seen_at,desired_expires_at=excluded.desired_expires_at,
                category='MANUAL',source='MANUAL',last_error=NULL""",
                (entry_id, ip, now.isoformat(), now.isoformat(), expires.isoformat()),
            )
            target = conn.execute("SELECT id,version FROM blacklist_entries WHERE ip=?", (ip,)).fetchone()
            EventService._enqueue(conn, "BLOCK", "blacklist", target["id"],
                                  {"ip": ip, "minutes": minutes, "category": "MANUAL"},
                                  f"manual-block:{target['id']}:{target['version']}", 100)
            audit(conn, g.identity.name, "create", "blacklist", target["id"], reason,
                  dict(existing) if existing else None,
                  {"ip": ip, "desired_state": "pending_block", "minutes": minutes})
        return ok({"id": target["id"], "ip": ip, "status": "pending_block"}), 201

    @app.get("/api/v1/reviews")
    @require_role("viewer")
    def reviews():
        status = request.args.get("status")
        clauses, params = [], []
        if status:
            clauses.append("r.status=?")
            params.append(status)
        add_time_filters(clauses, params, "r.created_at")
        add_like_filter(clauses, params, "e.src_ip", "src_ip")
        add_like_filter(clauses, params, "e.dst_ip", "dst_ip")
        add_like_filter(clauses, params, "e.category", "category")
        add_like_filter(clauses, params, "e.source", "source")
        add_text_search(clauses, params, ("e.src_ip", "e.dst_ip", "e.category", "e.source", "r.reason"))
        sql = """SELECT r.*,e.src_ip AS attack_source_ip,e.dst_ip AS target_ip,
                 COALESCE((SELECT d.location FROM policy_decisions d
                           WHERE d.event_id=r.event_id ORDER BY d.created_at DESC LIMIT 1),'UNKNOWN') AS location
                 FROM review_cases r LEFT JOIN security_events e ON e.id=r.event_id"""
        return paged_query(sql + where_clause(clauses) + " ORDER BY r.created_at DESC", tuple(params))

    @app.get("/api/v1/services")
    @require_role("viewer")
    def services():
        clauses, params = [], []
        add_like_filter(clauses, params, "service", "q")
        add_exact_filter(clauses, params, "status", "status")
        return paged_query("SELECT * FROM service_heartbeats" + where_clause(clauses) + " ORDER BY service",
                           tuple(params))

    @app.get("/api/v1/actions")
    @require_role("viewer")
    def actions():
        clauses, params = [], []
        add_exact_filter(clauses, params, "status", "status")
        add_like_filter(clauses, params, "action_type", "action_type")
        add_like_filter(clauses, params, "aggregate_type", "aggregate_type")
        add_text_search(clauses, params, ("action_type", "aggregate_type", "aggregate_id", "last_error"))
        add_time_filters(clauses, params, "created_at")
        order = " ORDER BY priority DESC,created_at" if query_text("status") else " ORDER BY created_at DESC"
        return paged_query("SELECT * FROM action_outbox" + where_clause(clauses) + order, tuple(params))

    @app.get("/api/v1/vpn/sessions")
    @require_role("viewer")
    def vpn():
        clauses, params = [], []
        add_like_filter(clauses, params, "username", "username")
        add_like_filter(clauses, params, "client_ip", "client_ip")
        add_like_filter(clauses, params, "virtual_ip", "virtual_ip")
        add_exact_filter(clauses, params, "status", "status")
        add_time_filters(clauses, params, "login_at")
        add_text_search(clauses, params, ("username", "client_ip", "virtual_ip", "location"))
        return paged_query("SELECT * FROM vpn_sessions" + where_clause(clauses) + " ORDER BY login_at DESC",
                           tuple(params))

    @app.get("/api/v1/hosts")
    @require_role("viewer")
    def hosts():
        clauses, params = [], []
        add_like_filter(clauses, params, "ip", "ip")
        add_like_filter(clauses, params, "name", "name")
        add_like_filter(clauses, params, "site", "site")
        add_exact_filter(clauses, params, "status", "status")
        add_exact_filter(clauses, params, "kind", "kind")
        add_text_search(clauses, params, ("ip", "name", "site", "kind"))
        return paged_query("SELECT * FROM hosts" + where_clause(clauses) + " ORDER BY ip", tuple(params))

    @app.get("/api/v1/alerts/recent")
    @require_role("viewer")
    def alerts():
        return paged_query(
            """SELECT d.created_at AS time,d.decision AS action,e.src_ip AS ip,e.category,e.source,d.reason
            FROM policy_decisions d JOIN security_events e ON e.id=d.event_id
            WHERE d.decision IN ('BLOCK','MANUAL_REVIEW','NOTIFY') ORDER BY d.created_at DESC"""
        )

    @app.get("/api/v1/stats/trend")
    @require_role("viewer")
    def trend():
        with db.connect() as conn:
            rows = [dict(x) for x in conn.execute(
                """SELECT substr(e.occurred_at,1,10) AS date,COUNT(*) AS events
                FROM security_events e WHERE e.occurred_at>=?
                AND EXISTS (SELECT 1 FROM policy_decisions d
                            WHERE d.event_id=e.id AND d.decision<>'IGNORE')
                GROUP BY substr(e.occurred_at,1,10) ORDER BY date""",
                ((utc_now() - timedelta(days=7)).isoformat(),),
            )]
        return ok(rows)

    @app.get("/api/v1/soc/brain")
    @require_role("viewer")
    def soc_brain():
        """A single read model for the SOC command-center overview."""
        cutoff = (utc_now() - timedelta(hours=24)).isoformat()
        with db.connect() as conn:
            sources = _limit_source_summaries(_source_summaries(conn, settings, cutoff), 20)
            categories = [dict(row) for row in conn.execute(
                """SELECT title AS category,COUNT(*) AS events
                FROM soc_alerts WHERE occurred_at>=?
                GROUP BY title ORDER BY events DESC LIMIT 10""", (cutoff,)
            )]
            hourly = [dict(row) for row in conn.execute(
                """SELECT hour,SUM(event_count) AS events,
                COUNT(DISTINCT CASE WHEN src_ip<>'' THEN src_ip END) AS unique_sources
                FROM source_alert_hourly_stats WHERE hour>=substr(?,1,13)
                GROUP BY hour ORDER BY hour""", (cutoff,)
            )]
            geography = [dict(row) for row in conn.execute(
                """SELECT COALESCE(NULLIF((SELECT d.location FROM policy_decisions d
                    WHERE d.event_id=a.event_id AND d.decision<>'IGNORE'
                    ORDER BY d.created_at DESC LIMIT 1),''),'UNKNOWN') AS location,
                COUNT(*) AS events,COUNT(DISTINCT a.src_ip) AS unique_sources
                FROM soc_alerts a WHERE a.occurred_at>=?
                GROUP BY location
                ORDER BY events DESC LIMIT 12""", (cutoff,)
            )]
            risks = [dict(row) for row in conn.execute(
                """SELECT a.src_ip,a.source,a.title AS category,a.severity,a.occurred_at,
                COALESCE((SELECT d.decision FROM policy_decisions d
                    WHERE d.event_id=a.event_id AND d.decision<>'IGNORE'
                    ORDER BY d.created_at DESC LIMIT 1),'OBSERVE') AS decision
                FROM soc_alerts a ORDER BY a.occurred_at DESC LIMIT 12"""
            )]
            services = [dict(row) for row in conn.execute(
                """SELECT service,status,updated_at,details_json
                FROM service_heartbeats ORDER BY service"""
            )]
            hosts = [dict(row) for row in conn.execute(
                """SELECT ip,name,kind,site,status,consecutive_failures,last_checked_at,last_changed_at
                FROM hosts ORDER BY CASE status WHEN 'offline' THEN 0 WHEN 'degraded' THEN 1
                WHEN 'online' THEN 2 ELSE 3 END,CASE kind WHEN 'site' THEN 0 ELSE 1 END,name,ip LIMIT 300"""
            )]
            vpn_sessions = [dict(row) for row in conn.execute(
                """SELECT username,client_ip,virtual_ip,login_at,last_seen_at,status,location,session_origin
                FROM vpn_sessions WHERE status='active' AND COALESCE(last_seen_at,login_at)>=?
                ORDER BY COALESCE(last_seen_at,login_at) DESC LIMIT 100""", (_vpn_active_cutoff(settings),)
            )]
            rollup = conn.execute(
                """SELECT COALESCE(SUM(event_count),0),
                COUNT(DISTINCT CASE WHEN src_ip<>'' THEN src_ip END)
                FROM source_alert_hourly_stats WHERE hour>=substr(?,1,13)""", (cutoff,)
            ).fetchone()
            totals = {
                "events_24h": int(rollup[0] or 0),
                "unique_sources_24h": int(rollup[1] or 0),
                "open_reviews": conn.execute(
                    "SELECT COUNT(*) FROM review_cases WHERE status IN ('open','claimed')"
                ).fetchone()[0],
                "active_blacklist": conn.execute(
                    "SELECT COUNT(*) FROM blacklist_entries WHERE desired_state IN ('pending_block','blocked')"
                ).fetchone()[0],
            }
        now = utc_now()
        healthy = 0
        normalized_services = []
        for row in services:
            updated = datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00"))
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
            age = max(0, int((now - updated).total_seconds()))
            maximum_age = _service_max_age(settings, row["service"])
            is_healthy = row["status"] in HEALTHY_STATUSES and age <= maximum_age
            if row["status"] == "degraded" and age <= maximum_age:
                state = "degraded"
            else:
                state = "fresh" if is_healthy and age <= min(180, maximum_age) else ("delayed" if is_healthy else "stale")
            healthy += int(is_healthy)
            details = json.loads(row["details_json"] or "{}")
            normalized_services.append({
                "service": row["service"], "status": row["status"],
                "healthy": is_healthy, "health_state": state, "age_seconds": age,
                "max_age_seconds": maximum_age,
                "source": details.get("source", ""), "file": details.get("file", ""),
            })
        totals["services_healthy"] = healthy
        totals["services_total"] = len(services)
        vpn_workers = [s for s in normalized_services if s['service'].startswith('vpn:')]
        vpn_status = {"collector_healthy": bool(vpn_workers) and all(s['healthy'] for s in vpn_workers),
                      "collector_age_seconds": max((s['age_seconds'] for s in vpn_workers), default=None),
                      "basis": "recent_activity",
                      "public_ip_known": sum(bool(s['client_ip']) for s in vpn_sessions),
                      "public_ip_missing": sum(not s['client_ip'] for s in vpn_sessions),
                      "public_ip_source": "USERLOGINSUCC.Client IP"}
        return ok({
            "totals": totals, "sources": sources, "categories": categories,
            "risks": risks, "services": normalized_services, "hourly": hourly,
            "geography": geography, "hosts": hosts, "vpn_sessions": vpn_sessions, "vpn_status": vpn_status,
            "generated_at": now.isoformat(),
        })

    @app.get("/api/v1/display/overview")
    @app.get("/api/v1/screen/overview")
    @require_role("viewer")
    def display_overview():
        """Sanitized aggregate read model for customer-facing wall displays."""
        cutoff = (utc_now() - timedelta(hours=24)).isoformat()
        with db.connect() as conn:
            totals = {
                "events": conn.execute("SELECT COUNT(*) FROM soc_alerts WHERE occurred_at>=?", (cutoff,)).fetchone()[0],
                "sources": conn.execute("SELECT COUNT(DISTINCT src_ip) FROM soc_alerts WHERE occurred_at>=?", (cutoff,)).fetchone()[0],
                "blocked": conn.execute("SELECT COUNT(*) FROM blacklist_entries WHERE desired_state IN ('pending_block','blocked')").fetchone()[0],
                "reviews": conn.execute("SELECT COUNT(*) FROM review_cases WHERE status IN ('open','claimed')").fetchone()[0],
                "assets_online": conn.execute("SELECT COUNT(*) FROM hosts WHERE status='online' AND kind<>'site'").fetchone()[0],
                "assets_total": conn.execute("SELECT COUNT(*) FROM hosts WHERE kind<>'site'").fetchone()[0],
                "vpn_online": conn.execute(
                    "SELECT COUNT(*) FROM vpn_sessions WHERE status='active' AND COALESCE(last_seen_at,login_at)>=?",
                    (_vpn_active_cutoff(settings),),
                ).fetchone()[0],
                "vpn_audited": conn.execute(
                    """SELECT COUNT(*) FROM vpn_sessions WHERE status='active'
                    AND COALESCE(last_seen_at,login_at)>=? AND client_ip<>''""",
                    (_vpn_active_cutoff(settings),),
                ).fetchone()[0],
            }
            hourly = [dict(x) for x in conn.execute(
                """SELECT substr(occurred_at,1,13) AS hour,COUNT(*) AS events
                FROM soc_alerts WHERE occurred_at>=?
                GROUP BY substr(occurred_at,1,13) ORDER BY hour""", (cutoff,))]
            sources = _limit_source_summaries(_source_summaries(conn, settings, cutoff), 8)
            categories = [dict(x) for x in conn.execute(
                """SELECT title AS category,COUNT(*) AS events FROM soc_alerts WHERE occurred_at>=?
                GROUP BY title ORDER BY events DESC LIMIT 8""", (cutoff,))]
            geography = [dict(x) for x in conn.execute(
                """SELECT COALESCE(NULLIF((SELECT d.location FROM policy_decisions d
                    WHERE d.event_id=a.event_id AND d.decision<>'IGNORE'
                    ORDER BY d.created_at DESC LIMIT 1),''),'UNKNOWN') AS location,
                COUNT(*) AS events FROM soc_alerts a WHERE a.occurred_at>=?
                GROUP BY location
                ORDER BY events DESC LIMIT 10""", (cutoff,))]
            risks = [dict(x) for x in conn.execute(
                """SELECT a.source,a.title AS category,a.severity,a.occurred_at,
                COALESCE(NULLIF((SELECT d.location FROM policy_decisions d
                    WHERE d.event_id=a.event_id AND d.decision<>'IGNORE'
                    ORDER BY d.created_at DESC LIMIT 1),''),'UNKNOWN') AS location,
                COALESCE((SELECT d.decision FROM policy_decisions d
                    WHERE d.event_id=a.event_id AND d.decision<>'IGNORE'
                    ORDER BY d.created_at DESC LIMIT 1),'OBSERVE') AS decision
                FROM soc_alerts a ORDER BY a.occurred_at DESC LIMIT 12""")]
            sites = [dict(x) for x in conn.execute(
                "SELECT name,status,last_checked_at FROM hosts WHERE kind='site' ORDER BY name")]
            service_rows = [dict(x) for x in conn.execute(
                "SELECT service,status,updated_at FROM service_heartbeats ORDER BY service")]
        now = utc_now()
        healthy_services = 0
        for row in service_rows:
            updated = datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00"))
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
            healthy_services += int(
                row["status"] in HEALTHY_STATUSES
                and (now - updated).total_seconds() <= _service_max_age(settings, row["service"])
            )
        totals["services_healthy"] = healthy_services
        totals["services_total"] = len(service_rows)
        totals["vpn_pending_audit"] = max(0, totals["vpn_online"] - totals["vpn_audited"])
        return ok({"totals": totals, "hourly": hourly, "sources": sources,
                   "categories": categories, "geography": geography,
                   "risks": risks, "sites": sites, "generated_at": now.isoformat()})

    @app.get("/api/v1/stats/daily")
    @require_role("viewer")
    def daily_stats():
        days = min(max(int(request.args.get("days", 30)), 1), 366)
        cutoff = (utc_now().date() - timedelta(days=days)).isoformat()
        return paged_query(
            "SELECT * FROM daily_stats WHERE stat_date>=? ORDER BY stat_date DESC,source,category", (cutoff,)
        )

    def audit(conn, actor, action, target_type, target_id, reason, before=None, after=None):
        conn.execute(
            """INSERT INTO audit_logs(actor,action,target_type,target_id,reason,before_json,after_json,source_ip,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (actor, action, target_type, target_id, reason,
             json.dumps(before, ensure_ascii=False) if before else None,
             json.dumps(after, ensure_ascii=False) if after else None,
             request.remote_addr, utc_now().isoformat()),
        )

    @app.post("/api/v1/reviews/<review_id>/<operation>")
    @require_role("reviewer")
    def review_action(review_id, operation):
        if operation not in ("claim", "approve", "reject"):
            return jsonify({"error": {"code": "BAD_OPERATION", "message": "不支持的操作"}}), 400
        body = request.get_json(silent=True) or {}
        actor, reason = g.identity.name, body.get("reason", "")
        with db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM review_cases WHERE id=?", (review_id,)).fetchone()
            if not row:
                return jsonify({"error": {"code": "NOT_FOUND", "message": "审核单不存在"}}), 404
            before = dict(row)
            status = {"claim": "claimed", "approve": "approved", "reject": "rejected"}[operation]
            closed = utc_now().isoformat() if operation in ("approve", "reject") else None
            conn.execute("UPDATE review_cases SET status=?,assignee=?,resolution=?,updated_at=?,closed_at=? WHERE id=?",
                         (status, actor, reason, utc_now().isoformat(), closed, review_id))
            if operation == "approve":
                blacklist_id = str(uuid.uuid4()); expires = utc_now() + timedelta(minutes=10000)
                conn.execute(
                    """INSERT INTO blacklist_entries(id,ip,desired_state,actual_state,first_seen_at,last_seen_at,
                    desired_expires_at,hit_count,category,source,location) VALUES(?,?,'pending_block','unknown',?,?,?,?,?,?,?)
                    ON CONFLICT(ip) DO UPDATE SET desired_state='pending_block',version=version+1,last_seen_at=excluded.last_seen_at,
                    desired_expires_at=excluded.desired_expires_at""",
                    (blacklist_id, row["ip"], utc_now().isoformat(), utc_now().isoformat(), expires.isoformat(),
                     row["count"], row["category"], row["source"], "REVIEW_APPROVED"),
                )
                target = conn.execute("SELECT id,version FROM blacklist_entries WHERE ip=?", (row["ip"],)).fetchone()
                EventService._enqueue(conn, "BLOCK", "blacklist", target["id"],
                                      {"ip": row["ip"], "minutes": 10000, "category": row["category"]},
                                      f"review-block:{review_id}:{target['version']}", 100)
            audit(conn, actor, operation, "review", review_id, reason, before, {"status": status})
        return ok({"id": review_id, "status": status})

    @app.delete("/api/v1/blacklist/<entry_id>")
    @require_role("operator")
    def unblock(entry_id):
        body = request.get_json(silent=True) or {}
        reason = body.get("reason", "")
        if not reason:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "必须填写 reason"}}), 400
        with db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM blacklist_entries WHERE id=?", (entry_id,)).fetchone()
            if not row:
                return jsonify({"error": {"code": "NOT_FOUND", "message": "黑名单不存在"}}), 404
            conn.execute("UPDATE blacklist_entries SET desired_state='pending_unblock',version=version+1 WHERE id=?", (entry_id,))
            EventService._enqueue(conn, "UNBLOCK", "blacklist", entry_id, {"ip": row["ip"]},
                                  f"manual-unblock:{entry_id}:{int(row['version'])+1}", 100)
            audit(conn, g.identity.name, "unblock", "blacklist", entry_id, reason, dict(row), {"desired_state": "pending_unblock"})
        return ok({"id": entry_id, "status": "pending_unblock"})

    @app.post("/api/v1/actions/<action_id>/retry")
    @require_role("operator")
    def retry_action(action_id):
        body = request.get_json(silent=True) or {}
        reason = str(body.get("reason", "")).strip()
        if not reason:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "reason is required"}}), 400
        with db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM action_outbox WHERE id=?", (action_id,)).fetchone()
            if not row:
                return jsonify({"error": {"code": "NOT_FOUND", "message": "action not found"}}), 404
            if row["status"] != "dead":
                return jsonify({"error": {"code": "CONFLICT", "message": "only dead actions can be retried"}}), 409
            now = utc_now().isoformat()
            conn.execute(
                """UPDATE action_outbox SET status='pending',attempts=0,available_at=?,locked_by=NULL,
                   locked_until=NULL,last_error=NULL,updated_at=? WHERE id=?""", (now, now, action_id)
            )
            audit(conn, g.identity.name, "retry", "action", action_id, reason, dict(row), {"status": "pending"})
        return ok({"id": action_id, "status": "pending"})

    @app.get("/api/v1/audit-logs")
    @require_role("admin")
    def audit_logs():
        return paged_query("SELECT * FROM audit_logs ORDER BY created_at DESC")

    @app.get("/api/v1/policies/status")
    @require_role("viewer")
    def policy_status():
        loader = RuleLoader(settings)
        try:
            rules = loader.load()
            return ok({"valid": True, "version": loader.version, "path": str(loader.path),
                       "policy_count": len(rules.get("policies", []))})
        except Exception as exc:
            return jsonify({"error": {"code": "INVALID_POLICY", "message": str(exc)},
                            "meta": {"request_id": g.request_id}}), 503

    @app.get("/api/v1/playbooks/status")
    @require_role("viewer")
    def playbook_status():
        loader = PlaybookLoader(settings, database=db)
        try:
            playbooks = loader.load()
            safe = [{"id": item["id"], "name": item.get("name", item["id"]),
                     "enabled": bool(item.get("enabled", False)),
                     "priority": int(item.get("priority", 0)),
                     "trigger": item.get("trigger", "review_created")}
                    for item in playbooks]
            return ok({"valid": True, "version": loader.version, "path": str(loader.path),
                       "playbook_count": len(playbooks),
                       "enabled_count": sum(1 for item in playbooks if item.get("enabled", False)),
                       "playbooks": safe})
        except Exception as exc:
            return jsonify({"error": {"code": "INVALID_PLAYBOOK", "message": str(exc)},
                            "meta": {"request_id": g.request_id}}), 503

    @app.get("/api/v1/playbooks/executions")
    @require_role("viewer")
    def playbook_executions():
        clauses, params = [], []
        add_time_filters(clauses, params, "created_at")
        add_like_filter(clauses, params, "playbook_id", "playbook_id")
        add_exact_filter(clauses, params, "status", "status")
        add_text_search(clauses, params, ("playbook_id", "trigger_type", "status", "error"))
        return paged_query("SELECT * FROM playbook_executions" + where_clause(clauses) +
                           " ORDER BY created_at DESC", tuple(params))

    @app.get("/api/v1/discovered-devices")
    @require_role("viewer")
    def discovered_devices():
        clauses, params = [], []
        add_exact_filter(clauses, params, "status", "status")
        add_like_filter(clauses, params, "source_ip", "source_ip")
        add_like_filter(clauses, params, "parser", "parser")
        add_like_filter(clauses, params, "source", "source")
        add_time_filters(clauses, params, "last_seen_at")
        add_text_search(clauses, params, ("source_ip", "name", "parser", "source", "last_error"))
        return paged_query("SELECT * FROM discovered_devices" + where_clause(clauses) +
                           " ORDER BY last_seen_at DESC", tuple(params))

    @app.get("/api/v1/device-parsers")
    @require_role("viewer")
    def device_parsers():
        labels = {"huawei_waf": "华为 WAF", "huawei_ips": "华为 IPS（兼容旧配置）",
                  "h3c_waf": "华三 H3C WAF", "h3c_security": "华三 H3C 防火墙/IPS",
                  "qianxin_ngfw": "奇安信/网神 防火墙", "qianxin_waf": "奇安信/网神 WAF",
                  "sangfor_ngaf": "深信服 NGAF", "hillstone_ngfw": "山石 NGFW",
                  "nsfocus_waf": "绿盟 WAF", "venustech_utm": "启明星辰 防火墙/UTM",
                  "cef_security": "通用 CEF 安全设备", "dptech_waf": "迪普 WAF",
                  "dptech_ips": "迪普 IPS", "topsec_waf": "天融信 WAF"}
        return ok([{"parser": parser, "source": source, "label": labels.get(parser, parser)}
                   for parser, source in PARSER_SOURCES.items()])

    @app.post("/api/v1/discovered-devices/<device_id>/confirm")
    @require_role("operator")
    def confirm_discovered_device(device_id):
        body = request.get_json(silent=True) or {}
        parser = str(body.get("parser", ""))
        device_name = str(body.get("device_name", "")).strip()
        reason = str(body.get("reason", "")).strip()
        if parser not in PARSER_SOURCES or not reason or len(device_name) > 80:
            return jsonify({"error": {"code": "VALIDATION_ERROR",
                                      "message": "valid parser, reason and device name are required"}}), 400
        with db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM discovered_devices WHERE id=?", (device_id,)).fetchone()
            if not row:
                return jsonify({"error": {"code": "NOT_FOUND", "message": "device not found"}}), 404
            now = utc_now().isoformat()
            generated = json.loads(row["config_json"] or "{}")
            generated.update({"parser": parser, "source": PARSER_SOURCES[parser]})
            if device_name:
                generated["name"] = device_name
            conn.execute(
                """UPDATE discovered_devices SET parser=?,source=?,name=CASE WHEN ?<>'' THEN ? ELSE name END,
                   status='observing',config_json=?,
                   confirmed_by=?,confirmed_at=?,last_error=NULL WHERE id=?""",
                (parser, PARSER_SOURCES[parser], device_name, device_name,
                 json.dumps(generated, ensure_ascii=False),
                 g.identity.name, now, device_id),
            )
            audit(conn, g.identity.name, "confirm", "discovered_device", device_id, reason,
                  dict(row), {"status": "observing", "parser": parser, "name": device_name})
        return ok({"id": device_id, "status": "observing", "parser": parser,
                   "name": device_name or row["name"]})

    @app.post("/api/v1/discovered-devices/<device_id>/promote")
    @require_role("operator")
    def promote_discovered_device(device_id):
        body = request.get_json(silent=True) or {}
        reason = str(body.get("reason", "")).strip()
        if not reason:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "reason is required"}}), 400
        cfg = settings.section("discovery")
        with db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM discovered_devices WHERE id=?", (device_id,)).fetchone()
            if not row:
                return jsonify({"error": {"code": "NOT_FOUND", "message": "device not found"}}), 404
            if row["status"] != "observing":
                return jsonify({"error": {"code": "CONFLICT", "message": "device is not observing"}}), 409
            checks = {
                "parsed_count": (row["parsed_count"], int(cfg.get("promote_min_parsed", 20))),
                "parse_success_rate": (row["parse_success_rate"], float(cfg.get("promote_min_success_rate", .9))),
                "field_completeness": (row["field_completeness"], float(cfg.get("promote_min_field_completeness", .75))),
            }
            failed = {name: {"actual": actual, "required": required}
                      for name, (actual, required) in checks.items() if actual < required}
            if failed and not bool(body.get("override", False)):
                return jsonify({"error": {"code": "QUALITY_GATE_FAILED",
                                           "message": "observation quality gate not met", "checks": failed}}), 409
            now = utc_now().isoformat()
            conn.execute("UPDATE discovered_devices SET status='active',promoted_at=? WHERE id=?", (now, device_id))
            audit(conn, g.identity.name, "promote", "discovered_device", device_id, reason,
                  dict(row), {"status": "active", "override": bool(failed)})
        return ok({"id": device_id, "status": "active"})

    @app.post("/api/v1/discovered-devices/<device_id>/observe")
    @require_role("operator")
    def demote_discovered_device(device_id):
        body = request.get_json(silent=True) or {}
        reason = str(body.get("reason", "")).strip()
        if not reason:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "reason is required"}}), 400
        with db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM discovered_devices WHERE id=?", (device_id,)).fetchone()
            if not row:
                return jsonify({"error": {"code": "NOT_FOUND", "message": "device not found"}}), 404
            conn.execute("UPDATE discovered_devices SET status='observing' WHERE id=?", (device_id,))
            audit(conn, g.identity.name, "observe", "discovered_device", device_id, reason,
                  dict(row), {"status": "observing"})
        return ok({"id": device_id, "status": "observing"})

    def validate_playbook_definition(definition):
        PlaybookLoader._validate([definition])
        return definition

    @app.get("/api/v1/playbooks")
    @require_role("viewer")
    def managed_playbooks():
        clauses, params = [], []
        add_exact_filter(clauses, params, "enabled", "enabled")
        add_text_search(clauses, params, ("id", "name", "definition_json", "created_by", "updated_by"))
        add_time_filters(clauses, params, "updated_at")
        sql = ("SELECT id,name,enabled,priority,version,created_by,updated_by,created_at,updated_at,definition_json "
               "FROM managed_playbooks" + where_clause(clauses) + " ORDER BY priority DESC,id LIMIT ? OFFSET ?")
        try:
            size = min(max(int(request.args.get("page_size", 50)), 1), 200)
            page = max(int(request.args.get("page", 1)), 1)
        except (TypeError, ValueError):
            return jsonify({"error": {"code": "VALIDATION_ERROR",
                                      "message": "page and page_size must be integers"},
                            "meta": {"request_id": g.request_id}}), 400
        with db.connect() as conn:
            fetched = [dict(row) for row in conn.execute(sql, (*params, size + 1, (page - 1) * size))]
        rows = fetched[:size]
        for row in rows:
            row["definition"] = json.loads(row.pop("definition_json"))
        return ok(rows, page=page, page_size=size, has_more=len(fetched) > size)

    @app.put("/api/v1/playbooks/<playbook_id>")
    @require_role("operator")
    def put_playbook(playbook_id):
        body = request.get_json(silent=True) or {}
        definition = body.get("definition", body)
        definition["id"] = playbook_id
        try:
            validate_playbook_definition(definition)
        except Exception as exc:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": str(exc)}}), 400
        now = utc_now().isoformat()
        encoded = json.dumps(definition, ensure_ascii=False, separators=(",", ":"))
        with db.transaction(immediate=True) as conn:
            before = conn.execute("SELECT * FROM managed_playbooks WHERE id=?", (playbook_id,)).fetchone()
            conn.execute(
                """INSERT INTO managed_playbooks
                (id,name,enabled,priority,definition_json,created_by,updated_by,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,
                enabled=excluded.enabled,priority=excluded.priority,definition_json=excluded.definition_json,
                version=managed_playbooks.version+1,updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                (playbook_id, str(definition.get("name", playbook_id)), int(bool(definition.get("enabled", False))),
                 int(definition.get("priority", 0)), encoded, g.identity.name, g.identity.name, now, now),
            )
            audit(conn, g.identity.name, "update" if before else "create", "playbook", playbook_id,
                  str(body.get("reason", "剧本配置变更")), dict(before) if before else None, definition)
        return ok({"id": playbook_id, "updated_at": now})

    @app.post("/api/v1/playbooks/replay")
    @require_role("reviewer")
    def replay_playbook():
        body = request.get_json(silent=True) or {}
        definition = body.get("definition")
        if not definition and body.get("id"):
            with db.connect() as conn:
                row = conn.execute("SELECT definition_json FROM managed_playbooks WHERE id=?", (body["id"],)).fetchone()
            definition = json.loads(row["definition_json"]) if row else None
        if not definition:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "definition or id is required"}}), 400
        definition = {**definition, "enabled": True}
        try:
            validate_playbook_definition(definition)
        except Exception as exc:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": str(exc)}}), 400
        limit = min(max(int(body.get("limit", 1000)), 1), 10000)
        with db.connect() as conn:
            rows = [dict(row) for row in conn.execute(
                """SELECT e.*,d.decision,d.window_count,d.location FROM security_events e
                   JOIN policy_decisions d ON d.event_id=e.id ORDER BY e.occurred_at DESC LIMIT ?""", (limit,))]
        engine, matched = PlaybookEngine([definition]), []
        for row in rows:
            event = SecurityEvent(row["source"], row["device_id"], row["event_type"],
                                  datetime.fromisoformat(row["occurred_at"].replace("Z", "+00:00")),
                                  row["src_ip"], row["dst_ip"], row["category"], row["vendor_category"],
                                  row["severity"], json.loads(row["attributes_json"] or "{}"), id=row["id"])
            threat = event.attributes.get("threat_intel", {})
            hit = engine.match_auto_close(event, PlaybookContext(
                row["decision"], row["window_count"], row["location"],
                tuple(threat.get("tags", [])), int(threat.get("confidence", 0))))
            if hit and len(matched) < 50:
                matched.append({"event_id": event.id, "time": row["occurred_at"], "source": event.source,
                                "src_ip": event.src_ip, "category": event.category,
                                "severity": event.severity, "decision": row["decision"]})
        total_matches = 0
        for row in rows:
            event = SecurityEvent(row["source"], row["device_id"], row["event_type"],
                                  datetime.fromisoformat(row["occurred_at"].replace("Z", "+00:00")),
                                  row["src_ip"], row["dst_ip"], row["category"], row["vendor_category"],
                                  row["severity"], json.loads(row["attributes_json"] or "{}"), id=row["id"])
            threat = event.attributes.get("threat_intel", {})
            if engine.match_auto_close(event, PlaybookContext(row["decision"], row["window_count"], row["location"],
                                                               tuple(threat.get("tags", [])),
                                                               int(threat.get("confidence", 0)))):
                total_matches += 1
        return ok({"analysis_only": True, "scanned": len(rows), "matched": total_matches,
                   "match_rate": round(total_matches / len(rows), 4) if rows else 0, "samples": matched})

    @app.post("/api/v1/policies/simulate")
    @require_role("reviewer")
    def policy_simulate():
        body = request.get_json(silent=True) or {}
        required = ("source", "category", "src_ip")
        missing = [field for field in required if not body.get(field)]
        if missing:
            return jsonify({"error": {"code": "VALIDATION_ERROR",
                                      "message": "缺少字段: " + ", ".join(missing)}}), 400
        try:
            ipaddress.ip_address(str(body["src_ip"]))
            count = max(0, int(body.get("count", 1)))
            confidence = max(0, min(100, int(body.get("threat_confidence", 0))))
        except (ValueError, TypeError):
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "IP或数值字段无效"}}), 400
        loader = RuleLoader(settings)
        rules = loader.load()
        report = simulate_policy(
            rules, source=str(body["source"]), category=str(body["category"]),
            src_ip=str(body["src_ip"]), count=count, location=str(body.get("location", "UNKNOWN")),
            severity=str(body.get("severity", "high")), threat_tags=list(body.get("threat_tags", [])),
            threat_confidence=confidence, local_region=str(settings.section("policy").get("local_region", "")),
        )
        report["analysis_only"] = True
        report["rules_version"] = loader.version
        return ok(report)

    @app.get("/api/v1/whitelist")
    @require_role("viewer")
    def whitelist_list():
        with db.connect() as conn:
            local_rows = [dict(row) | {"origin": "local", "direction": "src"}
                          for row in conn.execute(
                              "SELECT id,network,reason,enabled,expires_at,created_at FROM whitelist_entries ORDER BY network"
                          )]
            firewall_rows = [dict(row) for row in conn.execute(
                """SELECT id,ip AS network,description AS reason,1 AS enabled,
                expires_at,inserted_at AS created_at,direction,protocol,age_time,
                hit_count,description,'firewall' AS origin,synced_at
                FROM firewall_list_entries WHERE list_type='whitelist'
                ORDER BY inserted_at DESC,direction,ip"""
            )]
        by_network = {row["network"]: row for row in local_rows if row["enabled"]}
        merged = list(local_rows)
        for firewall_row in firewall_rows:
            local = by_network.get(firewall_row["network"]) or by_network.get(firewall_row["network"] + "/32")
            if local and firewall_row["direction"] == "src":
                local.update({key: value for key, value in firewall_row.items()
                              if key not in {"id", "network", "enabled"}})
                local["origin"] = "local+firewall"
            else:
                merged.append(firewall_row)
        rows = filter_memory_rows(
            merged,
            text_fields=("network", "reason", "description", "origin", "direction"),
            exact_fields={
                "direction": ("direction",),
                "origin": ("origin",),
                "status": ("enabled",),
            },
            date_field="created_at",
        )
        ip_value = query_text("ip") or query_text("network")
        if ip_value:
            rows = [row for row in rows if ip_value in str(row.get("network", ""))]
        return paged_rows(rows)

    @app.post("/api/v1/whitelist")
    @require_role("operator")
    def whitelist_create():
        body = request.get_json(silent=True) or {}
        try:
            network = str(ipaddress.ip_network(str(body.get("network", "")), strict=False))
        except ValueError:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "network 必须是有效 IP 或 CIDR"}}), 400
        reason = str(body.get("reason", "")).strip()
        if not reason:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "必须填写 reason"}}), 400
        expires_at = body.get("expires_at")
        if expires_at:
            try:
                datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            except ValueError:
                return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "expires_at 格式无效"}}), 400
        try:
            with db.transaction(immediate=True) as conn:
                cursor = conn.execute(
                    "INSERT INTO whitelist_entries(network,reason,expires_at,created_at) VALUES(?,?,?,?)",
                    (network, reason, expires_at, utc_now().isoformat()),
                )
                entry_id = str(cursor.lastrowid)
                audit(conn, g.identity.name, "create", "whitelist", entry_id, reason, None,
                      {"network": network, "expires_at": expires_at})
        except sqlite3.IntegrityError:
            return jsonify({"error": {"code": "CONFLICT", "message": "该白名单网络已存在"}}), 409
        return ok({"id": entry_id, "network": network}), 201

    @app.delete("/api/v1/whitelist/<int:entry_id>")
    @require_role("operator")
    def whitelist_disable(entry_id):
        body = request.get_json(silent=True) or {}
        reason = str(body.get("reason", "")).strip()
        if not reason:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "必须填写 reason"}}), 400
        with db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM whitelist_entries WHERE id=?", (entry_id,)).fetchone()
            if not row:
                return jsonify({"error": {"code": "NOT_FOUND", "message": "白名单不存在"}}), 404
            conn.execute("UPDATE whitelist_entries SET enabled=0 WHERE id=?", (entry_id,))
            audit(conn, g.identity.name, "disable", "whitelist", str(entry_id), reason,
                  dict(row), {"enabled": False})
        return ok({"id": entry_id, "enabled": False})

    register_soc_features(app, db, settings, require_role, ok, paged_query, audit)
    return app


def run_server(application, host: str, port: int) -> None:
    if platform.system() == "Windows":
        # Flask's built-in server is intentionally development-only. Waitress
        # gives Windows installations a production WSGI server while Linux
        # services and containers continue to use Gunicorn.
        from waitress import serve

        threads = max(4, int(os.getenv("MONITOR_API_THREADS", "8")))
        serve(application, host=host, port=port, threads=threads)
        return
    application.run(host=host, port=port, threaded=True)


def main():
    configure_logging()
    settings, db, _ = build_runtime()
    api = settings.section("api")
    host = os.getenv("MONITOR_API_HOST", str(api.get("host", "127.0.0.1")))
    port = int(os.getenv("MONITOR_API_PORT", str(api.get("port", 5001))))
    run_server(create_app(settings, db), host, port)


if __name__ == "__main__":
    main()
