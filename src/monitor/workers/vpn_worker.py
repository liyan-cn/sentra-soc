from __future__ import annotations

import argparse
import glob
import hashlib
import logging
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone

from monitor.common.logging import configure_logging
from monitor.domain.models import utc_now
from monitor.plugins.builtins import create_registry
from monitor.sources import FileTailSource
from monitor.parsers.vendor_time import syslog_time
from .runtime import build_runtime, heartbeat, install_shutdown_handlers


LOGIN = re.compile(
    r"USERLOGINSUCC.*?User Name=(?P<user>[^,]+),.*?"
    r"Virtual IP=\s*(?P<vip>\d{1,3}(?:\.\d{1,3}){3}),.*?"
    r"Client IP=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I)
LOGOUT = re.compile(
    r"USERLOGOUT.*?User Name=(?P<user>[^,]+),.*?"
    r"Virtual IP=\s*(?P<vip>\d{1,3}(?:\.\d{1,3}){3}),.*?"
    r"Client IP=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}),.*?"
    r"Logout Reason=(?P<reason>[^)]+)", re.I)
VPN_ACTIVITY = re.compile(
    r"SESSION_(?:TEARDOWN|SETUP).*?SourceIP=(?P<vip>172\.16\.90\.\d+),.*?"
    r"UserName=(?P<user>[^,\s]+)", re.I)


def vpn_log_time(line: str) -> datetime:
    """Huawei syslog prefixes are local firewall time; store them as UTC."""
    return syslog_time(line, reference=utc_now())


def process_line(db, geo, device_id: str, line: str) -> None:
    if match := LOGIN.search(line):
        user, ip, vip = (value.strip() for value in match.group("user", "ip", "vip"))
        login_at = vpn_log_time(line).isoformat()
        key = hashlib.sha256(f"{device_id}:{user}:{ip}:{vip}:{login_at}".encode()).hexdigest()
        try:
            location = geo.lookup(ip) or "UNKNOWN"
        except Exception:
            location = "UNKNOWN"
        # Acquire the writer lock before the lookup.  A deferred SQLite
        # transaction that reads first cannot reliably upgrade while another
        # worker is writing and may fail immediately despite busy_timeout.
        with db.transaction(immediate=True, retries=8) as conn:
            if conn.execute("SELECT 1 FROM vpn_sessions WHERE session_key=?", (key,)).fetchone():
                return
            if conn.execute("""SELECT 1 FROM vpn_sessions WHERE username=? AND virtual_ip=?
                            AND session_origin='logout' AND logout_at>=? LIMIT 1""",
                            (user, vip, login_at)).fetchone():
                return
            previous = conn.execute(
                """SELECT id,client_ip,virtual_ip,login_at,location,last_seen_at,session_origin
                FROM vpn_sessions
                WHERE username=? AND status='active' ORDER BY login_at DESC LIMIT 1""", (user,)
            ).fetchone()
            if (previous and previous["client_ip"] == ip and previous["virtual_ip"] == vip
                    and previous["login_at"] == login_at):
                return
            # A live SESSION_* record may arrive before the separately stored
            # USERLOGINSUCC audit is tailed. Enrich that same live row instead
            # of replacing it with an older audit timestamp and making the
            # user appear offline during the next expiry pass.
            if (previous and not previous["client_ip"] and previous["virtual_ip"] == vip
                    and (previous["last_seen_at"] or previous["login_at"]) >= login_at):
                conn.execute(
                    """UPDATE vpn_sessions SET client_ip=?,location=?,login_at=?,
                    session_origin='audit+activity' WHERE id=?""",
                    (ip, location, login_at, previous["id"]),
                )
                return
            if previous and previous["login_at"] > login_at:
                return
            if previous:
                conn.execute(
                    "UPDATE vpn_sessions SET status='closed',logout_at=? WHERE username=? AND status='active'",
                    (login_at, user),
                )
            conn.execute(
                """INSERT INTO vpn_sessions(id,session_key,username,client_ip,virtual_ip,login_at,
                status,location,last_seen_at,session_origin)
                VALUES(?,?,?,?,?,?,'active',?,?, 'login')""",
                (str(uuid.uuid4()), key, user, ip, vip, login_at, location, login_at),
            )
            if previous and (previous["client_ip"] != ip or previous["virtual_ip"] != vip):
                from monitor.services.event_service import EventService
                reason = "不同公网 IP 登录，疑似账号共享" if previous["client_ip"] != ip else "重复登录且旧会话未正常注销"
                EventService._enqueue(
                    conn, "NOTIFY", "vpn", user,
                    {"content": (
                        f"VPN 账号重复登录\n用户: {user}\n原因: {reason}\n"
                        f"原会话: {previous['client_ip']} → {previous['virtual_ip']} ({previous['location']})\n"
                        f"新会话: {ip} → {vip} ({location})")},
                    f"vpn:duplicate:{user}:{key}", 60,
                )
    elif match := LOGOUT.search(line):
        now = vpn_log_time(line).isoformat()
        user, ip, vip = (value.strip() for value in match.group("user", "ip", "vip"))
        reason = match.group("reason").strip().lower()
        valid_logout = any(marker in reason for marker in
                           ("proactively goes offline", "timeout", "life cycle", "offline", "logout"))
        if not valid_logout:
            return
        with db.transaction(immediate=True, retries=8) as conn:
            conn.execute(
                """UPDATE vpn_sessions SET status='closed',logout_at=?,session_origin='logout'
                WHERE username=? AND (client_ip=? OR client_ip='') AND virtual_ip=?
                AND status='active' AND COALESCE(last_seen_at,login_at)<=?""",
                (now, user, ip, vip, now),
            )
            # Keep an idempotent logout fence even if its login was never received.
            # Automatic inactivity expiry is not an explicit logout fence.
            logout_key = hashlib.sha256(f"logout:{device_id}:{user}:{vip}:{ip}:{now}".encode()).hexdigest()
            conn.execute("""INSERT OR IGNORE INTO vpn_sessions
                         (id,session_key,username,client_ip,virtual_ip,login_at,logout_at,
                          status,location,last_seen_at,session_origin)
                         VALUES(?,?,?,?,?,?,?,'closed','UNKNOWN',?,'logout')""",
                         (str(uuid.uuid4()), logout_key, user, ip, vip, now, now, now))
    elif "SSLVPN" in line.upper() and (match := VPN_ACTIVITY.search(line)):
        user, vip = (value.strip() for value in match.group("user", "vip"))
        user = user.removesuffix(".")
        seen_at = vpn_log_time(line).isoformat()
        key = hashlib.sha256(f"activity:{device_id}:{user}:{vip}".encode()).hexdigest()
        with db.transaction(immediate=True, retries=8) as conn:
            if conn.execute("""SELECT 1 FROM vpn_sessions WHERE username=? AND virtual_ip=?
                            AND session_origin='logout' AND logout_at>=? LIMIT 1""",
                            (user, vip, seen_at)).fetchone():
                return
            login_session = conn.execute(
                """SELECT id,client_ip,location FROM vpn_sessions
                WHERE username=? AND virtual_ip=? AND status='active' AND client_ip<>''
                AND session_origin IN ('login','audit+activity')
                AND COALESCE(last_seen_at,login_at)>=? AND login_at<=?
                ORDER BY login_at DESC LIMIT 1""", (user, vip,
                (vpn_log_time(line)-timedelta(minutes=10)).isoformat(),seen_at)).fetchone()
            if login_session:
                conn.execute("UPDATE vpn_sessions SET last_seen_at=MAX(COALESCE(last_seen_at,login_at),?) WHERE id=?", (seen_at, login_session["id"]))
                return
            previous = conn.execute(
                """SELECT client_ip,location FROM vpn_sessions
                WHERE username=? AND virtual_ip=? AND client_ip<>'' AND status='active'
                AND session_origin IN ('login','audit+activity')
                AND COALESCE(last_seen_at,login_at)>=? AND login_at<=?
                ORDER BY login_at DESC LIMIT 1""", (user, vip,
                (vpn_log_time(line)-timedelta(minutes=10)).isoformat(),seen_at)).fetchone()
            public_ip = previous["client_ip"] if previous else ""
            location = previous["location"] if previous else "UNKNOWN"
            conn.execute(
                """INSERT INTO vpn_sessions(id,session_key,username,client_ip,virtual_ip,login_at,
                status,location,last_seen_at,session_origin)
                VALUES(?,?,?,?,?,?,'active',?,?,'activity')
                ON CONFLICT(session_key) DO UPDATE SET status='active',logout_at=NULL,session_origin='activity',
                client_ip=excluded.client_ip,
                location=excluded.location,
                last_seen_at=MAX(COALESCE(vpn_sessions.last_seen_at,vpn_sessions.login_at),excluded.last_seen_at)""",
                (str(uuid.uuid4()), key, user, public_ip, vip, seen_at, location, seen_at),
            )

def expire_stale_sessions(db, timeout_seconds: int) -> int:
    """Close every session that has no recent login or tunnel activity.

    Login sessions used to stay active forever when a logout audit record was
    missed.  Presence is now bounded by the same activity window, preventing a
    historical replay from appearing as a current online user.
    """
    cutoff = (utc_now() - timedelta(seconds=timeout_seconds)).isoformat()
    now = utc_now().isoformat()
    with db.transaction(immediate=True, retries=8) as conn:
        cursor = conn.execute(
            """UPDATE vpn_sessions SET status='closed',logout_at=?
            WHERE status='active' AND COALESCE(last_seen_at,login_at)<?""",
            (now, cutoff),
        )
        return cursor.rowcount


def expire_activity_sessions(db, timeout_seconds: int) -> int:
    """Compatibility wrapper for callers of the original helper."""
    return expire_stale_sessions(db, timeout_seconds)


def build_sources(db, device_id: str, device: dict) -> list[FileTailSource]:
    """Build independent tails for traffic activity and login audit records.

    Huawei commonly stores ``SESSION_*`` and ``USERLOGIN*`` records in
    different category directories. A shared checkpoint can skip one stream
    whenever the other file is newer, so each stream owns its own checkpoint.
    """
    sources = [FileTailSource(
        # Keep the legacy checkpoint id so an upgrade never replays years of
        # high-volume combined firewall logs.
        db, f"vpn:{device_id}", device["log_glob"],
        bool(device.get("start_at_end", True)),
        int(device.get("max_checkpoint_lag_seconds", 0)),
        max_checkpoint_lag_bytes=int(device.get("max_checkpoint_lag_bytes", 16 * 1024 * 1024)),
    )]
    audit_glob = str(device.get("login_audit_glob", "")).strip()
    if audit_glob and audit_glob != str(device["log_glob"]):
        sources.insert(0, FileTailSource(
            db, f"vpn:{device_id}:login-audit", audit_glob,
            start_at_end=False,
            max_checkpoint_lag_seconds=int(device.get("audit_checkpoint_lag_seconds", 86400)),
            start_at_latest_file=True,
        ))
    if not audit_glob:
        # Legacy VPN scripts use this sibling category directory. Keep an
        # independent tail even if it is not populated yet; no remote probing.
        legacy_glob = str(os.path.join(os.path.dirname(str(device['log_glob'])), '%%01SSLVPN', '*.log'))
        sources.insert(0, FileTailSource(db, f'vpn:{device_id}:login-audit', legacy_glob,
            start_at_end=False, start_at_latest_file=True, max_checkpoint_lag_seconds=86400))
    return sources


def reconcile_recent_audits(db, geo, device_id: str, pattern: str,
                            max_files: int = 3, max_bytes: int = 64 * 1024 * 1024) -> int:
    """Replay only recent login/logout audits from combined Huawei log files.

    Production rsyslog layouts often combine SSLVPN audits and session traffic
    into hourly files. The live checkpoint may already be past the login line
    after an upgrade, so scan a bounded tail of the newest rotations once at
    startup and feed only audit records through the idempotent session logic.
    """
    paths = sorted(
        (path for path in glob.glob(pattern) if os.path.isfile(path)),
        key=lambda path: (os.path.getmtime(path), path),
    )[-max(1, int(max_files)):]
    processed = 0
    for path in paths:
        size = os.path.getsize(path)
        with open(path, "rb") as stream:
            if size > max_bytes:
                stream.seek(size - max_bytes)
                stream.readline()  # discard a possibly partial first line
            for raw in stream:
                if not raw.endswith(b"\n"):
                    break
                if b"USERLOGINSUCC" not in raw.upper() and b"USERLOGOUT" not in raw.upper():
                    continue
                process_line(db, geo, device_id, raw.decode("utf-8", errors="replace"))
                processed += 1
    return processed


def reconcile_recent_activity(db, geo, device_id: str, pattern: str, timeout_seconds: int,
                              max_files: int = 3, max_bytes: int = 64 * 1024 * 1024) -> int:
    """Rebuild live VPN presence from a bounded tail after an outage/restart."""
    paths = sorted(
        (path for path in glob.glob(pattern) if os.path.isfile(path)),
        key=lambda path: (os.path.getmtime(path), path),
    )[-max(1, int(max_files)):]
    cutoff = utc_now() - timedelta(seconds=max(60, int(timeout_seconds)))
    processed = 0
    latest_activity = {}
    for path in paths:
        size = os.path.getsize(path)
        with open(path, "rb") as stream:
            if size > max_bytes:
                stream.seek(size - max_bytes)
                stream.readline()
            for raw in stream:
                if not raw.endswith(b"\n"):
                    break
                # Replay logout fences as well as activity, in file order.
                if b"USERLOGOUT" in raw.upper():
                    process_line(db, geo, device_id, raw.decode("utf-8", errors="replace"))
                    continue
                if b"SSLVPN" not in raw.upper() or not VPN_ACTIVITY.search(
                        raw.decode("utf-8", errors="replace")):
                    continue
                line = raw.decode("utf-8", errors="replace")
                seen_at = vpn_log_time(line)
                if seen_at < cutoff:
                    continue
                match = VPN_ACTIVITY.search(line)
                key = match.group('user', 'vip')
                if key not in latest_activity or seen_at > latest_activity[key][0]:
                    latest_activity[key] = (seen_at, line)
                processed += 1
    for _, line in sorted(latest_activity.values()):
        process_line(db, geo, device_id, line)
    return processed


def run(device_id: str):
    settings, db, _ = build_runtime()
    stopping = install_shutdown_handlers()
    device = settings.device(device_id)
    geo_cfg = settings.section("geolocation")
    geo = create_registry().load("geolocation", str(geo_cfg.get("provider", "ip_api")))(geo_cfg, database=db)
    sources = build_sources(db, device_id, device)
    activity_timeout = int(device.get("activity_timeout_seconds", 600))
    audit_pattern = str(device.get("login_audit_glob") or device["log_glob"])
    logger = logging.getLogger(f"vpn.{device_id}")
    heartbeat(db, f"vpn:{device_id}", "running", {"phase": "startup_reconciliation"})
    try:
        reconcile_recent_audits(
            db, geo, device_id, audit_pattern,
            int(device.get("audit_scan_files", 3)),
            int(device.get("audit_scan_bytes", 64 * 1024 * 1024)),
        )
    except sqlite3.OperationalError as exc:
        if "locked" not in str(exc).lower():
            raise
        logger.warning("database busy during recent VPN audit reconciliation; live tail will retry")
    try:
        reconcile_recent_activity(
            db, geo, device_id, str(device["log_glob"]), activity_timeout,
            int(device.get("activity_scan_files", 3)),
            int(device.get("activity_scan_bytes", 64 * 1024 * 1024)),
        )
    except sqlite3.OperationalError as exc:
        if "locked" not in str(exc).lower():
            raise
        logger.warning("database busy during recent VPN activity reconciliation; live tail will retry")
    # Reconcile stale rows before the first dashboard request after a restart.
    try:
        expire_stale_sessions(db, activity_timeout)
    except sqlite3.OperationalError as exc:
        if "locked" not in str(exc).lower():
            raise
        logger.warning("database busy during VPN startup expiry; continuing live tail")
    last_reconcile = time.monotonic()
    while not stopping.is_set():
        if time.monotonic() - last_reconcile >= 60:
            try:
                # A bounded live-tail pass prevents missed batches/backlog from
                # hiding an active user. Only the newest activity per user writes.
                reconcile_recent_activity(db, geo, device_id, str(device['log_glob']),
                                          activity_timeout, max_files=2, max_bytes=4*1024*1024)
            except sqlite3.OperationalError:
                logger.warning("recent VPN activity reconciliation deferred; retrying next minute")
            last_reconcile = time.monotonic()
        processed = False
        for source in sources:
            records = source.poll(int(device.get("batch_size", 100)))
            if not records:
                continue
            processed = True
            last_checkpoint = None
            for record in records:
                try:
                    process_line(db, geo, device_id, record.data)
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower():
                        raise
                    logger.warning("database busy; retaining VPN checkpoint for retry")
                    break
                last_checkpoint = record.checkpoint
            if last_checkpoint:
                try:
                    source.commit(last_checkpoint)
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower():
                        raise
                    logger.warning("database busy; VPN checkpoint will retry")
        source_health = [source.health() for source in sources]
        if not processed:
            try:
                expire_stale_sessions(db, activity_timeout)
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower():
                    raise
                logger.warning("database busy during VPN expiry; retrying next cycle")
            status = "ready" if any(item["status"] == "ready" for item in source_health) else "waiting"
            heartbeat(db, f"vpn:{device_id}", status, {"sources": source_health})
            stopping.wait(float(device.get("poll_seconds", 1)))
            continue
        try:
            expire_stale_sessions(db, activity_timeout)
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower():
                raise
            logger.warning("database busy during VPN expiry; retrying next cycle")
        heartbeat(db, f"vpn:{device_id}", details={"sources": source_health})


def main():
    configure_logging()
    cli = argparse.ArgumentParser()
    cli.add_argument("--device", required=True)
    run(cli.parse_args().device)


if __name__ == "__main__":
    main()
