from __future__ import annotations

import concurrent.futures
import re
import platform
import socket
import subprocess  # Used only with argument arrays and bounded execution; no shell.  # nosec B404
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from monitor.common.logging import configure_logging
from monitor.domain.models import utc_now
from .runtime import build_runtime, heartbeat, install_shutdown_handlers


def ping(ip: str, count: int = 4, timeout_seconds: int = 2,
         loss_threshold: float = 0.75) -> tuple[bool, float | None, float | None, str]:
    """Probe a host and return online, loss ratio, average latency and raw detail."""
    command = (["ping", "-n", str(count), "-w", str(timeout_seconds * 1000), ip]
               if platform.system() == "Windows" else
               ["ping", "-c", str(count), "-W", str(timeout_seconds), "-q", ip])
    try:
        result = subprocess.run(command, capture_output=True,
                                timeout=max(8, count * timeout_seconds + 4), text=True)  # Fixed executable and argument array, no shell; execution is bounded.  # nosec B603
        detail = (result.stdout + result.stderr)[-1000:]
        loss_match = re.search(r"([\d.]+)%\s*(?:packet )?loss", detail, re.I)
        if not loss_match:
            loss_match = re.search(r"\((\d+)%\s*loss\)", detail, re.I)
        loss = float(loss_match.group(1)) / 100 if loss_match else (0.0 if result.returncode == 0 else 1.0)
        latency = None
        unix_latency = re.search(r"=\s*[\d.]+/([\d.]+)/", detail)
        windows_latency = re.search(r"Average\s*=\s*(\d+)ms", detail, re.I)
        if unix_latency or windows_latency:
            latency = float((unix_latency or windows_latency).group(1))
        return loss < loss_threshold, loss, latency, detail
    except Exception as exc:
        return False, 1.0, None, str(exc)


def load_targets(settings, db=None) -> list[dict]:
    targets = list(settings.raw.get("hosts", []))
    hosts_file = settings.raw.get("hosts_file")
    if hosts_file:
        path = Path(hosts_file)
        if not path.is_absolute():
            path = settings.config_path.parent.parent / path
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        targets.extend(document.get("hosts", document if isinstance(document, list) else []))
    unique = {}
    for target in targets:
        if not target.get("enabled", True):
            continue
        unique[target["ip"]] = target
    if db is not None:
        with db.connect() as conn:
            rows = conn.execute(
                "SELECT ip,name,asset_type,site,attributes_json FROM soc_assets "
                "WHERE ip IS NOT NULL AND source='host-monitor'"
            ).fetchall()
        for row in rows:
            attributes = json.loads(row["attributes_json"] or "{}")
            if attributes.get("monitor_enabled", True) is False:
                # A Web-managed resource explicitly disabled in the database
                # must override a matching legacy YAML target.
                unique.pop(row["ip"], None)
                continue
            probe = attributes.get("probe", {}) if isinstance(attributes.get("probe"), dict) else {}
            unique[row["ip"]] = {
                "ip": row["ip"], "name": row["name"], "kind": row["asset_type"], "site": row["site"],
                "tags": attributes.get("tags", []), "probe": probe,
                "mac_address": attributes.get("mac_address", ""),
                "physical_host_ip": attributes.get("physical_host_ip", ""),
                "failures": int(probe.get("failures", 4)),
            }
    return list(unique.values())


def tcp_connect(ip: str, port: int, timeout_seconds: float = 2.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout_seconds):
            return True, f"TCP/{port} connected"
    except OSError as exc:
        return False, f"TCP/{port} {type(exc).__name__}: {exc}"


def probe_target(target: dict, count: int, timeout_seconds: int,
                 loss_threshold: float) -> tuple[bool, float | None, float | None, str]:
    result = probe_target_evidence(target, count, timeout_seconds, loss_threshold)
    return result["online"], result["loss_rate"], result["latency_ms"], result["detail"]


def probe_target_evidence(target: dict, count: int, timeout_seconds: int,
                          loss_threshold: float) -> dict:
    probe = target.get("probe", {}) if isinstance(target.get("probe"), dict) else {}
    methods = probe.get("methods", ["icmp"])
    methods = methods if isinstance(methods, list) and methods else ["icmp"]
    checks, loss, latency, details = [], None, None, []
    icmp_result, tcp_results = None, {}
    if "icmp" in methods:
        # The 2.0 monitor retried a failed Ping before counting the round as a
        # failure.  Preserve that tolerance without doubling the normal load:
        # the second attempt runs only when the first one failed.
        attempts = max(1, min(3, int(probe.get("icmp_attempts", 2))))
        online, detail = False, ""
        for _ in range(attempts):
            online, loss, latency, detail = ping(target["ip"], count, timeout_seconds, loss_threshold)
            if online:
                break
        checks.append(online)
        icmp_result = {"online": online, "loss_rate": loss, "latency_ms": latency}
        loss_text = f"丢包率 {loss * 100:.0f}%" if loss is not None else "丢包率未知"
        latency_text = f"，平均延迟 {latency:.2f}ms" if latency is not None else ""
        details.append(f"Ping={'成功' if online else '失败'}，{loss_text}{latency_text}")
    if "tcp" in methods:
        ports = probe.get("ports", [])
        for port in ports[:10]:
            online, detail = tcp_connect(target["ip"], int(port), float(probe.get("timeout_seconds", 2)))
            checks.append(online)
            tcp_results[str(int(port))] = online
            details.append(f"TCP/{int(port)}={'成功' if online else '失败'}")
    if not checks:
        return {"online": False, "loss_rate": loss, "latency_ms": latency,
                "detail": "未配置有效探测方式", "icmp": None, "tcp": {}}
    policy = str(probe.get("success_policy", "any"))
    return {"online": all(checks) if policy == "all" else any(checks),
            "loss_rate": loss, "latency_ms": latency, "detail": "；".join(details),
            "icmp": icmp_result, "tcp": tcp_results}


def should_notify_transition(previous_status: str | None, status: str) -> bool:
    """Notify only confirmed outage and recovery from a confirmed outage."""
    return ((status == "offline" and previous_status not in (None, "offline")) or
            (status == "online" and previous_status == "offline"))


def transition_state(previous_status: str | None, consecutive_failures: int,
                     consecutive_successes: int, probe_online: bool,
                     failure_rounds: int, recovery_rounds: int,
                     failure_elapsed_seconds: float | None = None,
                     failure_confirm_seconds: float | None = None) -> tuple[str, int, int]:
    """Apply independent outage and recovery confirmation windows.

    A single successful round no longer recovers a confirmed outage.  This is
    the key protection against repeated recovery notifications on unstable
    links.
    """
    if probe_online:
        if previous_status == "offline":
            successes = consecutive_successes + 1
            return ("online", 0, 0) if successes >= recovery_rounds else (
                "offline", consecutive_failures, successes)
        return "online", 0, 0
    failures = consecutive_failures + 1
    timed_confirmation = bool(failure_confirm_seconds and failure_confirm_seconds > 0)
    confirmed = ((failure_elapsed_seconds or 0) >= float(failure_confirm_seconds or 0)
                 if timed_confirmation else failures >= failure_rounds)
    if previous_status == "offline" or confirmed:
        return "offline", failures, 0
    return "degraded", failures, 0


def _elapsed_seconds(start: str | None, end: str) -> float:
    if not start:
        return 0
    try:
        return max(0.0, (datetime.fromisoformat(end.replace("Z", "+00:00")) -
                         datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds())
    except ValueError:
        return 0


def _display_time(value: str | None) -> str:
    if not value:
        return "--"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def _duration(start: str | None, end: str) -> str:
    try:
        delta = max(0, int((datetime.fromisoformat(end.replace("Z", "+00:00")) -
                            datetime.fromisoformat((start or end).replace("Z", "+00:00"))).total_seconds()))
    except ValueError:
        return "未知"
    hours, remainder = divmod(delta, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}小时{minutes}分{seconds}秒" if hours else f"{minutes}分{seconds}秒"


def format_transition_message(target: dict, status: str, checked_at: str,
                              outage_started_at: str | None, outage_notified_at: str | None,
                              evidence: dict, failure_rounds: int, recovery_rounds: int,
                              failure_confirm_minutes: int = 0) -> str:
    ip, name = target["ip"], target.get("name") or target["ip"]
    kind = target.get("kind", "vm")
    kind_label = {"site": "机房出口", "physical": "物理机", "virtual": "虚拟机",
                  "vm": "虚拟机", "network": "网络设备"}.get(kind, "服务器")
    icmp = evidence.get("icmp")
    if icmp is None:
        ping_line = "未启用"
    else:
        ping_line = "成功" if icmp["online"] else "失败"
        if icmp.get("loss_rate") is not None:
            ping_line += f"，丢包率 {icmp['loss_rate'] * 100:.0f}%"
        if icmp.get("latency_ms") is not None:
            ping_line += f"，平均延迟 {icmp['latency_ms']:.2f}ms"
    tcp = evidence.get("tcp", {})
    tcp_lines = []
    for port, online in tcp.items():
        label = "SSH 22" if port == "22" else "RDP 3389" if port == "3389" else f"TCP {port}"
        tcp_lines.append(f"【当前{label}】{'成功' if online else '失败'}")
    common = [f"【资源名称】{name}", f"【资源类型】{kind_label}", f"【IP地址】{ip}"]
    if kind in {"virtual", "vm"}:
        common.append(f"【归属物理机IP】{target.get('physical_host_ip') or '未配置'}")
    if target.get("mac_address"):
        common.append(f"【MAC地址】{target['mac_address']}")
    if target.get("site"):
        common.append(f"【所属机房】{target['site']}")
    if status == "offline":
        lines = [f"🔴 {kind_label}掉线告警", *common,
                 f"【故障开始】{_display_time(outage_started_at)}",
                 f"【告警时间】{_display_time(checked_at)}"]
    else:
        lines = [f"✅ {kind_label}恢复通知", *common,
                 f"【故障开始】{_display_time(outage_started_at)}",
                 f"【告警时间】{_display_time(outage_notified_at)}",
                 f"【恢复时间】{_display_time(checked_at)}",
                 f"【持续时间】{_duration(outage_started_at, checked_at)}"]
    lines.extend([f"【当前Ping】{ping_line}", *tcp_lines,
                  ((f"【告警条件】连续{failure_confirm_minutes}分钟所有已配置探测均失败"
                    if failure_confirm_minutes else
                    f"【告警条件】连续{failure_rounds}轮所有已配置探测均失败") if status == "offline"
                   else f"【恢复条件】连续{recovery_rounds}轮至少一项探测成功"),
                  "【监控系统】Monitor 3.0 主机在线监控"])
    return "\n".join(lines)


def run():
    settings, db, _ = build_runtime()
    stopping = install_shutdown_handlers()
    host_cfg = settings.section("host_monitor")
    count = int(host_cfg.get("ping_count", 4))
    timeout_seconds = int(host_cfg.get("ping_timeout_seconds", 2))
    loss_threshold = float(host_cfg.get("loss_threshold", 0.75))
    while not stopping.is_set():
        targets = load_targets(settings, db)
        now = utc_now().isoformat()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, max(1, len(targets)))) as pool:
            results = list(zip(targets, pool.map(
                lambda item: probe_target_evidence(item, count, timeout_seconds, loss_threshold), targets)))
        # Under heavy Syslog ingestion SQLite has a single writer.  Wait
        # through short collector bursts instead of letting a monitoring
        # cycle fail after the default retry window.
        with db.transaction(immediate=True, retries=8) as conn:
            for target, evidence in results:
                online = bool(evidence["online"])
                loss_rate, latency_ms, detail = evidence["loss_rate"], evidence["latency_ms"], evidence["detail"]
                ip, name = target["ip"], target.get("name", "")
                kind, site = target.get("kind", "vm"), target.get("site", "")
                old = conn.execute("""SELECT status,consecutive_failures,consecutive_successes,
                                   outage_started_at,outage_notified_at FROM hosts WHERE ip=?""", (ip,)).fetchone()
                previous_status = old["status"] if old else None
                failure_rounds = max(2, int(target.get("failures", 4)))
                recovery_rounds = max(2, int(target.get("probe", {}).get("recovery_successes", 2)))
                methods = target.get("probe", {}).get("methods", ["icmp"])
                confirm_minutes = (max(1, int(target.get("probe", {}).get(
                    "failure_confirm_minutes", host_cfg.get("icmp_failure_confirm_minutes", 30))))
                    if "icmp" in methods else 0)
                outage_started = old["outage_started_at"] if old else None
                outage_notified = old["outage_notified_at"] if old else None
                if not online and not outage_started:
                    outage_started = now
                status, failures, successes = transition_state(
                    previous_status, int(old["consecutive_failures"] or 0) if old else 0,
                    int(old["consecutive_successes"] or 0) if old else 0, online,
                    failure_rounds, recovery_rounds,
                    _elapsed_seconds(outage_started, now), confirm_minutes * 60 if confirm_minutes else None)
                notify_transition = should_notify_transition(previous_status, status)
                if notify_transition and status == "offline":
                    outage_notified = now
                conn.execute(
                    """INSERT INTO hosts(ip,name,kind,site,status,consecutive_failures,consecutive_successes,
                    last_checked_at,last_changed_at,last_notified_at,outage_started_at,outage_notified_at,last_probe_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name,
                    kind=excluded.kind,site=excluded.site,status=excluded.status,
                    consecutive_failures=excluded.consecutive_failures,last_checked_at=excluded.last_checked_at,
                    consecutive_successes=excluded.consecutive_successes,
                    last_changed_at=CASE WHEN hosts.status<>excluded.status THEN excluded.last_changed_at ELSE hosts.last_changed_at END,
                    last_notified_at=CASE WHEN ? THEN excluded.last_notified_at ELSE hosts.last_notified_at END,
                    outage_started_at=excluded.outage_started_at,outage_notified_at=excluded.outage_notified_at,
                    last_probe_json=excluded.last_probe_json""",
                    (ip, name, kind, site, status, failures, successes, now, now,
                     now if notify_transition else None, outage_started, outage_notified,
                     json.dumps(evidence, ensure_ascii=False), int(notify_transition)),
                )
                conn.execute("""INSERT INTO host_checks(ip,checked_at,online,loss_rate,latency_ms,error)
                             VALUES(?,?,?,?,?,?)""",
                             (ip, now, int(online), loss_rate, latency_ms, None if online else detail))
                if notify_transition:
                    from monitor.services.event_service import EventService
                    content = format_transition_message(target, status, now, outage_started,
                                                        outage_notified, evidence,
                                                        failure_rounds, recovery_rounds, confirm_minutes)
                    EventService._enqueue(conn, "NOTIFY", "host", ip,
                                          {"content": content},
                                          f"host:{ip}:{status}:{outage_started or now}", 50)
                if status == "online":
                    conn.execute("UPDATE hosts SET outage_started_at=NULL,outage_notified_at=NULL WHERE ip=?", (ip,))
        heartbeat(db, "host-worker", details={"targets": len(targets)})
        stopping.wait(float(settings.section("workers").get("host_interval_seconds", 120)))


def main():
    configure_logging()
    run()


if __name__ == "__main__":
    main()
