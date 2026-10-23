from __future__ import annotations

import csv
import concurrent.futures
import io
import ipaddress
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import requests
from flask import Response, g, jsonify, request

from monitor.workers.host_worker import ping, tcp_connect
from monitor.infrastructure.notification_settings import encrypt_secret
from monitor.common.retention import effective_retention, RETENTION_DEFAULTS
from monitor.services.asset_discovery_jobs import DiscoveryJobs, validate_network


WORKSPACE_ID = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
SEVERITIES = {"low", "medium", "high", "critical"}


def register_soc_features(app, db, settings, require_role, ok, paged_query, audit):
    def workspace_id():
        return (request.headers.get("X-Workspace-ID") or request.args.get("workspace_id") or "default").strip()

    def workspace_exists(value: str) -> bool:
        with db.connect() as conn:
            return conn.execute("SELECT 1 FROM workspaces WHERE id=? AND status='active'", (value,)).fetchone() is not None

    def invalid(message: str, status: int = 400):
        return jsonify({"error": {"code": "VALIDATION_ERROR", "message": message},
                        "meta": {"request_id": g.request_id}}), status

    def body_json():
        return request.get_json(silent=True) or {}

    @app.get('/api/v1/data/backup-status')
    @require_role('admin')
    def data_backup_status():
        from monitor.infrastructure.backups import backup_status
        status=backup_status(db)
        with db.connect() as conn:
            rows=conn.execute("SELECT name,value_json FROM runtime_settings WHERE name IN ('backup_last_rehearsal','backup_run')").fetchall()
        for row in rows:
            try:
                value=json.loads(row['value_json'])
                if not isinstance(value,dict):raise ValueError('invalid status')
                if row['name']=='backup_run' and value.get('status')=='running':
                    checked=datetime.fromisoformat(value['checked_at'])
                    if (datetime.now(timezone.utc)-checked).total_seconds()>90*60:
                        value={**value,'status':'interrupted','error':'备份任务超过90分钟未完成，请检查服务状态'}
            except (ValueError,TypeError,KeyError):
                value={'status':'invalid','error':'备份运行记录异常，请检查任务日志'}
            status[row['name']]={key:value[key] for key in ('status','error','checked_at','integrity','live_database_modified','phase','phase_label','started_at','progress_percent','backup_verified') if key in value}
        return ok(status)

    def now():
        return datetime.now(timezone.utc).isoformat()

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

    @app.get("/api/v1/workspaces")
    @require_role("viewer")
    def workspaces_list():
        clauses, params = [], []
        add_like_filter(clauses, params, "name", "q")
        add_exact_filter(clauses, params, "mode", "mode")
        add_exact_filter(clauses, params, "status", "status")
        return paged_query("SELECT * FROM workspaces" + where_clause(clauses) + " ORDER BY created_at",  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
                           tuple(params))

    @app.post("/api/v1/workspaces")
    @require_role("admin")
    def workspaces_create():
        body = body_json()
        item_id = str(body.get("id", "")).strip().lower()
        name = str(body.get("name", "")).strip()
        mode = str(body.get("mode", "single"))
        if not WORKSPACE_ID.fullmatch(item_id) or not name or mode not in {"single", "centralized", "delegated"}:
            return invalid("工作空间 ID、名称或运营模式无效")
        timestamp = now()
        try:
            with db.transaction(immediate=True) as conn:
                conn.execute("""INSERT INTO workspaces(id,name,description,mode,region,status,created_by,created_at,updated_at)
                              VALUES(?,?,?,?,?,'active',?,?,?)""",
                             (item_id, name, str(body.get("description", ""))[:500], mode,
                              str(body.get("region", ""))[:100], g.identity.name, timestamp, timestamp))
                audit(conn, g.identity.name, "create", "workspace", item_id,
                      str(body.get("reason", "创建工作空间")), None, body)
        except Exception as exc:
            if "UNIQUE" in str(exc).upper():
                return invalid("工作空间 ID 已存在", 409)
            raise
        return ok({"id": item_id, "status": "active"})

    @app.get("/api/v1/workspaces/<item_id>/summary")
    @require_role("viewer")
    def workspace_summary(item_id):
        if not workspace_exists(item_id):
            return invalid("工作空间不存在", 404)
        with db.connect() as conn:
            data = {
                "assets": conn.execute("SELECT COUNT(*) FROM soc_assets WHERE workspace_id=?", (item_id,)).fetchone()[0],
                "assets_online": conn.execute("SELECT COUNT(*) FROM soc_assets WHERE workspace_id=? AND status='online'", (item_id,)).fetchone()[0],
                "open_alerts": conn.execute("SELECT COUNT(*) FROM soc_alerts WHERE workspace_id=? AND status IN ('open','investigating')", (item_id,)).fetchone()[0],
                "critical_alerts": conn.execute("SELECT COUNT(*) FROM soc_alerts WHERE workspace_id=? AND severity='critical' AND status<>'closed'", (item_id,)).fetchone()[0],
                "open_vulnerabilities": conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE workspace_id=? AND status='open'", (item_id,)).fetchone()[0],
                "failed_baselines": conn.execute("SELECT COUNT(*) FROM baseline_findings WHERE workspace_id=? AND status='failed'", (item_id,)).fetchone()[0],
                "enabled_models": conn.execute("SELECT COUNT(*) FROM threat_models WHERE workspace_id=? AND enabled=1", (item_id,)).fetchone()[0],
                "reports": conn.execute("SELECT COUNT(*) FROM operation_reports WHERE workspace_id=?", (item_id,)).fetchone()[0],
            }
        return ok(data)

    @app.get("/api/v1/workspace-delegations")
    @require_role("viewer")
    def delegations_list():
        return paged_query("""SELECT d.*,s.name AS source_name,t.name AS target_name
                           FROM workspace_delegations d JOIN workspaces s ON s.id=d.source_workspace_id
                           JOIN workspaces t ON t.id=d.target_workspace_id ORDER BY d.created_at DESC""")

    @app.post("/api/v1/workspace-delegations")
    @require_role("admin")
    def delegations_create():
        body = body_json(); source = str(body.get("source_workspace_id", "")); target = str(body.get("target_workspace_id", ""))
        kind = str(body.get("delegation_type", ""))
        if source == target or kind not in {"data", "operation"} or not workspace_exists(source) or not workspace_exists(target):
            return invalid("委托源、目标或委托类型无效")
        item_id, timestamp = str(uuid.uuid4()), now()
        with db.transaction(immediate=True) as conn:
            conn.execute("""INSERT INTO workspace_delegations(id,source_workspace_id,target_workspace_id,
                          delegation_type,status,created_by,created_at) VALUES(?,?,?,?,'active',?,?)""",
                         (item_id, source, target, kind, g.identity.name, timestamp))
            audit(conn, g.identity.name, "create", "workspace_delegation", item_id,
                  str(body.get("reason", "创建工作空间委托")), None, body)
        return ok({"id": item_id, "status": "active"})

    @app.get("/api/v1/assets")
    @require_role("viewer")
    def assets_list():
        clauses, params = ["workspace_id=?"], [workspace_id()]
        add_like_filter(clauses, params, "ip", "ip")
        add_like_filter(clauses, params, "name", "name")
        add_like_filter(clauses, params, "site", "site")
        add_exact_filter(clauses, params, "asset_type", "asset_type")
        add_exact_filter(clauses, params, "status", "status")
        add_exact_filter(clauses, params, "criticality", "criticality")
        add_like_filter(clauses, params, "source", "source")
        add_text_search(clauses, params, ("name", "ip", "site", "asset_type", "source", "attributes_json"))
        return paged_query("SELECT * FROM soc_assets" + where_clause(clauses) +  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
                           " ORDER BY criticality DESC,updated_at DESC", tuple(params))

    @app.post("/api/v1/assets/network-inventory")
    @require_role("admin")
    def assets_network_inventory_import():
        body = body_json()
        rows = body.get("rows", [])
        if not isinstance(rows, list) or not rows or len(rows) > 1000:
            return invalid("网络资产清单必须包含 1-1000 条记录")
        timestamp = now(); normalized = []
        for item in rows:
            if not isinstance(item, dict):
                return invalid("网络资产清单记录格式无效")
            try:
                ip = str(ipaddress.ip_address(str(item.get("ip", "")).strip()))
                parent = (str(ipaddress.ip_address(str(item["physical_host_ip"]).strip()))
                          if item.get("physical_host_ip") else "")
            except ValueError:
                return invalid("网络资产清单中存在无效 IP")
            compact_mac = re.sub(r"[^0-9a-fA-F]", "", str(item.get("mac_address", "")))
            if compact_mac and len(compact_mac) != 12:
                return invalid(f"{ip} 的 MAC 地址格式无效")
            mac = ":".join(compact_mac[i:i + 2] for i in range(0, 12, 2)).lower() if compact_mac else ""
            normalized.append({
                "ip": ip, "mac_address": mac, "physical_host_ip": parent,
                "vlan": str(item.get("vlan", ""))[:30], "interface": str(item.get("interface", ""))[:100],
                "arp_type": str(item.get("arp_type", ""))[:30],
                "source": str(item.get("source", body.get("source", "manual-network-inventory")))[:200],
                "observed_at": str(item.get("observed_at", body.get("observed_at", timestamp)))[:40],
            })
        matched = 0; matched_ips = set()
        with db.transaction(immediate=True) as conn:
            for item in normalized:
                conn.execute("""INSERT INTO asset_network_inventory(ip,mac_address,physical_host_ip,vlan,interface,
                             arp_type,source,observed_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)
                             ON CONFLICT(ip) DO UPDATE SET
                             mac_address=CASE WHEN excluded.mac_address<>'' THEN excluded.mac_address ELSE mac_address END,
                             physical_host_ip=CASE WHEN excluded.physical_host_ip<>'' THEN excluded.physical_host_ip ELSE physical_host_ip END,
                             vlan=CASE WHEN excluded.vlan<>'' THEN excluded.vlan ELSE vlan END,
                             interface=CASE WHEN excluded.interface<>'' THEN excluded.interface ELSE interface END,
                             arp_type=CASE WHEN excluded.arp_type<>'' THEN excluded.arp_type ELSE arp_type END,
                             source=excluded.source,observed_at=excluded.observed_at,updated_at=excluded.updated_at""",
                             (item["ip"], item["mac_address"], item["physical_host_ip"], item["vlan"],
                              item["interface"], item["arp_type"], item["source"], item["observed_at"], timestamp))
                assets = conn.execute("SELECT id,attributes_json FROM soc_assets WHERE ip=?", (item["ip"],)).fetchall()
                if assets:
                    matched_ips.add(item["ip"])
                for asset in assets:
                    try:
                        attrs = json.loads(asset["attributes_json"] or "{}")
                    except json.JSONDecodeError:
                        attrs = {}
                    if item["mac_address"]:
                        attrs["mac_address"] = item["mac_address"]
                    if item["physical_host_ip"]:
                        attrs["physical_host_ip"] = item["physical_host_ip"]
                    attrs["network_inventory_source"] = item["source"]
                    attrs["network_inventory_observed_at"] = item["observed_at"]
                    conn.execute("UPDATE soc_assets SET attributes_json=?,updated_at=? WHERE id=?",
                                 (json.dumps(attrs, ensure_ascii=False), timestamp, asset["id"]))
                    matched += 1
            audit(conn, g.identity.name, "import", "asset_network_inventory", "bulk",
                  str(body.get("reason", "导入现网 ARP/MAC 与虚拟机宿主关系")), None,
                  {"records": len(normalized), "matched_assets": matched})
        return ok({"imported": len(normalized), "matched_assets": matched,
                   "unmatched_inventory": len(normalized) - len(matched_ips)})

    @app.post("/api/v1/assets")
    @require_role("operator")
    def assets_create():
        body = body_json(); ws = workspace_id()
        name = str(body.get("name", "")).strip(); asset_type = str(body.get("asset_type", "")).strip()
        criticality = str(body.get("criticality", "medium"))
        try:
            ip = str(ipaddress.ip_address(str(body["ip"]))) if body.get("ip") else None
        except ValueError:
            return invalid("资产 IP 地址无效")
        if not workspace_exists(ws) or not name or not asset_type or criticality not in SEVERITIES:
            return invalid("资产名称、类型、重要性或工作空间无效")
        item_id, timestamp = str(uuid.uuid4()), now()
        attributes = body.get("attributes", {}) if isinstance(body.get("attributes", {}), dict) else {}
        tags = body.get("tags", attributes.get("tags", []))
        if isinstance(tags, str):
            tags = [item.strip() for item in re.split(r"[,，]", tags) if item.strip()]
        attributes["tags"] = list(dict.fromkeys(str(item)[:50] for item in tags))[:20]
        compact_mac = re.sub(r"[^0-9a-fA-F]", "", str(body.get("mac_address", attributes.get("mac_address", ""))))
        if compact_mac and len(compact_mac) != 12:
            return invalid("MAC 地址格式无效")
        if compact_mac:
            attributes["mac_address"] = ":".join(compact_mac[i:i + 2] for i in range(0, 12, 2)).lower()
        try:
            parent_value = str(body.get("physical_host_ip", attributes.get("physical_host_ip", ""))).strip()
            parent_ip = str(ipaddress.ip_address(parent_value)) if parent_value else ""
        except ValueError:
            return invalid("归属物理机 IP 无效")
        if parent_ip:
            attributes["physical_host_ip"] = parent_ip
        monitor_enabled = bool(body.get("monitor_enabled", attributes.get("monitor_enabled", False)))
        probe = body.get("probe", attributes.get("probe", {}))
        probe = probe if isinstance(probe, dict) else {}
        methods = [item for item in probe.get("methods", ["icmp"]) if item in {"icmp", "tcp"}]
        try:
            ports = sorted(set(int(item) for item in probe.get("ports", [])))
        except (TypeError, ValueError):
            return invalid("TCP 探测端口格式无效")
        if any(port < 1 or port > 65535 for port in ports) or len(ports) > 10:
            return invalid("TCP 探测端口必须在 1-65535，最多 10 个")
        if monitor_enabled and (not ip or not methods or ("tcp" in methods and not ports)):
            return invalid("启用在线监控时必须配置有效 IP 和探测方式")
        probe.update({"methods": methods, "ports": ports,
                      "success_policy": "all" if probe.get("success_policy") == "all" else "any",
                      "failures": max(2, min(20, int(probe.get("failures", 4))))})
        attributes.update({"monitor_enabled": monitor_enabled, "probe": probe})
        if monitor_enabled:
            result = _probe_asset(ip, probe)
            if not result["online"]:
                return invalid("连通性校验未通过，未启用持续监控：" + result["detail"], 409)
        with db.transaction(immediate=True) as conn:
            try:
                conn.execute("""INSERT INTO soc_assets(id,workspace_id,name,asset_type,ip,hostname,site,owner,criticality,
                          status,source,attributes_json,last_seen_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (item_id, ws, name, asset_type, ip, body.get("hostname"),
                          str(body.get("site", ""))[:200], str(body.get("owner", ""))[:200], criticality,
                          "online" if monitor_enabled else str(body.get("status", "unknown"))[:30],
                          "host-monitor" if monitor_enabled else str(body.get("source", "manual"))[:100],
                          json.dumps(attributes, ensure_ascii=False), body.get("last_seen_at"), timestamp, timestamp))
            except Exception as exc:
                if "UNIQUE" in str(exc).upper():
                    return invalid("该工作空间中已存在相同 IP 的资产", 409)
                raise
            if monitor_enabled:
                conn.execute("""INSERT INTO hosts(ip,name,kind,site,status,consecutive_failures,last_checked_at,last_changed_at)
                    VALUES(?,?,?,?, 'online',0,?,?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name,
                    kind=excluded.kind,site=excluded.site""",
                    (ip, name, asset_type, str(body.get("site", ""))[:200], timestamp, timestamp))
            audit(conn, g.identity.name, "create", "asset", item_id, str(body.get("reason", "新增资产")), None, body)
        return ok({"id": item_id})

    @app.put("/api/v1/assets/<item_id>")
    @require_role("operator")
    def assets_update(item_id):
        body = body_json(); ws = workspace_id()
        name, asset_type = str(body.get("name", "")).strip(), str(body.get("asset_type", "")).strip()
        criticality = str(body.get("criticality", "medium"))
        if not name or not asset_type or criticality not in SEVERITIES:
            return invalid("资产名称、类型或重要性无效")
        with db.connect() as conn:
            before = conn.execute("SELECT * FROM soc_assets WHERE id=? AND workspace_id=?", (item_id, ws)).fetchone()
        if not before:
            return invalid("资产不存在", 404)
        attrs = json.loads(before["attributes_json"] or "{}")
        tags = body.get("tags", attrs.get("tags", [])); tags = [x.strip() for x in re.split(r"[,，]", tags)] if isinstance(tags, str) else list(tags)
        attrs["tags"] = list(dict.fromkeys(str(x)[:50] for x in tags if str(x).strip()))[:20]
        compact_mac = re.sub(r"[^0-9a-fA-F]", "", str(body.get("mac_address", attrs.get("mac_address", ""))))
        if compact_mac and len(compact_mac) != 12:
            return invalid("MAC 地址格式无效")
        if compact_mac:
            attrs["mac_address"] = ":".join(compact_mac[i:i + 2] for i in range(0, 12, 2)).lower()
        elif "mac_address" in body:
            attrs.pop("mac_address", None)
        try:
            parent_value = str(body.get("physical_host_ip", attrs.get("physical_host_ip", ""))).strip()
            parent_ip = str(ipaddress.ip_address(parent_value)) if parent_value else ""
        except ValueError:
            return invalid("归属物理机 IP 无效")
        if parent_ip:
            attrs["physical_host_ip"] = parent_ip
        elif "physical_host_ip" in body:
            attrs.pop("physical_host_ip", None)
        monitor_enabled = bool(body.get(
            "monitor_enabled", attrs.get("monitor_enabled", before["source"] == "host-monitor")
        ))
        probe = body.get("probe", attrs.get("probe", {}))
        probe = probe if isinstance(probe, dict) else {}
        methods = list(dict.fromkeys(item for item in probe.get("methods", ["icmp"])
                                     if item in {"icmp", "tcp"}))
        try:
            ports = sorted(set(int(item) for item in probe.get("ports", [])))
            failures = max(2, min(20, int(probe.get("failures", 4))))
            timeout = max(1, min(15, float(probe.get("timeout_seconds", 5))))
        except (TypeError, ValueError):
            return invalid("TCP 探测端口或超时时间无效")
        if any(port < 1 or port > 65535 for port in ports) or len(ports) > 10:
            return invalid("TCP 探测端口必须在 1-65535，最多 10 个")
        if monitor_enabled and (not before["ip"] or not methods or ("tcp" in methods and not ports)):
            return invalid("启用在线监控时必须配置有效 IP 和探测方式")
        probe = {**probe, "methods": methods, "ports": ports,
                 "success_policy": "all" if probe.get("success_policy") == "all" else "any",
                 "failures": failures, "timeout_seconds": timeout}
        attrs.update({"monitor_enabled": monitor_enabled, "probe": probe})
        probe_result = _probe_asset(before["ip"], probe) if monitor_enabled else None
        if probe_result and not probe_result["online"]:
            return invalid("连通性校验未通过，未更新持续监控：" + probe_result["detail"], 409)
        with db.transaction(immediate=True) as conn:
            current = conn.execute("SELECT * FROM soc_assets WHERE id=? AND workspace_id=?", (item_id, ws)).fetchone()
            if not current:
                return invalid("资产不存在", 404)
            timestamp = now()
            source = "host-monitor" if monitor_enabled else current["source"]
            status = "online" if monitor_enabled else current["status"]
            conn.execute("""UPDATE soc_assets SET name=?,asset_type=?,hostname=?,site=?,owner=?,criticality=?,
                         status=?,source=?,attributes_json=?,last_seen_at=CASE WHEN ? THEN ? ELSE last_seen_at END,
                         updated_at=? WHERE id=?""",
                         (name, asset_type, body.get("hostname", current["hostname"]), str(body.get("site", current["site"] or ""))[:200],
                          str(body.get("owner", current["owner"] or ""))[:200], criticality,
                          status, source, json.dumps(attrs, ensure_ascii=False), int(monitor_enabled), timestamp,
                          timestamp, item_id))
            if monitor_enabled:
                conn.execute("""INSERT INTO hosts(ip,name,kind,site,status,consecutive_failures,last_checked_at,last_changed_at)
                    VALUES(?,?,?,?, 'online',0,?,?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name,
                    kind=excluded.kind,site=excluded.site,status='online',consecutive_failures=0,
                    last_checked_at=excluded.last_checked_at,
                    last_changed_at=CASE WHEN hosts.status<>'online' THEN excluded.last_changed_at ELSE hosts.last_changed_at END""",
                    (current["ip"], name, asset_type, str(body.get("site", current["site"] or ""))[:200],
                     timestamp, timestamp))
            elif current["source"] == "host-monitor":
                conn.execute("UPDATE hosts SET name=?,kind=?,site=? WHERE ip=?",
                             (name, asset_type, str(body.get("site", current["site"] or ""))[:200], current["ip"]))
            audit(conn, g.identity.name, "update", "asset", item_id, str(body.get("reason", "编辑资产")),
                  dict(current), {"name": name, "asset_type": asset_type,
                                 "monitor_enabled": monitor_enabled, "probe": probe})
        return ok({"id": item_id, "monitor_enabled": monitor_enabled,
                   "probe": probe_result or {"online": False, "detail": "monitor disabled"}})

    def _probe_asset(ip: str, probe: dict) -> dict:
        results, details, tcp_results = [], [], {}
        icmp_result = None
        if "icmp" in probe.get("methods", []):
            online, loss, latency, detail = ping(ip, count=2, timeout_seconds=1, loss_threshold=.75)
            if not online:
                online, loss, latency, detail = ping(ip, count=2, timeout_seconds=1, loss_threshold=.75)
            results.append(online); details.append(f"ICMP={'成功' if online else '失败'}" +
                                                   (f" {latency:.1f}ms" if latency is not None else ""))
            icmp_result = {"online": online, "loss_rate": loss, "latency_ms": latency}
        if "tcp" in probe.get("methods", []):
            for port in probe.get("ports", []):
                online, detail = tcp_connect(ip, port, float(probe.get("timeout_seconds", 5)))
                results.append(online); details.append(detail)
                tcp_results[str(port)] = online
        online = all(results) if probe.get("success_policy") == "all" else any(results)
        return {"online": bool(results) and online, "detail": "; ".join(details),
                "icmp": icmp_result, "tcp": tcp_results}

    @app.post("/api/v1/assets/probe")
    @require_role("operator")
    def assets_probe():
        body = body_json()
        try:
            ip = str(ipaddress.ip_address(str(body.get("ip", ""))))
            ports = [int(item) for item in body.get("ports", [])]
        except (ValueError, TypeError):
            return invalid("IP 或 TCP 端口无效")
        methods = [item for item in body.get("methods", []) if item in {"icmp", "tcp"}]
        if not methods or any(port < 1 or port > 65535 for port in ports):
            return invalid("至少选择一种探测方式，并使用有效端口")
        return ok(_probe_asset(ip, {"methods": methods, "ports": ports,
                                    "success_policy": body.get("success_policy", "any")}))

    def save_discovery(conn,body,ws,actor,result):
        created=existing=0;stamp=now();site=str(body.get('site',''))[:200]
        tags=body.get('tags',['自动探测'])
        if isinstance(tags,str):tags=[x.strip() for x in re.split('[,，]',tags) if x.strip()]
        for item in result['assets']:
            if conn.execute('SELECT id FROM soc_assets WHERE workspace_id=? AND ip=?',(ws,item['ip'])).fetchone():
                existing+=1;continue
            attrs={'tags':list(dict.fromkeys([*tags,item['os_guess']]))[:20],'os_guess':item['os_guess'],
                'discovered_network':body['network'],'monitor_enabled':True,
                'probe':{**body['_probe'],'failures':4,'recovery_successes':2,'icmp_attempts':2}}
            name=f"{item['os_guess']}主机 {item['ip']}"
            conn.execute('''INSERT INTO soc_assets(id,workspace_id,name,asset_type,ip,site,criticality,status,source,attributes_json,last_seen_at,created_at,updated_at)
                VALUES(?,?,?,'server',?,?,'medium','online','host-monitor',?,?,?,?)''',
                (str(uuid.uuid4()),ws,name,item['ip'],site,json.dumps(attrs,ensure_ascii=False),stamp,stamp,stamp))
            conn.execute("INSERT INTO hosts(ip,name,kind,site,status,consecutive_failures,last_checked_at,last_changed_at) VALUES(?,?,'server',?,'online',0,?,?) ON CONFLICT(ip) DO NOTHING",(item['ip'],name,site,stamp,stamp))
            created+=1
        result={**result,'created':created,'existing':existing}
        conn.execute('''INSERT INTO audit_logs(actor,action,target_type,target_id,reason,after_json,created_at)
            VALUES(?,'discover','asset_network',?,?,?,?)''',(actor,body['network'],str(body.get('reason','Web网段探测')),json.dumps(result),stamp))
        return result

    discovery_jobs=DiscoveryJobs(db,_probe_asset,save_discovery)
    app.extensions['discovery_jobs']=discovery_jobs

    @app.get('/api/v1/assets/discovery-jobs/<job_id>')
    @require_role('operator')
    def discovery_job_status(job_id):
        job=discovery_jobs.get(job_id,workspace_id())
        return ok(job) if job else invalid('任务不存在',404)

    @app.post('/api/v1/assets/discovery-jobs/<job_id>/retry-save')
    @require_role('operator')
    def discovery_job_retry(job_id):
        try:return ok(discovery_jobs.retry(job_id,workspace_id()))
        except ValueError as exc:return invalid(str(exc),409)

    @app.post("/api/v1/assets/discover")
    @require_role("operator")
    def assets_discover():
        body = body_json(); ws = workspace_id()
        if not workspace_exists(ws):return invalid('工作空间不存在',404)
        try:
            network = validate_network(body.get('network',''))
        except ValueError:
            return invalid("请输入 RFC1918 内网 /24 或更小网段，最多256个地址")
        if body.get('async'):
            try:return ok(discovery_jobs.submit(body,ws,g.identity.name)),202
            except (ValueError,TypeError) as exc:return invalid(str(exc))
        if network.version != 4 or not network.is_private:
            return invalid("自动探测仅允许 RFC1918 内部 IPv4 网段")
        hosts = [str(ip) for ip in network.hosts()]
        if not hosts or len(hosts) > 256:
            return invalid("单次探测最多 256 个主机地址，请使用 /24 或更小网段")
        ping_enabled = bool(body.get("ping", True))
        ports = []
        if body.get("ssh", True): ports.append(22)
        if body.get("rdp", True): ports.append(3389)
        methods = (["icmp"] if ping_enabled else []) + (["tcp"] if ports else [])
        if not methods:
            return invalid("请至少选择 Ping、SSH 22 或 RDP 3389 中的一项")
        try:
            workers = max(1, min(64, int(body.get("workers", 32))))
            timeout = max(.5, min(5.0, float(body.get("timeout_seconds", 1.5))))
        except (TypeError, ValueError):
            return invalid("探测并发数或超时时间无效")
        probe = {"methods": methods, "ports": ports, "success_policy": "any",
                 "timeout_seconds": timeout}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
            results = list(pool.map(lambda ip: (ip, _probe_asset(ip, probe)), hosts))
        online = []
        for ip, result in results:
            if not result["online"]:
                continue
            tcp = result.get("tcp", {})
            os_guess = "Windows" if tcp.get("3389") else "Linux" if tcp.get("22") else "未知"
            online.append({"ip": ip, "os_guess": os_guess, "detail": result["detail"]})
        created, existing = 0, 0
        timestamp = now(); site = str(body.get("site", ""))[:200]
        tags = body.get("tags", ["自动探测"])
        if isinstance(tags, str):
            tags = [item.strip() for item in re.split(r"[,，]", tags) if item.strip()]
        with db.transaction(immediate=True, retries=8) as conn:
            for item in online:
                row = conn.execute("SELECT id FROM soc_assets WHERE workspace_id=? AND ip=?", (ws, item["ip"])).fetchone()
                if row:
                    existing += 1
                    continue
                item_id = str(uuid.uuid4())
                attributes = {"tags": list(dict.fromkeys([*tags, item["os_guess"]]))[:20],
                              "os_guess": item["os_guess"], "discovered_network": str(network),
                              "monitor_enabled": True,
                              "probe": {**probe, "failures": 4, "recovery_successes": 2,
                                        "icmp_attempts": 2}}
                name = f"{item['os_guess']}主机 {item['ip']}" if item["os_guess"] != "未知" else f"待识别主机 {item['ip']}"
                conn.execute("""INSERT INTO soc_assets(id,workspace_id,name,asset_type,ip,site,criticality,
                             status,source,attributes_json,last_seen_at,created_at,updated_at)
                             VALUES(?,?,?,?,?,?,'medium','online','host-monitor',?,?,?,?)""",
                             (item_id, ws, name, "server", item["ip"], site,
                              json.dumps(attributes, ensure_ascii=False), timestamp, timestamp, timestamp))
                conn.execute("""INSERT INTO hosts(ip,name,kind,site,status,consecutive_failures,last_checked_at,last_changed_at)
                             VALUES(?,?, 'server',?,'online',0,?,?) ON CONFLICT(ip) DO NOTHING""",
                             (item["ip"], name, site, timestamp, timestamp))
                created += 1
            audit(conn, g.identity.name, "discover", "asset_network", str(network),
                  str(body.get("reason", "Web 网段自动探测")), None,
                  {"scanned": len(hosts), "online": len(online), "created": created, "existing": existing,
                   "methods": methods, "ports": ports})
        return ok({"network": str(network), "scanned": len(hosts), "online": len(online),
                   "created": created, "existing": existing, "assets": online})

    @app.get("/api/v1/assets/template.csv")
    @require_role("viewer")
    def assets_template():
        output = io.StringIO(); writer = csv.writer(output)
        writer.writerow(["name", "ip", "asset_type", "site", "criticality", "tags",
                         "monitor_enabled", "probe_methods", "tcp_ports"])
        writer.writerow(["示例业务服务器", "192.168.10.10", "virtual", "97机房", "medium",
                         "业务系统,数据库", "false", "icmp", ""])
        return Response("\ufeff" + output.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=monitor3-assets-template.csv"})

    @app.post("/api/v1/assets/import")
    @require_role("operator")
    def assets_import():
        upload = request.files.get("file")
        if not upload:
            return invalid("请选择 CSV 资产模板文件")
        try:
            rows = list(csv.DictReader(io.StringIO(upload.read().decode("utf-8-sig"))))
        except (UnicodeDecodeError, csv.Error):
            return invalid("CSV 文件编码或格式无效")
        if len(rows) > 2000:
            return invalid("单次最多导入 2000 条资产")
        created, errors = 0, []
        timestamp, ws = now(), workspace_id()
        with db.transaction(immediate=True) as conn:
            for index, row in enumerate(rows, 2):
                try:
                    ip = str(ipaddress.ip_address(row.get("ip", ""))) if row.get("ip") else None
                    name = str(row.get("name", "")).strip(); asset_type = str(row.get("asset_type", "")).strip()
                    if not name or not asset_type:
                        raise ValueError("名称和类型不能为空")
                    tags = [item.strip() for item in re.split(r"[,，]", row.get("tags", "")) if item.strip()]
                    attributes = {"tags": tags[:20], "monitor_enabled": False,
                                  "imported_probe": {"methods": row.get("probe_methods", "icmp").split(","),
                                                     "ports": row.get("tcp_ports", "").split(",")}}
                    conn.execute("""INSERT INTO soc_assets(id,workspace_id,name,asset_type,ip,site,criticality,
                        status,source,attributes_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'unknown','template-import',?,?,?)""",
                        (str(uuid.uuid4()), ws, name, asset_type, ip, row.get("site", "")[:200],
                         row.get("criticality", "medium"), json.dumps(attributes, ensure_ascii=False), timestamp, timestamp))
                    created += 1
                except Exception as exc:
                    errors.append({"row": index, "error": str(exc)[:160]})
        return ok({"created": created, "failed": len(errors), "errors": errors[:50]})

    @app.get("/api/v1/vulnerabilities")
    @require_role("viewer")
    def vulnerabilities_list():
        clauses, params = ["v.workspace_id=?"], [workspace_id()]
        add_like_filter(clauses, params, "a.ip", "ip")
        add_like_filter(clauses, params, "a.name", "asset")
        add_exact_filter(clauses, params, "v.severity", "severity")
        add_exact_filter(clauses, params, "v.status", "status")
        add_time_filters(clauses, params, "v.discovered_at")
        add_text_search(clauses, params, ("v.cve", "v.title", "a.name", "a.ip", "v.source"))
        return paged_query("""SELECT v.*,a.name AS asset_name,a.ip AS asset_ip FROM vulnerabilities v
                           LEFT JOIN soc_assets a ON a.id=v.asset_id""" + where_clause(clauses) +  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
                           """ ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
                           v.discovered_at DESC""", tuple(params))

    @app.post("/api/v1/vulnerabilities")
    @require_role("operator")
    def vulnerabilities_create():
        body = body_json(); ws = workspace_id(); title = str(body.get("title", "")).strip()
        severity = str(body.get("severity", "medium"))
        if not title or severity not in SEVERITIES or not workspace_exists(ws):
            return invalid("漏洞标题、等级或工作空间无效")
        item_id, timestamp = str(uuid.uuid4()), now()
        with db.transaction(immediate=True) as conn:
            conn.execute("""INSERT INTO vulnerabilities(id,workspace_id,asset_id,cve,title,severity,cvss,status,
                          remediation,source,discovered_at,due_at,updated_at) VALUES(?,?,?,?,?,?,?,'open',?,?,?,?,?)""",
                         (item_id, ws, body.get("asset_id"), body.get("cve"), title, severity, body.get("cvss"),
                          str(body.get("remediation", ""))[:2000], str(body.get("source", "manual"))[:100],
                          timestamp, body.get("due_at"), timestamp))
            audit(conn, g.identity.name, "create", "vulnerability", item_id,
                  str(body.get("reason", "录入漏洞")), None, body)
        return ok({"id": item_id})

    @app.get("/api/v1/baselines")
    @require_role("viewer")
    def baselines_list():
        clauses, params = ["b.workspace_id=?"], [workspace_id()]
        add_like_filter(clauses, params, "a.ip", "ip")
        add_like_filter(clauses, params, "a.name", "asset")
        add_exact_filter(clauses, params, "b.severity", "severity")
        add_exact_filter(clauses, params, "b.status", "status")
        add_like_filter(clauses, params, "b.standard", "standard")
        add_time_filters(clauses, params, "b.checked_at")
        add_text_search(clauses, params, ("b.title", "b.standard", "b.control_id", "a.name", "a.ip"))
        return paged_query("""SELECT b.*,a.name AS asset_name,a.ip AS asset_ip FROM baseline_findings b
                           LEFT JOIN soc_assets a ON a.id=b.asset_id""" + where_clause(clauses) +  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
                           " ORDER BY b.checked_at DESC", tuple(params))

    @app.post("/api/v1/baselines")
    @require_role("operator")
    def baselines_create():
        body = body_json(); ws = workspace_id()
        severity, status = str(body.get("severity", "medium")), str(body.get("status", "failed"))
        if (not all(str(body.get(key, "")).strip() for key in ("standard", "control_id", "title"))
                or severity not in SEVERITIES or status not in {"passed", "failed", "waived", "unknown"}
                or not workspace_exists(ws)):
            return invalid("合规标准、检查项和标题不能为空")
        item_id, timestamp = str(uuid.uuid4()), now()
        with db.transaction(immediate=True) as conn:
            conn.execute("""INSERT INTO baseline_findings(id,workspace_id,asset_id,standard,control_id,title,severity,
                          status,evidence,recommendation,checked_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (item_id, ws, body.get("asset_id"), str(body["standard"])[:100], str(body["control_id"])[:100],
                          str(body["title"])[:300], severity, status,
                          str(body.get("evidence", ""))[:4000], str(body.get("recommendation", ""))[:4000], timestamp, timestamp))
            audit(conn, g.identity.name, "create", "baseline", item_id,
                  str(body.get("reason", "录入基线检查结果")), None, body)
        return ok({"id": item_id})

    @app.get("/api/v1/alerts")
    @require_role("viewer")
    def alerts_list():
        clauses, params = ["a.workspace_id=?"], [workspace_id()]
        add_time_filters(clauses, params, "a.occurred_at")
        add_like_filter(clauses, params, "a.src_ip", "src_ip")
        add_like_filter(clauses, params, "a.dst_ip", "dst_ip")
        add_like_filter(clauses, params, "a.source", "source")
        add_like_filter(clauses, params, "a.title", "title")
        add_exact_filter(clauses, params, "a.severity", "severity")
        add_exact_filter(clauses, params, "a.status", "status")
        add_like_filter(clauses, params, "a.mitre_technique", "mitre")
        add_text_search(clauses, params, ("a.title", "a.source", "a.src_ip", "a.dst_ip", "a.mitre_tactic", "a.mitre_technique"))
        return paged_query(
            """SELECT a.*,
            COALESCE(
              NULLIF(json_extract(e.attributes_json,'$.source_location'),''),
              NULLIF(json_extract(e.attributes_json,'$.src_location'),''),
              NULLIF((SELECT d.location FROM policy_decisions d
                      WHERE d.event_id=a.event_id ORDER BY d.created_at DESC LIMIT 1),''),
              'UNKNOWN') AS source_location
            FROM soc_alerts a LEFT JOIN security_events e ON e.id=a.event_id
            """ + where_clause(clauses) + " ORDER BY a.occurred_at DESC", tuple(params)  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
        )

    @app.post("/api/v1/alerts/batch-status")
    @require_role("operator")
    def alerts_batch_status():
        body = body_json(); status = str(body.get("status", "")); reason = str(body.get("reason", "")).strip()
        ids = list(dict.fromkeys(str(item) for item in body.get("ids", []) if str(item).strip()))
        if status not in {"open", "investigating", "closed", "suppressed"} or not reason:
            return invalid("告警状态和操作原因无效")
        if not ids or len(ids) > 200:
            return invalid("请选择 1-200 条告警")
        placeholders = ",".join("?" for _ in ids)
        with db.transaction(immediate=True) as conn:
            rows = [dict(row) for row in conn.execute(
                f"SELECT * FROM soc_alerts WHERE workspace_id=? AND id IN ({placeholders})",  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
                (workspace_id(), *ids),
            )]
            timestamp = now()
            for before in rows:
                conn.execute("UPDATE soc_alerts SET status=?,assignee=?,resolution=?,updated_at=? WHERE id=?",
                             (status, g.identity.name, reason[:1000], timestamp, before["id"]))
                audit(conn, g.identity.name, "status", "alert", before["id"], reason,
                      before, {"status": status, "batch": True})
        return ok({"requested": len(ids), "updated": len(rows), "status": status})

    @app.post("/api/v1/alerts/<item_id>/status")
    @require_role("operator")
    def alert_status(item_id):
        body = body_json(); status = str(body.get("status", ""))
        if status not in {"open", "investigating", "closed", "suppressed"} or not str(body.get("reason", "")).strip():
            return invalid("告警状态和操作原因无效")
        with db.transaction(immediate=True) as conn:
            before = conn.execute("SELECT * FROM soc_alerts WHERE id=? AND workspace_id=?", (item_id, workspace_id())).fetchone()
            if not before:
                return invalid("告警不存在", 404)
            conn.execute("UPDATE soc_alerts SET status=?,assignee=?,resolution=?,updated_at=? WHERE id=?",
                         (status, g.identity.name, str(body.get("reason"))[:1000], now(), item_id))
            audit(conn, g.identity.name, "status", "alert", item_id, str(body["reason"]), dict(before), {"status": status})
        return ok({"id": item_id, "status": status})

    @app.get("/api/v1/threat-models")
    @require_role("viewer")
    def threat_models_list():
        clauses, params = ["workspace_id=?"], [workspace_id()]
        add_exact_filter(clauses, params, "enabled", "enabled")
        add_exact_filter(clauses, params, "severity", "severity")
        add_like_filter(clauses, params, "mitre_technique", "mitre")
        add_text_search(clauses, params, ("name", "description", "mitre_tactic", "mitre_technique"))
        return paged_query("SELECT * FROM threat_models" + where_clause(clauses) +  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
                           " ORDER BY enabled DESC,name", tuple(params))

    @app.post("/api/v1/threat-models")
    @require_role("operator")
    def threat_models_create():
        body = body_json(); ws = workspace_id(); name = str(body.get("name", "")).strip()
        query = body.get("query", {})
        if not name or not isinstance(query, dict) or not query or not workspace_exists(ws):
            return invalid("模型名称、规则或工作空间无效")
        item_id, timestamp = str(uuid.uuid4()), now()
        with db.transaction(immediate=True) as conn:
            conn.execute("""INSERT INTO threat_models(id,workspace_id,name,description,severity,mitre_tactic,
                          mitre_technique,query_json,enabled,created_by,created_at,updated_at)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (item_id, ws, name, str(body.get("description", ""))[:1000], str(body.get("severity", "high")),
                          str(body.get("mitre_tactic", ""))[:100], str(body.get("mitre_technique", ""))[:100],
                          json.dumps(query, ensure_ascii=False), 1 if body.get("enabled") else 0,
                          g.identity.name, timestamp, timestamp))
            audit(conn, g.identity.name, "create", "threat_model", item_id,
                  str(body.get("reason", "创建威胁模型")), None, body)
        return ok({"id": item_id})

    @app.post("/api/v1/threat-models/<item_id>/toggle")
    @require_role("operator")
    def threat_model_toggle(item_id):
        body = body_json()
        if not isinstance(body.get("enabled"), bool) or not str(body.get("reason", "")).strip():
            return invalid("必须明确启用状态和操作原因")
        with db.transaction(immediate=True) as conn:
            before = conn.execute("SELECT * FROM threat_models WHERE id=? AND workspace_id=?", (item_id, workspace_id())).fetchone()
            if not before: return invalid("威胁模型不存在", 404)
            conn.execute("UPDATE threat_models SET enabled=?,updated_at=? WHERE id=?", (1 if body["enabled"] else 0, now(), item_id))
            audit(conn, g.identity.name, "toggle", "threat_model", item_id, body["reason"], dict(before), {"enabled": body["enabled"]})
        return ok({"id": item_id, "enabled": body["enabled"]})

    @app.get("/api/v1/mitre/coverage")
    @require_role("viewer")
    def mitre_coverage():
        with db.connect() as conn:
            rows = [dict(row) for row in conn.execute("""SELECT mitre_tactic,mitre_technique,COUNT(*) alert_count,
                     COUNT(DISTINCT src_ip) source_count FROM soc_alerts WHERE workspace_id=? AND mitre_technique<>''
                     GROUP BY mitre_tactic,mitre_technique ORDER BY alert_count DESC""", (workspace_id(),))]
        return ok(rows)

    @app.get("/api/v1/governance/frameworks")
    @require_role("viewer")
    def governance_frameworks():
        return paged_query("SELECT * FROM governance_frameworks WHERE workspace_id=? ORDER BY name", (workspace_id(),))

    @app.get("/api/v1/data/connectors")
    @require_role("viewer")
    def connectors_list():
        return paged_query("SELECT * FROM data_connectors WHERE workspace_id=? ORDER BY direction,name", (workspace_id(),))

    @app.post("/api/v1/data/connectors")
    @require_role("admin")
    def connectors_create():
        body = body_json(); ws = workspace_id(); kind = str(body.get("connector_type", "")); direction = str(body.get("direction", ""))
        name = str(body.get("name", "")).strip(); config = body.get("config", {})
        if kind not in {"syslog", "api", "logstash", "kafka", "webhook", "file"} or direction not in {"ingest", "delivery"}:
            return invalid("连接器类型或方向无效")
        if not name or not isinstance(config, dict) or not workspace_exists(ws):
            return invalid("连接器名称、配置或工作空间无效")
        forbidden = {key for key in config if any(word in key.casefold() for word in ("password", "secret", "token", "api_key"))}
        if forbidden:
            return invalid("连接器配置不得直接保存密钥，请使用环境变量引用")
        item_id, timestamp = str(uuid.uuid4()), now()
        with db.transaction(immediate=True) as conn:
            conn.execute("""INSERT INTO data_connectors(id,workspace_id,name,connector_type,direction,status,
                          config_json,created_by,created_at,updated_at) VALUES(?,?,?,?,?,'disabled',?,?,?,?)""",
                         (item_id, ws, name, kind, direction, json.dumps(config, ensure_ascii=False),
                          g.identity.name, timestamp, timestamp))
            audit(conn, g.identity.name, "create", "data_connector", item_id,
                  str(body.get("reason", "创建数据连接器")), None, {"type": kind, "direction": direction})
        return ok({"id": item_id, "status": "disabled"})

    def report_metrics(ws: str, start: str, end: str):
        with db.connect() as conn:
            events = conn.execute("""SELECT COUNT(*) total,COUNT(DISTINCT src_ip) sources FROM soc_alerts
                                  WHERE workspace_id=? AND occurred_at>=? AND occurred_at<?""", (ws, start, end)).fetchone()
            top = [dict(row) for row in conn.execute("""SELECT title,COUNT(*) count FROM soc_alerts
                   WHERE workspace_id=? AND occurred_at>=? AND occurred_at<? GROUP BY title ORDER BY count DESC LIMIT 10""",
                                                        (ws, start, end))]
            severity = [dict(row) for row in conn.execute("""SELECT severity,COUNT(*) count FROM soc_alerts
                        WHERE workspace_id=? AND occurred_at>=? AND occurred_at<? GROUP BY severity""", (ws, start, end))]
            closed = conn.execute("""SELECT COUNT(*) FROM soc_alerts WHERE workspace_id=? AND occurred_at>=? AND
                                  occurred_at<? AND status='closed'""", (ws, start, end)).fetchone()[0]
        return {"events": events["total"], "unique_sources": events["sources"], "closed": closed,
                "top_threats": top, "severity": severity}

    @app.get("/api/v1/reports")
    @require_role("viewer")
    def reports_list():
        clauses, params = ["workspace_id=?"], [workspace_id()]
        add_exact_filter(clauses, params, "report_type", "report_type")
        add_like_filter(clauses, params, "created_by", "created_by")
        add_time_filters(clauses, params, "created_at")
        add_text_search(clauses, params, ("title", "summary", "created_by", "report_type"))
        return paged_query("SELECT * FROM operation_reports" + where_clause(clauses) +  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
                           " ORDER BY created_at DESC", tuple(params))

    @app.get("/api/v1/report-templates")
    @require_role("viewer")
    def report_templates_list():
        clauses, params = ["workspace_id=?"], [workspace_id()]
        add_exact_filter(clauses, params, "report_type", "report_type")
        add_text_search(clauses, params, ("name", "description", "report_type"))
        return paged_query("SELECT * FROM report_templates" + where_clause(clauses) +  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
                           " ORDER BY is_default DESC,name", tuple(params))

    @app.post("/api/v1/report-templates")
    @require_role("operator")
    def report_templates_create():
        body = body_json(); ws = workspace_id(); name = str(body.get("name", "")).strip(); kind = str(body.get("report_type", "daily")); sections = body.get("sections", [])
        if not name or kind not in {"daily","weekly","monthly","custom"} or not isinstance(sections, list) or not 2 <= len(sections) <= 12:
            return invalid("模板名称、周期或章节无效")
        item_id, timestamp = str(uuid.uuid4()), now()
        with db.transaction(immediate=True) as conn:
            conn.execute("INSERT INTO report_templates(id,workspace_id,name,description,report_type,sections_json,is_default,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,0,?,?,?)",
                         (item_id, ws, name, str(body.get("description", ""))[:500], kind, json.dumps([str(x)[:100] for x in sections], ensure_ascii=False), g.identity.name, timestamp, timestamp))
            audit(conn, g.identity.name, "create", "report_template", item_id, str(body.get("reason", "创建报告模板")), None, body)
        return ok({"id": item_id})

    @app.post("/api/v1/reports/generate")
    @require_role("operator")
    def reports_generate():
        body = body_json(); ws = workspace_id(); kind = str(body.get("report_type", "daily"))
        days = {"daily": 1, "weekly": 7, "monthly": 30, "custom": 1}.get(kind)
        if days is None or not workspace_exists(ws):
            return invalid("报告类型或工作空间无效")
        end_dt = datetime.now(timezone.utc); start_dt = end_dt - timedelta(days=days)
        if kind == "custom" and body.get("period_start") and body.get("period_end"):
            try:
                start_dt, end_dt = datetime.fromisoformat(body["period_start"]), datetime.fromisoformat(body["period_end"])
            except (TypeError, ValueError):
                return invalid("自定义报告时间范围无效")
            if start_dt >= end_dt:
                return invalid("报告开始时间必须早于结束时间")
        metrics = report_metrics(ws, start_dt.isoformat(), end_dt.isoformat())
        template_id = str(body.get("template_id", "")).strip()
        template = None
        if template_id:
            with db.connect() as conn:
                template = conn.execute("SELECT * FROM report_templates WHERE id=? AND workspace_id=?", (template_id, ws)).fetchone()
            if not template:
                return invalid("报告模板不存在", 404)
            if template["report_type"] != kind and template["report_type"] != "custom":
                return invalid("报告模板周期与报告类型不匹配")
        title = str(body.get("title") or (template["name"] if template else f"{kind} 安全运营报告"))[:300]
        summary = f"期间汇聚 {metrics['events']} 条告警，涉及 {metrics['unique_sources']} 个来源，已关闭 {metrics['closed']} 条。"
        if template:
            metrics["template"] = {"id": template["id"], "name": template["name"], "sections": json.loads(template["sections_json"] or "[]")}
        item_id, timestamp = str(uuid.uuid4()), now()
        with db.transaction(immediate=True) as conn:
            conn.execute("""INSERT INTO operation_reports(id,workspace_id,report_type,period_start,period_end,title,
                          summary,content_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                         (item_id, ws, kind, start_dt.isoformat(), end_dt.isoformat(), title, summary,
                          json.dumps(metrics, ensure_ascii=False), g.identity.name, timestamp))
            audit(conn, g.identity.name, "generate", "operation_report", item_id,
                  str(body.get("reason", "生成运营报告")), None, {"report_type": kind})
        return ok({"id": item_id, "title": title, "summary": summary, "content": metrics})

    @app.get("/api/v1/data/export/events.csv")
    @require_role("operator")
    def export_events():
        ws = workspace_id()
        try:
            limit = min(max(int(request.args.get("limit", 5000)), 1), 10000)
        except (TypeError, ValueError):
            return invalid("导出条数必须为整数")
        with db.connect() as conn:
            rows = conn.execute("""SELECT occurred_at,title,source,src_ip,dst_ip,severity,status,mitre_tactic,mitre_technique
                                 FROM soc_alerts WHERE workspace_id=? ORDER BY occurred_at DESC LIMIT ?""", (ws, limit)).fetchall()
            audit(conn, g.identity.name, "export", "security_data", ws,
                  f"导出安全告警 CSV，最多 {limit} 条", None, {"rows": len(rows)})
        output = io.StringIO(); writer = csv.writer(output)
        writer.writerow(["时间", "告警", "数据源", "源IP", "目的IP", "等级", "状态", "MITRE战术", "MITRE技术"])
        writer.writerows([tuple(row) for row in rows])
        return Response("\ufeff" + output.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=monitor3-alerts.csv"})

    @app.get("/api/v1/data/retention")
    @require_role("viewer")
    def retention_status():
        with db.connect() as conn:
            return ok(effective_retention(settings, conn))

    @app.put("/api/v1/data/retention")
    @require_role("admin")
    def retention_update():
        body = body_json()
        if not isinstance(body, dict):
            return invalid("请求必须是对象")
        values = body.get("retention")
        reason = str(body.get("reason", "")).strip()
        if not isinstance(values, dict) or not values or set(values) - set(RETENTION_DEFAULTS):
            return invalid("请选择支持的数据保留项目")
        if any(type(v) is not int or not 1 <= v <= 3650 for v in values.values()):
            return invalid("保留天数须为 1–3650 的整数")
        if not reason or len(reason) > 500:
            return invalid("请填写 1–500 字的修改原因")
        with db.transaction(immediate=True) as conn:
            before = effective_retention(settings, conn)
            if any(v < before[k] for k, v in values.items()) and body.get("confirm_shortening") is not True:
                return invalid("缩短期限将由维护任务清理过期数据，请确认后保存", 409)
            after = {k: values.get(k, before[k]) for k in RETENTION_DEFAULTS}
            conn.execute("""INSERT INTO runtime_settings(name,value_json,updated_at) VALUES('retention',?,?)
                         ON CONFLICT(name) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at""",
                         (json.dumps(after), now()))
            audit(conn, g.identity.name, "configure", "retention", "global", reason,
                  {k: before[k] for k in RETENTION_DEFAULTS}, after)
        return ok({**after, "effective": "next_maintenance_cycle"})

    @app.get("/api/v1/notification-channels")
    @require_role("admin")
    def notification_channels_list():
        with db.connect() as conn:
            rows = conn.execute("""SELECT id,provider,name,enabled,config_json,
                                  CASE WHEN secret_encrypted<>'' THEN 1 ELSE 0 END has_secret,updated_at
                                  FROM notification_channels WHERE workspace_id=? ORDER BY provider""",
                                (workspace_id(),)).fetchall()
        data = []
        for row in rows:
            item = dict(row); item["config"] = json.loads(item.pop("config_json") or "{}")
            data.append(item)
        return ok(data)

    @app.put("/api/v1/notification-channels/<provider>")
    @require_role("admin")
    def notification_channel_update(provider):
        if provider not in {"wechat", "smtp", "sms_webhook"}:
            return invalid("不支持的通知渠道")
        body = body_json(); ws = workspace_id(); config = body.get("config", {})
        if not isinstance(config, dict):
            return invalid("通知渠道配置格式无效")
        secret_fields = {"wechat": ("webhook",), "smtp": ("password",),
                         "sms_webhook": ("url", "token")}[provider]
        secret = {key: str(body.get(key, "")).strip() for key in secret_fields if str(body.get(key, "")).strip()}
        if provider == "smtp":
            config = {key: config.get(key) for key in ("host", "port", "username", "from", "to", "ssl", "starttls", "subject") if key in config}
            recipients = config.get("to", [])
            if isinstance(recipients, str): config["to"] = [x.strip() for x in re.split(r"[,，;；]", recipients) if x.strip()]
        if provider == "sms_webhook":
            recipients = config.get("recipients", [])
            if isinstance(recipients, str): config["recipients"] = [x.strip() for x in re.split(r"[,，;；]", recipients) if x.strip()]
        if provider == "wechat":
            config = {"timeout_seconds": max(1, min(15, int(config.get("timeout_seconds", 5))))}
        timestamp = now(); item_id = f"notify-{ws}-{provider}"
        with db.transaction(immediate=True) as conn:
            before = conn.execute("SELECT * FROM notification_channels WHERE workspace_id=? AND provider=?",
                                  (ws, provider)).fetchone()
            ciphertext = (encrypt_secret(settings, secret) if secret else
                          (before["secret_encrypted"] if before else ""))
            conn.execute("""INSERT INTO notification_channels(id,workspace_id,provider,name,enabled,config_json,
                         secret_encrypted,updated_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)
                         ON CONFLICT(workspace_id,provider) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,
                         config_json=excluded.config_json,secret_encrypted=excluded.secret_encrypted,
                         updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                         (item_id, ws, provider, str(body.get("name", provider))[:100], int(bool(body.get("enabled"))),
                          json.dumps(config, ensure_ascii=False), ciphertext, g.identity.name, timestamp, timestamp))
            audit(conn, g.identity.name, "configure", "notification_channel", provider,
                  str(body.get("reason", "Web 更新通知渠道")),
                  {"enabled": bool(before["enabled"]) if before else False},
                  {"enabled": bool(body.get("enabled")), "config": config,
                   "secret_updated": bool(secret)})
        return ok({"provider": provider, "enabled": bool(body.get("enabled")),
                   "has_secret": bool(ciphertext)})

    @app.get("/api/v1/ai/status")
    @require_role("viewer")
    def ai_status():
        config = settings.section("ai")
        return ok({"enabled": bool(config.get("enabled", False)), "local_available": True, "provider": config.get("provider", "openai_compatible"),
                   "model": config.get("model", ""), "key_configured": bool(os.getenv("MONITOR_AI_API_KEY")),
                   "privacy_mode": config.get("privacy_mode", "aggregate_only")})

    @app.get("/api/v1/ai/analyses")
    @require_role("viewer")
    def ai_analyses_list():
        clauses, params = ["workspace_id=?"], [workspace_id()]
        add_exact_filter(clauses, params, "status", "status")
        add_exact_filter(clauses, params, "analysis_type", "analysis_type")
        add_time_filters(clauses, params, "created_at")
        add_text_search(clauses, params, ("analysis_type", "provider", "model", "status", "error"))
        return paged_query("""SELECT id,workspace_id,analysis_type,provider,model,status,result_text,error,
                           created_by,created_at,completed_at FROM ai_analyses""" +  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608
                           where_clause(clauses) + " ORDER BY created_at DESC", tuple(params))

    @app.post("/api/v1/ai/analyze")
    @require_role("operator")
    def ai_analyze():
        config = settings.section("ai"); ws = workspace_id(); body = body_json()
        api_key = os.getenv("MONITOR_AI_API_KEY", "")
        try:
            hours = min(max(int(body.get("hours", 24)), 1), 720)
        except (TypeError, ValueError):
            return invalid("分析时间范围必须为整数小时")
        end_dt = datetime.now(timezone.utc); start_dt = end_dt - timedelta(hours=hours)
        metrics = report_metrics(ws, start_dt.isoformat(), end_dt.isoformat())
        if not config.get("enabled", False) or not api_key:
            result = (f"本地规则研判（{hours} 小时）：汇聚 {metrics['events']} 条有效告警，涉及 {metrics['unique_sources']} 个来源，"
                      f"已关闭 {metrics['closed']} 条。\n主要威胁：" + "、".join(f"{x['title']}({x['count']})" for x in metrics['top_threats'][:5]) +
                      "\n处置建议：优先核查高等级来源，结合白名单、MITRE 映射和剧本回放确认；本结果基于聚合数据，不替代人工研判。")
            item_id, timestamp = str(uuid.uuid4()), now()
            with db.transaction(immediate=True) as conn:
                conn.execute("""INSERT INTO ai_analyses(id,workspace_id,analysis_type,provider,model,status,input_summary_json,result_text,created_by,created_at,completed_at)
                             VALUES(?,?,?,?,?,'succeeded',?,?,?,?,?)""", (item_id, ws, str(body.get("analysis_type", "trend"))[:50], "local", "rule-based-soc-v1", json.dumps(metrics, ensure_ascii=False), result, g.identity.name, timestamp, timestamp))
                audit(conn, g.identity.name, "analyze", "ai_analysis", item_id, str(body.get("reason", "生成本地聚合趋势研判")), None, {"privacy_mode": "aggregate_only"})
            return ok({"id": item_id, "analysis": result, "input": metrics, "provider": "local"})
        prompt = ("你是安全运营分析师。仅依据下面的聚合统计生成中文研判，输出：态势摘要、异常变化、"
                  "主要攻击链推断、处置优先级、需人工核实事项。不得虚构资产或攻击事实。\n" +
                  json.dumps(metrics, ensure_ascii=False))
        provider = str(config.get("provider", "openai_compatible")); model = str(config.get("model", "gpt-5.6-terra"))
        item_id, timestamp = str(uuid.uuid4()), now()
        with db.transaction(immediate=True) as conn:
            conn.execute("""INSERT INTO ai_analyses(id,workspace_id,analysis_type,provider,model,status,
                          input_summary_json,created_by,created_at) VALUES(?,?,?,?,?,'running',?,?,?)""",
                         (item_id, ws, str(body.get("analysis_type", "trend"))[:50], provider, model,
                          json.dumps(metrics, ensure_ascii=False), g.identity.name, timestamp))
        try:
            api_mode = str(config.get("api_mode", "responses"))
            base_url = str(config.get("base_url", "https://api.openai.com/v1")).rstrip("/")
            if api_mode == "responses":
                endpoint = base_url + "/responses"
                payload = {"model": model, "input": prompt,
                           "instructions": "你是安全运营分析师。安全数据不得外推或臆测。",
                           "reasoning": {"effort": str(config.get("reasoning_effort", "medium"))}}
            else:
                endpoint = base_url + "/chat/completions"
                payload = {"model": model, "messages": [{"role": "system", "content": "安全数据不得外推或臆测。"},
                                                           {"role": "user", "content": prompt}]}
            request_timeout = min(max(int(config.get("timeout_seconds", 60)), 5), 180)
            response = requests.post(endpoint,
                                     headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                                     json=payload, timeout=request_timeout)
            response.raise_for_status(); document = response.json()
            if api_mode == "responses":
                result = "\n".join(content.get("text", "") for output in document.get("output", [])
                                   for content in output.get("content", []) if content.get("type") == "output_text").strip()
            else:
                result = document["choices"][0]["message"]["content"]
            if not result:
                raise ValueError("AI provider returned no output text")
            with db.transaction(immediate=True) as conn:
                conn.execute("UPDATE ai_analyses SET status='succeeded',result_text=?,completed_at=? WHERE id=?",
                             (str(result)[:20000], now(), item_id))
                audit(conn, g.identity.name, "analyze", "ai_analysis", item_id,
                      str(body.get("reason", "生成聚合趋势研判")), None, {"privacy_mode": "aggregate_only"})
            return ok({"id": item_id, "analysis": result, "input": metrics})
        except Exception as exc:
            with db.transaction(immediate=True) as conn:
                conn.execute("UPDATE ai_analyses SET status='failed',error=?,completed_at=? WHERE id=?",
                             (str(exc)[:1000], now(), item_id))
            return invalid("GPT 分析调用失败，请检查提供商配置", 502)
