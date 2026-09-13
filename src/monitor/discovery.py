from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from monitor.parsers import get_parser
from monitor.common.errors import IgnoredLog


PARSER_SOURCES = {
    "huawei_waf": "HUAWEI_WAF",
    "huawei_ips": "HUAWEI_IPS",
    "h3c_waf": "H3C_WAF",
    "h3c_security": "H3C_SECURITY",
    "qianxin_ngfw": "QIANXIN_NGFW",
    "qianxin_waf": "QIANXIN_WAF",
    "sangfor_ngaf": "SANGFOR_NGAF",
    "hillstone_ngfw": "HILLSTONE_NGFW",
    "nsfocus_waf": "NSFOCUS_WAF",
    "venustech_utm": "VENUSTECH_UTM",
    "cef_security": "CEF_SECURITY",
    "dptech_waf": "DPTECH_WAF",
    "dptech_ips": "DPTECH_IPS",
    "topsec_waf": "TOPSEC_WAF",
}


@dataclass(frozen=True, slots=True)
class Fingerprint:
    parser: str | None
    source: str | None
    confidence: float
    sample_count: int
    candidate_count: int
    parsed_count: int
    parse_success_rate: float
    field_completeness: float


def signature_score(parser: str, line: str) -> float:
    text = line.casefold()
    if parser == "huawei_waf":
        return 1.0 if any(tag in text for tag in ("ips/4/detect", "assoc/4/attack")) and "srcip=" in text else 0.0
    if parser == "huawei_ips":
        return 1.0 if "ips/4/detect" in text and "srcip=" in text and "dstip=" in text else 0.0
    if parser == "dptech_waf":
        if "%%waf/webattack" in text:
            return 1.0
        return 0.92 if "log-type:basic-attack" in text and "event:alert" in text else 0.0
    if parser == "dptech_ips":
        return 0.96 if "event:alert" in text and ("attack-name:" in text or "log-type:url_class" in text) else 0.0
    if parser == "topsec_waf":
        return 0.9 if "sip=" in text and "msg=" in text and ("dip=" in text or "topsec" in text) else 0.0
    if parser == "h3c_waf":
        return 0.98 if "h3cwaf:" in text and any(key in text for key in ("客户端ip/", "sip/")) else 0.0
    vendor_marks = {
        "qianxin_ngfw": ("qianxin", "奇安信", "网神", "legendsec"),
        "qianxin_waf": ("qianxin", "奇安信", "网神", "legendsec"),
        "h3c_security": (" h3c ", "h3c%", "%%"),
        "sangfor_ngaf": ("sangfor", "深信服", "ngaf"),
        "hillstone_ngfw": ("hillstone", "山石", "stoneos"),
        "nsfocus_waf": ("nsfocus", "绿盟"),
        "venustech_utm": ("venustech", "启明星辰", "天清"),
    }
    if parser in vendor_marks:
        vendor = any(mark in text for mark in vendor_marks[parser])
        fields = any(key in text for key in ("src=", "srcip=", "sip=", "source-ip", "客户端ip/", "srcipaddr("))
        if parser == "h3c_security":
            return 0.93 if vendor and "%%" in text and "srcipaddr(" in text else 0.0
        return 0.84 if vendor and fields else 0.0
    if parser == "cef_security":
        return 0.80 if "cef:" in text and " src=" in text else 0.0
    return 0.0


def fingerprint(lines: list[str], device_id: str = "discovery") -> Fingerprint:
    samples = [line for line in lines if line.strip()]
    if not samples:
        return Fingerprint(None, None, 0, 0, 0, 0, 0, 0)
    best = None
    for parser_name, source in PARSER_SOURCES.items():
        candidates = [(line, signature_score(parser_name, line)) for line in samples]
        candidates = [(line, score) for line, score in candidates if score > 0]
        if not candidates:
            continue
        parser = get_parser(parser_name)
        parsed = []
        completeness = []
        for line, _score in candidates:
            try:
                event = parser.parse(line, device_id)
                parsed.append(event)
                fields = (event.src_ip, event.dst_ip, event.category, event.occurred_at)
                completeness.append(sum(value not in (None, "", "Unknown") for value in fields) / len(fields))
            except IgnoredLog:
                # Normal allow/permit telemetry is successfully recognized and
                # contributes to parser quality, but never becomes an attack.
                parsed.append(None)
                completeness.append(0.75)
            except Exception:
                pass
        success = len(parsed) / len(candidates)
        signature = sum(score for _line, score in candidates) / len(candidates)
        coverage = min(1.0, len(candidates) / max(3, len(samples) * 0.1))
        confidence = round(signature * success * (0.85 + 0.15 * coverage), 4)
        result = Fingerprint(parser_name, source, confidence, len(samples), len(candidates), len(parsed),
                             round(success, 4), round(sum(completeness) / len(completeness), 4) if completeness else 0)
        if best is None or result.confidence > best.confidence:
            best = result
    return best or Fingerprint(None, None, 0, len(samples), 0, 0, 0, 0)


def discover_source_dirs(root: str | Path) -> list[tuple[str, Path]]:
    root = Path(root).resolve()
    if not root.exists():
        return []
    found = []
    for child in root.iterdir():
        if not child.is_dir() or child.is_symlink():
            continue
        try:
            ip = str(ipaddress.ip_address(child.name))
            resolved = child.resolve()
            if os.path.commonpath((str(root), str(resolved))) != str(root):
                continue
        except (ValueError, OSError):
            continue
        found.append((ip, resolved))
    return sorted(found)


def tail_samples(directory: Path, limit: int = 300, max_bytes: int = 2_000_000) -> list[str]:
    lines: list[str] = []
    files = sorted((item for item in directory.glob("*.log") if item.is_file()),
                   key=lambda item: item.stat().st_mtime, reverse=True)[:4]
    remaining = max_bytes
    for path in files:
        if remaining <= 0 or len(lines) >= limit:
            break
        size = min(path.stat().st_size, remaining)
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - size))
            data = stream.read(size)
        remaining -= len(data)
        decoded = data.decode("utf-8", errors="replace").splitlines()
        if path.stat().st_size > size and decoded:
            decoded = decoded[1:]
        lines.extend(reversed(decoded))
    return list(reversed(lines[:limit]))
