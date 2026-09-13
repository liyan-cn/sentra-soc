from __future__ import annotations

import re

from monitor.common.errors import IgnoredLog, ParseError
from monitor.domain.models import SecurityEvent
from .base import valid_ip
from .cef_security import parse_cef
from .vendor_time import syslog_time


def _value(line: str, names: tuple[str, ...]) -> str | None:
    for name in names:
        match = re.search(
            rf"(?:^|[\s,;/|]){re.escape(name)}\s*[=:／/]\s*(?:[\"']([^\"']+)[\"']|([^\s,;|/]+))",
            line, re.I,
        )
        if match:
            return (match.group(1) or match.group(2)).strip()
    return None


def _h3c_value(line: str, name: str) -> str | None:
    """Read H3C syslog fields such as ``SrcIPAddr(5)=1.2.3.4``."""
    match = re.search(rf"\b{re.escape(name)}\([^)]*\)\s*=\s*([^;\s]+)", line, re.I)
    return match.group(1).strip() if match else None


class VendorSecurityParser:
    def __init__(self, source: str, vendor: str, signatures: tuple[str, ...]):
        self.source, self.vendor, self.signatures = source, vendor, signatures

    def parse(self, line: str, device_id: str) -> SecurityEvent:
        folded = line.casefold()
        if not any(signature.casefold() in folded for signature in self.signatures):
            raise ParseError(f"not a {self.vendor} event")
        if "cef:" in folded:
            header, values = parse_cef(line)
            src, dst = values.get("src"), values.get("dst")
            category = values.get("cat") or values.get("act") or header[5]
            action, fmt = values.get("act", ""), "CEF"
        else:
            is_h3c_native = self.vendor.casefold() == "h3c" and ("srcipaddr(" in folded or "%%" in folded)
            if is_h3c_native:
                src = _h3c_value(line, "SrcIPAddr")
                dst = _h3c_value(line, "DstIPAddr")
                category = _h3c_value(line, "Type") or _h3c_value(line, "Event") or _h3c_value(line, "Policy")
                action = _h3c_value(line, "Event") or _h3c_value(line, "Action") or ""
                fmt = "H3C_NATIVE"
                if action.casefold() in {"permit", "allow", "accept", "forward", "normal", "pass"}:
                    raise IgnoredLog("H3C permit/traffic telemetry")
            else:
                src = _value(line, ("src", "srcip", "src_ip", "sip", "source-ip", "client_ip", "clientip"))
                dst = _value(line, ("dst", "dstip", "dst_ip", "dip", "destination-ip", "server_ip", "serverip"))
                category = _value(line, ("attack_name", "attack-name", "event_name", "event", "signature",
                                         "signname", "threat", "category", "msg", "name"))
                action, fmt = _value(line, ("action", "act", "result", "dispose")) or "", "VENDOR_KV"
        if not src:
            raise ParseError(f"{self.vendor} event has no source IP")
        category = (category or "SecurityEvent").strip()[:200]
        return SecurityEvent(
            source=self.source, device_id=device_id, event_type="attack", occurred_at=syslog_time(line),
            src_ip=valid_ip(src), dst_ip=valid_ip(dst) if dst else None,
            category=category, vendor_category=category, severity="high", raw_line=line.rstrip(),
            attributes={"format": fmt, "vendor": self.vendor, "action": action},
        )


def factory(source: str, vendor: str, signatures: tuple[str, ...]):
    return lambda: VendorSecurityParser(source, vendor, signatures)
