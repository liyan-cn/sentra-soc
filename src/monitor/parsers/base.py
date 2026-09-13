from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from monitor.common.errors import ParseError
from .vendor_time import LOCAL_TIMEZONE


def valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ParseError(f"invalid IP: {value}") from exc


def parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    normalized = value.replace("Z", "+00:00")
    for parser in (
        lambda: datetime.fromisoformat(normalized),
        lambda: datetime.strptime(value, "%Y-%m-%d %H:%M:%S"),
        lambda: datetime.strptime(value, "%Y-%m-%dT%H:%M:%S"),
    ):
        try:
            result = parser()
            return result.replace(tzinfo=result.tzinfo or LOCAL_TIMEZONE).astimezone(timezone.utc)
        except ValueError:
            pass
    raise ParseError(f"invalid timestamp: {value}")
