from __future__ import annotations

import ipaddress
import threading
import time
from datetime import timedelta

import requests

from monitor.domain.models import utc_now


class GeoLocationService:
    def __init__(self, database, endpoint: str = "http://ip-api.com/json/{ip}?lang=zh-CN", ttl_days: int = 7,
                 timeout_seconds: float = 3, failure_ttl_minutes: int = 60,
                 failure_threshold: int = 5, circuit_breaker_seconds: int = 60):
        self.db = database
        self.endpoint = endpoint
        self.ttl_days = ttl_days
        self.timeout_seconds = max(0.1, float(timeout_seconds))
        self.failure_ttl_minutes = max(1, int(failure_ttl_minutes))
        self.failure_threshold = max(1, int(failure_threshold))
        self.circuit_breaker_seconds = max(1, int(circuit_breaker_seconds))
        self._failures = 0
        self._open_until = 0.0
        self._lock = threading.Lock()

    def _circuit_open(self) -> bool:
        with self._lock:
            return time.monotonic() < self._open_until

    def _record_result(self, success: bool) -> None:
        with self._lock:
            if success:
                self._failures = 0
                self._open_until = 0.0
                return
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._open_until = time.monotonic() + self.circuit_breaker_seconds

    def lookup(self, ip: str) -> str:
        address = ipaddress.ip_address(ip)
        if address.is_private or address.is_loopback:
            return "INTERNAL"
        now = utc_now()
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM ip_geo_cache WHERE ip=? AND expires_at>?", (ip, now.isoformat())).fetchone()
            if row:
                return "/".join(x for x in (row["country"], row["region"], row["city"]) if x) or "UNKNOWN"
        if self._circuit_open():
            return "UNKNOWN"
        status, country, region, city = "error", "", "", ""
        try:
            response = requests.get(
                self.endpoint.format(ip=ip), timeout=self.timeout_seconds,
                headers={"User-Agent": "Monitor3-SOC/3.0"},
            )
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "success":
                status, country, region, city = "ok", data.get("country", ""), data.get("regionName", ""), data.get("city", "")
        except Exception:
            pass
        self._record_result(status == "ok")
        expires = (now + timedelta(days=self.ttl_days)) if status == "ok" else (
            now + timedelta(minutes=self.failure_ttl_minutes))
        with self.db.transaction(immediate=True, retries=8) as conn:
            conn.execute(
                """INSERT INTO ip_geo_cache(ip,country,region,city,status,expires_at,updated_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET country=excluded.country,
                region=excluded.region,city=excluded.city,status=excluded.status,
                expires_at=excluded.expires_at,updated_at=excluded.updated_at""",
                (ip, country, region, city, status, expires.isoformat(), now.isoformat()),
            )
        return "/".join(x for x in (country, region, city) if x) or "UNKNOWN"
