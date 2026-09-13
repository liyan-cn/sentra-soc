from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from monitor.domain.models import SecurityEvent


@dataclass(frozen=True, slots=True)
class RawRecord:
    data: str
    source_id: str
    checkpoint: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ActionResult:
    success: bool
    actual_state: str
    provider_reference: str = ""
    details: dict[str, Any] | None = None


@runtime_checkable
class EventSource(Protocol):
    def poll(self, batch_size: int = 100) -> list[RawRecord]: ...
    def commit(self, checkpoint: dict[str, Any]) -> None: ...
    def health(self) -> dict[str, Any]: ...


@runtime_checkable
class EventParser(Protocol):
    source: str
    def parse(self, line: str, device_id: str) -> SecurityEvent: ...


@runtime_checkable
class ActionProvider(Protocol):
    def apply(self, payload: dict[str, Any]) -> ActionResult: ...
    def revoke(self, payload: dict[str, Any]) -> ActionResult: ...
    def inspect(self, subject: str) -> ActionResult: ...


@runtime_checkable
class Notifier(Protocol):
    def send(self, content: str) -> None: ...


@runtime_checkable
class GeoProvider(Protocol):
    def lookup(self, ip: str) -> str: ...


@runtime_checkable
class ThreatIntelProvider(Protocol):
    def lookup(self, ip: str) -> dict[str, Any]: ...
