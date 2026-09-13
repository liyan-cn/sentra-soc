from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any, Callable


GROUPS = {
    "sources": "monitor3.sources",
    "parsers": "monitor3.parsers",
    "actions": "monitor3.actions",
    "notifiers": "monitor3.notifiers",
    "geolocation": "monitor3.geolocation",
    "threat_intel": "monitor3.threat_intel",
}


class PluginRegistry:
    """Built-ins and third-party entry points with deterministic precedence."""

    def __init__(self):
        self._builtins: dict[str, dict[str, Callable[..., Any]]] = {key: {} for key in GROUPS}

    def register(self, kind: str, name: str, factory: Callable[..., Any]) -> None:
        if kind not in GROUPS:
            raise ValueError(f"unknown plugin kind: {kind}")
        if not name or not name.replace("-", "_").isidentifier():
            raise ValueError(f"invalid plugin name: {name}")
        self._builtins[kind][name] = factory

    def names(self, kind: str) -> list[str]:
        return sorted(set(self._builtins[kind]) | {ep.name for ep in self._entry_points(kind)})

    def load(self, kind: str, name: str):
        if name in self._builtins[kind]:
            return self._builtins[kind][name]
        matches = [ep for ep in self._entry_points(kind) if ep.name == name]
        if not matches:
            raise LookupError(f"plugin not found: {kind}/{name}; available={self.names(kind)}")
        if len(matches) > 1:
            raise LookupError(f"duplicate plugins: {kind}/{name}")
        return matches[0].load()

    @staticmethod
    def _entry_points(kind: str):
        if kind not in GROUPS:
            raise ValueError(f"unknown plugin kind: {kind}")
        return entry_points().select(group=GROUPS[kind])
