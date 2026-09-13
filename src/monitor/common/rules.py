from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from monitor.common.errors import ConfigError


def rules_path(settings) -> Path:
    path = Path(settings.section("policy").get("rules_file", "./config/rules.yaml"))
    if path.is_absolute():
        return path
    project_candidate = (settings.config_path.parent.parent / path).resolve()
    config_candidate = (settings.config_path.parent / path).resolve()
    return project_candidate if project_candidate.exists() else config_candidate


def normalize_rules(document: dict) -> dict:
    defaults = document.get("defaults", {})
    merged = {"defaults": defaults, "policies": document.get("policies", [])}
    for source, rule in document.get("rules", {}).items():
        merged[source] = {**defaults, **(rule or {})}
    return merged


class RuleLoader:
    """Content-hash based loader that preserves the last valid configuration."""

    def __init__(self, settings):
        self.path = rules_path(settings)
        self.rules: dict | None = None
        self.version = ""
        self.last_error = ""

    def load(self) -> dict:
        if not self.path.exists():
            raise ConfigError(f"rules file not found: {self.path}")
        content = self.path.read_bytes()
        version = hashlib.sha256(content).hexdigest()[:12]
        if self.rules is not None and version == self.version:
            return self.rules
        try:
            document = yaml.safe_load(content.decode("utf-8")) or {}
            candidate = normalize_rules(document)
            self._validate(candidate)
        except Exception as exc:
            self.last_error = str(exc)
            if self.rules is not None:
                return self.rules
            raise ConfigError(f"invalid rules file: {exc}") from exc
        self.rules, self.version, self.last_error = candidate, version, ""
        return candidate

    def reload_if_changed(self) -> tuple[bool, dict]:
        old = self.version
        rules = self.load()
        return bool(self.version and self.version != old), rules

    @staticmethod
    def _validate(rules: dict) -> None:
        if not isinstance(rules.get("policies", []), list):
            raise ConfigError("policies must be a list")
        ids = set()
        for policy in rules.get("policies", []):
            if not isinstance(policy, dict) or not policy.get("id"):
                raise ConfigError("each policy requires an id")
            if policy["id"] in ids:
                raise ConfigError(f"duplicate policy id: {policy['id']}")
            ids.add(policy["id"])
            if str(policy.get("decision", "OBSERVE")).upper() not in {
                "IGNORE", "OBSERVE", "NOTIFY", "MANUAL_REVIEW", "BLOCK"
            }:
                raise ConfigError(f"invalid decision in policy {policy['id']}")
