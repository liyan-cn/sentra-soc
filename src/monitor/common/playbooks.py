from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from monitor.common.errors import ConfigError


class PlaybookLoader:
    """Validated, hot-reloadable playbook configuration loader."""

    def __init__(self, settings, database=None):
        configured = settings.section("playbooks").get("file", "./config/playbooks.yaml")
        path = Path(configured)
        self.path = path if path.is_absolute() else (settings.config_path.parent.parent / path).resolve()
        self.playbooks: list[dict] | None = None
        self.version = ""
        self.last_error = ""
        self.database = database

    def load(self) -> list[dict]:
        if self.database is not None:
            with self.database.connect() as conn:
                try:
                    rows = conn.execute("SELECT definition_json,updated_at FROM managed_playbooks ORDER BY id").fetchall()
                except Exception:
                    rows = []
            if rows:
                import json
                content = "\n".join(row["definition_json"] + row["updated_at"] for row in rows).encode()
                version = hashlib.sha256(content).hexdigest()[:12]
                if self.playbooks is not None and version == self.version:
                    return self.playbooks
                candidate = [json.loads(row["definition_json"]) for row in rows]
                self._validate(candidate)
                self.playbooks, self.version, self.last_error = candidate, version, ""
                return candidate
        if not self.path.exists():
            self.playbooks, self.version, self.last_error = [], "", ""
            return []
        content = self.path.read_bytes()
        version = hashlib.sha256(content).hexdigest()[:12]
        if self.playbooks is not None and version == self.version:
            return self.playbooks
        try:
            document = yaml.safe_load(content.decode("utf-8")) or {}
            candidate = document.get("playbooks", [])
            self._validate(candidate)
        except Exception as exc:
            self.last_error = str(exc)
            if self.playbooks is not None:
                return self.playbooks
            raise ConfigError(f"invalid playbook file: {exc}") from exc
        self.playbooks, self.version, self.last_error = candidate, version, ""
        return candidate

    def reload_if_changed(self) -> tuple[bool, list[dict]]:
        previous = self.version
        playbooks = self.load()
        return bool(self.version and self.version != previous), playbooks

    @staticmethod
    def _validate(playbooks) -> None:
        if not isinstance(playbooks, list):
            raise ConfigError("playbooks must be a list")
        ids: set[str] = set()
        for item in playbooks:
            if not isinstance(item, dict) or not item.get("id"):
                raise ConfigError("each playbook requires an id")
            if item["id"] in ids:
                raise ConfigError(f"duplicate playbook id: {item['id']}")
            ids.add(str(item["id"]))
            if item.get("trigger", "review_created") != "review_created":
                raise ConfigError(f"unsupported trigger in playbook {item['id']}")
            match = item.get("match")
            if not isinstance(match, dict) or not match:
                raise ConfigError(f"playbook {item['id']} requires a non-empty match")
            actions = item.get("actions")
            if not isinstance(actions, list) or not actions:
                raise ConfigError(f"playbook {item['id']} requires actions")
            for action in actions:
                if action.get("type") != "close_review":
                    raise ConfigError(f"unsupported action in playbook {item['id']}")
                if not str(action.get("reason", "")).strip():
                    raise ConfigError(f"close_review in {item['id']} requires reason")
