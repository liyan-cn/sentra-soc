from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources
from urllib.parse import unquote_plus

import yaml


@lru_cache(maxsize=1)
def load_url_rules() -> tuple[dict, ...]:
    document = yaml.safe_load(resources.files("monitor.resources").joinpath(
        "local_detection_rules.yaml").read_text(encoding="utf-8")) or {}
    compiled = []
    for rule in document.get("url_rules", []):
        compiled.append({**rule, "compiled": tuple(re.compile(item, re.I) for item in rule["patterns"])})
    return tuple(compiled)


def detect_malicious_url(host: str, url: str) -> dict | None:
    """Return the first matching local rule; ordinary URL/flow logs return None."""
    candidate = unquote_plus(f"{host} {url}")[:8192]
    for rule in load_url_rules():
        if any(pattern.search(candidate) for pattern in rule["compiled"]):
            return {key: value for key, value in rule.items() if key not in {"patterns", "compiled"}}
    return None

