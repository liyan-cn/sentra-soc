from pathlib import Path

from monitor.common.rules import RuleLoader


class Settings:
    def __init__(self, root): self.config_path = root / "config" / "base.yaml"
    def section(self, name): return {"rules_file": "./config/rules.yaml"}


def test_rule_hot_reload_preserves_last_valid_version(tmp_path):
    config = tmp_path / "config"; config.mkdir()
    rules = config / "rules.yaml"
    rules.write_text("defaults: {warn_threshold: 10}\npolicies: []\n", encoding="utf-8")
    loader = RuleLoader(Settings(tmp_path)); first = loader.load(); version = loader.version
    assert first["defaults"]["warn_threshold"] == 10
    rules.write_text("policies: [{id: p1, decision: BLOCK, match: {count_gte: 1}}]\n", encoding="utf-8")
    changed, second = loader.reload_if_changed()
    assert changed and second["policies"][0]["id"] == "p1"
    good_version = loader.version
    rules.write_text("policies: [", encoding="utf-8")
    changed, retained = loader.reload_if_changed()
    assert not changed and retained is second and loader.version == good_version
    assert loader.last_error
