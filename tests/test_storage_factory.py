from pathlib import Path

import pytest

from monitor.common.errors import ConfigError
from monitor.infrastructure.storage_factory import create_storage


class Settings:
    database_path = Path("test.db")
    def __init__(self, driver): self.driver = driver
    def section(self, name): return {"driver": self.driver}


def test_sqlite_storage_capabilities():
    storage = create_storage(Settings("sqlite"))
    assert storage.dialect == "sqlite"
    assert storage.supports_multi_node is False


def test_postgresql_fails_explicitly_instead_of_silently_using_sqlite():
    with pytest.raises(ConfigError, match="not production-ready"):
        create_storage(Settings("postgresql"))
