from __future__ import annotations

from monitor.common.errors import ConfigError
from monitor.infrastructure.database import Database


def create_storage(settings):
    config = settings.section("database")
    driver = str(config.get("driver", "sqlite")).lower()
    if driver == "sqlite":
        return Database(settings.database_path, int(config.get("busy_timeout_ms", 10000)))
    if driver == "postgresql":
        raise ConfigError(
            "PostgreSQL is a reserved storage dialect but is not production-ready in this release; "
            "use sqlite or install a future monitor3-postgresql provider"
        )
    raise ConfigError(f"unsupported database.driver: {driver}")

