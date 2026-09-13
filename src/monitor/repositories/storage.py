from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class StorageBackend(Protocol):
    dialect: str
    supports_multi_node: bool

    def connect(self) -> Any: ...
    def transaction(self, immediate: bool = False, retries: int = 4) -> AbstractContextManager: ...
    def initialize(self) -> None: ...
    def migrate(self) -> None: ...

