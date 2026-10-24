"""Storage interface shared by local disk and S3."""

from __future__ import annotations

from typing import Protocol

_FORBIDDEN_PARTS = {"", ".", ".."}


class StorageKeyError(ValueError):
    """A storage key is malformed or attempts path traversal."""


def validate_key(key: str) -> str:
    if not key or key.startswith("/") or "\\" in key:
        raise StorageKeyError(f"invalid key: {key!r}")
    if any(part in _FORBIDDEN_PARTS for part in key.split("/")):
        raise StorageKeyError(f"invalid key: {key!r}")
    return key


class Storage(Protocol):
    def put_bytes(self, key: str, data: bytes, *, overwrite: bool = False) -> None:
        """Store ``data``. Raises ``FileExistsError`` if the key exists and not ``overwrite``."""

    def get_bytes(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...

    def list_keys(self, prefix: str = "") -> list[str]: ...
