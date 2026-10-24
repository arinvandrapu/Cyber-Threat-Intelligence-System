"""Write to a primary store and a replica (e.g. local disk + S3); read from primary."""

from __future__ import annotations

from cti.storage.base import Storage


class MirroredStorage:
    def __init__(self, primary: Storage, replica: Storage) -> None:
        self.primary = primary
        self.replica = replica

    def put_bytes(self, key: str, data: bytes, *, overwrite: bool = False) -> None:
        self.primary.put_bytes(key, data, overwrite=overwrite)
        self.replica.put_bytes(key, data, overwrite=overwrite)

    def get_bytes(self, key: str) -> bytes:
        if self.primary.exists(key):
            return self.primary.get_bytes(key)
        return self.replica.get_bytes(key)

    def exists(self, key: str) -> bool:
        return self.primary.exists(key) or self.replica.exists(key)

    def list_keys(self, prefix: str = "") -> list[str]:
        return sorted(set(self.primary.list_keys(prefix)) | set(self.replica.list_keys(prefix)))
