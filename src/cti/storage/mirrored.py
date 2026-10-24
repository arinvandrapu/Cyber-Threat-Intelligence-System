"""Write to a primary store and a replica (e.g. local disk + S3); read from primary."""

from __future__ import annotations

from cti.storage.base import Storage, put_once


class MirroredStorage:
    def __init__(self, primary: Storage, replica: Storage) -> None:
        self.primary = primary
        self.replica = replica

    def put_bytes(self, key: str, data: bytes, *, overwrite: bool = False) -> None:
        if overwrite:
            self.primary.put_bytes(key, data, overwrite=True)
            self.replica.put_bytes(key, data, overwrite=True)
            return
        # If a previous attempt reached the primary but not the replica, a retry with the
        # same bytes completes the replica instead of failing on the primary.
        wrote_primary = put_once(self.primary, key, data)
        wrote_replica = put_once(self.replica, key, data)
        if not (wrote_primary or wrote_replica):
            raise FileExistsError(key)

    def get_bytes(self, key: str) -> bytes:
        if self.primary.exists(key):
            return self.primary.get_bytes(key)
        return self.replica.get_bytes(key)

    def exists(self, key: str) -> bool:
        return self.primary.exists(key) or self.replica.exists(key)

    def list_keys(self, prefix: str = "") -> list[str]:
        return sorted(set(self.primary.list_keys(prefix)) | set(self.replica.list_keys(prefix)))
