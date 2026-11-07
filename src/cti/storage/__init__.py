"""Storage backends. There is deliberately no delete operation."""

from cti.storage.base import (
    StaleWriteError,
    Storage,
    StorageKeyError,
    put_once,
    validate_key,
)
from cti.storage.local import LocalStorage
from cti.storage.mirrored import MirroredStorage
from cti.storage.s3 import S3Storage

__all__ = [
    "LocalStorage",
    "MirroredStorage",
    "S3Storage",
    "StaleWriteError",
    "Storage",
    "StorageKeyError",
    "put_once",
    "validate_key",
]
