"""Immutable raw snapshots with a manifest.

Layout under a storage backend::

    <snapshot_id>/manifest.json
    <snapshot_id>/raw/<source>/<attempt>/<name>

A snapshot is created once. Creating it again fails with :class:`SnapshotExistsError`.
The only way to change a source afterwards is :meth:`Snapshot.begin_refetch`, which
records a reason and writes under a new attempt number, so earlier data is never
overwritten and every change is auditable.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, date, datetime

from pydantic import BaseModel, Field

from cti.storage.base import Storage, put_once

MANIFEST = "manifest.json"
_ID_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")


class SnapshotExistsError(RuntimeError):
    """The snapshot already exists; ingest runs once."""


def _now() -> datetime:
    return datetime.now(UTC)


class ManifestEntry(BaseModel):
    source: str
    attempt: int
    name: str
    key: str
    url: str | None
    sha256: str
    bytes: int
    fetched_at: datetime
    source_version: str | None = None


class RefetchRecord(BaseModel):
    source: str
    attempt: int
    reason: str
    at: datetime


class Manifest(BaseModel):
    snapshot_id: str
    created_at: datetime
    entries: list[ManifestEntry] = Field(default_factory=list)
    refetches: list[RefetchRecord] = Field(default_factory=list)


class Snapshot:
    def __init__(self, storage: Storage, manifest: Manifest) -> None:
        self.storage = storage
        self.manifest = manifest

    @property
    def id(self) -> str:
        return self.manifest.snapshot_id

    @staticmethod
    def _manifest_key(snapshot_id: str) -> str:
        return f"{snapshot_id}/{MANIFEST}"

    @classmethod
    def create(cls, storage: Storage, snapshot_id: str) -> Snapshot:
        if not _ID_RE.fullmatch(snapshot_id):
            raise ValueError(f"snapshot id must be YYYY-MM-DD, got {snapshot_id!r}")
        date.fromisoformat(snapshot_id)  # rejects impossible dates like 2026-99-99
        if storage.list_keys(f"{snapshot_id}/"):
            raise SnapshotExistsError(
                f"snapshot {snapshot_id} already exists; use a refetch to change a source"
            )
        snap = cls(storage, Manifest(snapshot_id=snapshot_id, created_at=_now()))
        # overwrite=False: if another ingest raced us here, this fails instead of clobbering
        snap.save(overwrite=False)
        return snap

    @classmethod
    def open(cls, storage: Storage, snapshot_id: str) -> Snapshot:
        data = storage.get_bytes(cls._manifest_key(snapshot_id))
        return cls(storage, Manifest.model_validate_json(data))

    def save(self, *, overwrite: bool = True) -> None:
        """Persist the manifest, the only object in a snapshot that is ever rewritten."""
        self.storage.put_bytes(
            self._manifest_key(self.id),
            self.manifest.model_dump_json(indent=2).encode(),
            overwrite=overwrite,
        )

    def current_attempt(self, source: str) -> int:
        attempts = [e.attempt for e in self.manifest.entries if e.source == source]
        attempts += [r.attempt for r in self.manifest.refetches if r.source == source]
        return max(attempts, default=1)

    def begin_refetch(self, source: str, reason: str) -> int:
        if not reason.strip():
            raise ValueError("a refetch needs a reason")
        if not any(e.source == source for e in self.manifest.entries):
            raise ValueError(f"source {source!r} has no data to refetch")
        attempt = self.current_attempt(source) + 1
        self.manifest.refetches.append(
            RefetchRecord(source=source, attempt=attempt, reason=reason, at=_now())
        )
        self.save()
        return attempt

    def write_raw(
        self,
        source: str,
        name: str,
        data: bytes,
        *,
        url: str | None = None,
        source_version: str | None = None,
    ) -> ManifestEntry:
        for label, value in (("source", source), ("name", name)):
            if not _NAME_RE.fullmatch(value):
                raise ValueError(f"invalid {label}: {value!r}")
        attempt = self.current_attempt(source)
        key = f"{self.id}/raw/{source}/{attempt}/{name}"
        # put_once makes a retry after a partial failure (e.g. the manifest save failed)
        # safe: identical bytes are accepted, different bytes still raise FileExistsError.
        put_once(self.storage, key, data)
        if existing := next((e for e in self.manifest.entries if e.key == key), None):
            self.save()  # a previous save may have failed after the entry was recorded
            return existing
        entry = ManifestEntry(
            source=source,
            attempt=attempt,
            name=name,
            key=key,
            url=url,
            sha256=hashlib.sha256(data).hexdigest(),
            bytes=len(data),
            fetched_at=_now(),
            source_version=source_version,
        )
        self.manifest.entries.append(entry)
        self.save()
        return entry

    def entries(self, source: str) -> list[ManifestEntry]:
        """Entries from the latest attempt for ``source``."""
        attempt = self.current_attempt(source)
        return [e for e in self.manifest.entries if e.source == source and e.attempt == attempt]

    def read_raw(self, entry: ManifestEntry) -> bytes:
        data = self.storage.get_bytes(entry.key)
        if hashlib.sha256(data).hexdigest() != entry.sha256:
            raise ValueError(f"checksum mismatch for {entry.key}")
        return data
