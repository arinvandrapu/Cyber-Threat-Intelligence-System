"""Copy a finished local snapshot and the frozen gold fixture to remote storage (S3).

Everything is write-once: re-running after a partial failure skips objects already stored
with identical bytes (compared by checksum, not by downloading them) and refuses if
different bytes are there. Each raw file is checked against its manifest SHA-256 before
upload, and S3 verifies a SHA-256 checksum on every PUT (see :class:`S3Storage`).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from cti import gold
from cti.snapshot import MANIFEST, Manifest, Snapshot
from cti.storage.base import Storage, put_once

GOLD_KEY = "gold.jsonl.gz"


class RemoteConflictError(FileExistsError):
    """Remote storage holds different bytes, or a newer manifest, than the local copy."""


@dataclass
class UploadResult:
    snapshot_id: str
    uploaded: int = 0
    already_present: int = 0
    bytes_uploaded: int = 0
    manifest_updated: bool = False
    missing: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing


def _put_once_checked(remote: Storage, key: str, data: bytes, present: set[str]) -> bool:
    """Like :func:`put_once`, but keys listed as present are compared by checksum."""
    if key in present:
        if remote.sha256(key) != hashlib.sha256(data).hexdigest():
            raise RemoteConflictError(f"remote {key} differs from the local copy")
        return False
    try:
        return put_once(remote, key, data)
    except FileExistsError as exc:
        raise RemoteConflictError(f"remote {key} differs from the local copy") from exc


def _check_manifest_superset(local: Manifest, remote: Manifest) -> None:
    """Refuse to replace a remote manifest that records anything the local one doesn't
    (e.g. a stale local copy restored from a backup)."""
    local_keys = {e.key for e in local.entries}
    local_refetches = {(r.source, r.attempt) for r in local.refetches}
    extra = sorted({e.key for e in remote.entries} - local_keys) + sorted(
        f"refetch {s} attempt {a}"
        for s, a in {(r.source, r.attempt) for r in remote.refetches} - local_refetches
    )
    if extra:
        raise RemoteConflictError(
            f"remote manifest for {local.snapshot_id} records items the local one lacks: "
            f"{extra[:5]}; refusing to overwrite it"
        )


def upload_snapshot(local: Storage, remote: Storage, snapshot_id: str) -> UploadResult:
    snap = Snapshot.open(local, snapshot_id)
    sources = {e.source for e in snap.manifest.entries}
    if incomplete := sorted(s for s in sources if not snap.is_complete(s)):
        raise ValueError(
            f"snapshot {snapshot_id} has incomplete sources {incomplete}; "
            "finish them with `cti ingest --resume` before uploading"
        )
    result = UploadResult(snapshot_id)
    present = set(remote.list_keys(f"{snapshot_id}/"))
    # Every attempt is uploaded, not only the latest: earlier attempts are the audit trail.
    for entry in snap.manifest.entries:
        data = snap.read_raw(entry)  # raises on a local checksum mismatch
        if _put_once_checked(remote, entry.key, data, present):
            result.uploaded += 1
            result.bytes_uploaded += len(data)
        else:
            result.already_present += 1

    # The manifest goes last, so a remote manifest never lists objects that aren't there.
    # It is the only object ever overwritten (after a refetch); IAM denies overwriting
    # anything else, and bucket versioning keeps the old manifest for 30 days.
    key = f"{snapshot_id}/{MANIFEST}"
    manifest = local.get_bytes(key)
    if key not in present:
        result.manifest_updated = put_once(remote, key, manifest)
    elif remote.sha256(key) != hashlib.sha256(manifest).hexdigest():
        _check_manifest_superset(snap.manifest, Manifest.model_validate_json(remote.get_bytes(key)))
        remote.put_bytes(key, manifest, overwrite=True)
        result.manifest_updated = True

    stored = set(remote.list_keys(f"{snapshot_id}/"))
    expected = {e.key for e in snap.manifest.entries} | {key}
    result.missing = sorted(expected - stored)
    return result


def upload_gold(
    path: Path, remote: Storage, expected_sha256: str | None = gold.GOLD_SHA256
) -> bool:
    """Upload the gold fixture after verifying its frozen checksum. False if already there."""
    data = gold.read_verified(path, expected_sha256)
    return _put_once_checked(remote, GOLD_KEY, data, set(remote.list_keys(GOLD_KEY)))
