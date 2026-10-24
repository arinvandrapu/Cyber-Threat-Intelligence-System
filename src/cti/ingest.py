"""The one-time ingest: fetch every source into a new snapshot.

Run once per snapshot date. ``resume`` continues a run that failed part-way: completed
sources are skipped, and a source that wrote partial data is re-fetched under a new,
logged attempt. ``refetch`` re-downloads a single completed source and requires a reason.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date

import httpx

from cti.config import Settings
from cti.snapshot import Snapshot
from cti.sources.base import FetchContext, Source
from cti.storage.base import Storage

log = logging.getLogger(__name__)


@dataclass
class IngestResult:
    snapshot_id: str
    completed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.failed


def _context(snap: Snapshot, client: httpx.Client, settings: Settings) -> FetchContext:
    # Every configured secret is redacted from recorded URLs and error messages.
    secrets = [
        s.get_secret_value() for s in (settings.abusech_auth_key, settings.github_token) if s
    ]
    return FetchContext(
        snapshot=snap, client=client, settings=settings, snapshot_date=snap.date, secrets=secrets
    )


def _fetch(source: Source, ctx: FetchContext, result: IngestResult) -> None:
    log.info("fetching %s", source.name)
    try:
        source.fetch(ctx)
    except Exception as exc:  # one failed source must not abort the others
        message = ctx.redact(f"{type(exc).__name__}: {exc}")
        log.error("%s failed: %s", source.name, message)
        result.failed[source.name] = message
        return
    ctx.snapshot.mark_complete(source.name)
    result.completed.append(source.name)


def ingest(
    storage: Storage,
    settings: Settings,
    snapshot_date: date,
    sources: list[Source],
    client: httpx.Client,
    *,
    resume: bool = False,
) -> IngestResult:
    snapshot_id = snapshot_date.isoformat()
    snap = Snapshot.open(storage, snapshot_id) if resume else Snapshot.create(storage, snapshot_id)
    ctx = _context(snap, client, settings)
    result = IngestResult(snapshot_id)
    for source in sources:
        if snap.is_complete(source.name):
            result.skipped.append(source.name)
            continue
        if snap.has_data(source.name):
            snap.begin_refetch(source.name, "resume: previous fetch did not complete")
        _fetch(source, ctx, result)
    return result


def refetch(
    storage: Storage,
    settings: Settings,
    snapshot_id: str,
    source: Source,
    reason: str,
    client: httpx.Client,
) -> IngestResult:
    snap = Snapshot.open(storage, snapshot_id)
    snap.begin_refetch(source.name, reason)
    result = IngestResult(snapshot_id)
    _fetch(source, _context(snap, client, settings), result)
    return result
