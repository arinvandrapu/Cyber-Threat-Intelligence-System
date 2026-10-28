"""The one-time ingest: fetch every source into a new snapshot.

Run once per snapshot date. ``resume`` continues a run that failed part-way: completed
sources are skipped, and a source that wrote partial data is re-fetched under a new,
logged attempt. ``refetch`` re-downloads a single completed source and requires a reason;
with ``new_dates_only`` it copies the previous attempt's dated files byte for byte and
downloads only the pinned dates that are missing (e.g. extra cutoffs added later).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date

import httpx

from cti.config import Settings
from cti.snapshot import Snapshot
from cti.sources.base import FetchContext, Source, as_of_from_name
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
    *,
    new_dates_only: bool = False,
) -> IngestResult:
    snap = Snapshot.open(storage, snapshot_id)
    kept = snap.entries(source.name) if new_dates_only else []
    # Every check runs before begin_refetch, so a refused call changes nothing.
    if new_dates_only:
        if not kept:
            raise ValueError(f"{source.name} has no earlier files to keep")
        if not snap.is_complete(source.name):
            # its latest attempt may hold only part of the dated files (e.g. a copy that
            # crashed); carrying that forward would re-pin the rest at a later time
            raise ValueError(
                f"{source.name} is incomplete; earlier attempts are in the manifest, "
                "so recover by hand instead of --new-dates-only"
            )
    skip = {as_of_from_name(e.name) for e in kept}  # raises for sources without dated files
    held = {e.name: snap.read_raw(e) for e in kept}  # checksum-verified before the new attempt
    snap.begin_refetch(source.name, reason)
    for e in kept:
        snap.write_raw(
            source.name, e.name, held[e.name], url=e.url, source_version=e.source_version
        )
    ctx = _context(snap, client, settings)
    ctx.skip_as_of = skip
    result = IngestResult(snapshot_id)
    _fetch(source, ctx, result)
    return result
