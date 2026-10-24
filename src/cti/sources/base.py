"""Shared plumbing for sources: fetch context, downloads, and compression helpers."""

from __future__ import annotations

import gzip
import io
import logging
import tempfile
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import IO, ClassVar
from urllib.parse import quote

import httpx
from pydantic import BaseModel

from cti.config import Settings
from cti.http.client import RETRY_STATUS, get_with_retry
from cti.snapshot import Snapshot

MAX_DOWNLOAD_BYTES = 2 * 1024**3  # hard ceiling for any single download (2 GiB)
ARCHIVE_TIMEOUT = httpx.Timeout(30.0, read=300.0)  # archives can be slow to start
log = logging.getLogger(__name__)


@dataclass
class FetchContext:
    snapshot: Snapshot
    client: httpx.Client
    settings: Settings
    snapshot_date: date
    secrets: list[str] = field(default_factory=list)  # redacted from URLs we record

    @property
    def cutoff_date(self) -> date:
        return self.snapshot_date - timedelta(days=self.settings.cutoff_days)

    def redact(self, text: str) -> str:
        for secret in self.secrets:
            if secret:
                # also the percent-encoded form, which is what httpx puts in error messages
                for form in {secret, quote(secret, safe="")}:
                    text = text.replace(form, "<redacted>")
        return text

    def download(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> bytes:
        return get_with_retry(self.client, url, headers=headers, params=params).content

    def get_json(self, url: str, params: dict[str, str] | None = None):
        return get_with_retry(self.client, url, params=params).json()

    @contextmanager
    def download_to_file(self, url: str, attempts: int = 3) -> Iterator[Path]:
        """Stream a large download to a temporary file (with retries); deleted afterwards."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "download"
            for attempt in range(1, attempts + 1):
                try:
                    self._stream_to(url, path)
                    break
                except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                    retryable = not isinstance(exc, httpx.HTTPStatusError) or (
                        exc.response.status_code in RETRY_STATUS
                    )
                    if not retryable or attempt == attempts:
                        raise
                    log.warning("download attempt %d failed: %s", attempt, type(exc).__name__)
                    time.sleep(5 * attempt)
            yield path

    def _stream_to(self, url: str, path: Path) -> None:
        with (
            self.client.stream("GET", url, timeout=ARCHIVE_TIMEOUT) as response,
            path.open("wb") as fh,
        ):
            response.raise_for_status()
            written = 0
            for chunk in response.iter_bytes():
                written += len(chunk)
                if written > MAX_DOWNLOAD_BYTES:
                    raise ValueError(f"download exceeds {MAX_DOWNLOAD_BYTES} bytes")
                fh.write(chunk)

    def write(
        self, source: str, name: str, data: bytes, url: str | None, version: str | None = None
    ):
        return self.snapshot.write_raw(
            source, name, data, url=self.redact(url) if url else None, source_version=version
        )


class Source(ABC):
    """A data source. ``fetch`` needs the network; ``parse`` never does."""

    name: ClassVar[str]
    requires: ClassVar[tuple[str, ...]] = ()  # Settings fields that must be set

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @abstractmethod
    def fetch(self, ctx: FetchContext) -> None: ...

    @abstractmethod
    def parse(self, snapshot: Snapshot) -> Iterator[BaseModel]: ...

    @abstractmethod
    def probe_url(self) -> str:
        """A cheap URL whose success shows the source is reachable (and the key works)."""


def gz(data: bytes) -> bytes:
    """Deterministic gzip (fixed mtime) so identical content gives identical bytes."""
    return gzip.compress(data, compresslevel=9, mtime=0)


def gunzip_stream(data: bytes) -> IO[bytes]:
    return gzip.GzipFile(fileobj=io.BytesIO(data))


def copy_capped(src: IO[bytes], dst: IO[bytes], limit: int) -> None:
    """Copy at most ``limit`` bytes; raise if the source is larger (zip/gzip bombs)."""
    copied = 0
    while chunk := src.read(1024 * 1024):
        copied += len(chunk)
        if copied > limit:
            raise ValueError(f"decompressed size exceeds {limit} bytes")
        dst.write(chunk)
