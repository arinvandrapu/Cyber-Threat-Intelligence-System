"""Polite, SSRF-safe scraping of selected CVE reference pages.

- Every request goes through :class:`cti.http.safe_fetch.SafeFetcher`.
- robots.txt is honoured per RFC 9309 (``protego``: wildcards, longest match): a 4xx
  robots.txt means "no rules", while a 5xx or network error means "disallow everything".
  A redirect to another host is checked against that host's robots.txt too.
- One honest User-Agent (with contact address), per-host spacing between requests,
  and a small worker pool.
- Failures are recorded per page and never abort the run.
"""

from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from itertools import batched
from urllib.parse import urlsplit

from protego import Protego

from cti.http.safe_fetch import BlockedURLError, SafeFetcher
from cti.references.selection import Target

STORED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain", "application/pdf")
ROBOTS_AGENT = "cti-pipeline"


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


_ALLOW_ALL = Protego.parse("")
_DISALLOW_ALL = Protego.parse("User-agent: *\nDisallow: /")


class RobotsCache:
    def __init__(self, fetcher: SafeFetcher, agent: str = ROBOTS_AGENT) -> None:
        self._fetcher = fetcher
        self._agent = agent
        self._rules: dict[str, Protego] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def allowed(self, url: str, before_fetch: Callable[[str], None] | None = None) -> bool:
        """``before_fetch`` runs only when robots.txt must be downloaded (for throttling)."""
        origin = _origin(url)
        with self._guard:
            lock = self._locks.setdefault(origin, threading.Lock())
        with lock:
            if origin not in self._rules:
                if before_fetch:
                    before_fetch(url)
                self._rules[origin] = self._load(origin)
        return self._rules[origin].can_fetch(url, self._agent)

    def _load(self, origin: str) -> Protego:
        try:
            result = self._fetcher.fetch(f"{origin}/robots.txt")
        except Exception:  # blocked, network, TLS, decode: unreachable -> disallow
            return _DISALLOW_ALL
        if result.status_code >= 500:
            return _DISALLOW_ALL
        if result.status_code >= 400:
            return _ALLOW_ALL
        return Protego.parse(result.content.decode("utf-8", errors="replace"))


class HostThrottle:
    """Space requests to the same host at least ``interval`` seconds apart."""

    def __init__(
        self,
        interval: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._interval = interval
        self._clock = clock
        self._sleep = sleep
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, url: str) -> None:
        host = urlsplit(url).hostname or ""
        with self._lock:
            now = self._clock()
            start = max(now, self._next.get(host, now))
            self._next[host] = start + self._interval
        if start > now:
            self._sleep(start - now)


def scrape_one(
    target: Target, fetcher: SafeFetcher, robots: RobotsCache, throttle: HostThrottle
) -> dict:
    """Fetch one page. Never raises: every outcome is recorded on the returned dict."""
    record: dict = {
        "cve": target.cve,
        "url": target.url,
        "ref_type": str(target.ref_type),
        "fetched_at": datetime.now(UTC).isoformat(),
    }
    try:
        fetcher.validate(target.url)  # SSRF check first, so blocks are recorded as such
        if not robots.allowed(target.url, before_fetch=throttle.wait):
            record["skipped"] = "robots"
            return record
        throttle.wait(target.url)
        result = fetcher.fetch(target.url)
        if _origin(result.url) != _origin(target.url) and not robots.allowed(
            result.url, before_fetch=throttle.wait
        ):
            record.update(skipped="robots (redirect target)", final_url=result.url)
            return record
    except BlockedURLError as exc:
        record["skipped"] = f"blocked: {exc}"
        return record
    except Exception as exc:  # one bad page must never abort the ingest
        record["error"] = type(exc).__name__
        return record
    content_type = (result.content_type or "").split(";")[0].strip().lower()
    record.update(
        status=result.status_code,
        final_url=result.url,
        content_type=content_type,
        truncated=result.truncated,
    )
    if result.status_code == 200 and content_type in STORED_CONTENT_TYPES:
        record["body_b64"] = base64.b64encode(result.content).decode("ascii")
    return record


def scrape(
    targets: Iterable[Target],
    fetcher: SafeFetcher,
    *,
    workers: int,
    host_interval: float,
) -> Iterator[dict]:
    robots = RobotsCache(fetcher)
    throttle = HostThrottle(host_interval)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # Bounded batches keep at most ~4 x workers pages in memory, in order.
        for batch in batched(targets, workers * 4):
            yield from pool.map(lambda t: scrape_one(t, fetcher, robots, throttle), batch)
