"""HTTP client with bounded retries.

Retries only what is worth retrying: transport errors, 429, and 5xx. Other 4xx
responses fail immediately. Credentials belong in headers, never in URLs, so they
can't leak into logs or exception messages.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable, Mapping

import httpx

from cti.http.ratelimit import RateLimiter

log = logging.getLogger(__name__)

RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def make_client(user_agent: str, **kwargs) -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": user_agent},
        timeout=kwargs.pop("timeout", DEFAULT_TIMEOUT),
        follow_redirects=kwargs.pop("follow_redirects", True),
        **kwargs,
    )


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


def get_with_retry(
    client: httpx.Client,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, str] | None = None,
    limiter: RateLimiter | None = None,
    max_attempts: int = 4,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    sleep: Callable[[float], None] = time.sleep,
) -> httpx.Response:
    """GET ``url``. Returns the successful response or raises ``httpx.HTTPError``."""
    for attempt in range(1, max_attempts + 1):
        if limiter:
            limiter.acquire()
        try:
            response = client.get(url, headers=headers, params=params)
        except httpx.TransportError as exc:
            if attempt == max_attempts:
                raise
            delay = min(max_delay, base_delay * 2 ** (attempt - 1))
            log.warning("transport error on attempt %d: %s", attempt, type(exc).__name__)
        else:
            if response.status_code not in RETRY_STATUS or attempt == max_attempts:
                response.raise_for_status()
                return response
            delay = _retry_after(response)
            if delay is None:
                delay = min(max_delay, base_delay * 2 ** (attempt - 1))
            log.warning("HTTP %d on attempt %d", response.status_code, attempt)
        sleep(min(max_delay, delay) + random.uniform(0, base_delay / 2))  # noqa: S311
    raise AssertionError("unreachable")
