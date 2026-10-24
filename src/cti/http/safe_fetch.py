"""SSRF-safe fetching of untrusted URLs.

Reference URLs on CVE records can be submitted by anyone, so they are untrusted input.
Before every request (including every redirect hop) the fetcher:

1. allows only http/https on ports 80/443, with no credentials in the URL;
2. resolves the hostname and rejects it if *any* resolved address is not public
   (loopback, private, link-local such as cloud metadata 169.254.169.254, CGNAT,
   multicast, reserved, IPv4-mapped/6to4/Teredo-embedded private addresses);
3. connects to the validated IP itself, sending the original Host header and TLS SNI,
   so a second DNS lookup can't swap in an internal address (DNS rebinding).

Redirects are followed manually and capped; response bodies are size-capped.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})

# Ranges that some Python versions classify as global but must never be fetched.
_EXTRA_BLOCKED = tuple(
    ipaddress.ip_network(n)
    for n in ("fec0::/10", "3fff::/20", "2001:db8::/32", "192.0.0.0/24", "198.18.0.0/15")
)

Resolver = Callable[[str, int], list[str]]
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class BlockedURLError(ValueError):
    """The URL (or a redirect target) is not allowed to be fetched."""


@dataclass(frozen=True)
class FetchResult:
    url: str
    status_code: int
    content_type: str | None
    content: bytes
    truncated: bool


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def _embedded_ipv4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if addr.ipv4_mapped:
        return addr.ipv4_mapped
    if addr.sixtofour:
        return addr.sixtofour
    if addr.teredo:
        return addr.teredo[1]
    return None


def is_public_ip(ip: str) -> bool:
    try:
        addr: IPAddress = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and (inner := _embedded_ipv4(addr)):
        addr = inner
    if any(addr in net for net in _EXTRA_BLOCKED):
        return False
    return addr.is_global and not (addr.is_multicast or addr.is_reserved)


class SafeFetcher:
    def __init__(
        self,
        user_agent: str,
        *,
        resolver: Resolver = system_resolver,
        max_redirects: int = 3,
        max_bytes: int = 2_000_000,
        timeout: float = 15.0,
        deadline: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._resolver = resolver
        self._max_redirects = max_redirects
        self._max_bytes = max_bytes
        self._deadline = deadline
        self._client = httpx.Client(
            # identity encoding: the size cap applies to bytes on the wire, no gzip bombs
            headers={"User-Agent": user_agent, "Accept-Encoding": "identity"},
            follow_redirects=False,
            timeout=timeout,
            transport=transport,
            # Pooled connections are keyed by IP only; reusing one for a different hostname
            # would skip that hostname's certificate check. Ignore proxy env vars.
            limits=httpx.Limits(max_keepalive_connections=0),
            trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SafeFetcher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def validate(self, url: str | httpx.URL) -> tuple[httpx.URL, str]:
        """Return the parsed URL and the public IP to connect to, or raise."""
        try:
            parsed = httpx.URL(url)
        except (httpx.InvalidURL, TypeError) as exc:
            raise BlockedURLError(f"invalid URL: {exc}") from exc
        if parsed.scheme not in ALLOWED_SCHEMES:
            raise BlockedURLError(f"scheme not allowed: {parsed.scheme!r}")
        if parsed.userinfo:
            raise BlockedURLError("credentials in URL not allowed")
        if not parsed.host:
            raise BlockedURLError("missing host")
        host = parsed.raw_host.decode("ascii")  # IDNA-encoded, same form as the Host header
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in ALLOWED_PORTS:
            raise BlockedURLError(f"port not allowed: {port}")
        try:
            ips = self._resolver(host, port)
        except OSError as exc:
            raise BlockedURLError(f"cannot resolve {host!r}") from exc
        if not ips:
            raise BlockedURLError(f"no addresses for {host!r}")
        blocked = [ip for ip in ips if not is_public_ip(ip)]
        if blocked:
            raise BlockedURLError(f"{host!r} resolves to non-public address {blocked[0]}")
        return parsed, ips[0]

    def fetch(self, url: str) -> FetchResult:
        current: str | httpx.URL = url
        give_up_at = time.monotonic() + self._deadline
        for _ in range(self._max_redirects + 1):
            parsed, ip = self.validate(current)
            request = self._client.build_request(
                "GET",
                parsed.copy_with(host=ip),
                headers={"Host": parsed.netloc.decode("ascii")},
                extensions={"sni_hostname": parsed.raw_host.decode("ascii")},
            )
            try:
                response = self._client.send(request, stream=True)
            except httpx.RemoteProtocolError as exc:  # includes unparseable Location headers
                raise BlockedURLError(f"protocol error: {exc}") from exc
            try:
                if response.status_code in REDIRECT_STATUS and "location" in response.headers:
                    try:
                        current = parsed.join(response.headers["location"])
                    except httpx.InvalidURL as exc:
                        raise BlockedURLError(f"invalid redirect: {exc}") from exc
                    continue
                content, truncated = self._read_capped(response, give_up_at)
                return FetchResult(
                    url=str(parsed),
                    status_code=response.status_code,
                    content_type=response.headers.get("content-type"),
                    content=content,
                    truncated=truncated,
                )
            finally:
                response.close()
        raise BlockedURLError(f"more than {self._max_redirects} redirects")

    def _read_capped(self, response: httpx.Response, give_up_at: float) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_bytes():
            if time.monotonic() > give_up_at:
                raise BlockedURLError("fetch exceeded overall deadline")
            remaining = self._max_bytes - size
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                return b"".join(chunks), True
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks), False
