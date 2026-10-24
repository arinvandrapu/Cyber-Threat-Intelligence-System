"""Defang indicators so they can't be clicked or auto-linked.

``https://evil.example.com/x`` -> ``hxxps://evil[.]example[.]com/x``,
``203.0.113.7`` -> ``203.0.113[.]7``.
"""

from __future__ import annotations

import re

_SCHEME_RE = re.compile(r"^http(s?)(?=://)", re.IGNORECASE)


def defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    if ":" in ip:  # IPv6: colons are not auto-linked; bracket for consistency
        return f"[{ip}]"
    head, _, last = ip.rpartition(".")
    return f"{head}[.]{last}" if head else ip


def defang_url(url: str) -> str:
    url = _SCHEME_RE.sub(lambda m: f"hxxp{m.group(1).lower()}", url)
    scheme, sep, rest = url.partition("://")
    if not sep:
        scheme, rest = "", url
    host, slash, path = rest.partition("/")
    return f"{scheme}{sep}{defang_host(host)}{slash}{path}"


def refang(text: str) -> str:
    return re.sub(r"^hxxp", "http", text.replace("[.]", "."), flags=re.IGNORECASE)
