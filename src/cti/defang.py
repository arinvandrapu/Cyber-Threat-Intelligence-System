"""Defang indicators so they can't be clicked or auto-linked.

``https://evil.example.com/x`` -> ``hxxps://evil[.]example[.]com/x``,
``203.0.113.7`` -> ``203.0.113[.]7``, ``2001:db8::1`` -> ``2001[:]db8[:][:]1``.
``refang`` undoes these and the other common in-text forms (``(.)``, ``{.}``, ``[dot]``,
``[:]``, ``[@]``, ``hxxp``/``fxp`` anywhere).
"""

from __future__ import annotations

import re

_SCHEME_RE = re.compile(r"^http(s?)(?=://)", re.IGNORECASE)


def defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    if ":" in ip:  # IPv6; "[...]" would read as a URL host, so bracket the colons instead
        return ip.replace(":", "[:]")
    head, _, last = ip.rpartition(".")
    return f"{head}[.]{last}" if head else ip


def defang_url(url: str) -> str:
    url = _SCHEME_RE.sub(lambda m: f"hxxp{m.group(1).lower()}", url)
    scheme, sep, rest = url.partition("://")
    if not sep:
        scheme, rest = "", url
    host, slash, path = rest.partition("/")
    return f"{scheme}{sep}{defang_host(host)}{slash}{path}"


_REFANG = (
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\bhxxp", re.IGNORECASE), "http"),
    (re.compile(r"\bfxp(?=s?(?::|\[:\])//)", re.IGNORECASE), "ftp"),
)


def refang(text: str) -> str:
    for pattern, plain in _REFANG:
        text = pattern.sub(plain, text)
    return text
