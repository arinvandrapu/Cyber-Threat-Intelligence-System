"""Regex IOC extraction: IPs, domains, URLs, hashes, CVE IDs, and CVSS vectors.

Matching runs on the original text, so ``start``/``end`` index it. Defanged forms in the
text (``hxxp``, ``[.]``, ``(.)``, ``[dot]``, ``[:]``) are matched directly, then normalized
with ``refang``. A regex match is only a candidate: IPs are checked with ``ipaddress``,
domains against the public-suffix list bundled with tldextract (never fetched), and CVSS
vectors against the FIRST grammar. Network indicators are stored defanged, so
``refang(ioc.value)`` is the normalized indicator.

Spans never overlap: a URL's host is not also reported as a domain, and a version string
inside a URL is not an IP. Earlier types in ``PRIORITY`` win.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from functools import cache
from urllib.parse import urlsplit

import tldextract

from cti.defang import defang_host, defang_ip, defang_url, refang

PRIORITY = ("url", "cvss", "cve", "sha256", "sha1", "md5", "ipv4", "ipv6", "domain")

_DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))"
_COLON = r"(?::|\[:\])"

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"  # 0-255, no leading zeros
# `(?![\w]|DOT\w)` rejects the first four parts of 10.0.19041.1 or 1.2.3.4.5 while still
# allowing a sentence-ending dot after the address
IPV4_RE = re.compile(rf"(?<![\w.-]){_OCTET}(?:{_DOT}{_OCTET}){{3}}(?!\w|{_DOT}\w)", re.IGNORECASE)
# version numbers written like addresses: "version 10.0.0.1", "prior to versions 8.1.2.1,
# 8.0.4.1, and 7.2.3.1" (a version keyword, then only version-like items), "7.3.0.0 through"
_VERSION_ITEM = r"[\w.()+-]*\d[\w.()+-]*"
_VERSION_BEFORE = re.compile(
    r"(?:\bv|\bver|\bversions?|\bbuild|\brelease|\bfirmware|\bupdate|\bpatch|\bLTS|\bthrough"
    r"|\bbefore|\bprior to|\bup to|(?<![=-])[<>]=?)"
    rf"(?:[\s,:#]+(?:{_VERSION_ITEM}|and|or|through|to|including|n/a))*[\s,:#]*$",
    re.IGNORECASE,
)
# a three-part version nearby means a version list: "OTP 28.4.2 and OTP 27.3.4.10"
_VERSION_NEAR = re.compile(r"(?<![\w.\]])\d+\.\d+\.\d+(?![\w.\[(]|\.\d)")
# "Netgear EX6200 1.0.3.94", "Kirby 3.10.1.2": a product name right before the number
_PRODUCT_BEFORE = re.compile(r"\b(?P<word>[A-Za-z][\w-]*[A-Z0-9][\w-]*|[A-Z][a-z]+)[:,]?\s+$")
_IP_WORDS = frozenset({"ip", "ips", "ipv4", "address", "addresses", "host", "server", "c2", "cnc"})
_VERSION_AFTER = re.compile(
    r"(?:-\d|\s*(?:\(\d|through\b|and (?:earlier|later|prior|before)\b|or (?:earlier|later)\b"
    r"|-r\d|iFix|SP\d|build\b|LTS\b|and (?:above|newer)\b))",
    re.IGNORECASE,
)

IPV6_RE = re.compile(
    rf"(?<![\w:.])(?:[0-9a-f]{{0,4}}{_COLON}){{2,7}}[0-9a-f]{{0,4}}(?![\w:.])", re.IGNORECASE
)

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN_RE = re.compile(
    rf"(?<![\w.@/\\>-])(?:{_LABEL}{_DOT})+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{2,59}})"
    rf"(?![\w-]|{_DOT}\w|\()",  # "(": a method call such as "obj.name(", not a host
    re.IGNORECASE,
)
# Plain-text names are mostly code (Foo.java, list.next, subprocess.run, os.Open), so a name
# that the text did not defang must end in a legacy gTLD or a two-letter ccTLD. Real IOCs
# on newer TLDs (.xyz, .top, .dev) are nearly always written defanged, which is accepted.
_LEGACY_TLDS = frozenset({"com", "net", "org", "edu", "gov", "mil", "int", "info", "biz"})
# Newer TLDs with at least 30 hosts in the 2026-10-26 ThreatFox + URLhaus data, minus those
# that are also common code identifiers (run, app, dev, download, host, store, click...)
_ABUSED_TLDS = frozenset(
    {"xyz", "top", "lat", "surf", "shop", "bet", "garden", "pics", "beer", "icu", "cfd"}
    | {"online", "lol", "site", "pro", "cyou", "sbs", "onion", "casino", "club", "asia"}
    | {"buzz", "vip", "ink", "monster", "mom", "website", "bond", "quest", "cam", "best"}
    | {"digital", "life", "christmas", "courses", "poker", "football"}
)
# ccTLDs that are far more often a file extension, when the name has no subdomain:
# setup.py, README.md, build.sh, lib.rs, Makefile.in, login.do, model.pt
_CODE_SUFFIXES = frozenset(
    {"py", "md", "sh", "rs", "pl", "pm", "so", "cc", "ps", "id", "do", "mk", "tf", "in", "la"}
    | {"ml", "pt", "mo"}
)
_CAMEL = re.compile(r"[a-z][A-Z]")

_URL_CHAR = r"[^\s<>\"'`{}|\\^\[\]()]"
URL_RE = re.compile(
    rf"\b(?:h(?:tt|xx)ps?|s?ftp|fxp){_COLON}//"
    rf"(?:{_URL_CHAR}|\[\.\]|\[:\]|\[dot\]|\(\.\)|\{{\.\}}|\(dot\)|\[[0-9a-f:.]+\])+",
    re.IGNORECASE,
)
_URL_TRAIL = ".,;:!?'\""

HASH_RE = re.compile(
    r"(?<![\w/.=@#-])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![\w/.=-])", re.IGNORECASE
)
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
# commit IDs: "commit 1a2b...", "before e28e...", "up to 92f5...", "check-in 8bdc..."
_GIT_CONTEXT = re.compile(
    r"\b(?:commit|revision|rev|git|check-in|before|through|up to|prior to|version)\b"
    r"[^\n]{0,12}$",
    re.IGNORECASE,
)

CVE_RE = re.compile(r"(?<![\w-])CVE-\d{4}-\d{4,7}(?!\d)", re.IGNORECASE)

CVSS_RE = re.compile(r"CVSS:(3\.[01]|4\.0)((?:/[A-Za-z]{1,3}:[A-Za-z]{1,5})+)")

# CVSS v3.x: the 8 base metrics are required, each metric appears once, order is free
_V3 = {
    **{"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC"},
    **{"C": "HLN", "I": "HLN", "A": "HLN"},
    **{"E": "XUPFH", "RL": "XOTWU", "RC": "XURC", "CR": "XLMH", "IR": "XLMH", "AR": "XLMH"},
    **{"MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC"},
    **{"MC": "XHLN", "MI": "XHLN", "MA": "XHLN"},
}
_V3_BASE = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
# CVSS v4.0: fixed order; the first 11 (base) are required, the rest optional
_V4 = (
    *(("AV", "NALP"), ("AC", "LH"), ("AT", "NP"), ("PR", "NLH"), ("UI", "NPA")),
    *(("VC", "HLN"), ("VI", "HLN"), ("VA", "HLN"), ("SC", "HLN"), ("SI", "HLN"), ("SA", "HLN")),
    *(("E", "XAPU"), ("CR", "XHML"), ("IR", "XHML"), ("AR", "XHML")),
    *(("MAV", "XNALP"), ("MAC", "XLH"), ("MAT", "XNP"), ("MPR", "XNLH"), ("MUI", "XNPA")),
    *(("MVC", "XHLN"), ("MVI", "XHLN"), ("MVA", "XHLN"), ("MSC", "XHLN")),
    *(("MSI", "XSHLN"), ("MSA", "XSHLN")),
    *(("S", "XNP"), ("AU", "XNY"), ("R", "XAUI"), ("V", "XDC"), ("RE", "XLMH")),
    ("U", ("X", "Clear", "Green", "Amber", "Red")),
)
_V4_BASE_COUNT = 11


@dataclass(frozen=True, slots=True)
class Ioc:
    type: str
    value: str  # normalized; defanged for network types (refang() restores it)
    start: int
    end: int
    defanged_in_source: bool  # the text already had it defanged
    public: bool | None = None  # IPs only: globally routable

    def as_dict(self) -> dict:
        return asdict(self)


@cache
def _psl() -> tldextract.TLDExtract:
    # suffix_list_urls=() and no cache: use the snapshot bundled with the package, never
    # the network (offline, reproducible)
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def valid_cvss(vector: str) -> bool:
    m = re.fullmatch(CVSS_RE, vector)
    if not m:
        return False
    pairs = [p.split(":") for p in m.group(2).lstrip("/").split("/")]
    if m.group(1).startswith("3"):
        names = [k for k, _ in pairs]
        if len(set(names)) != len(names) or not set(_V3_BASE) <= set(names):
            return False
        return all(k in _V3 and len(v) == 1 and v in _V3[k] for k, v in pairs)
    i = 0
    for k, v in pairs:
        while i < len(_V4) and _V4[i][0] != k:
            if i < _V4_BASE_COUNT:
                return False  # a base metric is missing or out of order
            i += 1
        if i == len(_V4) or v not in _V4[i][1] or (isinstance(_V4[i][1], str) and len(v) != 1):
            return False
        i += 1
    return i >= _V4_BASE_COUNT


def _is_domain(name: str, surface: str, defanged: bool) -> bool:
    ext = _psl()(name)
    if not (ext.domain and ext.suffix) or not re.search("[a-z]", ext.domain):
        return False  # 4.1.135.Final
    if any(label.isdigit() for label in name.split(".")[1:]):
        return False  # version strings: rel-1.16.0-0-g...-prebuilt.qemu.org
    if defanged:
        return True
    tld = ext.suffix.rsplit(".", 1)[-1]
    if tld not in _LEGACY_TLDS and tld not in _ABUSED_TLDS and len(tld) != 2:
        return False
    bare = not ext.subdomain
    if bare and ext.suffix in _CODE_SUFFIXES:
        return False
    if _CAMEL.search(surface):
        return False  # downloadDocEx.do, CloudTaskService.java
    last = surface.rsplit(".", 1)[-1]
    # ASP.NET (a product), "supported.You" (a missing space after a full stop)
    return not (bare and (surface.isupper() or last.istitle()))


def _looks_like_version(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - 80) : start]
    if _VERSION_BEFORE.search(before) or _VERSION_AFTER.match(text, end):
        return True
    # search the whole text (not a slice) so a quad cut at the window edge isn't a version
    near = _VERSION_NEAR.search(text, max(0, start - 60))
    if near and near.start() <= end + 60:
        return True
    product = _PRODUCT_BEFORE.search(before)
    return bool(product) and product["word"].lower() not in _IP_WORDS


def _candidates(text: str):
    for m in URL_RE.finditer(text):
        raw = m.group().rstrip(_URL_TRAIL)
        url = refang(raw)
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        if host and ("." in host or ":" in host):
            yield "url", defang_url(url), m.start(), m.start() + len(raw), raw != url, None
    for m in CVSS_RE.finditer(text):
        if valid_cvss(m.group()):
            yield "cvss", m.group(), m.start(), m.end(), False, None
    for m in CVE_RE.finditer(text):
        yield "cve", m.group().upper(), m.start(), m.end(), False, None
    for m in HASH_RE.finditer(text):
        value = m.group().lower()
        if not (re.search("[a-f]", value) and re.search("[0-9]", value)):
            continue  # 9999...: a number, not a digest
        if _GIT_CONTEXT.search(text, max(0, m.start() - 40), m.start()):
            continue
        yield _HASH_TYPES[len(value)], value, m.start(), m.end(), False, None
    for m in IPV4_RE.finditer(text):
        ip = refang(m.group())
        defanged = ip != m.group()
        # an address the text defanged is an indicator; only plain ones can be versions
        if not defanged and _looks_like_version(text, m.start(), m.end()):
            continue
        public = ipaddress.ip_address(ip).is_global
        yield "ipv4", defang_ip(ip), m.start(), m.end(), defanged, public
    for m in IPV6_RE.finditer(text):
        ip = refang(m.group())
        if ip.count(":") < 2 or not re.search(r"[0-9a-f]", ip, re.IGNORECASE):
            continue
        try:
            addr = ipaddress.IPv6Address(ip)
        except ValueError:
            continue
        yield "ipv6", defang_ip(str(addr)), m.start(), m.end(), ip != m.group(), addr.is_global
    for m in DOMAIN_RE.finditer(text):
        name = refang(m.group()).lower()
        defanged = name != m.group().lower()
        if _is_domain(name, m.group(), defanged):
            yield "domain", defang_host(name), m.start(), m.end(), defanged, None


def extract(text: str) -> list[Ioc]:
    """All IOCs in ``text``, sorted by position, with no overlapping spans."""
    rank = {t: i for i, t in enumerate(PRIORITY)}
    found = sorted(_candidates(text), key=lambda c: (rank[c[0]], c[2]))
    taken: list[tuple[int, int]] = []
    out = []
    for kind, value, start, end, defanged, public in found:
        if any(start < e and s < end for s, e in taken):
            continue
        taken.append((start, end))
        out.append(Ioc(kind, value, start, end, defanged, public))
    return sorted(out, key=lambda i: (i.start, i.type))
