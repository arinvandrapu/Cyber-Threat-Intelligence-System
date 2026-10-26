"""Rule-based classification of CVE reference URLs by host and path."""

from __future__ import annotations

import re
from enum import StrEnum
from urllib.parse import urlsplit


class RefType(StrEnum):
    VENDOR_ADVISORY = "vendor_advisory"
    GOVERNMENT = "government"
    GITHUB_ADVISORY = "github_advisory"
    GITHUB_COMMIT = "github_commit"
    GITHUB_ISSUE = "github_issue"
    GITHUB_REPO = "github_repo"
    PATCH = "patch"
    MAILING_LIST = "mailing_list"
    CODE = "code"
    MEDIA = "media"
    ARTICLE = "article"
    UNKNOWN = "unknown"


# Hosts are compared after lowercasing and stripping a leading "www.".
ADVISORY_HOSTS = frozenset(
    {
        "security.gentoo.org",
        "debian.org",
        "ubuntu.com",
        "access.redhat.com",
        "security.netapp.com",
        "cert.org",
        "kb.cert.org",
        "jvn.jp",
        "jvndb.jvn.jp",
        "oracle.com",
        "zerodayinitiative.com",
        "exploit-db.com",
        "packetstormsecurity.com",
        "msrc.microsoft.com",
        "portal.msrc.microsoft.com",
        "chromereleases.googleblog.com",
        "support.apple.com",
        "mozilla.org",
        "bugzilla.mozilla.org",
        "bugzilla.redhat.com",
        "bugs.chromium.org",
        "wpscan.com",
        "patchstack.com",
        "wordfence.com",
        "vuldb.com",
    }
)
GOVERNMENT_HOSTS = frozenset(
    {
        "cyber.gov.au",
        "ncsc.gov.uk",
        "cert.europa.eu",
        "cert.ssi.gouv.fr",
        "bsi.bund.de",
    }
)
MAILING_LIST_HOSTS = frozenset(
    {
        "seclists.org",
        "openwall.com",
        "marc.info",
        "mail-archive.com",
    }
)
MEDIA_HOSTS = frozenset({"youtube.com", "youtu.be", "vimeo.com", "dailymotion.com"})
CODE_HOSTS = frozenset(
    {
        "pastebin.com",
        "paste.debian.net",
        "dpaste.org",
        "hastebin.com",
        "gist.github.com",
        "raw.githubusercontent.com",
    }
)
# Pages that only restate the CVE record itself: never worth fetching.
SELF_REFERENCE_HOSTS = frozenset({"nvd.nist.gov", "cve.org", "cve.mitre.org"})
# Same idea for one page on a host that is otherwise worth fetching: the KEV catalog page
# restates the KEV feed we already ingest (and cisa.gov answers 403 to non-browser clients).
SELF_REFERENCE_PAGES = frozenset({("cisa.gov", "/known-exploited-vulnerabilities-catalog")})

_ADVISORY_PATH = re.compile(
    r"/(advisory|advisories|security-advisory|security-notice|security-bulletin|vuln/"
    r"|vulnerability/|cve-\d{4})",
    re.IGNORECASE,
)
_PATCH_PATH = re.compile(r"/(patch|diff|changeset)(/|$)", re.IGNORECASE)


def normalize_host(netloc: str) -> str:
    host = netloc.lower().rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".")
    return host.removeprefix("www.")


def classify_url(url: str) -> RefType:
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return RefType.UNKNOWN
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return RefType.UNKNOWN
    host = normalize_host(parts.netloc)
    path = parts.path or ""

    if host in SELF_REFERENCE_HOSTS or (host, path.rstrip("/").lower()) in SELF_REFERENCE_PAGES:
        return RefType.UNKNOWN
    if host in CODE_HOSTS:
        return RefType.CODE
    if host == "github.com":
        if "/advisories/GHSA-" in path:
            return RefType.GITHUB_ADVISORY
        lowered = path.lower()
        if "/commit/" in lowered:
            return RefType.GITHUB_COMMIT
        if "/issues/" in lowered or "/pull/" in lowered:
            return RefType.GITHUB_ISSUE
        return RefType.GITHUB_REPO
    if host in MEDIA_HOSTS:
        return RefType.MEDIA
    if host in MAILING_LIST_HOSTS or host.startswith("lists."):
        return RefType.MAILING_LIST
    if host.endswith((".gov", ".gov.uk", ".gov.au", ".mil")) or host in GOVERNMENT_HOSTS:
        return RefType.GOVERNMENT
    if host in ADVISORY_HOSTS:
        return RefType.VENDOR_ADVISORY
    if _PATCH_PATH.search(path):
        return RefType.PATCH
    if _ADVISORY_PATH.search(path):
        return RefType.VENDOR_ADVISORY
    return RefType.ARTICLE


# Order in which reference types are worth scraping for analyst-readable text.
SCRAPE_PRIORITY: tuple[RefType, ...] = (
    RefType.VENDOR_ADVISORY,
    RefType.GOVERNMENT,
    RefType.GITHUB_ADVISORY,
    RefType.ARTICLE,
    RefType.MAILING_LIST,
    RefType.GITHUB_ISSUE,
)
