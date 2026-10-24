"""Choose which CVE reference pages the one-time ingest scrapes.

Bounded by design: KEV-listed CVEs first (most recently added first), then the highest
snapshot EPSS scores, up to ``per_cve`` pages per CVE and ``max_pages`` overall.

These pages reflect snapshot-time knowledge and the selection itself uses KEV/EPSS, so
scraped text is never a feature in the forward-looking risk evaluation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from cti.references.classifier import SCRAPE_PRIORITY, RefType, classify_url, normalize_host


@dataclass(frozen=True)
class Target:
    cve: str
    url: str
    ref_type: RefType


def rank_cves(
    window_cves: Iterable[str],
    kev_added: Mapping[str, str],
    epss: Mapping[str, float],
) -> list[str]:
    in_window = set(window_cves)
    kev = sorted(
        (c for c in in_window if c in kev_added), key=lambda c: (kev_added[c], c), reverse=True
    )
    rest = sorted(
        (c for c in in_window if c not in kev_added), key=lambda c: (-epss.get(c, 0.0), c)
    )
    return kev + rest


def pick_references(urls: Iterable[str], per_cve: int) -> list[tuple[str, RefType]]:
    """Best ``per_cve`` scrape-worthy URLs, at most one per host."""
    priority = {t: i for i, t in enumerate(SCRAPE_PRIORITY)}
    candidates = []
    for position, url in enumerate(dict.fromkeys(urls)):
        ref_type = classify_url(url)
        if ref_type in priority:
            candidates.append((priority[ref_type], position, url, ref_type))
    picked, hosts = [], set()
    for _, _, url, ref_type in sorted(candidates):
        host = normalize_host(urlsplit(url).netloc)
        if host in hosts:
            continue
        hosts.add(host)
        picked.append((url, ref_type))
        if len(picked) == per_cve:
            break
    return picked


def select_targets(
    references: Mapping[str, list[str]],
    kev_added: Mapping[str, str],
    epss: Mapping[str, float],
    *,
    per_cve: int,
    max_pages: int,
) -> list[Target]:
    targets: list[Target] = []
    seen_urls: set[str] = set()
    for cve in rank_cves(references, kev_added, epss):
        for url, ref_type in pick_references(references[cve], per_cve):
            if url in seen_urls:
                continue
            seen_urls.add(url)
            targets.append(Target(cve, url, ref_type))
            if len(targets) >= max_pages:
                return targets
    return targets
