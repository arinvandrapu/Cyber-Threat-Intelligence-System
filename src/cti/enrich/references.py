"""Cleaned reference pages: the long-form text corpus for NER and ATT&CK mapping.

Read from the raw snapshot (the parsed records hold flattened text, not HTML). A page is in
the corpus when it has at least ``MIN_CHARS`` of extracted text; JavaScript shells and PDFs
are kept as rows, flagged, so coverage is reported honestly. Only a completed references
source is cleaned, so a partial scrape can't pass for the corpus. Page text is never a risk
feature (it reflects snapshot-time knowledge and scrape selection favored KEV CVEs).
"""

from __future__ import annotations

import statistics
from collections import Counter
from urllib.parse import urlsplit

from cti.enrich.cleaner import CVE_ID, MIN_CHARS, clean, with_length_flag
from cti.references.classifier import RefType, classify_url, normalize_host
from cti.snapshot import Snapshot
from cti.sources.references import iter_pages, page_id

SCHEMA = 1


def build(snapshot: Snapshot) -> tuple[list[dict], dict]:
    if not snapshot.is_complete("references"):
        raise ValueError(f"references is not complete in snapshot {snapshot.id}")
    rows = []
    for record, body in iter_pages(snapshot):
        url = record["url"]
        ref_type = classify_url(url)  # reclassified: the stored type predates EXPLOIT
        cleaned = with_length_flag(
            clean(
                body, record.get("content_type", ""), mailing_list=ref_type == RefType.MAILING_LIST
            )
        )
        rows.append(
            {
                "schema": SCHEMA,
                "id": f"references:{page_id(url)}",
                "cve": record["cve"],
                "url": url,
                "final_url": record.get("final_url"),
                "ref_type": str(ref_type),
                "content_type": record.get("content_type"),
                "truncated": record.get("truncated", False),
                "method": cleaned.method,
                "flags": sorted(cleaned.flags),
                "text": cleaned.text,
                "chars": len(cleaned.text),
                "full_chars": cleaned.full_chars,
                "cve_ids": sorted({m.upper() for m in CVE_ID.findall(cleaned.text)}),
                "in_corpus": len(cleaned.text) >= MIN_CHARS,
            }
        )
    rows.sort(key=lambda r: r["id"])
    return rows, _summary(rows)


def _summary(rows: list[dict]) -> dict:
    html = [r for r in rows if r["content_type"] not in ("application/pdf", "text/plain")]
    extracted = [r for r in html if r["method"] != "none"]
    own_cve = [r for r in extracted if r["cve"] in r["cve_ids"]]
    flagged = Counter(f for r in rows for f in r["flags"])
    shell_hosts = Counter(
        normalize_host(urlsplit(r["url"]).netloc) for r in rows if "js_shell" in r["flags"]
    )
    return {
        "schema": SCHEMA,
        "pages": len(rows),
        "in_corpus": sum(r["in_corpus"] for r in rows),
        "cves_with_corpus_page": len({r["cve"] for r in rows if r["in_corpus"]}),
        "methods": dict(sorted(Counter(r["method"] for r in rows).items())),
        "flags": dict(sorted(flagged.items())),
        "js_shell_hosts": dict(shell_hosts.most_common(10)),
        # pages whose cleaned text still names their CVE (headers/sidebars often carry it)
        "own_cve_in_text": f"{len(own_cve)}/{len(extracted)}",
        "median_chars_html": {
            "full_page": statistics.median([r["full_chars"] for r in extracted] or [0]),
            "cleaned": statistics.median([r["chars"] for r in extracted] or [0]),
        },
    }
