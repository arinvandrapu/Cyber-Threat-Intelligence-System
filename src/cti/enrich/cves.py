"""One record per NVD CVE, joining every per-CVE source, shaped against label leakage.

Record layout (``schema`` 1)::

    cve, published
    signals:  {<as_of>: {epss, exploitdb, metasploit, nuclei, vulnrichment}}
    eligible: {<as_of>: bool}     published by that date and not yet in KEV
    kev:      {date_added, ransomware_use} | None            label source only
    context_snapshot: {vuln_status, cvss_nvd, cvss_cna, cwes, ref_count, ref_types,
                       page_count}                           as known at the snapshot

Only ``signals[<as_of>]`` is pinned to a date, so :func:`features_at` is the one allowed
path to point-in-time risk features. ``context_snapshot`` holds what was known at the
snapshot: NVD analysts work on KEV-listed CVEs first, so NVD status, scores, CWEs, and
reference lists are biased toward the label (see vault/risk-scoring-design.md). Phase 7
uses them only in a labelled ablation. The join is generic over ``as_of`` labels, so more
cutoffs can be added later without changing it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from cti.enrich import read_jsonl
from cti.enrich.cwe import CweEntry, describe
from cti.references.classifier import classify_url

SCHEMA = 1
SIGNAL_SOURCES = ("epss", "exploitdb", "metasploit", "nuclei", "vulnrichment")


def cve_sort_key(cve: str) -> tuple[int, int]:
    _, year, number = cve.split("-")
    return int(year), int(number)


def features_at(record: dict, as_of: str) -> dict:
    """The point-in-time features of ``record`` as of ``as_of``: nothing else is safe."""
    return record["signals"].get(as_of, {})


def known_in_kev(record: dict, date: str) -> bool:
    kev = record["kev"]
    return kev is not None and kev["date_added"] <= date


def _signals(processed: Path) -> Iterator[dict]:
    for source in SIGNAL_SOURCES:
        for row in read_jsonl(processed / f"{source}.jsonl.gz"):
            if "as_of" in row:  # ExploitDB also emits documents
                yield row


def build(
    processed: Path, catalog: dict[str, CweEntry], as_of_dates: dict[str, str]
) -> tuple[list[dict], dict]:
    """Join everything onto NVD CVEs. Returns sorted records and summary counts."""
    records: dict[str, dict] = {}
    ref_totals: Counter[str] = Counter()
    for doc in read_jsonl(processed / "nvd.jsonl.gz"):
        meta = doc["metadata"]
        ref_types = Counter(str(classify_url(u)) for u in meta["references"])
        ref_totals.update(ref_types)
        records[doc["source_id"]] = {
            "schema": SCHEMA,
            "cve": doc["source_id"],
            "published": doc["published"],
            "signals": {},
            "eligible": {},
            "kev": None,
            "context_snapshot": {
                "vuln_status": meta["vuln_status"],
                "cvss_nvd": meta["cvss_nvd"],
                "cvss_cna": meta["cvss_cna"],
                "cwes": [describe(catalog, c) for c in meta["cwes"]],
                "ref_count": len(meta["references"]),
                "ref_types": dict(sorted(ref_types.items())),
                "page_count": 0,
            },
        }

    for doc in read_jsonl(processed / "kev.jsonl.gz"):
        if record := records.get(doc["source_id"]):
            meta = doc["metadata"]
            record["kev"] = {
                "date_added": meta["date_added"],
                "ransomware_use": meta["ransomware_use"],
            }

    signal_counts: Counter[tuple[str, str]] = Counter()
    for row in _signals(processed):
        if row["as_of"] not in as_of_dates:
            raise ValueError(f"no date for as_of label {row['as_of']!r}")
        if record := records.get(row["cve"]):
            record["signals"].setdefault(row["as_of"], {})[row["source"]] = row["values"]
            signal_counts[row["as_of"], row["source"]] += 1

    for doc in read_jsonl(processed / "references.jsonl.gz"):
        for cve in doc["cves"]:
            if record := records.get(cve):
                record["context_snapshot"]["page_count"] += 1

    for record in records.values():
        for label, date in as_of_dates.items():
            record["eligible"][label] = record["published"][:10] <= date and not known_in_kev(
                record, date
            )

    rows = [records[c] for c in sorted(records, key=cve_sort_key)]
    return rows, _summary(rows, catalog, as_of_dates, signal_counts, ref_totals)


def _summary(rows, catalog, as_of_dates, signal_counts, ref_totals) -> dict:
    cwe_kinds = Counter(c["kind"] for r in rows for c in r["context_snapshot"]["cwes"])
    unknown = Counter(
        c["id"] for r in rows for c in r["context_snapshot"]["cwes"] if c["kind"] == "unknown"
    )
    labels = sorted(as_of_dates, key=as_of_dates.get)
    # Forward-looking positives: eligible at an earlier date, in KEV by a later one.
    positives = {
        f"{early}->{late}": sum(
            r["eligible"][early]
            and r["kev"] is not None
            and as_of_dates[early] < r["kev"]["date_added"] <= as_of_dates[late]
            for r in rows
        )
        for i, early in enumerate(labels)
        for late in labels[i + 1 :]
    }
    return {
        "schema": SCHEMA,
        "as_of_dates": as_of_dates,
        "cves": len(rows),
        "in_kev": sum(r["kev"] is not None for r in rows),
        "eligible": {label: sum(r["eligible"][label] for r in rows) for label in labels},
        "kev_positives": positives,
        "signals": {f"{a}/{s}": n for (a, s), n in sorted(signal_counts.items())},
        "cwe_mentions_by_kind": dict(sorted(cwe_kinds.items())),
        "cwe_unknown_ids": dict(unknown.most_common()),
        "catalog_entries": len(catalog),
        "reference_types": dict(sorted(ref_totals.items())),
    }
