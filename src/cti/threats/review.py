"""The owner's blind review sheet: the most frequent named families, labelled by hand.

The sheet is written before any automatic label exists and shows only names, ThreatFox
family IDs and row counts (aggregates), so the owner's labels are independent of the
MISP-derived ones they are later compared with. Writing never overwrites a sheet, so
filled-in labels cannot be lost to a re-run.
"""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from cti.threats.config import CATEGORIES, LABEL_SEPARATOR, REVIEW_TOP_N, UNKNOWN_MARKER

COLUMNS = ("rank", "family", "malware_ids", "ioc_rows", "categories", "notes")


@dataclass(frozen=True)
class Family:
    name: str  # ThreatFox malware_printable: one family across platforms
    ids: tuple[str, ...]  # its Malpedia-style IDs (elf.mirai, win.mirai)
    rows: int


def families(iocs: Iterable[dict]) -> list[Family]:
    """Families in parsed ThreatFox records, most rows first (ties by name)."""
    rows: Counter[str] = Counter()
    ids: dict[str, set[str]] = defaultdict(set)
    for doc in iocs:
        meta = doc["metadata"]
        rows[meta["malware"]] += 1
        if meta.get("malware_id"):
            ids[meta["malware"]].add(meta["malware_id"])
    return [
        Family(name, tuple(sorted(ids[name])), n)
        for name, n in sorted(rows.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def is_named(family: Family) -> bool:
    return UNKNOWN_MARKER not in family.name.lower()


def write_sheet(path: Path, fams: list[Family], top_n: int = REVIEW_TOP_N) -> list[Family]:
    """Write the blank sheet for the top ``top_n`` named families; never overwrites."""
    top = [f for f in fams if is_named(f)][:top_n]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", newline="", encoding="utf-8") as fh:  # "x": refuse an existing sheet
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(COLUMNS)
        for rank, fam in enumerate(top, 1):
            writer.writerow([rank, fam.name, LABEL_SEPARATOR.join(fam.ids), fam.rows, "", ""])
    return top


def read_labels(path: Path) -> dict[str, tuple[str, ...]]:
    """Family -> owner categories. Every row must be labelled from ``CATEGORIES``."""
    labels: dict[str, tuple[str, ...]] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cats = tuple(
                c.strip().lower() for c in row["categories"].split(LABEL_SEPARATOR) if c.strip()
            )
            if not cats:
                raise ValueError(f"{path}: {row['family']!r} has no category")
            unknown = sorted(set(cats) - set(CATEGORIES))
            if unknown:
                raise ValueError(f"{path}: {row['family']!r} has unknown categories {unknown}")
            labels[row["family"]] = tuple(sorted(set(cats)))
    return labels
