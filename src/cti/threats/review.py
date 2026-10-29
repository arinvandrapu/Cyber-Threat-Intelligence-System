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
# Link review: does the evidence report this family using or exploiting this CVE?
LINK_COLUMNS = ("family", "cve", "via", "surface", "evidence_url", "correct", "notes")
CORRECT = ("yes", "no")


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


def append_families(path: Path, fams: list[Family], ranks: dict[str, int]) -> list[Family]:
    """Add blank rows for families the sheet lacks; existing rows are never touched.

    ``ranks``: family -> its frequency rank among named families (the ``rank`` column).
    """
    with path.open(newline="", encoding="utf-8") as fh:
        present = {row["family"] for row in csv.DictReader(fh)}
    new = [f for f in fams if f.name not in present]
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        for fam in new:
            writer.writerow(
                [ranks[fam.name], fam.name, LABEL_SEPARATOR.join(fam.ids), fam.rows, "", ""]
            )
    return new


def status(path: Path, column: str = "categories") -> str:
    """``missing``, ``blank`` (written, not yet labelled) or ``labelled``."""
    if not path.exists():
        return "missing"
    with path.open(newline="", encoding="utf-8") as fh:
        filled = any(row[column].strip() for row in csv.DictReader(fh))
    return "labelled" if filled else "blank"


def read_labels(path: Path) -> dict[str, tuple[str, ...]]:
    """Family -> owner categories. Every row must be labelled from ``CATEGORIES``, so a
    half-finished sheet is refused rather than silently mixed with automatic labels."""
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


def write_link_sheet(path: Path, links: list[dict]) -> int:
    """Every CVE link, one row per (family, CVE, via), for the owner to mark; never overwrites.

    ``links``: dicts with family, cve, via, surface, evidence_url. Rows are sorted, so the
    sheet is the same on every run.
    """
    rows = sorted({tuple(link[c] for c in LINK_COLUMNS[:5]) for link in links})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(LINK_COLUMNS)
        writer.writerows([*row, "", ""] for row in rows)
    return len(rows)


def append_links(path: Path, links: list[dict]) -> int:
    """Add blank rows for links the sheet lacks; existing rows (and marks) are untouched."""
    present = link_keys(path)
    rows = sorted(
        r
        for r in {tuple(link[c] for c in LINK_COLUMNS[:5]) for link in links}
        if r[:3] not in present
    )
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerows([*row, "", ""] for row in rows)
    return len(rows)


def link_keys(path: Path) -> set[tuple[str, str, str]]:
    """The (family, CVE, via) rows a link sheet lists."""
    with path.open(newline="", encoding="utf-8") as fh:
        return {(r["family"], r["cve"], r["via"]) for r in csv.DictReader(fh)}


def read_link_labels(path: Path) -> dict[tuple[str, str, str], bool]:
    """(family, CVE, via) -> correct, for rows marked yes or no. A blank row is a link not
    yet reviewed (e.g. appended by a later run) and is left out; anything else is refused."""
    labels = {}
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            mark = row["correct"].strip().lower()
            if not mark:
                continue
            if mark not in CORRECT:
                raise ValueError(f"{path}: {row['family']} {row['cve']}: correct must be yes/no")
            labels[(row["family"], row["cve"], row["via"])] = mark == "yes"
    return labels
