"""CWE lookup: name, kind, and View-1000 pillar for every ID in the catalog.

The ``cwe`` parser emits only current Weaknesses (the NLP corpus). NVD also cites
categories (e.g. CWE-264) and deprecated IDs, so the join re-reads the raw catalog and keeps
everything, plus each weakness's primary ``ChildOf`` parent in the Research Concepts view
(1000), which leads up to one of its ten Pillars: a coarse, stable weakness class.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import IO

from defusedxml.ElementTree import iterparse

from cti.sources.cwe import NS

RESEARCH_VIEW = "1000"
_KINDS = {f"{NS}Weakness": "weakness", f"{NS}Category": "category", f"{NS}View": "view"}


@dataclass(frozen=True)
class CweEntry:
    name: str
    kind: str  # weakness | category | view | deprecated
    abstraction: str | None = None
    parent: str | None = None  # primary ChildOf in view 1000


def load_catalog(fh: IO[bytes]) -> dict[str, CweEntry]:
    catalog: dict[str, CweEntry] = {}
    for _, elem in iterparse(fh, events=("end",)):
        kind = _KINDS.get(elem.tag)
        if kind is None:
            continue
        parent = next(
            (
                r.get("CWE_ID")
                for r in elem.iter(f"{NS}Related_Weakness")
                if r.get("Nature") == "ChildOf"
                and r.get("View_ID") == RESEARCH_VIEW
                and r.get("Ordinal") == "Primary"
            ),
            None,
        )
        catalog[f"CWE-{elem.get('ID')}"] = CweEntry(
            name=elem.get("Name", ""),
            kind="deprecated" if elem.get("Status") == "Deprecated" else kind,
            abstraction=elem.get("Abstraction"),
            parent=f"CWE-{parent}" if parent else None,
        )
        elem.clear()
    return catalog


def pillar(catalog: dict[str, CweEntry], cwe_id: str) -> str | None:
    """The Pillar above ``cwe_id`` in view 1000, or None (categories, unknown IDs, cycles)."""
    seen: set[str] = set()
    current: str | None = cwe_id
    while current and current not in seen:
        seen.add(current)
        entry = catalog.get(current)
        if entry is None or entry.kind != "weakness":
            return None
        if entry.abstraction == "Pillar":
            return current
        current = entry.parent
    return None


def describe(catalog: dict[str, CweEntry], cwe_id: str) -> dict:
    entry = catalog.get(cwe_id)
    if entry is None:
        return {"id": cwe_id, "name": None, "kind": "unknown", "pillar": None}
    return {"id": cwe_id, "name": entry.name, "kind": entry.kind, "pillar": pillar(catalog, cwe_id)}
