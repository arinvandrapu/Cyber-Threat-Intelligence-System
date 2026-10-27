"""``cti extract``: regex IOCs and alias mentions over the corpus, one row per document.

Inputs: the cleaned reference pages in the corpus (``data/enriched/<date>/references``,
``in_corpus`` rows) and the NVD descriptions (``data/processed/<date>/nvd``). Only
documents with at least one hit get a row. Rows are sorted by ``(origin, doc_id)`` and IOC
values are defanged, so outputs are deterministic and safe to display.

NVD-origin IOCs are mostly example, vendor, or loopback values rather than indicators, so
``HEADLINE_ORIGIN`` names the origin that headline IOC counts (README, dashboard) use.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from importlib.metadata import version
from pathlib import Path

from cti.enrich import read_jsonl
from cti.nlp import iocs
from cti.nlp.aliases import AliasIndex, build_index

SCHEMA = 1
REFERENCE_PAGE = "reference_page"
NVD_DESCRIPTION = "nvd_description"
HEADLINE_ORIGIN = REFERENCE_PAGE


def iter_texts(processed: Path, enriched: Path) -> Iterator[tuple[str, str, str | None, str]]:
    """``(doc_id, origin, cve, text)`` for every document in the corpus."""
    for row in read_jsonl(enriched / "references.jsonl.gz"):
        if row["in_corpus"]:
            yield row["id"], REFERENCE_PAGE, row["cve"], row["text"]
    for doc in read_jsonl(processed / "nvd.jsonl.gz"):
        if doc["text"]:
            yield doc["id"], NVD_DESCRIPTION, doc["source_id"], doc["text"]


def _sorted(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (r["origin"], r["doc_id"]))


def build_iocs(processed: Path, enriched: Path) -> tuple[list[dict], dict]:
    rows = []
    docs: Counter = Counter()
    by_type: dict[str, Counter] = {}
    defanged: Counter = Counter()
    public: Counter = Counter()
    for doc_id, origin, cve, text in iter_texts(processed, enriched):
        docs[origin] += 1
        found = iocs.extract(text)
        if not found:
            continue
        counts = by_type.setdefault(origin, Counter())
        for ioc in found:
            counts[ioc.type] += 1
            defanged[origin] += ioc.defanged_in_source
            public[origin] += bool(ioc.public)
        rows.append(
            {
                "schema": SCHEMA,
                "doc_id": doc_id,
                "origin": origin,
                "cve": cve,
                "iocs": [ioc.as_dict() for ioc in found],
            }
        )
    rows = _sorted(rows)
    with_hits = Counter(r["origin"] for r in rows)
    summary = {
        "schema": SCHEMA,
        "headline_origin": HEADLINE_ORIGIN,
        "docs": dict(sorted(docs.items())),
        "docs_with_iocs": dict(sorted(with_hits.items())),
        "iocs": {o: dict(sorted(c.items())) for o, c in sorted(by_type.items())},
        "defanged_in_source": dict(sorted(defanged.items())),
        "public_ips": dict(sorted(public.items())),
        "tldextract": version("tldextract"),  # its bundled public-suffix list
    }
    return rows, summary


def alias_index(processed: Path) -> AliasIndex:
    return build_index(
        read_jsonl(processed / "attack.jsonl.gz"), read_jsonl(processed / "threatfox.jsonl.gz")
    )


def build_aliases(processed: Path, enriched: Path) -> tuple[list[dict], dict]:
    index = alias_index(processed)
    rows = []
    matches: Counter = Counter()
    ambiguous: Counter = Counter()
    entities: Counter = Counter()
    for doc_id, origin, cve, text in iter_texts(processed, enriched):
        found = index.find(text)
        if not found:
            continue
        for m in found:
            matches[origin] += 1
            ambiguous[origin] += m.ambiguous
            if not m.ambiguous:
                entities[m.ids[0]] += 1
        rows.append(
            {
                "schema": SCHEMA,
                "doc_id": doc_id,
                "origin": origin,
                "cve": cve,
                "aliases": [m.as_dict() for m in found],
            }
        )
    rows = _sorted(rows)
    summary = {
        "schema": SCHEMA,
        "index": index.stats(),
        "docs_with_aliases": dict(sorted(Counter(r["origin"] for r in rows).items())),
        "matches": dict(sorted(matches.items())),
        "ambiguous_matches": dict(sorted(ambiguous.items())),
        "top_entities": [
            {"id": i, "name": index.entities[i].name, "mentions": n}
            for i, n in sorted(entities.items(), key=lambda kv: (-kv[1], kv[0]))[:25]
        ],
    }
    return rows, summary
