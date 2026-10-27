"""SecureBERT stages: ``cti ner`` (entities), ``cti ner-eval`` (gold set), and ``cti embed``
(NVD description embeddings for Phase 7). All need the ``nlp`` extra.

Output scope and leakage:

- **Entities** cover the reference-page corpus, which is snapshot-time and KEV-biased:
  for display and analysis, never a risk feature (``vault/risk-scoring-design.md``).
- **Embeddings** cover every NVD description. Each row carries ``kev_language``: the
  description says the CVE is exploited in the wild, wording vendors add after the fact.
  Phase 7 must report its text ablation with and without these rows.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path

import numpy as np

from cti.enrich import read_jsonl
from cti.gold import GoldRecord
from cti.nlp.aliases import STOPLIST, AliasIndex, key
from cti.nlp.extract import REFERENCE_PAGE

SCHEMA = 1
KEV_LANGUAGE = re.compile(
    r"\b(?:exploited in the wild|actively exploited|exploitation in the wild"
    r"|in-the-wild exploitation|known to (?:have been|be) exploited|(?:has|have) been exploited"
    r"|may have been exploited|limited,? targeted (?:attacks|exploitation)"
    r"|reports? (?:of|that) (?:this )?(?:vulnerability )?(?:is being |has been |was )?exploited)",
    re.IGNORECASE,
)
LINKED = ("Malware", "Organization")
# Spans are all kept with their score. On scraped pages (code, tables, logs: far from the
# model's prose training data) low scores are mostly noise: in a spot sample, junk
# "Malware" spans ("for", "CWE", "exposed") had median score 0.61, real families 0.94.
# Displays use CONFIDENT or an alias link; this is a stated rule, not a measured precision.
CONFIDENT = 0.9
# gold entity type -> NER label; cvss_score has no counterpart
GOLD_TO_NER = {
    "organization": "Organization",
    "system": "System",
    "malware": "Malware",
    "indicator": "Indicator",
    "ipv4": "Indicator",
    "domain": "Indicator",
    "cve_id": "Indicator",  # the model (CyNER schema) tags CVE IDs as Indicator
}
# Vulnerability (the model's label for bug descriptions) has no gold counterpart


def link(entity_text: str, index: AliasIndex) -> list[str]:
    """ATT&CK/ThreatFox IDs for a Malware/Organization span: the whole span, else names
    found inside it ("X-Agent malware" -> S0023). Stoplisted words ("payload", "Play") are
    never linked: a model span is no better evidence than running text."""
    ids = set() if key(entity_text) in STOPLIST else {e.id for e in index.lookup(entity_text)}
    if not ids:
        ids = {i for m in index.find(entity_text) for i in m.ids}
    return sorted(ids)


def build_entities(
    enriched: Path, tagger, index: AliasIndex, progress: Callable | None = None
) -> tuple[list[dict], dict]:
    pages = [r for r in read_jsonl(enriched / "references.jsonl.gz") if r["in_corpus"]]
    tagged = tagger.tag([p["text"] for p in pages], progress=progress)
    rows, labels, linked, confident = [], Counter(), Counter(), Counter()
    for page, entities in zip(pages, tagged, strict=True):
        out = []
        for e in entities:
            d = e.as_dict()
            if e.label in LINKED:
                d["ids"] = link(page["text"][e.start : e.end], index)
                linked[e.label] += bool(d["ids"])
            labels[e.label] += 1
            confident[e.label] += e.score >= CONFIDENT
            out.append(d)
        if out:
            rows.append(
                {
                    "schema": SCHEMA,
                    "doc_id": page["id"],
                    "origin": REFERENCE_PAGE,
                    "cve": page["cve"],
                    "entities": out,
                }
            )
    rows.sort(key=lambda r: r["doc_id"])
    summary = {
        "schema": SCHEMA,
        "model": {"repo": tagger.spec.repo, "revision": tagger.spec.revision},
        "pages": len(pages),
        "pages_with_entities": len(rows),
        "entities": dict(sorted(labels.items())),
        "linked_to_alias_index": dict(sorted(linked.items())),
        f"score_ge_{CONFIDENT}": dict(sorted(confident.items())),
    }
    return rows, summary


def ner_gold_eval(records: list[GoldRecord], tagger, text_only: bool = False) -> dict:
    """Per label: exact-span and overlap matching against the gold set.

    Only labels the gold set annotates in a source are scored for that source's records
    (like ``cti extract-eval``). ``text_only`` drops spans the gold set took from record
    metadata rather than the text.
    """
    labelled = defaultdict(set)  # NER label -> sources with gold spans of it
    for rec in records:
        for e in rec.entities:
            if e.type in GOLD_TO_NER:
                labelled[GOLD_TO_NER[e.type]].add(rec.source)
    predicted = tagger.tag([r.text for r in records])
    counts = {mode: defaultdict(Counter) for mode in ("exact", "overlap")}
    for rec, preds in zip(records, predicted, strict=True):
        gold = [
            (GOLD_TO_NER[e.type], e.start, e.end)
            for e in rec.entities
            if e.type in GOLD_TO_NER and not (text_only and e.derivation.startswith("metadata"))
        ]
        for label in LABELS_SCORED:
            if rec.source not in labelled.get(label, ()):
                continue
            g = [(s, e) for lab, s, e in gold if lab == label]
            p = [(x.start, x.end) for x in preds if x.label == label]
            for mode in counts:
                c = counts[mode][label]
                c["gold"] += len(g)
                c["pred"] += len(p)
                if mode == "exact":
                    c["tp_p"] += len(set(p) & set(g))
                    c["tp_g"] += len(set(p) & set(g))
                else:
                    c["tp_p"] += sum(any(a < f and e < b for e, f in g) for a, b in p)
                    c["tp_g"] += sum(any(a < f and e < b for a, b in p) for e, f in g)
    out = {}
    for mode, per_label in counts.items():
        out[mode] = {}
        for label, c in sorted(per_label.items()):
            prec = c["tp_p"] / c["pred"] if c["pred"] else 0.0
            rec_ = c["tp_g"] / c["gold"] if c["gold"] else 0.0
            f1 = 2 * prec * rec_ / (prec + rec_) if prec + rec_ else 0.0
            out[mode][label] = {
                "predicted": c["pred"],
                "gold": c["gold"],
                "precision": round(prec, 4),
                "recall": round(rec_, 4),
                "f1": round(f1, 4),
            }
    return {
        "records": len(records),
        "scored_sources": {k: sorted(v) for k, v in sorted(labelled.items())},
        "text_derived_spans_only": text_only,
        **out,
    }


LABELS_SCORED = ("Indicator", "Malware", "Organization", "System")


def nvd_descriptions(processed: Path) -> Iterable[tuple[str, str]]:
    for doc in read_jsonl(processed / "nvd.jsonl.gz"):
        if doc["text"]:
            yield doc["source_id"], doc["text"]


def build_embeddings(
    processed: Path, encoder, progress: Callable | None = None
) -> tuple[np.ndarray, list[dict], dict]:
    docs = sorted(nvd_descriptions(processed))
    vectors = encoder.encode([t for _, t in docs], progress=progress).astype(np.float16)
    index = [
        {"row": i, "cve": cve, "kev_language": bool(KEV_LANGUAGE.search(text))}
        for i, (cve, text) in enumerate(docs)
    ]
    summary = {
        "schema": SCHEMA,
        "model": {"repo": encoder.spec.repo, "revision": encoder.spec.revision},
        "rows": len(docs),
        "dim": int(vectors.shape[1]),
        "dtype": "float16",
        "pooling": "attention-masked mean, L2-normalized",
        "max_tokens": encoder.max_tokens,
        "kev_language_rows": sum(r["kev_language"] for r in index),
        "note": "float results vary in the last digits across machines; no bitwise claim",
    }
    return vectors, index, summary
