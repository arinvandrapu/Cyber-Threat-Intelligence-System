"""Evaluation of the regex IOC extractor (``cti extract-eval``).

Two measures, because the gold set alone can't grade the extractor fairly
(``vault/gold-set-provenance.md``):

- **Review sample** (the primary, non-circular one): a seeded sample of extracted IOCs,
  stratified by ``(type, origin)``, labelled correct or not. Precision is reported per
  stratum (Wilson 95% interval) and per type, origin, and overall, weighted by stratum
  size. "Correct" means the span is a value of that type, not that it is malicious:
  a real address, hostname, or URL; for hashes, a cryptographic digest (file hashes, git
  object and build IDs count; keys, IVs, secrets, and message IDs don't).
- **Gold set**: precision/recall for ``cve_id`` and ``domain`` only. The gold ``ipv4``
  spans were produced by a regex over ThreatFox rows (circular), and its ``cvss_score``
  spans are partly wrong (the version "3.1" in ``CVSS:3.1/``, sub-scores, misplaced
  offsets); those are counted, not scored. Only aggregates are written: gold text holds
  live phishing URLs.
"""

from __future__ import annotations

import csv
import math
import random
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from cti.defang import refang
from cti.gold import GoldRecord
from cti.nlp import iocs

REVIEW_FIELDS = ("doc_id", "origin", "type", "start", "end", "value", "context", "correct")
CONTEXT = 60


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4)}


def _predicted(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"cve_id": set(), "domain": set()}
    for ioc in iocs.extract(text):
        if ioc.type == "cve":
            out["cve_id"].add(ioc.value)
        elif ioc.type == "domain":
            out["domain"].add(refang(ioc.value))
        elif ioc.type == "url":  # the gold set labels URL hosts as domains too
            host = urlsplit(refang(ioc.value)).hostname or ""
            if host and not host.replace(".", "").isdigit() and ":" not in host:
                out["domain"].add(host)
    return out


def _cvss_label_audit(records: Iterable[GoldRecord]) -> dict:
    audit: Counter = Counter()
    for rec in records:
        for ent in rec.entities:
            if ent.type != "cvss_score":
                continue
            audit["spans"] += 1
            before = rec.text[max(0, ent.start - 12) : ent.start]
            if before.endswith("CVSS:"):
                audit["vector_version_labelled_as_score"] += 1
            elif ent.derivation == "regex_cvss_sub":
                audit["sub_score_labelled_as_score"] += 1
            elif not before.rstrip().endswith(("Score:", "score:")):
                audit["offset_not_at_a_score"] += 1
    return dict(sorted(audit.items()))


def gold_eval(records: list[GoldRecord]) -> dict:
    """Scored only on the sources where the gold set labels that type at all (domains: the
    ThreatFox records' "Malicious domains" lists). Other real names the extractor finds in
    those records are unlabelled, so precision is a lower bound; recall is the useful number.
    """
    kinds = ("cve_id", "domain")
    labelled = {k: {r.source for r in records for e in r.entities if e.type == k} for k in kinds}
    counts = {k: Counter() for k in kinds}
    by_source: dict[str, Counter] = defaultdict(Counter)
    for rec in records:
        predicted = _predicted(rec.text)
        for kind, c in counts.items():
            if rec.source not in labelled[kind]:
                continue
            gold = {refang(e.value).lower() for e in rec.entities if e.type == kind}
            if kind == "cve_id":
                gold = {g.upper() for g in gold}
            pred = predicted[kind]
            hits = (len(gold & pred), len(pred - gold), len(gold - pred))
            for name, n in zip(("tp", "fp", "fn"), hits, strict=True):
                c[name] += n
                by_source[f"{kind}:{rec.source}"][name] += n
    return {
        "records": len(records),
        "scored_sources": {k: sorted(v) for k, v in labelled.items()},
        "scores": {k: _prf(c["tp"], c["fp"], c["fn"]) for k, c in counts.items()},
        "by_source": {k: _prf(c["tp"], c["fp"], c["fn"]) for k, c in sorted(by_source.items())},
        "cvss_score_label_audit": _cvss_label_audit(records),
        "not_scored": {
            "ipv4": "gold spans are regex output over ThreatFox rows (circular)",
            "cvss_score": "gold spans are partly mislabelled; see cvss_score_label_audit",
        },
    }


def _population(rows: Iterable[dict]) -> dict[tuple[str, str], list[tuple[dict, dict]]]:
    strata: dict[tuple[str, str], list[tuple[dict, dict]]] = defaultdict(list)
    for row in rows:
        for ioc in row["iocs"]:
            strata[(ioc["type"], row["origin"])].append((row, ioc))
    return strata


def draw_sample(rows: list[dict], n: int, seed: int) -> list[tuple[dict, dict]]:
    """Equal allocation across ``(type, origin)`` strata; spare slots go round-robin to
    strata that still have unsampled IOCs. Deterministic for a given ``seed``."""
    strata = _population(rows)
    rng = random.Random(seed)  # noqa: S311 - reproducible sampling, not security
    pools = {s: rng.sample(items, len(items)) for s, items in sorted(strata.items())}
    take = dict.fromkeys(pools, 0)
    left = n
    while left and any(take[s] < len(pools[s]) for s in pools):
        for s in pools:
            if left and take[s] < len(pools[s]):
                take[s] += 1
                left -= 1
    return [item for s in pools for item in pools[s][: take[s]]]


_LINK = re.compile(r"\b(h)tt(ps?)://", re.IGNORECASE)


def _safe_context(text: str, ioc: dict) -> str:
    """The text around one IOC with every IOC in it defanged and the target marked.

    IOCs are re-extracted from the window; any scheme left (e.g. a URL cut at the window
    edge) is defanged too, so nothing in the sheet is clickable.
    """
    start, end = ioc["start"], ioc["end"]
    lo, hi = max(0, start - CONTEXT), min(len(text), end + CONTEXT)
    parts, pos = [], lo
    window = text[lo:hi]
    for ioc in iocs.extract(window):
        a, b = lo + ioc.start, lo + ioc.end
        if a < pos:
            continue
        parts.append(text[pos:a])
        shown = ioc.value
        parts.append(f"[[{shown}]]" if (a, b) == (start, end) else shown)
        pos = b
    parts.append(text[pos:hi])
    out = "".join(parts)
    if "[[" not in out:  # the target isn't an IOC on its own in the window
        out = f"{text[lo:start]}[[{ioc['value']}]]{text[end:hi]}"
    return " ".join(_LINK.sub(r"\1xx\2[:]//", out).split())


def write_review_sheet(path: Path, sample: list[tuple[dict, dict]], texts: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=REVIEW_FIELDS)
        w.writeheader()
        for row, ioc in sample:
            context = _safe_context(texts[row["doc_id"]], ioc)
            w.writerow(
                {
                    "doc_id": row["doc_id"],
                    "origin": row["origin"],
                    "type": ioc["type"],
                    "start": ioc["start"],
                    "end": ioc["end"],
                    "value": ioc["value"],
                    "context": context,
                    "correct": "",
                }
            )


def read_labels(path: Path) -> dict[tuple[str, str, int, int], bool]:
    labels = {}
    with path.open(newline="", encoding="utf-8") as fh:
        for rec in csv.DictReader(fh):
            mark = rec["correct"].strip().lower()
            if mark not in ("y", "n"):
                raise ValueError(f"{path}: label for {rec['doc_id']} must be y or n, not {mark!r}")
            labels[(rec["doc_id"], rec["type"], int(rec["start"]), int(rec["end"]))] = mark == "y"
    return labels


def score_review(rows: list[dict], labels: dict[tuple[str, str, int, int], bool]) -> dict:
    strata = _population(rows)
    index = {
        (row["doc_id"], ioc["type"], ioc["start"], ioc["end"]): (ioc["type"], row["origin"])
        for items in strata.values()
        for row, ioc in items
    }
    if missing := [k for k in labels if k not in index]:
        raise ValueError(
            f"{len(missing)} labelled IOCs are not in the extraction, e.g. {missing[0]}"
        )
    hits: dict[tuple[str, str], list[bool]] = defaultdict(list)
    for k, ok in labels.items():
        hits[index[k]].append(ok)
    per_stratum = {}
    for s, marks in sorted(hits.items()):
        k, n = sum(marks), len(marks)
        per_stratum[f"{s[0]}:{s[1]}"] = {
            "population": len(strata[s]),
            "labelled": n,
            "correct": k,
            "precision": round(k / n, 4),
            "ci95": wilson(k, n),
        }

    def weighted(keys: list[tuple[str, str]]) -> dict:
        """Stratified estimate: strata weighted by population. The interval uses each
        stratum's Agresti-Coull proportion, so a stratum with all labels correct still
        contributes variance (a plain normal interval would collapse to [1, 1])."""
        total = sum(len(strata[s]) for s in keys)
        p = var = 0.0
        for s in keys:
            w, k, n = len(strata[s]) / total, sum(hits[s]), len(hits[s])
            p += w * k / n
            adj = (k + 2) / (n + 4)
            var += w * w * adj * (1 - adj) / (n + 4)
        half = 1.96 * math.sqrt(var)
        return {
            "population": total,
            "labelled": sum(len(hits[s]) for s in keys),
            "precision": round(p, 4),
            "ci95": (round(max(0.0, p - half), 4), round(min(1.0, p + half), 4)),
        }

    by_type = defaultdict(list)
    by_origin = defaultdict(list)
    for s in hits:
        by_type[s[0]].append(s)
        by_origin[s[1]].append(s)
    return {
        "labelled": len(labels),
        "overall": weighted(sorted(hits)),
        "per_stratum": per_stratum,
        "per_type": {t: weighted(v) for t, v in sorted(by_type.items())},
        "per_origin": {o: weighted(v) for o, v in sorted(by_origin.items())},
        "unsampled_strata": sorted(f"{t}:{o}" for t, o in strata if (t, o) not in hits),
    }
