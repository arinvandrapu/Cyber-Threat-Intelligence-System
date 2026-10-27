"""Grade CVE -> ATT&CK technique ranking against MITRE CTID's KEV mappings.

Ground truth is the pinned CTID Mappings Explorer KEV file (ATT&CK 16.1, Apache-2.0; see
``data/reference/ctid/NOTICE.md``). Only ``capability_id``, ``mapping_type``, and
``attack_object_id`` are read. The file's ``comments``, ``capability_group``, and
``references`` are the labellers' own reasoning, so they never reach a ranker.

- **Splits.** Test = the CTID CVEs in our NVD corpus (published 2024 or later). Dev = the
  rest, used only for the majority prior and for any choice made before scoring test.
- **Text.** ``nvd`` = the NVD description (test only, the primary variant). ``kev`` = the
  KEV feed's own title and short description (dev and test, so the splits compare).
- **Labels.** Technique level: sub-techniques roll up to parents, and revoked IDs are
  remapped to v20. Each ``mapping_type`` is graded separately. The primary one is
  ``exploitation_technique`` (how the CVE is exploited), which a description can state.
  Impact labels (what an attacker does next) are reported as harder.
- **Metrics.** hit@k (at least one label in the top k), recall@k, and MRR, each with a
  seeded bootstrap 95% interval over CVEs. Every method is also compared with the majority
  baseline on the same CVEs (paired bootstrap of the difference).
- **Bias.** Every CVE here is in KEV (mostly appliance and web RCE), so the scores say
  nothing about non-KEV CVEs.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

import numpy as np

from cti.nlp.attack_catalog import Technique, parent

CTID_FILE = Path("reference/ctid/kev-07.28.2025_attack-16.1-enterprise.json")  # under data_dir
CTID_SHA256 = "b57b3d382809d9159fdda6701d21f0e67a2d655444d89301caab2c39ad54bdc7"
MAPPING_TYPES = ("exploitation_technique", "primary_impact", "secondary_impact")
PRIMARY_TYPE = "exploitation_technique"
KS = (1, 3, 5, 10)
N_BOOT = 2000
SEED = 20261027

Gold = dict[str, dict[str, set[str]]]  # cve -> mapping_type -> parent technique IDs
Ranking = dict[str, list[str]]  # cve -> parent technique IDs, best first


def load_ctid(path: Path, expected_sha256: str | None = CTID_SHA256) -> list[dict]:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 and digest != expected_sha256:
        raise ValueError(f"{path}: SHA-256 {digest} does not match the pinned {expected_sha256}")
    return [
        {"cve": m["capability_id"], "type": m["mapping_type"], "technique": m["attack_object_id"]}
        for m in json.loads(data)["mapping_objects"]
    ]


def gold_labels(rows: list[dict], revoked: dict[str, str]) -> tuple[Gold, int]:
    """Technique-level labels per CVE and type, and how many rows were remapped."""
    gold: Gold = defaultdict(lambda: defaultdict(set))
    remapped = 0
    for row in rows:
        tid = row["technique"]
        if tid in revoked:
            tid = revoked[tid]
            remapped += 1
        gold[row["cve"]][row["type"]].add(parent(tid))
    return {c: dict(t) for c, t in gold.items()}, remapped


def parent_matrix(
    scores: np.ndarray, techniques: Sequence[Technique]
) -> tuple[list[str], np.ndarray]:
    """Technique scores -> parent scores (max over a parent and its sub-techniques)."""
    parents = sorted({parent(t.id) for t in techniques})
    col = {p: i for i, p in enumerate(parents)}
    best = np.full((scores.shape[0], len(parents)), -np.inf)
    for j, t in enumerate(techniques):
        k = col[parent(t.id)]
        best[:, k] = np.maximum(best[:, k], scores[:, j])
    return parents, best


def rank_matrix(parents: list[str], scores: np.ndarray) -> list[list[str]]:
    """Per row: parents best first; ties break by technique ID (deterministic)."""
    ids = np.arange(len(parents))[None, :].repeat(len(scores), 0)
    order = np.lexsort((ids, -scores), axis=1)
    return [[parents[i] for i in row] for row in order]


def rank_parents(scores: np.ndarray, techniques: Sequence[Technique]) -> list[list[str]]:
    return rank_matrix(*parent_matrix(scores, techniques))


def log_prior(counts: Counter, parents: list[str], exclude: Iterable[str] = ()) -> np.ndarray:
    """Add-one smoothed log label frequency per parent, optionally leaving one CVE's labels
    out (``exclude``), so a dev CVE is never scored with a prior that counted it."""
    c = np.array([counts[p] for p in parents], dtype=float)
    for t in exclude:
        if t in counts:
            c[parents.index(t)] -= 1
    return np.log((c + 1) / (c.sum() + len(parents)))


def _per_cve(ranking: list[str], labels: set[str]) -> dict[str, float]:
    out = {}
    for k in KS:
        top = set(ranking[:k])
        out[f"hit@{k}"] = float(bool(top & labels))
        out[f"recall@{k}"] = len(top & labels) / len(labels)
    first = next((i for i, t in enumerate(ranking) if t in labels), None)
    out["mrr"] = 0.0 if first is None else 1.0 / (first + 1)
    return out


def _table(rankings: Ranking, gold: Gold, mapping_type: str) -> tuple[list[str], np.ndarray]:
    cves = sorted(c for c in rankings if gold.get(c, {}).get(mapping_type))
    rows = [_per_cve(rankings[c], gold[c][mapping_type]) for c in cves]
    names = list(rows[0]) if rows else []
    return names, np.array([[r[n] for n in names] for r in rows])


def _ci(values: np.ndarray, rng: np.random.Generator) -> tuple[float, float]:
    idx = rng.integers(0, len(values), size=(N_BOOT, len(values)))
    means = values[idx].mean(axis=1)
    lo, hi = np.percentile(means, [2.5, 97.5])
    return round(float(lo), 4), round(float(hi), 4)


def score(rankings: Ranking, gold: Gold, mapping_type: str) -> dict:
    names, table = _table(rankings, gold, mapping_type)
    if not len(table):
        return {"cves": 0}
    rng = np.random.default_rng(SEED)
    out: dict = {"cves": len(table)}
    for i, name in enumerate(names):
        out[name] = {"value": round(float(table[:, i].mean()), 4), "ci95": _ci(table[:, i], rng)}
    return out


def compare(a: Ranking, b: Ranking, gold: Gold, mapping_type: str, metric: str) -> dict:
    """Paired bootstrap of ``metric(a) - metric(b)`` over the same CVEs."""
    names, ta = _table(a, gold, mapping_type)
    _, tb = _table(b, gold, mapping_type)
    if not len(ta):
        return {"cves": 0}
    diff = ta[:, names.index(metric)] - tb[:, names.index(metric)]
    return {
        "cves": len(diff),
        "metric": metric,
        "difference": round(float(diff.mean()), 4),
        "ci95": _ci(diff, np.random.default_rng(SEED)),
    }


class MajorityRanker:
    """The same list for every CVE: parents by label frequency on the dev split."""

    def __init__(self, dev_gold: Gold, mapping_type: str, techniques: Sequence[Technique]):
        counts = Counter(t for labels in dev_gold.values() for t in labels.get(mapping_type, ()))
        parents = sorted({parent(t.id) for t in techniques})
        self.order = sorted(parents, key=lambda p: (-counts[p], p))

    def rank(self, texts: Sequence[str]) -> list[list[str]]:
        return [list(self.order) for _ in texts]


class TfidfRanker:
    """Cosine similarity between CVE text and technique text, TF-IDF weighted.

    Fit on the technique texts only (never on graded CVE text). The settings are fixed
    defaults chosen before any scoring, not tuned.
    """

    def __init__(self, techniques: Sequence[Technique]):
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.techniques = list(techniques)
        self.vectorizer = TfidfVectorizer(
            sublinear_tf=True, stop_words="english", ngram_range=(1, 2), min_df=1
        )
        self.matrix = self.vectorizer.fit_transform([t.text for t in self.techniques])

    def scores(self, texts: Sequence[str]) -> np.ndarray:
        return (self.vectorizer.transform(texts) @ self.matrix.T).toarray()

    def rank(self, texts: Sequence[str]) -> list[list[str]]:
        return rank_parents(self.scores(texts), self.techniques)


def rankings_for(
    rank: Callable[[Sequence[str]], list[list[str]]], texts: dict[str, str]
) -> Ranking:
    cves = sorted(texts)
    return dict(zip(cves, rank([texts[c] for c in cves]), strict=True))


def cve_texts(processed: Path, cves: set[str]) -> dict[str, dict[str, str]]:
    """``{"nvd": {cve: description}, "kev": {cve: title + short description}}``."""
    from cti.enrich import read_jsonl

    texts: dict[str, dict[str, str]] = {"nvd": {}, "kev": {}}
    for doc in read_jsonl(processed / "nvd.jsonl.gz"):
        if doc["source_id"] in cves and doc["text"]:
            texts["nvd"][doc["source_id"]] = doc["text"]
    for doc in read_jsonl(processed / "kev.jsonl.gz"):
        if doc["source_id"] in cves:
            texts["kev"][doc["source_id"]] = f"{doc['title']}. {doc['text']}"
    return texts


BETAS = (0.0, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0)


def _counts(gold: Gold, mapping_type: str) -> Counter:
    return Counter(t for labels in gold.values() for t in labels.get(mapping_type, ()))


def _prior_rows(
    cves: list[str],
    counts: Counter,
    parents: list[str],
    gold: Gold,
    mapping_type: str,
    leave_one_out: bool,
) -> np.ndarray:
    if not leave_one_out:
        return np.tile(log_prior(counts, parents), (len(cves), 1))
    return np.array(
        [log_prior(counts, parents, gold.get(c, {}).get(mapping_type, ())) for c in cves]
    ).reshape(len(cves), len(parents))


def _select_beta(sim: np.ndarray, prior: np.ndarray, parents, cves, gold) -> dict:
    """Pick the prior weight on dev only: best hit@5 on the primary type, then MRR, then the
    smaller weight."""
    grid = {}
    for beta in BETAS:
        ranking = dict(zip(cves, rank_matrix(parents, sim + beta * prior), strict=True))
        names, table = _table(ranking, gold, PRIMARY_TYPE)
        grid[beta] = (table[:, names.index("hit@5")].mean(), table[:, names.index("mrr")].mean())
    best = max(BETAS, key=lambda b: (round(grid[b][0], 6), round(grid[b][1], 6), -b))
    return {
        "beta": best,
        "selected_on": f"dev/kev/{PRIMARY_TYPE}, leave-one-out prior, hit@5",
        "grid_hit@5": {str(b): round(float(v[0]), 4) for b, v in grid.items()},
    }


def evaluate(
    gold: Gold,
    texts: dict[str, dict[str, str]],
    techniques: Sequence[Technique],
    scorers: dict[str, Callable[[Sequence[str]], np.ndarray]],
) -> dict:
    """Score every method on every split and text variant, per mapping type.

    ``scorers`` maps a name to a ``scores(texts)`` function returning technique-level
    similarities. Methods graded:

    - ``majority``: the dev label prior (on dev CVEs, leave-one-out);
    - each scorer on its own (zero-shot similarity);
    - ``prior+<scorer>``: similarity + beta * log prior, with beta picked on dev only.
    """
    test = sorted(c for c in gold if c in texts["nvd"])
    dev = sorted(set(gold) - set(test))
    dev_gold = {c: gold[c] for c in dev}
    splits = {
        "test": {"nvd": _pick(texts["nvd"], test), "kev": _pick(texts["kev"], test)},
        "dev": {"kev": _pick(texts["kev"], dev)},
    }
    parents = sorted({parent(t.id) for t in techniques})
    sims = {
        (split, variant, name): parent_matrix(fn([subset[c] for c in subset]), techniques)[1]
        for split, variants in splits.items()
        for variant, subset in variants.items()
        for name, fn in scorers.items()
    }
    primary_counts = _counts(dev_gold, PRIMARY_TYPE)
    betas = {}
    for name in scorers:
        cves = list(splits["dev"]["kev"])
        prior = _prior_rows(cves, primary_counts, parents, gold, PRIMARY_TYPE, True)
        betas[name] = _select_beta(sims[("dev", "kev", name)], prior, parents, cves, gold)

    results: dict = {}
    for split, variants in splits.items():
        for variant, subset in variants.items():
            cves = list(subset)
            cell = results.setdefault(split, {}).setdefault(variant, {})
            for mapping_type in MAPPING_TYPES:
                prior = _prior_rows(
                    cves,
                    _counts(dev_gold, mapping_type),
                    parents,
                    gold,
                    mapping_type,
                    leave_one_out=split == "dev",
                )
                ranked = {"majority": dict(zip(cves, rank_matrix(parents, prior), strict=True))}
                for name in scorers:
                    sim = sims[(split, variant, name)]
                    ranked[name] = dict(zip(cves, rank_matrix(parents, sim), strict=True))
                    hybrid = sim + betas[name]["beta"] * prior
                    ranked[f"prior+{name}"] = dict(
                        zip(cves, rank_matrix(parents, hybrid), strict=True)
                    )
                for method, ranking in ranked.items():
                    entry = cell.setdefault(method, {})
                    entry[mapping_type] = score(ranking, gold, mapping_type)
                    if method != "majority":
                        entry[mapping_type]["vs_majority"] = compare(
                            ranking, ranked["majority"], gold, mapping_type, "hit@5"
                        )
    methods = ["majority", *scorers, *(f"prior+{n}" for n in scorers)]
    return {
        "splits": {"dev": len(dev), "test": len(test)},
        "primary": {"split": "test", "variant": "nvd", "mapping_type": PRIMARY_TYPE},
        "methods": methods,
        "prior_weight": betas,
        "results": results,
    }


def _pick(texts: dict[str, str], cves: list[str]) -> dict[str, str]:
    return {c: texts[c] for c in cves if c in texts}


def _subset(texts: dict[str, str], cves: set[str]) -> dict[str, str]:
    return {c: t for c, t in texts.items() if c in cves}
