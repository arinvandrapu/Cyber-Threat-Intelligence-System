"""``cti cwe-eval``: classify NVD CVE descriptions into CWE classes (Phase 6).

Every choice is pre-registered in ``cwe_config`` (committed before any test score). Labels
are human-assigned CWEs with their assigner (Phase 6a provenance); see
``vault/cwe-classification.md`` for the label facts that shaped the design.

- **Label** per CVE: the first source in ``LABEL_CHAIN`` with a usable CWE (not
  ``Prohibited``, not noinfo/Other). One CWE -> single-label example; several -> the
  multi-label pool (graded only as "any label in the top k").
- **Split** by publication date (train / dev / test).
- **Classes:** CWEs with at least ``MIN_TRAIN_EXAMPLES`` single-label train CVEs; others
  are ``OTHER``. Macro-F1 is over the known classes (``OTHER`` is a grab-bag).
- **Text:** literal ``CWE-<n>`` IDs are masked for every method. The CWE's *name* often
  appears in templated CNA descriptions, so results are reported by stratum and the
  headline is the name-absent stratum.
- **Methods:** majority; TF-IDF + logistic regression; SecureBERT 2.0 bi-encoder embeddings
  + logistic regression; nearest centroid on the embeddings. C is chosen on dev, then the
  model is refit on train + dev and scored on test once.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from cti.enrich import read_jsonl
from cti.enrich.cwe import CweEntry
from cti.nlp import cwe_config as cfg

_CWE_ID = re.compile(cfg.CWE_ID_PATTERN, re.IGNORECASE)
NO_CWE = ("NVD-CWE-noinfo", "NVD-CWE-Other")


@dataclass(frozen=True, slots=True)
class Example:
    cve: str
    split: str  # train | dev | test
    labels: tuple[str, ...]  # sorted CWE IDs from the chosen source
    source: str  # nvd | cna | cisa_adp
    assigner: str  # the CVE's sourceIdentifier (its CNA)
    text: str  # with CWE IDs masked
    raw_text: str
    has_cwe_id: bool
    name_present: bool

    @property
    def single(self) -> bool:
        return len(self.labels) == 1


def split_of(published: str) -> str:
    day = published[:10]
    return "train" if day <= cfg.TRAIN_END else "dev" if day <= cfg.DEV_END else "test"


def mask_ids(text: str) -> str:
    return _CWE_ID.sub(cfg.CWE_ID_MASK, text)


def name_in_text(text: str, cwe_ids: Sequence[str], catalog: dict[str, CweEntry]) -> bool:
    low = text.lower()
    for cwe_id in cwe_ids:
        entry = catalog.get(cwe_id)
        if entry is None or not entry.name:
            continue
        name = entry.name.lower()
        short = name.split(" (", 1)[0].strip()
        if name in low or (short and short in low):
            return True
    return False


def choose_label(assignments: list[dict], catalog: dict[str, CweEntry]) -> tuple[str, set[str]]:
    for source in cfg.LABEL_CHAIN:
        ids = {
            a["id"]
            for a in assignments
            if a["source_kind"] == source
            and a["id"] not in NO_CWE
            and (catalog.get(a["id"]) is None or catalog[a["id"]].usage not in cfg.EXCLUDED_USAGE)
        }
        if ids:
            return source, ids
    return "", set()


def load_examples(processed: Path, catalog: dict[str, CweEntry]) -> list[Example]:
    out = []
    for doc in read_jsonl(processed / "nvd.jsonl.gz"):
        source, ids = choose_label(doc["metadata"].get("cwe_assignments", []), catalog)
        if not ids:
            continue
        labels = tuple(sorted(ids))
        out.append(
            Example(
                cve=doc["source_id"],
                split=split_of(doc["published"]),
                labels=labels,
                source=source,
                assigner=doc["metadata"].get("assigner") or "",
                text=mask_ids(doc["text"]),
                raw_text=doc["text"],
                has_cwe_id=bool(_CWE_ID.search(doc["text"])),
                name_present=name_in_text(doc["text"], labels, catalog),
            )
        )
    return sorted(out, key=lambda e: e.cve)


def known_classes(examples: Sequence[Example]) -> list[str]:
    counts = Counter(e.labels[0] for e in examples if e.split == "train" and e.single)
    return sorted(c for c, n in counts.items() if n >= cfg.MIN_TRAIN_EXAMPLES)


def target(example: Example, known: set[str]) -> str:
    label = example.labels[0]
    return label if label in known else cfg.OTHER


# ---- metrics ---------------------------------------------------------------------------------


def _macro_f1(y: np.ndarray, p: np.ndarray, n_known: int) -> float:
    """Macro-F1 over class codes 0..n_known-1 (OTHER has code n_known and is excluded)."""
    k = n_known + 1
    tp = np.bincount(y[y == p], minlength=k)[:n_known]
    pred = np.bincount(p, minlength=k)[:n_known]
    true = np.bincount(y, minlength=k)[:n_known]
    denom = pred + true
    present = true > 0  # classes absent from this sample don't count
    f1 = np.where(denom > 0, 2 * tp / np.maximum(denom, 1), 0.0)
    return float(f1[present].mean()) if present.any() else 0.0


def _boot(stat: Callable[[np.ndarray], float], n: int, rng) -> tuple[float, float]:
    vals = [stat(rng.integers(0, n, n)) for _ in range(cfg.N_BOOT)]
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return round(float(lo), 4), round(float(hi), 4)


def evaluate_scores(
    scores: np.ndarray, y: np.ndarray, n_known: int, mask: np.ndarray | None = None
) -> dict:
    """Metrics for one method on one set of single-label examples.

    ``scores``: (n, n_known + 1) class scores (column n_known = OTHER); ``y``: true codes.
    """
    if mask is not None:
        scores, y = scores[mask], y[mask]
    n = len(y)
    if n == 0:
        return {"n": 0}
    order = np.argsort(-scores, axis=1, kind="stable")
    pred = order[:, 0]
    rng = np.random.default_rng(cfg.SEED)
    out = {
        "n": n,
        "macro_f1": round(_macro_f1(y, pred, n_known), 4),
        "macro_f1_ci95": _boot(lambda i: _macro_f1(y[i], pred[i], n_known), n, rng),
        "accuracy": round(float((pred == y).mean()), 4),
    }
    for k in cfg.TOP_K:
        hit = (order[:, :k] == y[:, None]).any(axis=1)
        out[f"top{k}"] = round(float(hit.mean()), 4)
    return out


def paired_macro_f1(
    a: np.ndarray, b: np.ndarray, y: np.ndarray, n_known: int, mask: np.ndarray
) -> dict:
    """Paired bootstrap of macro-F1(a) - macro-F1(b) over the same examples."""
    pa, pb, yy = a[mask].argmax(1), b[mask].argmax(1), y[mask]
    rng = np.random.default_rng(cfg.SEED)
    diff = _macro_f1(yy, pa, n_known) - _macro_f1(yy, pb, n_known)
    ci = _boot(
        lambda i: _macro_f1(yy[i], pa[i], n_known) - _macro_f1(yy[i], pb[i], n_known),
        len(yy),
        rng,
    )
    return {"n": int(mask.sum()), "difference": round(diff, 4), "ci95": ci}


def any_in_top_k(scores: np.ndarray, label_sets: list[set[int]], k: int) -> float:
    order = np.argsort(-scores, axis=1, kind="stable")[:, :k]
    hits = [bool(set(row) & labels) for row, labels in zip(order, label_sets, strict=True)]
    return round(float(np.mean(hits)), 4) if hits else 0.0


# ---- methods ---------------------------------------------------------------------------------


class Majority:
    def fit(self, y: np.ndarray, n_classes: int):
        self.prior = np.bincount(y, minlength=n_classes).astype(float)
        return self

    def scores(self, n: int) -> np.ndarray:
        return np.tile(self.prior, (n, 1))


def _full_scores(model, x, n_classes: int) -> np.ndarray:
    """Class scores in code order, with -inf for classes the model never saw."""
    raw = (
        model.decision_function(x)
        if hasattr(model, "decision_function")
        else model.predict_proba(x)
    )
    if raw.ndim == 1:  # two classes: sklearn returns one score for the second class
        raw = np.column_stack([-raw, raw])
    out = np.full((raw.shape[0], n_classes), -np.inf)
    out[:, model.classes_] = raw
    return out


def fit_tfidf(texts: Sequence[str], y: np.ndarray, c: float):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    t = cfg.TFIDF
    vec = TfidfVectorizer(
        ngram_range=t.ngram_range,
        min_df=t.min_df,
        max_features=t.max_features,
        sublinear_tf=t.sublinear_tf,
        stop_words=t.stop_words,
    )
    model = LogisticRegression(C=c, solver=t.solver, max_iter=t.max_iter, tol=t.tol)
    model.fit(vec.fit_transform(texts), y)
    return vec, model


def tfidf_scores(fitted, texts: Sequence[str], n_classes: int) -> np.ndarray:
    vec, model = fitted
    return _full_scores(model, vec.transform(texts), n_classes)


def fit_embedding(x: np.ndarray, y: np.ndarray, c: float):
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    e = cfg.EMBEDDING
    scaler = StandardScaler().fit(x)
    model = LogisticRegression(C=c, solver=e.solver, max_iter=e.max_iter, tol=e.tol)
    model.fit(scaler.transform(x), y)
    return scaler, model


def embedding_scores(fitted, x: np.ndarray, n_classes: int) -> np.ndarray:
    scaler, model = fitted
    return _full_scores(model, scaler.transform(x), n_classes)


def centroid_scores(x_fit: np.ndarray, y_fit: np.ndarray, x: np.ndarray, n_classes: int):
    """Cosine similarity to each class's mean embedding (vectors are L2-normalized)."""
    cent = np.zeros((n_classes, x_fit.shape[1]))
    np.add.at(cent, y_fit, x_fit)
    norms = np.linalg.norm(cent, axis=1, keepdims=True)
    cent = np.divide(cent, norms, out=np.zeros_like(cent), where=norms > 0)
    out = x @ cent.T
    out[:, norms[:, 0] == 0] = -np.inf
    return out


# ---- orchestration ---------------------------------------------------------------------------

SPLITS = ("train", "dev", "test")


def label_facts(examples: Sequence[Example], known: set[str], catalog) -> dict:
    facts = {}
    for split in SPLITS:
        rows = [e for e in examples if e.split == split]
        single = [e for e in rows if e.single]
        facts[split] = {
            "labelled": len(rows),
            "single_label": len(single),
            "multi_label": len(rows) - len(single),
            "label_source": dict(sorted(Counter(e.source for e in rows).items())),
            "other_share": _share(sum(target(e, known) == cfg.OTHER for e in single), single),
            "name_present_share": _share(sum(e.name_present for e in single), single),
            "cwe_id_in_text": sum(e.has_cwe_id for e in rows),
            "discouraged_share": _share(
                sum(
                    (catalog.get(e.labels[0]) is not None)
                    and catalog[e.labels[0]].usage == "Discouraged"
                    for e in single
                ),
                single,
            ),
        }
    return facts


def _share(k: int, rows: Sequence) -> float:
    return round(k / len(rows), 4) if rows else 0.0


def run(
    examples: list[Example],
    vectors: Callable[[Sequence[str], bool], np.ndarray],
    catalog: dict[str, CweEntry],
    log: Callable[[str], None] = print,
) -> dict:
    """The whole evaluation. ``vectors(cves, masked)`` returns bi-encoder embeddings
    (``masked=True``: of the ID-masked text)."""
    known = known_classes(examples)
    known_set = set(known)
    code = {c: i for i, c in enumerate([*known, cfg.OTHER])}
    n_known, n_classes = len(known), len(known) + 1
    single = {s: [e for e in examples if e.split == s and e.single] for s in SPLITS}
    y = {s: np.array([code[target(e, known_set)] for e in single[s]]) for s in SPLITS}
    absent = {s: np.array([not e.name_present for e in single[s]]) for s in SPLITS}
    texts = {s: [e.text for e in single[s]] for s in SPLITS}
    raw_texts = {s: [e.raw_text for e in single[s]] for s in SPLITS}
    emb = {s: vectors([e.cve for e in single[s]], True) for s in SPLITS}
    raw_emb = {s: vectors([e.cve for e in single[s]], False) for s in SPLITS}
    fit_y = np.concatenate([y["train"], y["dev"]])

    def dev_score(scores):
        return _macro_f1(y["dev"][absent["dev"]], scores[absent["dev"]].argmax(1), n_known)

    selection = {"tfidf": {}, "embedding": {}}
    for c in cfg.TFIDF.c_grid:
        log(f"  select tfidf C={c}")
        fitted = fit_tfidf(texts["train"], y["train"], c)
        selection["tfidf"][c] = dev_score(tfidf_scores(fitted, texts["dev"], n_classes))
    for c in cfg.EMBEDDING.c_grid:
        log(f"  select embedding C={c}")
        fitted = fit_embedding(emb["train"], y["train"], c)
        selection["embedding"][c] = dev_score(embedding_scores(fitted, emb["dev"], n_classes))
    best = {
        m: max(sorted(g), key=lambda c, g=g: (round(g[c], 6), -c)) for m, g in selection.items()
    }

    log("  refit on train + dev, score test")
    fit_texts = texts["train"] + texts["dev"]
    fit_emb = np.vstack([emb["train"], emb["dev"]])
    final_tfidf = fit_tfidf(fit_texts, fit_y, best["tfidf"])
    final_emb = fit_embedding(fit_emb, fit_y, best["embedding"])
    test_scores = {
        "majority": Majority().fit(fit_y, n_classes).scores(len(y["test"])),
        "tfidf": tfidf_scores(final_tfidf, texts["test"], n_classes),
        "embedding": embedding_scores(final_emb, emb["test"], n_classes),
        "centroid": centroid_scores(fit_emb, fit_y, emb["test"], n_classes),
    }
    yt, at = y["test"], absent["test"]
    results = {
        m: {
            "name_absent": evaluate_scores(s, yt, n_known, at),
            "all": evaluate_scores(s, yt, n_known),
            "name_present": evaluate_scores(s, yt, n_known, ~at),
        }
        for m, s in test_scores.items()
    }
    paired = {
        stratum: paired_macro_f1(test_scores["embedding"], test_scores["tfidf"], yt, n_known, mask)
        for stratum, mask in (("name_absent", at), ("all", np.ones_like(at)))
    }

    log("  secondary: train-only models, unmasked IDs")
    train_only = {
        "tfidf": tfidf_scores(
            fit_tfidf(texts["train"], y["train"], best["tfidf"]), texts["test"], n_classes
        ),
        "embedding": embedding_scores(
            fit_embedding(emb["train"], y["train"], best["embedding"]), emb["test"], n_classes
        ),
    }
    unmasked = {
        "tfidf": tfidf_scores(
            fit_tfidf(raw_texts["train"] + raw_texts["dev"], fit_y, best["tfidf"]),
            raw_texts["test"],
            n_classes,
        ),
        "embedding": embedding_scores(
            fit_embedding(np.vstack([raw_emb["train"], raw_emb["dev"]]), fit_y, best["embedding"]),
            raw_emb["test"],
            n_classes,
        ),
    }

    by_source = {}
    for source in cfg.LABEL_CHAIN:
        mask = np.array([e.source == source for e in single["test"]])
        by_source[source] = {
            m: evaluate_scores(s, yt, n_known, mask)["accuracy"] if mask.any() else None
            for m, s in test_scores.items()
        } | {"n": int(mask.sum())}
    top = Counter(e.assigner for e in single["test"]).most_common(cfg.TOP_ASSIGNERS)
    by_assigner = {}
    for assigner, n in top:
        mask = np.array([e.assigner == assigner for e in single["test"]])
        by_assigner[assigner] = {
            m: evaluate_scores(s, yt, n_known, mask)["accuracy"] for m, s in test_scores.items()
        } | {"n": n}

    multi = [e for e in examples if e.split == "test" and not e.single]
    multi_sets = [{code.get(c, n_known) for c in e.labels} for e in multi]
    multi_result = {"n": len(multi)}
    if multi:
        m_texts = [e.text for e in multi]
        m_emb = vectors([e.cve for e in multi], True)
        m_scores = {
            "tfidf": tfidf_scores(final_tfidf, m_texts, n_classes),
            "embedding": embedding_scores(final_emb, m_emb, n_classes),
        }
        multi_result |= {m: any_in_top_k(s, multi_sets, 5) for m, s in m_scores.items()}

    support = Counter(int(v) for v in yt[at] if v < n_known)
    per_class = {}
    for k, _ in support.most_common(20):
        cls = known[k]
        row = {"support_name_absent": support[k]}
        for m in ("tfidf", "embedding"):
            pred = test_scores[m][at].argmax(1)
            tp = int(((pred == k) & (yt[at] == k)).sum())
            prec = tp / max(int((pred == k).sum()), 1)
            rec = tp / support[k]
            row[m] = round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0
        per_class[cls] = row

    return {
        "config_file": "src/cti/nlp/cwe_config.py",
        "headline": cfg.HEADLINE,
        "classes": {"known": n_known, "names": known},
        "label_facts": label_facts(examples, known_set, catalog),
        "selection_dev_name_absent_macro_f1": {
            m: {str(c): round(v, 4) for c, v in g.items()} for m, g in selection.items()
        },
        "chosen_c": best,
        "test": results,
        "paired_embedding_minus_tfidf_macro_f1": paired,
        "secondary": {
            "train_only_models": {
                m: evaluate_scores(s, yt, n_known, at) for m, s in train_only.items()
            },
            "unmasked_cwe_ids": {
                m: evaluate_scores(s, yt, n_known, at) for m, s in unmasked.items()
            },
            "test_accuracy_by_label_source": by_source,
            "test_accuracy_by_assigner": by_assigner,
            "multi_label_pool_any_in_top5": multi_result,
            "per_class_f1_top20_name_absent": per_class,
        },
    }


def gold_check(records) -> dict:
    """The circular gold-set row: per-source majority vs TF-IDF + LR, stratified k-fold."""
    from sklearn.model_selection import StratifiedKFold

    labels = np.array([r.primary_label for r in records])
    names = sorted(set(labels))
    y = np.array([names.index(lab) for lab in labels])
    sources = [r.source for r in records]
    texts = [r.text for r in records]
    source_hits, tfidf_hits = np.zeros(len(y), bool), np.zeros(len(y), bool)
    folds = StratifiedKFold(cfg.GOLD_FOLDS, shuffle=True, random_state=cfg.SEED)
    for train, test in folds.split(texts, y):
        by_source: dict[str, Counter] = {}
        for i in train:
            by_source.setdefault(sources[i], Counter())[y[i]] += 1
        overall = Counter(y[train]).most_common(1)[0][0]
        for i in test:
            counts = by_source.get(sources[i])
            source_hits[i] = (counts.most_common(1)[0][0] if counts else overall) == y[i]
        vec, model = fit_tfidf([texts[i] for i in train], y[train], cfg.GOLD_C)
        pred = model.predict(vec.transform([texts[i] for i in test]))
        tfidf_hits[test] = pred == y[test]
    return {
        "records": len(records),
        "primary_label_equals_source_share": round(
            float(np.mean([r.primary_label == _SOURCE_LABEL.get(r.source) for r in records])), 4
        ),
        "accuracy": {
            "source_only": round(float(source_hits.mean()), 4),
            "tfidf_lr": round(float(tfidf_hits.mean()), 4),
        },
        "note": "circular: labels were generated from the source feed; a sanity check only",
    }


_SOURCE_LABEL = {
    "nvd_ref": "vulnerability",
    "cisa_kev": "vulnerability",
    "threatfox": "ioc",
    "mitre_attack": "threat_actor",
    "phishtank": "phishing",
    "ransomwatch": "ransomware",
    "exploitdb": "exploit",
}
