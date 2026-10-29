"""Phase 10b: re-evaluate CVE -> ATT&CK ranking on a fresh, CVE-disjoint test set.

Every choice is pre-registered in :mod:`cti.nlp.attack2_config` (committed before any
test score). Training = CTID's KEV mappings; test = CTID ``attack_to_cve``. Methods rank
parent techniques per CVE; scoring reuses Phase 5b's per-CVE metrics.

Features are matrices (CVE x parent). Label-free ones (bi-encoder, TF-IDF, CAPEC paths,
CVSS rule) are computed once; the log prior depends on which CVEs count as training, so
it is rebuilt inside every cross-validation fold (leave-one-out for fold-training CVEs).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import numpy as np

from cti.nlp import attack2_config as cfg
from cti.nlp import attack_data
from cti.nlp.attack_eval import _per_cve, log_prior, rank_matrix

Gold = dict[str, dict[str, set[str]]]
TIE = 1000.0  # rule scores are scaled past any log-prior magnitude, so the prior only breaks ties


@dataclass
class Signals:
    """Label-free signals for a set of CVEs, rows in ``cves`` order, columns ``parents``."""

    cves: list[str]
    biencoder: np.ndarray
    tfidf: np.ndarray
    capec: np.ndarray  # log1p(path count)
    cvss: np.ndarray  # 0/1
    replay: np.ndarray  # 2 * CWE table hit + CVSS rule hit

    def rows(self, cves: Sequence[str]) -> Signals:
        pos = {c: i for i, c in enumerate(self.cves)}
        idx = [pos[c] for c in cves]
        return Signals(
            list(cves),
            *(m[idx] for m in (self.biencoder, self.tfidf, self.capec, self.cvss, self.replay)),
        )


def build_signals(
    cves: list[str],
    records: Mapping[str, attack_data.NvdRecord],
    parents: list[str],
    biencoder: np.ndarray,
    tfidf: np.ndarray,
    cwe_capec: Mapping[str, set[str]],
    capec_attack: Mapping[str, set[str]],
) -> Signals:
    """``biencoder``/``tfidf``: parent-level similarity, rows in ``cves`` order."""
    col = {p: i for i, p in enumerate(parents)}
    capec = np.zeros((len(cves), len(parents)))
    cvss = np.zeros_like(capec)
    table = np.zeros_like(capec)
    for i, cve in enumerate(cves):
        rec = records[cve]
        for p, n in attack_data.capec_paths(rec.cwes, cwe_capec, capec_attack).items():
            if p in col:
                capec[i, col[p]] = np.log1p(n)
        for p in attack_data.cvss_parents(rec.cvss):
            if p in col:
                cvss[i, col[p]] = 1.0
        for cwe in rec.cwes:
            for p in cfg.CWE_EXPLOITATION.get(cwe, ()):
                if p in col:
                    table[i, col[p]] = 1.0
    return Signals(cves, biencoder, tfidf, capec, cvss, 2 * table + cvss)


# ---- priors -----------------------------------------------------------------------------


def _counts(gold: Gold, cves: Sequence[str], mapping_type: str) -> Counter:
    return Counter(t for c in cves for t in gold[c].get(mapping_type, ()))


def prior_rows(
    gold: Gold, train: Sequence[str], rows: Sequence[str], parents: list[str], mapping_type: str
) -> np.ndarray:
    """Log prior per row CVE from ``train`` CVEs; leave-one-out for rows that are in ``train``."""
    counts = _counts(gold, train, mapping_type)
    train_set = set(train)
    full = log_prior(counts, parents)
    return np.array(
        [
            log_prior(counts, parents, gold[c].get(mapping_type, ())) if c in train_set else full
            for c in rows
        ]
    ).reshape(len(rows), len(parents))


# ---- methods ----------------------------------------------------------------------------


def _features(sig: Signals, prior: np.ndarray, drop: str | None = None) -> np.ndarray:
    """(CVE x parent) pairs as rows, FEATURES as columns (minus ``drop``)."""
    cols = {
        "log_prior": prior,
        "biencoder": sig.biencoder,
        "tfidf": sig.tfidf,
        "capec_paths": sig.capec,
        "cvss_rule": sig.cvss,
    }
    names = [f for f in cfg.FEATURES if f != drop]
    return np.stack([cols[f].ravel() for f in names], axis=1)


def _labels(gold: Gold, cves: Sequence[str], parents: list[str], mapping_type: str) -> np.ndarray:
    y = np.zeros((len(cves), len(parents)))
    col = {p: i for i, p in enumerate(parents)}
    for i, c in enumerate(cves):
        for p in gold[c].get(mapping_type, ()):
            if p in col:
                y[i, col[p]] = 1
    return y.ravel()


def fit_combiner(sig, prior, y, c_value, drop=None):
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    model = make_pipeline(
        StandardScaler(), LogisticRegression(C=c_value, random_state=cfg.SEED, **cfg.COMBINER)
    )
    return model.fit(_features(sig, prior, drop), y)


def combiner_scores(model, sig, prior, drop=None) -> np.ndarray:
    proba = model.predict_proba(_features(sig, prior, drop))[:, 1]
    return proba.reshape(len(sig.cves), -1)


# ---- metrics ----------------------------------------------------------------------------


def _rankings(cves, parents, scores) -> dict[str, list[str]]:
    return dict(zip(cves, rank_matrix(parents, scores), strict=True))


def per_cve_table(rankings, gold: Gold, mapping_type: str) -> tuple[list[str], np.ndarray, list]:
    cves = sorted(c for c in rankings if gold.get(c, {}).get(mapping_type))
    rows = [_per_cve(rankings[c], gold[c][mapping_type]) for c in cves]
    names = list(rows[0]) if rows else []
    return names, np.array([[r[n] for n in names] for r in rows]), cves


def _ci(values: np.ndarray) -> list[float]:
    rng = np.random.default_rng(cfg.SEED)
    idx = rng.integers(0, len(values), size=(cfg.N_BOOT, len(values)))
    lo, hi = np.percentile(values[idx].mean(axis=1), [2.5, 97.5])
    return [round(float(lo), 4), round(float(hi), 4)]


def score(rankings, gold: Gold, mapping_type: str) -> dict:
    names, table, _ = per_cve_table(rankings, gold, mapping_type)
    if not len(table):
        return {"cves": 0}
    out: dict = {"cves": len(table)}
    for i, name in enumerate(names):
        out[name] = {"value": round(float(table[:, i].mean()), 4), "ci95": _ci(table[:, i])}
    return out


def compare(a, b, gold: Gold, mapping_type: str, metric: str) -> dict:
    """Paired percentile bootstrap of metric(a) - metric(b) over the same CVEs."""
    names, ta, _ = per_cve_table(a, gold, mapping_type)
    _, tb, _ = per_cve_table(b, gold, mapping_type)
    if not len(ta):
        return {"cves": 0}
    diff = ta[:, names.index(metric)] - tb[:, names.index(metric)]
    return {
        "cves": len(diff),
        "metric": metric,
        "difference": round(float(diff.mean()), 4),
        "ci95": _ci(diff),
    }


def _hit5_mrr(rankings, gold, mapping_type) -> tuple[float, float]:
    names, table, _ = per_cve_table(rankings, gold, mapping_type)
    if not len(table):
        return 0.0, 0.0
    return float(table[:, names.index("hit@5")].mean()), float(table[:, names.index("mrr")].mean())


# ---- cross-validated selection ----------------------------------------------------------


def folds(cves: Sequence[str]) -> list[list[str]]:
    order = list(cves)
    np.random.default_rng(cfg.SEED).shuffle(order)
    return [order[i :: cfg.CV_FOLDS] for i in range(cfg.CV_FOLDS)]


def _pick(grid: dict, values: Sequence[float]) -> float:
    """Best mean hit@5, then MRR, then the smaller value."""
    return max(values, key=lambda v: (round(grid[v][0], 6), round(grid[v][1], 6), -v))


def select(
    sig: Signals,
    gold: Gold,
    train: list[str],
    parents: list[str],
    mapping_type: str,
    kind: str,
    drop: str | None = None,
) -> dict:
    """CV over training CVEs for beta (``kind="beta"``) or C (``kind="C"``)."""
    values = cfg.BETAS if kind == "beta" else cfg.COMBINER_C
    pooled: dict[float, list[dict[str, list[str]]]] = {v: [] for v in values}
    for held in folds(train):
        fit = [c for c in train if c not in set(held)]
        held_sig, held_prior = sig.rows(held), prior_rows(gold, fit, held, parents, mapping_type)
        if kind == "beta":
            for b in values:
                scores = held_sig.biencoder + b * held_prior
                pooled[b].append(_rankings(held, parents, scores))
            continue
        fit_sig = sig.rows(fit)
        fit_prior = prior_rows(gold, fit, fit, parents, mapping_type)
        y = _labels(gold, fit, parents, mapping_type)
        for c_value in values:
            model = fit_combiner(fit_sig, fit_prior, y, c_value, drop)
            pooled[c_value].append(
                _rankings(held, parents, combiner_scores(model, held_sig, held_prior, drop))
            )
    grid = {}
    for v, parts in pooled.items():
        merged = {c: r for part in parts for c, r in part.items()}
        grid[v] = _hit5_mrr(merged, gold, mapping_type)
    best = _pick(grid, values)
    return {
        "value": best,
        "cv_hit@5": {str(v): round(g[0], 4) for v, g in grid.items()},
        "cv_mrr": {str(v): round(g[1], 4) for v, g in grid.items()},
    }


# ---- evaluation -------------------------------------------------------------------------


def rank_all(
    train_sig: Signals,
    test_sig: Signals,
    gold: Gold,
    parents: list[str],
    mapping_type: str,
    chosen: Mapping[str, float],
) -> dict[str, dict[str, list[str]]]:
    """Test rankings of every method (and ablation) for one mapping type."""
    train = train_sig.cves
    test = test_sig.cves
    test_prior = prior_rows(gold, train, test, parents, mapping_type)
    train_prior = prior_rows(gold, train, train, parents, mapping_type)
    y = _labels(gold, train, parents, mapping_type)
    out = {
        "majority": _rankings(test, parents, test_prior),
        "prior+biencoder": _rankings(
            test, parents, test_sig.biencoder + chosen["beta"] * test_prior
        ),
        "capec-chain": _rankings(test, parents, TIE * test_sig.capec + test_prior),
    }
    if mapping_type == cfg.PRIMARY_TYPE:
        out["methodology-replay"] = _rankings(test, parents, TIE * test_sig.replay + test_prior)
    for name, drop in (("combiner", None), *((a, a.split("no-")[1]) for a in cfg.ABLATIONS)):
        model = fit_combiner(train_sig, train_prior, y, chosen[name], drop)
        out[name] = _rankings(test, parents, combiner_scores(model, test_sig, test_prior, drop))
    return out


def evaluate(
    train_sig: Signals,
    test_sig: Signals,
    gold: Gold,
    parents: list[str],
    raw: Mapping[str, set[str]],
    families: Mapping[str, str],
    max_cos: Mapping[str, float],
) -> dict:
    """Every method, mapping type and pre-registered report. ``gold`` covers both splits;
    ``raw``: unrolled test exploitation IDs; ``families``: CVE -> CVSS family used ("v2",
    "v3", "none"); ``max_cos``: test CVE -> max bi-encoder cosine to a training text."""
    feasibility = train_feasibility(train_sig, gold, parents, families)
    results: dict = {}
    selection: dict = {}
    sensitivity: dict = {}
    for mapping_type in (cfg.PRIMARY_TYPE, *cfg.SECONDARY_TYPES):
        train = [c for c in train_sig.cves if gold[c].get(mapping_type)]
        tsig = train_sig.rows(train)
        chosen_sel = {"beta": select(tsig, gold, train, parents, mapping_type, "beta")}
        chosen_sel["combiner"] = select(tsig, gold, train, parents, mapping_type, "C")
        for a in cfg.ABLATIONS:
            chosen_sel[a] = select(tsig, gold, train, parents, mapping_type, "C", a.split("no-")[1])
        chosen = {k: v["value"] for k, v in chosen_sel.items()}
        selection[mapping_type] = chosen_sel
        ranked = rank_all(tsig, test_sig, gold, parents, mapping_type, chosen)
        cell = results.setdefault(mapping_type, {})
        for method, ranking in ranked.items():
            cell[method] = score(ranking, gold, mapping_type)
            if method != "majority":
                cell[method]["vs_majority"] = compare(
                    ranking, ranked["majority"], gold, mapping_type, "hit@5"
                )
        if mapping_type == cfg.PRIMARY_TYPE:
            primary = ranked
            sensitivity = _sensitivity(tsig, test_sig, gold, parents, chosen)
    decision = compare(
        primary[cfg.HEADLINE], primary[cfg.BASELINE], gold, cfg.PRIMARY_TYPE, cfg.DECISION_METRIC
    )
    decision["combiner_better"] = decision.get("ci95", [0, 0])[0] > 0
    return {
        "decision": decision,
        "headline_vs_baseline": {
            m: compare(primary[cfg.HEADLINE], primary[cfg.BASELINE], gold, cfg.PRIMARY_TYPE, m)
            for m in ("hit@1", "mrr")
        },
        "results": results,
        "selection": selection,
        "per_technique": _per_technique(primary, gold),
        "by_cvss_family": {
            fam: {
                m: _subset_score(primary[m], gold, [c for c in test_sig.cves if families[c] == fam])
                for m in (cfg.HEADLINE, cfg.BASELINE, "majority")
            }
            for fam in ("v2", "v3", "none")
        },
        "below_near_duplicate": {
            "threshold": cfg.NEAR_DUPLICATE,
            "excluded": sum(max_cos[c] >= cfg.NEAR_DUPLICATE for c in test_sig.cves),
            "results": {
                m: _subset_score(
                    primary[m], gold, [c for c in test_sig.cves if max_cos[c] < cfg.NEAR_DUPLICATE]
                )
                for m in (cfg.HEADLINE, cfg.BASELINE, "majority")
            },
        },
        "train_feasibility": feasibility,
        "subtechnique": _subtechnique(primary, gold, raw),
        "post_hoc_sensitivity": sensitivity,
    }


def _subset_score(rankings, gold, cves, mapping_type=cfg.PRIMARY_TYPE) -> dict:
    return score({c: rankings[c] for c in cves if c in rankings}, gold, mapping_type)


def _per_technique(primary, gold) -> dict:
    by_parent: dict[str, list[str]] = {}
    for c in primary[cfg.HEADLINE]:
        for p in gold[c].get(cfg.PRIMARY_TYPE, ()):
            by_parent.setdefault(p, []).append(c)
    out = {}
    for p, cves in sorted(by_parent.items()):
        if len(cves) >= cfg.PER_TECHNIQUE_MIN:
            out[p] = {
                m: round(float(np.mean([p in primary[m][c][:5] for c in cves])), 4)
                for m in (cfg.HEADLINE, cfg.BASELINE, "majority")
            } | {"cves": len(cves)}
    return out


def train_feasibility(train_sig: Signals, gold: Gold, parents, families) -> dict:
    """Training-only checks (TRAIN_FEASIBILITY): rule firing and hit rates per CVSS family,
    CAPEC coverage, positives per mapping type."""
    rule = {}
    for fam in ("v2", "v3", "none"):
        idx = [i for i, c in enumerate(train_sig.cves) if families[c] == fam]
        fired = [i for i in idx if train_sig.cvss[i].any()]
        hits = sum(
            bool(
                {parents[j] for j in np.flatnonzero(train_sig.cvss[i])}
                & gold[train_sig.cves[i]].get(cfg.PRIMARY_TYPE, set())
            )
            for i in fired
        )
        rule[fam] = {"cves": len(idx), "fired": len(fired), "fired_and_hit_a_label": hits}
    return {
        "cvss_rule_by_family": rule,
        "capec_coverage": round(float((train_sig.capec.sum(axis=1) > 0).mean()), 4),
        "positives_per_type": {
            t: sum(len(gold[c].get(t, ())) for c in train_sig.cves)
            for t in (cfg.PRIMARY_TYPE, *cfg.SECONDARY_TYPES)
        },
        "graded_cves_per_type": {
            t: sum(bool(gold[c].get(t)) for c in train_sig.cves)
            for t in (cfg.PRIMARY_TYPE, *cfg.SECONDARY_TYPES)
        },
    }


def _subtechnique(primary, gold, raw) -> dict:
    out = {}
    for fam in cfg.SUBTECHNIQUE_REPORT:
        subs = sorted({t for ids in raw.values() for t in ids if t.split(".")[0] == fam})
        for sub in subs:
            cves = [c for c, ids in raw.items() if sub in ids and c in primary[cfg.HEADLINE]]
            out[sub] = {
                m: round(float(np.mean([fam in primary[m][c][:5] for c in cves])), 4)
                for m in (cfg.HEADLINE, cfg.BASELINE)
            } | {"cves": len(cves)}
    return out


def _sensitivity(train_sig, test_sig, gold, parents, chosen) -> dict:
    """Post hoc, never used for any choice: test hit@5 across the beta and C grids."""
    mt = cfg.PRIMARY_TYPE
    train = train_sig.cves
    test_prior = prior_rows(gold, train, test_sig.cves, parents, mt)
    train_prior = prior_rows(gold, train, train, parents, mt)
    y = _labels(gold, train, parents, mt)
    beta = {
        str(b): _hit5_mrr(
            _rankings(test_sig.cves, parents, test_sig.biencoder + b * test_prior), gold, mt
        )[0]
        for b in cfg.BETAS
    }
    c_grid = {}
    for c_value in cfg.COMBINER_C:
        model = fit_combiner(train_sig, train_prior, y, c_value)
        r = _rankings(test_sig.cves, parents, combiner_scores(model, test_sig, test_prior))
        c_grid[str(c_value)] = _hit5_mrr(r, gold, mt)[0]
    return {
        "note": "post hoc on test; not used for selection",
        "beta_hit@5": {k: round(v, 4) for k, v in beta.items()},
        "C_hit@5": {k: round(v, 4) for k, v in c_grid.items()},
        "chosen": dict(chosen),
    }
