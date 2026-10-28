"""``cti risk-eval``: forward-looking KEV prediction with rolling-origin folds (Phase 7b).

Every choice is pre-registered in ``risk_config`` (committed before any test score); see
``vault/risk-eval.md``. Each CVE is scored with only what was known at a cutoff
(``features_at(record, as_of)``), and the label is whether CISA added it to KEV in the
window that followed. Each test fold is trained only on windows that closed before it.

- **Models:** L2 logistic regression (headline) and a monotonic gradient-boosting
  challenger, both with fixed hyperparameters.
- **Baselines:** EPSS at the cutoff, an SSVC rule, and CNA CVSS (snapshot-time, labelled).
- **Metrics:** recall@k with fractional credit for the tie group at rank k, pooled over the
  folds with Wilson intervals; a paired, label-stratified bootstrap of the hit difference
  against EPSS (the only significance claim); AP and ROC-AUC per fold; rank-fraction tiers.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from itertools import pairwise

import numpy as np

from cti.enrich.cves import cve_sort_key, features_at
from cti.nlp import risk_config as cfg

FEATURES = list(cfg.FEATURES)
EPSS_FEATURES = ("epss_logit", "epss_missing")
SSVC_FEATURES = ("ssvc_exploitation", "ssvc_automatable", "ssvc_total_impact", "ssvc_missing")


@dataclass
class Window:
    """Every eligible CVE at one cutoff, its features, and its label."""

    label: str
    day: str
    cves: list[str]
    x: np.ndarray  # (n, len(FEATURES)); NaN where EPSS/SSVC values are missing
    y: np.ndarray  # bool: added to KEV in (day, window end]
    epss: np.ndarray  # EPSS probability at the cutoff, -inf if missing
    ssvc_rule: np.ndarray
    cvss_cna: np.ndarray  # snapshot-time; -inf if missing
    details: list[dict]  # per-CVE facts for the case table


def _logit(p: float) -> float:
    lo, hi = cfg.EPSS_CLIP
    p = min(max(p, lo), hi)
    return math.log(p / (1 - p))


def featurize(record: dict, as_of: str, day: str) -> tuple[list[float], dict]:
    """The pre-registered features of ``record`` at ``as_of`` (read via features_at only)."""
    s = features_at(record, as_of)
    epss, vr = s.get("epss"), s.get("vulnrichment")
    if epss is not None and (epss.get("score_date") or "")[:10] > day:
        raise ValueError(f"{record['cve']}: EPSS scored after {as_of}")
    if vr is not None and (vr.get("decided_at") or "")[:10] > day:
        raise ValueError(f"{record['cve']}: SSVC decided after {as_of}")
    nan = float("nan")
    age = (date.fromisoformat(day) - date.fromisoformat(record["published"][:10])).days
    values = {
        "epss_logit": _logit(epss["percentile"]) if epss else nan,
        "epss_missing": float(epss is None),
        "ssvc_exploitation": float(cfg.SSVC_EXPLOITATION.get(vr.get("exploitation"), nan))
        if vr
        else nan,
        "ssvc_automatable": {"yes": 1.0, "no": 0.0}.get(vr.get("automatable"), nan) if vr else nan,
        "ssvc_total_impact": {"total": 1.0, "partial": 0.0}.get(vr.get("technical_impact"), nan)
        if vr
        else nan,
        "ssvc_missing": float(vr is None),
        "exploitdb": float(bool(s.get("exploitdb", {}).get("exploit_count"))),
        "metasploit": float("metasploit" in s),
        "nuclei": float("nuclei" in s),
        "log_age_days": math.log1p(min(max(age, 0), cfg.AGE_CAP_DAYS)),
    }
    return [values[f] for f in FEATURES], {
        "epss": epss["epss"] if epss else None,
        "epss_percentile": epss["percentile"] if epss else None,
        "ssvc_exploitation": vr.get("exploitation") if vr else None,
        "exploit_sources": [k for k in ("exploitdb", "metasploit", "nuclei") if values[k]],
    }


def window_end(day: str) -> str:
    nxt = (date.fromisoformat(day) + timedelta(days=cfg.WINDOW_DAYS)).isoformat()
    return min(nxt, cfg.KEV_LAST_DATE)


def build_windows(records: Iterable[dict], as_of_dates: dict[str, str]) -> dict[str, Window]:
    """One Window per cutoff label in ``cfg.CUTOFFS``."""
    days = {label: as_of_dates[label] for label in cfg.CUTOFFS}
    for older, newer in pairwise(cfg.CUTOFFS):
        expected = (date.fromisoformat(days[older]) + timedelta(days=cfg.WINDOW_DAYS)).isoformat()
        if days[newer] != expected:
            raise ValueError(f"{newer} is {days[newer]}, expected {expected}")
    rows: dict[str, list] = {label: [] for label in cfg.CUTOFFS}
    for record in records:
        if record["published"][:10] < cfg.NVD_WINDOW_START:
            raise ValueError(f"{record['cve']} is outside the NVD window")
        kev = (record["kev"] or {}).get("date_added")
        cna = (record["context_snapshot"].get("cvss_cna") or {}).get("base_score")
        for label, day in days.items():
            if not record["eligible"].get(label):
                continue
            x, detail = featurize(record, label, day)
            y = kev is not None and day < kev <= window_end(day)
            rows[label].append((record["cve"], x, y, detail, cna))
    windows = {}
    for label, items in rows.items():
        items.sort(key=lambda r: cve_sort_key(r[0]))
        x = np.array([r[1] for r in items], dtype=float).reshape(len(items), len(FEATURES))
        epss = np.array([d["epss"] if d["epss"] is not None else -np.inf for *_, d, _ in items])
        expl = x[:, FEATURES.index("ssvc_exploitation")]
        rule = np.where(np.isnan(expl), -1.0, expl) * 10 + np.where(np.isinf(epss), -1.0, epss)
        windows[label] = Window(
            label=label,
            day=days[label],
            cves=[r[0] for r in items],
            x=x,
            y=np.array([r[2] for r in items], dtype=bool),
            epss=epss,
            ssvc_rule=rule,
            cvss_cna=np.array([r[4] if r[4] is not None else -np.inf for r in items]),
            details=[r[3] for r in items],
        )
    return windows


# ---- models ----------------------------------------------------------------------------------


@dataclass
class Fitted:
    columns: list[int]
    medians: np.ndarray
    model: object
    mean: np.ndarray | None = None
    std: np.ndarray | None = None
    pca: object | None = None

    def matrix(self, x: np.ndarray, text: np.ndarray | None) -> np.ndarray:
        m = x[:, self.columns].copy()
        holes = np.isnan(m)
        m[holes] = np.take(self.medians, np.nonzero(holes)[1])
        if self.pca is not None:
            m = np.hstack([m, self.pca.transform(text)])
        if self.mean is not None:
            m = (m - self.mean) / self.std
        return m

    def score(self, x: np.ndarray, text: np.ndarray | None = None) -> np.ndarray:
        return self.model.predict_proba(self.matrix(x, text))[:, 1]


def fit(
    x: np.ndarray,
    y: np.ndarray,
    features: Sequence[str],
    kind: str = "logistic",
    text: np.ndarray | None = None,
) -> Fitted:
    from sklearn.decomposition import PCA
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression

    columns = [FEATURES.index(f) for f in features]
    sub = x[:, columns]
    seen = ~np.isnan(sub)
    # a column with no values at all (e.g. SSVC before it existed) imputes 0
    medians = np.array(
        [np.median(sub[seen[:, j], j]) if seen[:, j].any() else 0.0 for j in range(sub.shape[1])]
    )
    fitted = Fitted(columns=columns, medians=medians, model=None)
    if text is not None:
        fitted.pca = PCA(n_components=cfg.TEXT_PCA, random_state=cfg.SEED).fit(text)
    m = fitted.matrix(x, text)
    if kind == "logistic":
        fitted.mean = m.mean(axis=0)
        fitted.std = np.where(m.std(axis=0) > 0, m.std(axis=0), 1.0)
        m = (m - fitted.mean) / fitted.std
        lr = cfg.LOGISTIC
        fitted.model = LogisticRegression(
            C=lr.c, solver=lr.solver, max_iter=lr.max_iter, class_weight=lr.class_weight
        ).fit(m, y)
    else:
        hgb = cfg.BOOSTING
        fitted.model = HistGradientBoostingClassifier(
            max_depth=hgb.max_depth,
            min_samples_leaf=hgb.min_samples_leaf,
            learning_rate=hgb.learning_rate,
            max_iter=hgb.max_iter,
            l2_regularization=hgb.l2_regularization,
            early_stopping=hgb.early_stopping,
            monotonic_cst=[int(f in hgb.monotonic_increasing) for f in features],
            random_state=cfg.SEED,
        ).fit(m, y)
    return fitted


# ---- metrics ---------------------------------------------------------------------------------


def hits_at_k(scores: np.ndarray, y: np.ndarray, k: int) -> float:
    """Expected positives in the top k under a random tie-break: the tie group at rank k
    gets credit (k - ranked above) / group size per CVE."""
    n = len(scores)
    if k >= n:
        return float(y.sum())
    kth = np.partition(scores, n - k)[n - k]
    above = scores > kth
    tied = scores == kth
    return float(y[above].sum() + (k - above.sum()) * y[tied].sum() / tied.sum())


def wilson(hits: float, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = hits / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)


def ranks(scores: np.ndarray) -> np.ndarray:
    """1-based rank, best first; ties get their average rank."""
    from scipy.stats import rankdata

    return rankdata(-scores, method="average")


def k_fraction(n: int) -> int:
    return max(1, round(cfg.K_FRACTION * n))


def fold_metrics(scores: np.ndarray, y: np.ndarray) -> dict:
    from sklearn.metrics import average_precision_score, roc_auc_score

    n, pos = len(y), int(y.sum())
    out = {"n": n, "positives": pos, "k_1%": k_fraction(n)}
    for k in cfg.K_ABS:
        out[f"hits@{k}"] = round(hits_at_k(scores, y, k), 3)
    out["hits@1%"] = round(hits_at_k(scores, y, k_fraction(n)), 3)
    finite = np.where(np.isinf(scores), np.nanmin(scores[np.isfinite(scores)]) - 1, scores)
    out["average_precision"] = round(float(average_precision_score(y, finite)), 4)
    out["roc_auc"] = round(float(roc_auc_score(y, finite)), 4)
    return out


def pooled(per_fold: dict[str, dict]) -> dict:
    pos = sum(f["positives"] for f in per_fold.values())
    out = {"positives": pos}
    for name in (*(f"hits@{k}" for k in cfg.K_ABS), "hits@1%"):
        hits = sum(f[name] for f in per_fold.values())
        recall = name.replace("hits", "recall")
        out[name] = round(hits, 3)
        out[recall] = round(hits / pos, 4) if pos else 0.0
        out[f"{recall}_wilson95"] = wilson(hits, pos)
    out["mean_average_precision"] = round(
        float(np.mean([f["average_precision"] for f in per_fold.values()])), 4
    )
    return out


def paired_bootstrap(
    a: dict[str, np.ndarray], b: dict[str, np.ndarray], y: dict[str, np.ndarray], k_of
) -> dict:
    """Pooled hits@k of a minus b, CVEs resampled within each fold stratified by label."""
    rng = np.random.default_rng(cfg.SEED)
    point = sum(hits_at_k(a[f], y[f], k_of(f)) - hits_at_k(b[f], y[f], k_of(f)) for f in y)
    strata = {f: (np.flatnonzero(y[f]), np.flatnonzero(~y[f])) for f in y}
    diffs = []
    for _ in range(cfg.N_BOOT):
        total = 0.0
        for f, (pos, neg) in strata.items():
            parts = [rng.choice(g, len(g)) for g in (pos, neg) if len(g)]
            i = np.concatenate(parts)
            total += hits_at_k(a[f][i], y[f][i], k_of(f)) - hits_at_k(b[f][i], y[f][i], k_of(f))
        diffs.append(total)
    lo, hi = np.percentile(diffs, [2.5, 97.5])
    return {
        "difference_hits": round(point, 3),
        "ci95": [round(float(lo), 3), round(float(hi), 3)],
        "excludes_zero": bool(lo > 0 or hi < 0),
    }


def assign_tiers(scores: np.ndarray) -> np.ndarray:
    """Tier name per CVE from its rank fraction (best first; ties share their average rank)."""
    r = ranks(scores) / len(scores)
    assigned = np.full(len(r), cfg.TIERS[-1][0], dtype=object)
    for name, cut in reversed(cfg.TIERS):
        assigned[r <= cut] = name
    return assigned


def tiers(scores: dict[str, np.ndarray], y: dict[str, np.ndarray]) -> dict:
    counts = {name: [0, 0] for name, _ in cfg.TIERS}
    for f in y:
        assigned = assign_tiers(scores[f])
        for name, _ in cfg.TIERS:
            mask = assigned == name
            counts[name][0] += int(mask.sum())
            counts[name][1] += int(y[f][mask].sum())
    rows = {
        name: {
            "cves": n,
            "kev_positives": pos,
            "hit_rate": round(pos / n, 5) if n else 0.0,
            "wilson95": wilson(pos, n),
        }
        for name, (n, pos) in counts.items()
    }
    rates = [pos / n if n else 0.0 for n, pos in counts.values()]
    return {"tiers": rows, "monotonic": all(a > b for a, b in pairwise(rates))}


# ---- the evaluation ----------------------------------------------------------------------------


def run(
    windows: dict[str, Window],
    vectors: Callable[[Sequence[str]], np.ndarray],
    kev_language: set[str],
    log: Callable[[str], None] = print,
) -> dict:
    """The whole pre-registered evaluation. ``vectors(cves)`` returns NVD-description
    embeddings (snapshot-time; used only by the text ablations)."""
    tests = list(cfg.FOLDS)
    y = {f: windows[f].y for f in tests}

    def train(f: str, keep: Callable[[Window], np.ndarray] | None = None):
        parts = [windows[w] for w in cfg.FOLDS[f]]
        masks = [keep(w) if keep else np.ones(len(w.y), bool) for w in parts]
        x = np.vstack([w.x[m] for w, m in zip(parts, masks, strict=True)])
        yy = np.concatenate([w.y[m] for w, m in zip(parts, masks, strict=True)])
        cves = [
            c
            for w, m in zip(parts, masks, strict=True)
            for c, k in zip(w.cves, m, strict=True)
            if k
        ]
        return x, yy, cves

    def model_scores(features, kind="logistic", use_text=False, keep=None):
        out, fits = {}, {}
        for f in tests:
            x, yy, cves = train(f, keep)
            w = windows[f]
            m = keep(w) if keep else np.ones(len(w.y), bool)
            text_tr = vectors(cves) if use_text else None
            text_te = (
                vectors([c for c, k in zip(w.cves, m, strict=True) if k]) if use_text else None
            )
            fits[f] = fit(x, yy, features, kind, text_tr)
            out[f] = fits[f].score(w.x[m], text_te)
        return out, fits

    log("  fitting logistic (headline)")
    scores = {}
    scores["logistic"], lr_fits = model_scores(FEATURES)
    log("  fitting boosting (challenger)")
    scores["boosting"], _ = model_scores(FEATURES, kind="boosting")
    for base in cfg.BASELINES:
        scores[base] = {f: getattr(windows[f], base) for f in tests}

    methods = {
        m: {"per_fold": {f: fold_metrics(scores[m][f], y[f]) for f in tests}} for m in scores
    }
    for m in methods.values():
        m["pooled"] = pooled(m["per_fold"])
    pos_total = sum(int(y[f].sum()) for f in tests)
    random_recall = {
        f"recall@{k}": round(sum(min(k / len(y[f]), 1) * y[f].sum() for f in tests) / pos_total, 5)
        for k in cfg.K_ABS
    }
    random_recall["recall@1%"] = cfg.K_FRACTION

    log("  bootstrap: logistic vs EPSS")

    def k_of(_fold: str) -> int:
        return 100

    def k1(fold: str) -> int:
        return k_fraction(len(y[fold]))

    decision = paired_bootstrap(scores["logistic"], scores["epss"], y, k_of)
    secondary_paired = {
        "logistic_minus_epss_hits@1%": paired_bootstrap(scores["logistic"], scores["epss"], y, k1),
        "boosting_minus_epss_hits@100": paired_bootstrap(
            scores["boosting"], scores["epss"], y, k_of
        ),
    }

    log("  ablations")
    ablations = {}
    for name, feats in (
        ("no_ssvc", [f for f in FEATURES if f not in SSVC_FEATURES]),
        ("no_epss", [f for f in FEATURES if f not in EPSS_FEATURES]),
    ):
        s, _ = model_scores(feats)
        per = {f: fold_metrics(s[f], y[f]) for f in tests}
        ablations[name] = {"per_fold": per, "pooled": pooled(per)}
    s, _ = model_scores(FEATURES, use_text=True)
    per = {f: fold_metrics(s[f], y[f]) for f in tests}
    ablations["text"] = {"per_fold": per, "pooled": pooled(per)}

    def no_kev_language(w: Window) -> np.ndarray:
        return np.array([c not in kev_language for c in w.cves])

    s, _ = model_scores(FEATURES, use_text=True, keep=no_kev_language)
    keep = {f: no_kev_language(windows[f]) for f in tests}
    yk = {f: y[f][keep[f]] for f in tests}
    epss_k = {f: windows[f].epss[keep[f]] for f in tests}
    per = {f: fold_metrics(s[f], yk[f]) for f in tests}
    per_epss = {f: fold_metrics(epss_k[f], yk[f]) for f in tests}
    ablations["text_no_kev_language"] = {
        "dropped_cves": {f: int((~keep[f]).sum()) for f in tests},
        "per_fold": per,
        "pooled": pooled(per),
        "epss_same_population": {"per_fold": per_epss, "pooled": pooled(per_epss)},
    }

    cases = []
    for f in tests:
        w = windows[f]
        r_lr, r_epss = ranks(scores["logistic"][f]), ranks(scores["epss"][f])
        for i in np.flatnonzero(w.y):
            cases.append(
                {
                    "fold": f,
                    "cve": w.cves[i],
                    "logistic_rank": float(r_lr[i]),
                    "epss_rank": float(r_epss[i]),
                    # by average rank: a tie group straddling rank 100 can show False here
                    # while getting fractional credit in hits@100
                    "top100_by_average_rank": {
                        "logistic": bool(r_lr[i] <= 100),
                        "epss": bool(r_epss[i] <= 100),
                    },
                    **w.details[i],
                }
            )

    last = lr_fits[tests[-1]]
    names = [FEATURES[c] for c in last.columns]
    coefficients = {n: round(float(c), 4) for n, c in zip(names, last.model.coef_[0], strict=True)}

    return {
        "config_file": "src/cti/nlp/risk_config.py",
        "headline": cfg.HEADLINE,
        "folds": {
            f: {
                "cutoff": windows[f].day,
                "window_end": window_end(windows[f].day),
                "train_windows": list(cfg.FOLDS[f]),
                "train_positives": int(sum(windows[t].y.sum() for t in cfg.FOLDS[f])),
                "eligible": len(y[f]),
                "positives": int(y[f].sum()),
            }
            for f in tests
        },
        "methods": methods,
        "random_expected": random_recall,
        "logistic_iterations": {f: int(lr_fits[f].model.n_iter_[0]) for f in tests},
        "decision": {
            "rule": "logistic beats EPSS iff the paired 95% CI of pooled hits@100 excludes 0",
            "logistic_minus_epss_hits@100": decision,
            "verdict": (
                ("logistic better" if decision["difference_hits"] > 0 else "EPSS better")
                if decision["excludes_zero"]
                else "no detectable difference"
            ),
        },
        "secondary_paired": secondary_paired,
        "ablations": ablations,
        "tiers_logistic": tiers(scores["logistic"], y),
        "logistic_coefficients_last_fold_standardized": coefficients,
        "positives": cases,
    }
