"""Pre-registered configuration for ``cti cwe-eval`` (Phase 6).

Every choice the CWE evaluation makes is fixed here, and this file was committed before any
test-split score was computed (``git log -- src/cti/nlp/cwe_config.py`` is the evidence).
Feasibility (solver, iteration limits) was checked on train -> dev only. Changing anything
here after test scoring must be disclosed as a deviation in ``vault/cwe-classification.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---- data ----------------------------------------------------------------------------------
TRAIN_END = "2025-12-31"  # published on or before: train
DEV_END = "2026-04-29"  # the Phase 7 cutoff; after it: test (to the 2026-10-26 snapshot)
LABEL_CHAIN = ("nvd", "cna", "cisa_adp")  # first source with a usable CWE wins
EXCLUDED_USAGE = ("Prohibited",)  # categories, views, deprecated IDs: never labels
MIN_TRAIN_EXAMPLES = 50  # classes with fewer single-label train CVEs collapse to OTHER
OTHER = "other"

# literal IDs in the text are masked for every method; the unmasked run is secondary
CWE_ID_PATTERN = r"\bCWE-\d+\b"
CWE_ID_MASK = "CWE-[id]"
# "name present": the label's catalog name, or its part before " (", lowercased, appears
# as a substring of the lowercased description (templated CNA wording)

# ---- methods -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Tfidf:
    ngram_range: tuple[int, int] = (1, 2)
    min_df: int = 2
    max_features: int = 200_000
    sublinear_tf: bool = True
    stop_words: str = "english"
    c_grid: tuple[float, ...] = (0.1, 1.0, 10.0, 100.0)
    solver: str = "saga"
    max_iter: int = 300
    tol: float = 1e-3


@dataclass(frozen=True)
class Embedding:
    # SecureBERT 2.0 bi-encoder vectors (precomputed by `cti embed`), standardized
    c_grid: tuple[float, ...] = (0.01, 0.1, 1.0)
    solver: str = "lbfgs"
    max_iter: int = 3000
    tol: float = 1e-4


TFIDF = Tfidf()
EMBEDDING = Embedding()
# nearest centroid on the (L2-normalized) embeddings: no parameters

# ---- selection, refit, metrics --------------------------------------------------------------
# C per method: best dev macro-F1 over known classes on the name-absent stratum (ties: the
# smaller C). Then refit on train + dev with that C and score test once. The train-only
# model's test score is also reported.
HEADLINE = "macro-F1 over known classes (OTHER excluded), test split, name-absent stratum"
TOP_K = (1, 3, 5)
N_BOOT = 1000
SEED = 20261027
TOP_ASSIGNERS = 5  # breakdown of test by the assigning CNA

# ---- added after the pre-registration commit (gold sanity row only; never the test split) ----
# The rule-generated gold set (299 docs; primary label == source feed for 298) gets one
# circular row: per-source majority vs TF-IDF + logistic regression, stratified 5-fold CV.
GOLD_FOLDS = 5
GOLD_C = 1.0
