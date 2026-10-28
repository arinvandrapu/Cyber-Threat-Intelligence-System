"""Pre-registered configuration for ``cti risk-eval`` (Phase 7b).

Every choice the forward-looking KEV evaluation makes is fixed here, and this file was
committed before any test-fold score was computed (``git log -- src/cti/nlp/risk_config.py``
is the evidence; the output JSON also records this file's SHA-256 and the git commit).
Feasibility (convergence, run time) may be checked on training windows only. Changing
anything here after test scoring must be disclosed as a deviation in
``vault/risk-eval.md``.

Design (vault/risk-scoring-design.md): score each CVE with only what was known at a cutoff,
then ask whether CISA added it to KEV in the next 180 days. Rolling origin over four
cutoffs 180 days apart: each test fold is trained only on windows that closed before it.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---- folds ---------------------------------------------------------------------------------
# as_of labels oldest first; each window's label is KEV date_added in (cutoff, next cutoff]
# (the last window ends at cutoff + WINDOW_DAYS = the snapshot).
CUTOFFS = ("cutoff4", "cutoff3", "cutoff2", "cutoff")
WINDOW_DAYS = 180
# test fold -> training windows (all closed by the test cutoff)
FOLDS = {
    "cutoff3": ("cutoff4",),
    "cutoff2": ("cutoff4", "cutoff3"),
    "cutoff": ("cutoff4", "cutoff3", "cutoff2"),
}
# Population per window: eligible[as_of] = CVEs published from NVD_WINDOW_START up to the
# cutoff and not yet in KEV. Older CVEs later added to KEV are out of scope (stated).
NVD_WINDOW_START = "2024-01-01"
# Labels come from KEV catalog 2026.10.23 (1,756 entries, released 2026-10-23, fetched
# 2026-10-26 16:15 UTC). Every window ends at min(next cutoff, KEV_LAST_DATE), so the last
# window is (2026-04-29, 2026-10-23]: 177 days, disclosed. KEV entries removed or
# re-dated before the snapshot are invisible here (limitation).
KEV_CATALOG_VERSION = "2026.10.23"
KEV_LAST_DATE = "2026-10-23"

# ---- features (read only through features_at(record, as_of)) ------------------------------
# EPSS and SSVC can be missing (not yet scored): the value is imputed with the training
# median (fit on training rows only) and an indicator is set; never 0. ExploitDB,
# Metasploit and Nuclei flags are real absences: no entry at the cutoff commit = 0.
FEATURES = (
    "epss_logit",  # logit(clip(EPSS percentile, EPSS_CLIP)): comparable across v3/v4 and
    # spreads the top tail, where recall@100 is decided
    "epss_missing",
    "ssvc_exploitation",  # none=0, poc=1, active=2 (CISA Vulnrichment at the cutoff commit)
    "ssvc_automatable",  # yes=1, no=0
    "ssvc_total_impact",  # technical impact total=1, partial=0
    "ssvc_missing",
    "exploitdb",  # any ExploitDB entry naming the CVE at the cutoff commit
    "metasploit",  # any Metasploit module referencing the CVE at the cutoff commit
    "nuclei",  # any Nuclei template for the CVE at the cutoff commit
    "log_age_days",  # log1p(min(days from publication to the cutoff, AGE_CAP_DAYS))
)
EPSS_CLIP = (1e-5, 1 - 1e-5)
# The NVD window starts 2024-01-01, so the oldest eligible CVE is ~310 days old at cutoff4
# but ~850 at cutoff: the cap keeps every fold inside the range its training data saw.
AGE_CAP_DAYS = 365
SSVC_EXPLOITATION = {"none": 0, "poc": 1, "active": 2}  # "active" is on 2 eligible CVEs in
# total, so in practice this is poc vs none

# ---- models (fixed hyperparameters; nothing is tuned) ----------------------------------------


@dataclass(frozen=True)
class Logistic:  # headline model: features standardized on training rows
    c: float = 1.0
    penalty: str = "l2"
    solver: str = "lbfgs"
    max_iter: int = 2000
    class_weight: None = None  # ranking metrics only; no reweighting


@dataclass(frozen=True)
class Boosting:  # challenger: HistGradientBoostingClassifier
    max_depth: int = 3
    min_samples_leaf: int = 50
    learning_rate: float = 0.05
    max_iter: int = 200
    l2_regularization: float = 1.0
    early_stopping: bool = False
    # +1 (increasing) for these, 0 for the rest
    monotonic_increasing: tuple[str, ...] = (
        "epss_logit",
        "ssvc_exploitation",
        "exploitdb",
        "metasploit",
        "nuclei",
    )


LOGISTIC = Logistic()
BOOSTING = Boosting()

# ---- baselines ----------------------------------------------------------------------------
# epss:      EPSS probability at the cutoff (missing ranks last)
# ssvc_rule: SSVC exploitation (active > poc > none > missing), ties by EPSS
# cvss_cna:  CNA CVSS base score from context_snapshot. SNAPSHOT-TIME and label-biased:
#            reported as an illustration only, never as a fair comparison.
# random:    expected recall@k = k / N (analytic)
BASELINES = ("epss", "ssvc_rule", "cvss_cna")

# ---- ablations (all secondary; logistic model; labelled) -------------------------------------
# no_ssvc:  without the four SSVC features (CISA scores both SSVC and KEV)
# no_epss:  without the two EPSS features (is this just EPSS?)
# text:     + first TEXT_PCA components of the SecureBERT NVD-description embeddings (PCA
#           fit on training rows). Descriptions are SNAPSHOT-TIME: optimistic by design.
# text_no_kev_language: the text ablation with every kev_language CVE dropped from train
#           and test; compared with EPSS on that same reduced population (its own n_pos).
ABLATIONS = ("no_ssvc", "no_epss", "text", "text_no_kev_language")
TEXT_PCA = 5

# ---- metrics -------------------------------------------------------------------------------
HEADLINE = (
    "pooled recall@100 over the 3 test folds (top 100 per fold; hits summed / 68 positives) "
    "for CVEs published 2024-01-01 onward and not in KEV at the cutoff: logistic model vs "
    "EPSS at the cutoff"
)
# k = 100 is a fixed analyst budget per 180 days (fold sizes differ ~2x; K_FRACTION covers
# the proportional view).
K_ABS = (25, 100, 500)  # per fold
K_FRACTION = 0.01  # top 1% of each fold's eligible CVEs
# Ties: the tie group straddling rank k gets fractional credit, (k - ranked above) / group
# size per CVE: the expected value under a random tie-break, with no seed and no order bias
# (CVE ID order tracks publication date). Average precision and ROC-AUC treat tied scores
# as one threshold (scikit-learn).
# Also reported: hits and positives per fold; the CVE IDs caught by each of the model and
# EPSS at k = 100 (both, only one); AP per fold and mean AP; ROC-AUC per fold (labelled
# flattering at this prevalence); Wilson 95% intervals for pooled recall.
N_BOOT = 2000  # paired bootstrap: CVEs resampled within each fold, stratified by label;
# ranks are recomputed in every resample. It covers test-sample variation only, not refits.
SEED = 20261028
CI = 0.95
# Decision rule (the only significance claim): the model beats EPSS iff the 95% paired
# bootstrap interval of (model hits@100 - EPSS hits@100), pooled over folds, excludes 0;
# otherwise "no detectable difference". Every other number is descriptive.
# Power (stated before scoring): with 68 positives one hit is ~1.5 points of recall and a
# Wilson interval on pooled recall is roughly +/-11 points, so only large gains (about 8+
# extra hits) are likely to be detectable.

# ---- tiers ---------------------------------------------------------------------------------
# Rank-based (probabilities drift across EPSS versions): fraction of each fold's eligible
# CVEs, best first. Hit rate per tier is pooled over the test folds with Wilson 95%
# intervals; "monotonic" means each tier's hit rate exceeds the next one's. No merging
# or re-cutting after test scoring.
TIERS = (("critical", 0.001), ("high", 0.01), ("elevated", 0.05), ("baseline", 1.0))
# Tiers are assigned by the headline logistic model.
