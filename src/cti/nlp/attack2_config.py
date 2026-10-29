"""Pre-registered configuration for ``cti attack-eval2`` (Phase 10b).

Every choice the CVE -> ATT&CK re-evaluation makes is fixed here, and this file is
committed on its own before any test score is computed (``git log --
src/cti/nlp/attack2_config.py`` is the evidence; the output JSON records this file's
SHA-256 and the git commit). Feasibility may be checked on training CVEs only (see
TRAIN_FEASIBILITY). Any change after test scoring is a deviation and must be disclosed in
``vault/attack-mapping-v2.md``.

Question: does a combiner of structured signals (a CVSS exploitation-flow heuristic,
CWE -> CAPEC -> ATT&CK paths) and text similarity rank a CVE's exploitation technique
better than the Phase 5b method (log prior + bi-encoder similarity)?

Disclosures fixed before scoring:
- The test file's exploitation-column counts were seen while planning (2026-10-28) and
  re-derived on 2026-10-29 to check this line: T1190 51, T1078 34, T1204.002 32, T1133 27,
  T1204.001 26, T1189 21, T1566 18, T1110 11 (T1189 and T1566 happen to equal the
  training counts). No other test statistic, text or score was looked at.
- The CVSS rule (CVSS_RULES) is the author's heuristic, written after those counts were
  seen; CTID's exploitation tips describe behaviours, not CVSS fields. The headline is
  judged with the rule included, and ablations without it are reported (ABLATIONS).
- This is a CVE-disjoint, non-KEV **population-shift** test (training: CTID's KEV
  mappings, CVEs 2007-2025, almost all CVSS v3; test: CTID's ``attack_to_cve``, CVEs
  2008-2020, mostly CVSS v2), not a time split. Test CVEs with an exploitation label are
  the ones CTID labellers chose to give one, not a random sample.
- No power analysis is claimed: with ~195 test CVEs only a large hit@5 gain (on the order
  of 0.1) can be distinguished from zero.
- Test labels were made with CTID's methodology (vulnerability type -> technique, plus
  exploitation tips), so ``methodology-replay`` and the CWE/CAPEC features partly encode
  the labelling procedure. Replay is a reference row, not evidence of learning.
- Labels are graded at parent level (Phase 5b practice), which merges sub-techniques with
  different meanings (T1204.001 link vs .002 file; T1566.001/.002/.003). A sub-technique
  level result is reported for the headline comparison (SUBTECHNIQUE_REPORT).
- The bi-encoder (cisco-ai/SecureBERT2.0-biencoder) is pretrained on public security text
  that may include CTID's mappings or the test descriptions; this cannot be checked.
"""

from __future__ import annotations

# ---- data ----------------------------------------------------------------------------------
# Training: every CVE in the pinned CTID KEV mappings (cti.nlp.attack_eval.CTID_FILE, 419
# CVEs; Phase 5b's test split is spent, so all of it trains). Text: NVD only (not KEV).
# Test: CVEs in cti.reference.CTID_ATTACK_TO_CVE, excluded in this order and each count
# reported: (1) training CVEs (KEV overlap), (2) NVD-Rejected or absent from NVD,
# (3) no English NVD description.
TEST_COLUMNS = {  # attack_to_cve column -> mapping type (as in the KEV file)
    "Exploitation Technique": "exploitation_technique",
    "Primary Impact": "primary_impact",
    "Secondary Impact": "secondary_impact",
}
DROPPED_COLUMNS = ("Uncategorized",)  # not a mapping type; holds malformed IDs
# Labels (training and test): a CVE with several rows gets the union per type. IDs are
# split on ";", stripped, remapped through ATT&CK v20 revocations, then rolled up to the
# parent. IDs that are neither current nor revoked are dropped and counted. A CVE graded
# for a type is one with >= 1 surviving label of that type; a CVE whose labels were all
# dropped is not graded for that type (counted). A test parent never seen in training
# stays in the gold set (no method can rank it highly; that is a real miss).
PRIMARY_TYPE = "exploitation_technique"
SECONDARY_TYPES = ("primary_impact", "secondary_impact")  # descriptive only: no decision;
# expected to track CWE closely because CTID's vulnerability-type table produced them
CANDIDATES = "ATT&CK v20 enterprise techniques, rolled up to parents (cti.nlp.attack_catalog)"
# Ranking ties are broken by parent technique ID (attack_eval.rank_matrix).

# ---- signals (each a score per CVE x parent technique) --------------------------------------
# log_prior: add-one smoothed log label frequency over training CVEs (attack_eval.log_prior).
# biencoder: max cosine between the CVE text and the parent's techniques (Phase 5b ranker).
# tfidf: the Phase 5b TfidfRanker (fit on technique text only), max over the parent.
# capec_paths: log1p(number of CWE -> CAPEC -> ATT&CK paths ending at the parent). CWEs:
#   the CVE's NVD ``weaknesses`` from any source, NVD-CWE-Other/noinfo ignored. CWE ->
#   CAPEC: Related_Attack_Pattern in the snapshot's pinned CWE catalog. CAPEC -> ATT&CK:
#   CAPEC 3.9 Taxonomy_Mapping (ATTACK) entries, "T" prefixed, remapped through v20
#   revocations, rolled up to the parent; targets neither current nor revoked are dropped.
# cvss_rule: 1 if CVSS_RULES marks the parent, else 0.
FEATURES = ("log_prior", "biencoder", "tfidf", "capec_paths", "cvss_rule")

# CVSS exploitation-flow heuristic (author's; see disclosures). Score choice: source
# priority first (NVD's own, nvd@nist.gov; else the CVE's CNA), then the newest version of
# that source among v3.1 / v3.0 / v2 (v4 not used). No CVSS: no rule fires. AV:A and AV:P
# fire no AV-based rule. v2 booleans are metric-level, optional and NVD-only; a missing
# boolean counts as false for every condition.
CVSS_RULES = {
    "v3": (
        ("AV:N and UI:N", ("T1190",)),  # exploits a remote, public-facing application
        ("UI:R", ("T1204", "T1189")),  # a user must open, click or visit something
        ("AV:L", ("T1068",)),  # local access: usually privilege escalation
        ("AV:N and PR in (L, H)", ("T1078",)),  # needs an account first
    ),
    "v2": (  # the same logic on the v2 vector; obtain*Privilege flags describe impact and
        # are not used
        ("AV:N and not userInteractionRequired", ("T1190",)),
        ("userInteractionRequired", ("T1204", "T1189")),
        ("AV:L", ("T1068",)),
        ("AV:N and Au in (S, M)", ("T1078",)),
    ),
}

# methodology-replay (reference row, PRIMARY_TYPE only; undefined for impact types): CWE ->
# CTID vulnerability type -> its exploitation technique(s), from methodology.md
# "Vulnerability type mappings" (exploitation column) and the tip "hardcoded credentials
# -> T1078". A closed list: no CWE-1000 descendant expansion; types whose exploitation
# entry is N/A are absent. Score = 2 if a CVE CWE maps to the parent, + 1 if CVSS_RULES
# marks it; ties broken by log_prior, then ID.
CWE_EXPLOITATION = {
    "CWE-294": ("T1040",),  # authentication bypass by capture-replay
    "CWE-307": ("T1110",),  # improper restriction of excessive authentication attempts
    "CWE-645": ("T1110",),  # overly restrictive account lockout
    "CWE-319": ("T1040",),  # cleartext transmission of sensitive information
    "CWE-521": ("T1110",),  # weak password requirements
    "CWE-916": ("T1110",),  # password hash with insufficient computational effort
    "CWE-328": ("T1110",),  # weak hash
    "CWE-310": ("T1110",),  # cryptographic issues (category)
    "CWE-326": ("T1110",),  # inadequate encryption strength
    "CWE-327": ("T1110",),  # broken or risky cryptographic algorithm
    "CWE-601": ("T1566",),  # open redirect (T1566.002)
    "CWE-79": ("T1189", "T1204"),  # XSS: stored -> T1189, others -> T1204.001
    "CWE-80": ("T1189", "T1204"),
    "CWE-78": ("T1133",),  # OS command injection
    "CWE-22": ("T1202",),  # path traversal
    "CWE-23": ("T1202",),
    "CWE-36": ("T1202",),
    "CWE-59": ("T1202",),  # symlink following
    "CWE-61": ("T1202",),
    "CWE-352": ("T1204",),  # CSRF (T1204.001)
    "CWE-918": ("T1133",),  # SSRF
    "CWE-798": ("T1078",),  # hard-coded credentials (tip)
    "CWE-259": ("T1078",),
    "CWE-1392": ("T1078",),  # default credentials
}

# ---- methods ---------------------------------------------------------------------------------
# majority: training label frequency, the same list for every CVE.
# prior+biencoder: biencoder + beta * log_prior (Phase 5b), beta re-selected below.
# capec-chain: capec_paths, ties broken by log_prior, then ID.
# methodology-replay: reference row (above).
# combiner (headline): one logistic regression over (CVE, parent) pairs with FEATURES,
#   standardised. Positive = the parent is a label of the CVE for that mapping type. Fit
#   per mapping type on training CVEs graded for that type (secondary_impact has few
#   positives per parent; only C regularises it). Ranking = predicted probability.
METHODS = ("majority", "prior+biencoder", "capec-chain", "methodology-replay", "combiner")
HEADLINE = "combiner"
BASELINE = "prior+biencoder"
ABLATIONS = ("combiner-no-cvss_rule", "combiner-no-capec_paths")  # secondary, same procedure
BETAS = (0.0, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0)  # Phase 5b grid
COMBINER_C = (0.01, 0.1, 1.0, 10.0)
COMBINER = {"class_weight": "balanced", "max_iter": 2000, "solver": "lbfgs"}
# Selection (beta for prior+biencoder, C for the combiner and each ablation, separately):
# 5-fold cross-validation over training CVEs (folds by CVE, shuffled with SEED). Inside a
# fold, the prior counts that fold's training CVEs; fold-training pairs use a
# leave-one-out prior over those CVEs; the scaler and model are fit on fold-training pairs
# only; held-out fold CVEs get the fold's full prior. Criterion: mean hit@5 on the mapping
# type being fit, then MRR, then the smaller value. The chosen value is refit on all
# training CVEs (leave-one-out prior for training pairs, full prior for test). Test CVEs
# are never used.
CV_FOLDS = 5
SEED = 20261029

# ---- metrics and decision --------------------------------------------------------------------
KS = (1, 3, 5, 10)  # hit@k and recall@k; plus MRR
N_BOOT = 2000  # percentile bootstrap over test CVEs, seeded with SEED
# Decision (single pre-specified comparison, no multiplicity correction): the combiner is
# better than prior+biencoder if the two-sided 95% percentile CI of the paired difference
# hit@5(combiner) - hit@5(prior+biencoder) on test / PRIMARY_TYPE lies above 0 (one-sided
# alpha 0.025). Otherwise "no evidence of improvement" (not "equal"). Predicted
# techniques appear in the dashboard (Phase 10c) only if the combiner passes.
DECISION_METRIC = "hit@5"
# Also reported, never used for the decision: every method vs majority (hit@5); hit@1 and
# MRR differences; the ablations; per-parent hit@5 for parents with >= PER_TECHNIQUE_MIN
# test CVEs; results by CVSS family used (v2 / v3 / none); results on test CVEs whose max
# bi-encoder cosine to any training description is below NEAR_DUPLICATE; the full beta
# and C grids scored on test (sensitivity, labelled post hoc); label drop/remap counts.
NEAR_DUPLICATE = 0.9
PER_TECHNIQUE_MIN = 5
# SUBTECHNIQUE_REPORT: every method ranks parents, so it cannot tell T1204.001 (link) from
# .002 (file). For these parents, hit@5 of combiner and prior+biencoder is reported
# separately for test CVEs whose exploitation labels (before roll-up) name each
# sub-technique, to show which behaviours the parent credit covers.
SUBTECHNIQUE_REPORT = ("T1204", "T1566")
# Train-only checks run before the test is scored, recorded in the output: CVSS rule
# firing rate and label hit rate per CVSS family; share of training CVEs with >= 1 CAPEC
# path; positives per mapping type.
TRAIN_FEASIBILITY = ("cvss_rule_by_family", "capec_coverage", "positives_per_type")
