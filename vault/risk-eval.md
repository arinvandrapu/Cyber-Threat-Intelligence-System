---
tags: [evaluation, risk, pre-registration]
---

# Risk Evaluation (Phase 7b, `cti risk-eval`)

Status 2026-10-28: pre-registered (`c528d07`), implemented (`1ff8527`, clean tree), run
once (`data/eval/2026-10-26/risk-eval.json`, ≈30 s). README section: "Forward-looking risk
scoring".

## Question

Using only what was known at a cutoff, does a model rank the CVEs CISA adds to KEV in the
next 180 days above EPSS alone? Design and leakage rules: [[risk-scoring-design]].

## Folds (rolling origin)

| Test fold | Trained on | Test positives |
|---|---|---|
| `cutoff3` (2025-05-04) | `cutoff4` | 21 |
| `cutoff2` (2025-10-31) | `cutoff4`, `cutoff3` | 30 |
| `cutoff` (2026-04-29) | `cutoff4`, `cutoff3`, `cutoff2` | 17 |

Label: KEV `date_added` in (cutoff, min(next cutoff, 2026-10-23)]. Population: `eligible[as_of]`.

## Pre-registered choices (summary; the config is authoritative)

- Population: published 2024-01-01 → cutoff, not in KEV. Labels: KEV 2026.10.23; last
  window ends 2026-10-23 (177 d).
- Features via `features_at(record, as_of)`: logit EPSS percentile, SSVC (exploitation,
  automatable, total impact), ExploitDB/Metasploit/Nuclei flags (absence = 0), log age
  capped at 365 d; EPSS/SSVC missing → train median + indicator.
- Headline: L2 logistic regression, C = 1.0, no tuning. Challenger: monotonic HGB.
- Baselines: EPSS, SSVC rule, CVSS-CNA (snapshot-time, illustration only).
- Ablations: no SSVC, no EPSS, + text PCA(5), + text without `kev_language` CVEs.
- Headline metric: pooled recall@100 (68 positives). Ties get fractional credit (CVE-ID
  order tracks age). Decision rule: model beats EPSS iff the paired bootstrap 95% CI of
  pooled hit difference excludes 0. Power: ~±11 points, so only ~8+ extra hits show.
- Reported too: per-fold hits, CVE IDs caught by model/EPSS, AP, ROC-AUC, tiers
  (0.1% / 1% / 5% / rest, Wilson CIs, monotonic check).

## Results (2026-10-28, 3 folds pooled, 68 positives)

- Hits in top 100 per fold, pooled (expected values under ties): logistic 6, boosting 8,
  EPSS 2, SSVC rule 2, CVSS 1.2, random 0.1. **Decision rule: logistic beats EPSS**, +4
  (paired 95% CI +1 to +8). Per fold 2025-05/2025-10/2026-04: LR 1/3/2, EPSS 1/1/0.
- Top 1%: logistic 16, EPSS 15 (+1, CI −6 to +9). Mean AP: EPSS 0.015 > LR 0.011.
  Boosting vs EPSS +6 (CI +1 to +12, secondary). Tiers monotonic: 2.6% / 0.48% / 0.17% /
  0.016%.
- Exploratory (no CIs): no-EPSS 9 @100, AP 0.033 mostly from the latest fold (0.072);
  no-SSVC 6 @100, 18 @1%; text 20 @500 vs 16; last-fold EPSS ROC-AUC 0.41, median
  percentile of positives 0.16 (16 scored). Largest last-fold LR weights: recency −0.70,
  SSVC total impact 0.64, EPSS 0.63.
- No deviations from the config. Plan-audit changes were applied before the commit.

## Inputs from due diligence (2026-10-28)

- The `-masked` embeddings mask CWE IDs (Phase 6), not KEV wording; the text ablation
  drops `kev_language` CVEs itself ([[nlp-design]]).
- EPSS v3 trains on KEV as an input feature; excluded CVEs aren't in KEV yet, so no direct
  leak, but EPSS targets sensor-seen exploitation, not KEV listing.
- With 68 positives, 1 hit ≈ 1.5 points of recall: report estimates with CIs.

Deviations after test scoring must be listed here.
