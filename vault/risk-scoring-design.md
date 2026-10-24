---
tags: [design, risk, evaluation]
---

# Risk Scoring Design

## Problem to avoid

A prioritization that puts most items in the top tier ranks nothing. An earlier
prototype tiered ~94% of items "high". The cause was hand-tuned weights and fixed
thresholds that were never validated.

## Approach

- **Inputs:** CVSS, EPSS, exploit availability (ExploitDB), recency, CWE class.
- **Evaluation is forward-looking:** score every CVE using only data as of a cutoff date
  (snapshot − 180 days: EPSS at cutoff, KEV entries with `dateAdded` < cutoff). The
  ground truth is whether the CVE was **added to KEV after the cutoff**.
- **Metrics:** precision@50/100 and PR-AUC against CVSS-only and EPSS-only baselines.
- **Tiers:** thresholds are chosen from the evaluation so each tier has a distinct,
  monotonic hit rate. Report per-tier counts and hit rates. Don't force a target
  distribution, because hitting a quota proves nothing.

## Caveats

- KEV additions are rare (tens per quarter), so positives are few; report counts and
  intervals.
- KEV is US-government-focused and lags real exploitation.

Requires point-in-time data from [[ingest-once-snapshot]]; sources in [[data-sources]].
