---
tags: [design, risk, evaluation]
---

# Risk Scoring Design

## Problem to avoid

A prioritization that puts most items in the top tier ranks nothing. An earlier
prototype tiered ~94% of items "high". The cause was hand-tuned weights and fixed
thresholds that were never validated.

## Approach

- **Inputs:** CVSS, EPSS, CISA SSVC (Vulnrichment), exploit availability (ExploitDB,
  Metasploit, Nuclei), recency, CWE class, SecureBERT text features ([[nlp-design]]).
- **Model:** scikit-learn (logistic regression or gradient boosting); explainable per CVE.
- **Evaluation is forward-looking:** score every CVE using only data as of a cutoff date
  (snapshot − 180 days: EPSS at cutoff, KEV entries with `dateAdded` < cutoff). The
  ground truth is whether the CVE was **added to KEV after the cutoff**.
- **Metrics:** precision@50/100 and PR-AUC against CVSS-only and EPSS-only baselines.
- **Tiers:** thresholds are chosen from the evaluation so each tier has a distinct,
  monotonic hit rate. Report per-tier counts and hit rates. Don't force a target
  distribution, because hitting a quota proves nothing.

## Leakage rules (enforced at parse time)

- Only `as_of="cutoff"` signals (EPSS, SSVC, Metasploit, Nuclei) may be features.
- Never use NVD's `cisa*` KEV fields (dropped), the Vulnrichment ADP `kev` block
  (dropped), or Nuclei `kev`/`epss` tags (not read).
- ExploitDB: use only the **cutoff-commit copy**. `date_published` is the original
  publication date, not when ExploitDB added the exploit, and CVE codes are added later,
  so filtering the current file by date still leaks.
- Git-hosted signals are pinned to the branch head via **first-parent** history
  ([[point-in-time-pinning]]).
- NVD records are the snapshot-time version: CVSS base metrics only; no reference tags,
  no CVSS v4 threat metric (`E:`). Known limitation: analysis done after the cutoff.
- Scraped reference pages reflect snapshot-time knowledge, so they are **not** risk-eval
  features (used for NER/ATT&CK/dashboard only).

## Caveats

- KEV additions are rare (tens per quarter), so positives are few; report counts and
  intervals.
- KEV is US-government-focused and lags real exploitation.

Requires point-in-time data from [[ingest-once-snapshot]]; sources in [[data-sources]].
