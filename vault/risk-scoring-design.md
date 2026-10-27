---
tags: [design, risk, evaluation]
---

# Risk Scoring Design

## Problem to avoid

A prioritization that puts most items in the top tier ranks nothing. An earlier
prototype tiered ~94% of items "high". The cause was hand-tuned weights and fixed
thresholds that were never validated.

## Approach

- **Inputs (point-in-time):** `features_at(record, "cutoff")`: EPSS, CISA SSVC
  (Vulnrichment), exploit availability (ExploitDB, Metasploit, Nuclei); recency from
  `record["published"]` (safe: fixed at publication). Text features from the NVD
  description ([[nlp-design]]) are **snapshot-time, not safe**: CNAs add "exploited in the
  wild" wording after KEV listing (35/549 KEV CVEs vs 46/~168k others, 2026-10-26).
  Phase 5 flags these descriptions; Phase 7 reports the ablation with and without them.
  `cti embed` (2026-10-27, ≈47 min CPU): 168,393 NVD descriptions → 768-d float16
  bi-encoder vectors (`data/extracted/<date>/nvd-embeddings.npy` + index); 181 rows carry
  `kev_language` (34 of 549 KEV CVEs vs 147 others). These are the Phase 7 text features.
- **Snapshot-time, ablation only:** CVSS and CWE class live in `context_snapshot` and are
  label-biased (below). `cvss_cna` is the least biased, but a CNA can rescore later too.
- **Model:** scikit-learn (logistic regression or gradient boosting); explainable per CVE.
- **Evaluation is forward-looking:** score every CVE using only data as of a cutoff date
  (snapshot − 180 days). Population: `eligible["cutoff"]` (published on or before the
  cutoff day, not in KEV by then; KEV `dateAdded <= cutoff` counts as known). Ground
  truth: **added to KEV strictly after the cutoff**. 2026-10-26 snapshot: 102,772
  eligible, **17 positives** (evaluation design still open; more cutoffs possible).
- **Metrics:** precision@50/100 and PR-AUC against EPSS-only and CVSS-only baselines (the
  CVSS baseline is snapshot-biased; report it as such).
- **Missing EPSS at the cutoff:** 85 eligible CVEs have none (mostly published later on
  the cutoff day, after EPSS ran at 12:55 UTC). Treat as "not yet scored", never as 0.
- **Tiers:** thresholds are chosen from the evaluation so each tier has a distinct,
  monotonic hit rate. Report per-tier counts and hit rates. Don't force a target
  distribution, because hitting a quota proves nothing.

## Leakage rules (enforced at parse time and in the enriched record)

- Features come **only** from `cti.enrich.cves.features_at(record, "cutoff")`
  (`signals[as_of]`: EPSS, SSVC, ExploitDB, Metasploit, Nuclei at that date).
- `context_snapshot` (NVD `vuln_status`, `cvss_nvd`, `cvss_cna`, CWEs, reference-type
  counts, scraped page count) is snapshot-time and **label-biased**: NVD analyzes KEV CVEs
  first (17/17 positives "Analyzed" vs ~49% of negatives), and scrape selection put KEV
  CVEs first. Use only in a labelled ablation; `cvss_cna` (75% coverage) is the least
  biased score.
- Never use NVD's `cisa*` KEV fields (dropped), the Vulnrichment ADP `kev` block
  (dropped), or Nuclei `kev`/`epss` tags (not read).
- ExploitDB: use only the **cutoff-commit copy**. `date_published` is the original
  publication date, not when ExploitDB added the exploit, and CVE codes are added later,
  so filtering the current file by date still leaks.
- Git-hosted signals are pinned to the branch head via **first-parent** history
  ([[point-in-time-pinning]]).
- NVD records are the snapshot-time version: no reference tags, and CVSS v4 scores with
  the threat metric (`E:` set) are skipped for an older version (the score includes E).
- Scraped reference pages reflect snapshot-time knowledge, so they are **not** risk-eval
  features (used for NER/ATT&CK/dashboard only).
- Phase 5 extraction (`data/extracted/`): `reference_page` rows are never features.
  `nvd_description` rows are allowed only in the labelled snapshot-time ablation, like
  description text. Alias matches are snapshot-time too: the index is built from ATT&CK
  v20 and ThreatFox as of the snapshot.

## Caveats

- KEV additions are rare (tens per quarter), so positives are few; report counts and
  intervals.
- KEV is US-government-focused and lags real exploitation.

Requires point-in-time data from [[ingest-once-snapshot]]; sources in [[data-sources]].
