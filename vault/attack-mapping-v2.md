---
tags: [nlp, attack, evaluation, phase-10]
---

# ATT&CK Mapping v2 (Phase 10b, planned)

Status 2026-10-28: planned, owner-approved; plan of record `tasks/todo.md` § 10.
Why: Phase 5b's mapping is weak and its test split is spent ([[attack-mapping]]).

## Test set

- No newer CTID KEV file exists (repo checked 2026-10-28: only ATT&CK 15.1 and 16.1).
- Fresh test: CTID `attack_to_cve` (committed as `data/reference/ctid/attack_to_cve.csv`,
  Apache-2.0): 839 rows / **836 CVEs** from 2008–2020, ATT&CK v8/9 IDs, Phase 1 (456) /
  Phase 2 (383) rows, multi-technique cells, an `Uncategorized` column. 204 have an
  exploitation technique; 27 overlap the KEV set.
- Gotchas: 3 CVEs have a Phase 1 and a Phase 2 row (none with an exploitation label):
  merge per CVE. Malformed IDs (`T11190`, `T1036.`, `T828` = ICS IDs missing a 0) occur
  **only** in `Uncategorized`, which is dropped; graded columns are clean (tested).
- **Seen while planning (disclose):** exploitation counts T1190 51, T1078 34,
  T1204.002 32, T1133 27, T1204.001 26, T1189 21, T1566 18.
- Framing: KEV training CVEs span 2007–2025, so this is a **CVE-disjoint, non-KEV
  population-shift test, not a time split**. MDE ≈ 0.08–0.10 hit@5 at n ≈ 195.
- The labels were made with CTID's `methodology.md` vulnerability-type → technique table,
  so a rule replaying that table is a reference row, not a baseline to beat.

## Data gaps

- NVD parse keeps `published ≥ 2024-01-01` (`config.py:33`): the 284 old dev CVEs and all
  test CVEs need NVD 2002–2022 feeds plus an unfiltered parse path.
- Fetched 2026-10-29 (`cti fetch-nvd-archive`, 21 feeds, 125 MB, all `.meta`-verified):
  203,721 non-rejected CVEs; 830 of 836 CTID CVEs present, the other 6 are NVD-Rejected
  ("DO NOT USE"), so the test set is ≤ 830. Best CVSS: v3.1 84,747, v2 75,077, v3.0 41,577.
- Old CVEs are mostly CVSS v2. NVD v2 carries `userInteractionRequired` and
  `obtain*Privilege`, which `_best_cvss` (`nvd.py:64-79`) drops.
- CAPEC: ATT&CK v20 active techniques have 0 CAPEC refs (36 on revoked/deprecated
  ones). CWE 4.20 has 1,212 `Related_Attack_Pattern` links. CAPEC 3.9 (2023) maps to
  ATT&CK v12: remap through `revoked-by`.

## Methods (pre-registered in `nlp/attack2_config.py` before scoring)

- Baselines: majority; prior+biencoder with β re-chosen by CV on train (0.2 was also
  the best test value in 5b).
- Headline: one shared logistic model over (CVE, technique) pairs. Features: log prior,
  bi-encoder and TF-IDF similarity, CAPEC path count, CVSS exploitation-flow rule.
  Per-technique models were rejected: most of the 227 parents have 0–3 positives.
- Literature: CWE → CAPEC → ATT&CK fans out with low precision (BRON critiques);
  Bonhomme & Dulaunoy 2026 report recall@5 0.673 on 1,207 CTID CVEs (other set, not
  comparable).

Related: [[nlp-design]], [[cwe-classification]], [[threat-layer]].
