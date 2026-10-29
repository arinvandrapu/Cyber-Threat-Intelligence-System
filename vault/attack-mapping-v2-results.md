---
tags: [nlp, attack, evaluation, results, phase-10]
---

# ATT&CK Mapping v2: Results (2026-10-29)

One pre-registered run of `cti attack-eval2 --date 2026-10-26 --archive-date 2026-10-29`
(config [[attack-mapping-v2]], commit `2a34423`). Output `data/eval/2026-10-26/attack-eval2.json`.

## Data

- Train 419 CTID KEV CVEs. Test: 369 `attack_to_cve` CVEs with a label after excluding
  27 training overlaps (Phase 1 rows are mostly `Uncategorized` only); 200 graded for
  exploitation. Dropped labels: 28 unknown IDs; 4 / 7 / 6 CVEs lost every label of a type.
- **Correction:** the config disclosed the test as "mostly CVSS v2". Wrong: NVD re-scored
  old CVEs; 699 / 836 test CVEs carry NVD v3, and all 200 graded ones are scored with v3.

## Exploitation (primary), hit@5 [95% CI], n = 200

| Method | hit@1 | hit@5 | MRR |
|---|---|---|---|
| majority | 0.255 | 0.685 [0.62, 0.75] | 0.461 |
| prior+biencoder (β = 1.0 by CV) | 0.255 | 0.685 | 0.447 |
| capec-chain | 0.130 | 0.525 | 0.343 |
| **combiner** | 0.290 | **0.720** [0.66, 0.78] | 0.479 |
| combiner − cvss_rule | 0.255 | 0.700 | 0.436 |
| combiner − capec_paths | 0.295 | 0.725 | 0.485 |
| methodology-replay (reference) | 0.555 | 0.815 | 0.670 |

- **Decision: passes.** Combiner − prior+biencoder hit@5 +0.035 [+0.005, +0.070]; hit@1
  +0.035 [+0.010, +0.065]; MRR +0.031.
- What the pass means: CV chose β = 1.0, so the baseline equals majority (identical
  hit@5). The gain is small and comes from the **CVSS rule** (without it +0.015, CI
  crosses 0), almost all at **T1189** (0.57 vs 0 in top 5) via UI:R. That rule was written
  after the test counts were seen (disclosed). CAPEC paths add nothing (ablation is better).
- Text similarity does not help on this population: post hoc, bi-encoder alone (β = 0)
  hit@5 0.095. Every method misses T1566 (24) and T1110 (11); T1133 0.04.
- Replay at 0.815 shows how much the labels follow CTID's own method (circular; reference).
- Near-duplicates: 3 test CVEs ≥ 0.9 cosine; results unchanged without them.

## Impact types (descriptive, no decision)

- Primary impact: combiner 0.593 vs majority 0.472 (+0.12 [0.08, 0.16]).
- Secondary impact: nothing beats majority (0.362).

Related: [[attack-mapping]], [[attack-mapping-v2]], [[nlp-design]].
