---
tags: [nlp, attack, evaluation]
---

# ATT&CK Mapping Evaluation (Phase 5b, `cti attack-eval`)

Ranks ATT&CK techniques for a CVE and grades the ranking against MITRE CTID's expert
KEV mappings. Code: `nlp/attack_catalog.py` (candidates), `nlp/attack_eval.py` (grading).
Design context: [[nlp-design]]; feature rules: [[risk-scoring-design]].

## Ground truth

- CTID Mappings Explorer KEV file, ATT&CK 16.1, commit `e51d7f5`, SHA-256 pinned in code,
  committed under `data/reference/ctid/` with the Apache-2.0 notice (owner decision
  2026-10-27: reference data, not a feed, so "ingest once" holds).
- 419 CVEs, 1,183 rows. Only `capability_id`, `mapping_type` and `attack_object_id` are
  read. `comments` holds the labellers' rationale and `capability_group` their category,
  so both would leak the label.
- 6 rows use techniques revoked by v20 (T1562 → T1685, etc.). They are remapped through
  the bundle's `revoked-by` relationships.

## Design

- Splits: test = 135 CVEs in our NVD corpus; dev = 284 others (majority prior and any
  choice made before scoring test). Grading is per `mapping_type`; the primary type is
  `exploitation_technique`.
- Technique level: sub-techniques roll up, and a parent scores the max of itself and its
  sub-techniques. 706 candidates, 227 parents.
- Text: `nvd` (primary, test only) or `kev` (the KEV title + short description; dev and
  test). CTID labellers saw the KEV entry, so `kev` is the text closest to the labels.
- Metrics: hit@k, recall@k, MRR, with a CVE-level bootstrap CI (2,000 resamples, seeded).
  Each method is compared with majority by a paired bootstrap of hit@5.

## Results so far (2026-10-26)

| test / nvd / exploitation (n=132) | hit@5 | MRR |
|---|---|---|
| Majority (dev prior) | 0.41 (0.33–0.50) | 0.37 |
| TF-IDF (fixed defaults, untuned) | 0.14 (0.08–0.20) | 0.11 |

- TF-IDF is far below majority on every split and type. Technique text describes attacker
  behaviour ("Valid Accounts"), while CVE text describes the bug ("authentication
  bypass"), so the words barely overlap. That is the gap embeddings must close.
- Shift: majority hit@5 is 0.77 on dev but 0.41 on test. Test (published 2024+) has many
  T1068 privilege-escalation labels; dev is mostly T1190/T1204/T1078.
- KEV-only selection: the scores don't generalize to non-KEV CVEs.
