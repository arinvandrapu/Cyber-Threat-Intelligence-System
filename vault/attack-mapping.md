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
- 6 rows (`revoked_rows_remapped` counts rows) use techniques revoked by v20 (T1562 →
  T1685, etc.). They are remapped through the bundle's `revoked-by` relationships.

## Design

- Splits are by time: test = 135 CVEs in our NVD corpus (published 2024+); dev = 284
  older CVEs (majority prior and any choice made before scoring test). Grading is per `mapping_type`; the primary type is
  `exploitation_technique`.
- Technique level: sub-techniques roll up, and a parent scores the max of itself and its
  sub-techniques. 706 candidates, 227 parents.
- Text: `nvd` (primary, test only) or `kev` (the KEV title + short description; dev and
  test). CTID labellers saw the KEV entry, so `kev` is the text closest to the labels.
- Metrics: hit@k, recall@k, MRR, with a CVE-level bootstrap CI (2,000 resamples, seeded).
  Each method is compared with majority by a paired bootstrap of hit@5.

## Methods

- `majority`: dev label prior per type (leave-one-out on dev CVEs).
- `tfidf`, `biencoder`: zero-shot cosine similarity of CVE text to technique text.
  Bi-encoder = `cisco-ai/SecureBERT2.0-biencoder@b42d43a`, mean pooling, 1,024 tokens.
- `prior+X`: similarity + β·log prior (add-one smoothed). β comes from a grid, picked
  only on dev/kev/exploitation with a leave-one-out prior: β = 0.2 (bi-encoder), 0.1 (TF-IDF).

## Results (2026-10-26, test/nvd/exploitation, n=132)

| Method | hit@5 (95% CI) | vs majority (paired) |
|---|---|---|
| majority | 0.41 (0.33–0.50) | — |
| tfidf | 0.14 (0.08–0.20) | −0.27 |
| biencoder | 0.20 (0.13–0.27) | −0.21 |
| prior+tfidf | 0.43 (0.35–0.52) | +0.02 (0.00–0.05) |
| **prior+biencoder** | **0.57 (0.48–0.65)** | **+0.16 (0.10–0.23)** |

- Zero-shot similarity loses to the prior on every split and type: technique text
  describes attacker behaviour, CVE text describes the bug, and a few labels (T1190,
  T1068, T1203) dominate. Combining the two works. The gain shows on test (2024+, more
  T1068 privilege escalation) and on test/kev too (+0.15), but not on dev (+0.01), where
  the prior alone is already strong.
- Impact types: prior+biencoder matches majority on primary impact (+0.01) and helps on
  secondary impact (+0.09, CI touches 0; n=47).
- Dev majority stays 0.77 with leave-one-out, so the gap between dev and test is a real
  time shift, not in-sample optimism.
- **Disclosure:** the hybrid was designed after the zero-shot test numbers were seen.
  β was then picked on dev only, from a grid fixed in code (`BETAS`).
- KEV-only selection: the scores don't generalize to non-KEV CVEs. The bi-encoder may
  have seen ATT&CK or CVE text in pretraining; TF-IDF is the control.
