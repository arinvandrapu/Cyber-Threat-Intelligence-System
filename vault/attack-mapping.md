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
  describes attacker behaviour, CVE text describes the bug, and T1190 + T1068 account for
  half the test CVEs.
- **Where the gain comes from** (`diagnostics` in `attack-eval.json`, post hoc): 22 wins
  and 1 loss against majority. 17 of the wins are T1068 (8 of 300 dev labels, 32 of 160
  on test), 4 are T1203, 1 is T1566. hit@1 shows no gain (0.258 vs 0.265). The hybrid fixes
  a time-shifted prior; it is not general semantic mapping.
- **β fragility:** dev hit@5 is flat over β 0.1–1.0 (0.77–0.78), but test is 0.57 at
  0.1–0.2 and 0.41–0.42 at 0.5–1.0. TF-IDF at β = 0.02 reaches 0.58, so the encoder
  comparison is not established. Dev: hybrid +0.01 (−0.01–0.04); dev secondary impact
  −0.08 (−0.19–0.02, n=113); test secondary impact +0.09 (−0.00–0.19, n=47).
- Dev majority stays 0.77 with leave-one-out, so the gap between dev and test is a real
  time shift, not in-sample optimism.
- **Disclosures:** the hybrid and the `BETAS` grid were written after the zero-shot
  test numbers were seen. β is picked on dev KEV text and applied to test NVD text. KEV-only
  selection: the scores don't generalize to non-KEV CVEs. The bi-encoder may have seen
  ATT&CK or CVE text in pretraining; TF-IDF is the control.
- Open: a lexical T1068 control (a keyword rule + prior) would test whether any cue for
  privilege escalation gives the same gain. Not run, because it would be designed knowing
  the answer.

## Future work (2026-10-28, not started)

- Test split above is burned: a new method needs newer CTID mappings or dev-only CV.
- ATT&CK v20 has **0 of 706** techniques with CAPEC refs; CWE 4.20 has 1,212
  `Related_Attack_Pattern` links. A CWE → CAPEC → ATT&CK chain needs pinned CAPEC XML.
- Plan (CVSS-rule baseline, CAPEC chain, combiner): `tasks/future-extensions.md` E1.
