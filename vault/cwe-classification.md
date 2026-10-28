---
tags: [nlp, cwe, evaluation, data]
---

# CWE Classification (Phase 6)

Main Phase 6 evaluation (owner decision 2026-10-27): classify NVD CVE descriptions into CWE
classes. Labels are human-assigned, unlike the gold set ([[gold-set-provenance]]: primary
label = source feed for 298/299 docs). Design context: [[nlp-design]].

## Label provenance (6a)

- `nvd.py` keeps `cwe_assignments: [{source_kind, type, id}]` next to the old flat `cwes`
  (unchanged). `source_kind` is by role: `nvd` (nvd@nist.gov), `cna` (equals the CVE's
  `sourceIdentifier`), `cisa_adp` (`134c704f-…`, Vulnrichment), `other_adp` (any other
  source, e.g. `0b0ca135-…`, which is never a CNA of record). Classifying by a fixed UUID
  once mislabelled that second ADP as `cna` (1,120 blocks, mostly 2026: the audit caught it).
- 2026-10-26 assignments: CNA 141,338; NVD 33,075 (23,089 real CWEs + 9,986
  noinfo/Other); CISA-ADP 31,430; other ADP 1,120. Output deterministic; `cwes` unchanged.
- CWE catalog keeps `Mapping_Notes/Usage`. Over CVE CWE mentions: Allowed 110k,
  Allowed-with-Review 41k, Discouraged 31k (17%), Prohibited 502. All categories, views and
  deprecated IDs are Prohibited; all pillars are Discouraged; CWE-20/119/200/74 are Discouraged.

## Facts that shape 6b (recomputed 2026-10-27 after the fix)

Split by publication date: train 2024–2025, dev 2026-01-01..04-29, test after.
Label chain NVD > CNA > CISA-ADP (other ADPs not used).

| | train | dev | test |
|---|---|---|---|
| labelled CVEs | 79,471 | 19,046 | 58,973 |
| label from NVD | 24% | 10% | 3% |
| NVD & CNA share ≥1 CWE (both labelled) | 74% (10,983) | 63% (941) | 35% (228) |
| single-label, CWE name in text | 29.9% | 28.4% | 26.2% |

- The name-in-text matcher: the CWE's catalog name, or its part before "(", lowercased
  substring. It is templated CNA wording ("Missing Authorization vulnerability in…"),
  hence the headline on the name-absent stratum. Literal `CWE-\d+` IDs: only 1,314 CVEs.
- Label source and assigners shift: test is CNA-labelled (VulnCheck, GitHub, Microsoft);
  train has more NVD and Patchstack/MITRE. Discouraged share of single labels ~9% train vs
  ~18% test (CWE-284 1.8% → 6%).

## 6b: `cti cwe-eval` (2026-10-27, ≈8 min CPU, `ml` extra only)

- Pre-registration: `src/cti/nlp/cwe_config.py` in `2e69e14`; implementation `4f54975`;
  both before any test score. Feasibility was checked on train → dev only. Deviation,
  disclosed: `GOLD_FOLDS`/`GOLD_C` were added later (gold row only, never the test split).
- 118 known classes. Test single-label n = 51,243 (name-absent 37,794); `other` 8.8%.

| test, name-absent (headline) | macro-F1 (95% CI) | acc | top-5 |
|---|---|---|---|
| majority | 0.002 | 0.10 | 0.29 |
| **TF-IDF + LR** (C = 100) | **0.394 (0.382–0.402)** | 0.56 | 0.84 |
| SecureBERT bi-encoder + LR (C = 0.01) | 0.265 (0.257–0.272) | 0.44 | 0.75 |
| nearest centroid (embeddings) | 0.137 | 0.20 | 0.46 |

- Paired, embedding − TF-IDF: −0.13 (−0.14 to −0.12) name-absent; −0.20 over all test.
  Hypothesis (untested): frozen retrieval embeddings, mean pooled, blur lexical bug cues
  that TF-IDF keeps. Fine-tuned transformers (V2W-BERT, arXiv 2102.11498) are what the
  literature uses; out of scope on CPU.
- Name leakage confirmed: name-present stratum TF-IDF 0.91, embedding 0.52.
- **Both chosen C values sit at an edge of their grid** (TF-IDF top, embedding bottom).
  Better values may lie outside; not explored, per the pre-registration.
- Secondary: train-only models score lower (TF-IDF 0.36), so the refit on train + dev
  helps. ID masking barely matters (552 test CVEs). Multi-label pool, any label in top 5:
  TF-IDF 0.96. That is inflated, because an unknown label maps to `other` and `other` in
  the top 5 counts (1,564 of 7,641 sets have an unknown label). Accuracy by assigner ranges from 0.52 (GitHub) to 0.91
  (Microsoft) for TF-IDF; by label source 0.65 (NVD) / 0.68 (CNA) / 0.56 (CISA-ADP).
- Below the rough published 70–88% top-1 (V2W-BERT, ThreatZoom; not measured here),
  likely because of the time split, the CNA-heavy test, the name-absent stratum, and
  macro over 118 classes. Top-1 counts a correct `other` as a hit; macro-F1 excludes it.
- Counts differ slightly between the 6a table (79,471 / 19,046 / 58,973 labelled) and
  `cwe-eval.json` (79,338 / 19,017 / 58,884): 6b drops Prohibited CWEs (categories,
  views, deprecated IDs), which removes 133 / 29 / 89 CVEs whose only CWEs are Prohibited
  (verified), and moves 5 to a later source in the chain. Name-present shares match to
  within 0.1 point.
- Gold row (circular), on 249 docs (50 ThreatFox dropped, abuse.ch §7.3): source-only
  0.996 = TF-IDF 0.996 = the label-equals-source share (was 0.997 on all 299).
- TF-IDF runs are not bit-identical: `saga` has no `random_state`. Re-run 2026-10-28: ±0.002
  at 4 d.p.; every published (rounded) number and the chosen C unchanged. Seed = config deviation.
