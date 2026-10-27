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
