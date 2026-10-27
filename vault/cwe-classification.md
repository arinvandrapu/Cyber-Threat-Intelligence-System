---
tags: [nlp, cwe, evaluation, data]
---

# CWE Classification (Phase 6)

Main Phase 6 evaluation (owner decision 2026-10-27): classify NVD CVE descriptions into CWE
classes. Labels are human-assigned, unlike the gold set ([[gold-set-provenance]]: primary
label = source feed for 298/299 docs). Design context: [[nlp-design]].

## Label provenance (6a)

- `nvd.py` keeps `cwe_assignments: [{source_kind, type, id}]` next to the old flat `cwes`
  (unchanged). `source_kind`: `nvd` (nvd@nist.gov), `adp` (CISA-ADP UUID `134c704f-…`,
  Vulnrichment), `cna` (anything else: emails or UUIDs). `NVD-CWE-noinfo`/`Other` are kept
  in assignments, never in `cwes`.
- 2026-10-26: 141,979 CNA, 33,075 NVD, 31,430 ADP assignments. Re-parse content and enrich
  output byte-identical across runs; only the new fields changed.
- CWE catalog keeps `Mapping_Notes/Usage` (MITRE's mapping guidance). Over CVE CWE
  mentions: Allowed 110k, Allowed-with-Review 41k, Discouraged 31k (17%), Prohibited 502.
  All categories/views are Prohibited, all pillars Discouraged; CWE-20/119/200/74 are
  Discouraged.

## Facts that shape 6b (plan audit, 2026-10-27)

- The label source shifts with time. NVD labels are 23% of train but 3% of test; CNA
  dominates test. Top assigners: train Patchstack/MITRE; test VulnCheck/GitHub/Microsoft.
- Where NVD and the CNA both labelled a CVE, they agree on 53% overall, but only 30% in the
  test months (90/298): a label-noise ceiling.
- **Name leakage:** ~28% of single-label descriptions contain the CWE's full name ("Missing
  Authorization vulnerability in…", templated CNAs). Literal `CWE-\d+` IDs are only 1,314
  CVEs. Hence the headline is on the name-absent stratum.
- Discouraged share of single labels: ~9% train, ~18% test (CWE-284 rises from 1.8% to 6%).
