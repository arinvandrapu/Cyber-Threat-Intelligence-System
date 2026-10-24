---
tags: [evaluation, data, honesty]
---

# Gold Set Provenance

The classification gold set (300 documents, threat-category labels plus entity spans)
is reused from an earlier prototype **as-is**, by owner decision.

## Known limitations

- Labels are **rule-generated, not hand-labeled**. Most primary labels equal the
  label implied by the source feed, so a source-only predictor scores very high.
- Entity spans were partly derived from record metadata, not annotated from text.
- One duplicate record (`exploitdb_47122_c2903c40`).
- Some documents come from feeds that are no longer used (PhishTank, Ransomwatch) and
  contain live URLs or victim names.

## How it is used

- Frozen as a private fixture (full text + labels), deduplicated, IOCs defanged,
  SHA-256 recorded. Not committed to the public repo.
- Labeling rules may **not** read the source feed.
- Results are reported as a **sanity check** next to the source-only and majority
  baselines, with this limitation stated in the README. They are never presented as
  accuracy on real-world text.

Related: [[data-sources]], [[risk-scoring-design]] (the stronger evaluation in this project).
