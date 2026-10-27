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

- Frozen once with `cti gold-import` (2026-10-24): **299 docs** (1 duplicate dropped),
  1,958 entity spans kept, 5 dropped (span text didn't match the document).
- Fixture `data/gold/gold.jsonl.gz` (gitignored; uploaded to S3 in Phase 3). Its SHA-256
  is committed in `cti/gold.py`; every load verifies it.
- Text is stored **unmodified**, because entity offsets index into it. It contains live
  phishing URLs and victim names, so it stays private and is defanged at display time.
- Each record keeps the labeling-rule `label_signals` (e.g. `source_threatfox`), which
  documents the circularity.
- Sources: nvd_ref 50, mitre_attack 50, threatfox 50, phishtank 49, ransomwatch 46,
  exploitdb 45, cisa_kev 9. 27% of entity spans came from record metadata, not text.
- Labeling rules may **not** read the source feed.
- Results are reported as a **sanity check** next to the source-only and majority
  baselines, with this limitation stated in the README. They are never presented as
  accuracy on real-world text.

- Label errors found in Phase 5a: of 103 `cvss_score` spans, 35 label the vector version
  ("3.1" in `CVSS:3.1/`) and 33 label sub-scores. Domains are labelled only in ThreatFox
  records. IOC extraction is scored around this ([[ioc-extraction]]).

Related: [[data-sources]], [[risk-scoring-design]] (the stronger evaluation in this project).
