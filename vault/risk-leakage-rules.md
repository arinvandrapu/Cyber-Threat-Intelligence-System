---
tags: [risk-model, leakage, point-in-time]
---

# Risk Scoring: Leakage Rules

Split from [[risk-scoring-design]] (note length). How features stay point-in-time; see also [[point-in-time-pinning]].

## Leakage rules (enforced at parse time and in the enriched record)

- Features come **only** from `cti.enrich.cves.features_at(record, "cutoff")`
  (`signals[as_of]`: EPSS, SSVC, ExploitDB, Metasploit, Nuclei at that date).
- `context_snapshot` (NVD `vuln_status`, `cvss_nvd`, `cvss_cna`, CWEs, reference-type
  counts, scraped page count) is snapshot-time and **label-biased**: NVD analyzes KEV CVEs
  first (17/17 positives "Analyzed" vs ~49% of negatives), and scrape selection put KEV
  CVEs first. Use only in a labelled ablation; `cvss_cna` (75% coverage) is the least
  biased score.
- Never use NVD's `cisa*` KEV fields (dropped), the Vulnrichment ADP `kev` block
  (dropped), or Nuclei `kev`/`epss` tags (not read).
- ExploitDB: use only the **cutoff-commit copy**. `date_published` is the original
  publication date, not when ExploitDB added the exploit, and CVE codes are added later,
  so filtering the current file by date still leaks.
- Git-hosted signals are pinned to the branch head via **first-parent** history
  ([[point-in-time-pinning]]).
- NVD records are the snapshot-time version: no reference tags, and CVSS v4 scores with
  the threat metric (`E:` set) are skipped for an older version (the score includes E).
- Scraped reference pages reflect snapshot-time knowledge, so they are **not** risk-eval
  features (used for NER/ATT&CK/dashboard only).
- Phase 5 extraction (`data/extracted/`): `reference_page` rows are never features.
  `nvd_description` rows are allowed only in the labelled snapshot-time ablation, like
  description text. Alias matches are snapshot-time too: the index is built from ATT&CK
  v20 and ThreatFox as of the snapshot.
