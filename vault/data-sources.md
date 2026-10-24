---
tags: [data, sources, licensing]
---

# Data Sources

Verified 2026-10-24. Captured once per [[ingest-once-snapshot]].

| Source | Access | Key | Notes |
|---|---|---|---|
| NVD CVE 2.0 | Yearly `nvdcve-2.0-{year}.json.gz` feeds | none | Legacy 1.1 feeds removed 2025-08-20. API capped at 120-day date ranges; feeds avoid paging. |
| CISA KEV | JSON feed | none | CC0. Use `dateAdded` for point-in-time evaluation. |
| FIRST EPSS | Bulk CSV from `epss.empiricalsecurity.com` | none | EPSS v5 since 2026-06-15; record model version. API is for lookups, not bulk. |
| ExploitDB | `files_exploits.csv` (GitLab) | none | GPL-2.0; `codes` column maps to CVEs. Don't redistribute. |
| MITRE ATT&CK | attack-stix-data, pinned v20.0 | none | STIX 2.1. |
| MITRE CWE | `cwec_latest.xml.zip`, pinned 4.20 | none | |
| ThreatFox | abuse.ch export (6 months) | free Auth-Key | Key required since 2025-06-30. No redistribution without consent: publish aggregates only. |
| URLhaus | abuse.ch dump | same key | Same terms as ThreatFox. |

## Not used

- **PhishTank**: new registrations disabled.
- **Ransomwatch**: archived 2026-03-03. Replacements publish victim names, which
  this project avoids for ethical reasons.
- **AlienVault OTX**: active, but overlaps the abuse.ch feeds; cut for scope.

## Handling

- Raw data stays in the private bucket ([[aws-cost-and-security]]), never in the repo.
- IOCs are defanged at rest and in display (`hxxp`, `[.]`).
