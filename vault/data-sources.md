---
tags: [data, sources, licensing]
---

# Data Sources

Verified 2026-10-24. Captured once per [[ingest-once-snapshot]]. Reader-facing version with
why-each-source and corpus counts: `docs/data-sources.md`.

| Source | Access | Key | Notes |
|---|---|---|---|
| NVD CVE 2.0 | Yearly `nvdcve-2.0-{year}.json.gz` feeds | none | Grouped by CVE-ID year, so window start − 1 is fetched and filtered by `published`. Verified against `.meta` SHA-256. ~37% of 2026 CVEs are "Deferred" (no NVD analysis); CNA CVSS still present. **Match CVSS by `source`, not `type`:** ~1,500 CNA metrics are labelled `Primary` and some `nvd@nist.gov` ones `Secondary`; `cvss_nvd` = source `nvd@nist.gov`, `cvss_cna` = source == `sourceIdentifier` (fixed 2026-10-26, PR #14). |
| CISA KEV | JSON feed | none | CC0. Use `dateAdded` for point-in-time evaluation. |
| FIRST EPSS | Dated bulk CSV `epss_scores-YYYY-MM-DD.csv.gz` | none | Model changed between cutoff (`v2025.03.14`) and snapshot (`v2026.06.15`); model version kept per signal. |
| ExploitDB | `files_exploits.csv` (GitLab) | none | GPL-2.0; `codes` column maps to CVEs. Don't redistribute. |
| MITRE ATT&CK | attack-stix-data, pinned v20.0 | none | STIX 2.1. |
| MITRE CWE | `cwec_latest.xml.zip`, pinned 4.20 | none | |
| ThreatFox | `threatfox-api.abuse.ch/v2/files/exports/<KEY>/full.csv.zip` | free Auth-Key | Old keyless URLs return 410 (since ~2026-10-22). **Key goes in the URL path**, so recorded URLs and errors are redacted. Publish aggregates only. |
| URLhaus | `urlhaus-api.abuse.ch/v2/files/exports/<KEY>/recent.csv` (30 days) | same key | Same terms. CSV header is the last `#` line *before* the data (footers also use `#`). Split on `\n` only: `splitlines()` breaks on `\x85` inside malicious URLs. Redact the key in plain and percent-encoded form (httpx errors use the latter). |

## Prioritization signals (added 2026-10-24)

| Source | Access | Key | Notes |
|---|---|---|---|
| CISA Vulnrichment | Archive of a pinned `develop` commit | none | CC0. SSVC under `containers.adp[]` (CISA-ADP). History starts 2024-04-24. Per-record timestamps are overwritten on rescoring, so point-in-time state comes **only** from git history. Drop the ADP KEV block (leakage). |
| Metasploit | `db/modules_metadata_base.json` at a pinned commit | none | BSD-3. CVE refs as plain strings. `mod_time` is bulk-reset: never treat it as a creation date. |
| Nuclei templates | `cves.json` (JSONL) at a pinned commit | none | MIT. History since 2023-01-18. Current templates carry `kev`/`epss` tags: leakage, drop them. |

Every signal is captured **as of the cutoff date** for [[risk-scoring-design]].

## ThreatFox facts (2026-10-26 snapshot)

- 126,917 IOCs, 481 families (`fk_malware`, Malpedia-style). `threat_type` is
  infrastructure role only (payload, botnet_cc, payload_delivery, cc_skimming), not a
  threat category; categories come from MISP galaxies + owner review ([[threat-layer]]).
- abuse.ch terms §7.3 (2026-10-21): no training AI models on ThreatFox/URLhaus data.
- Only 166 rows (16 CVEs) carry CVE tags; 39,572 have a report `reference` URL.

## Not used

- **PhishTank**: new registrations disabled.
- **Ransomwatch**: archived 2026-03-03. Replacements publish victim names, which
  this project avoids for ethical reasons.
- **Feodo Tracker**: CC0, but no update since 2026-03-04 and no CVE link. Dropped.
- **AlienVault OTX**: active, but overlaps the abuse.ch feeds; cut for scope.

## Handling

- Raw data stays in the private bucket ([[aws-cost-and-security]]), never in the repo.
- IOCs are defanged at rest and in display (`hxxp`, `[.]`).
