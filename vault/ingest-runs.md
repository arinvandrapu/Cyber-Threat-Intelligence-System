---
tags: [ingest, snapshot, history]
---

# Ingest Runs (2026-10-26 snapshot)

Split from [[ingest-once-snapshot]] (note length). What the one ingest and its logged refetches actually did.

## The 2026-10-26 run

- Ingest ran once (≈ 25 min, 202 MB, all 12 sources complete). EPSS model differs
  between cutoff (v2025.03.14) and snapshot (v2026.06.15): don't compare scores across them.
- References attempt 1 lost 527 of 2,000 slots to CISA's KEV catalog page
  (`cisa.gov/known-exploited-vulnerabilities-catalog?search=…`): it restates the KEV feed
  and cisa.gov returns 403 to non-browser clients. The classifier now treats it as a
  self-reference (like NVD), and references was refetched as attempt 2 (logged in the
  manifest). Attempt 1 is kept as the audit trail.

## 2026-10-28: extra cutoffs (Phase 7a, owner approved)

- EPSS, ExploitDB, Metasploit, Nuclei, Vulnrichment refetched as attempt 2 with
  `cti ingest --refetch <src> --new-dates-only`: the attempt-1 `cutoff`/`snapshot` files
  are copied byte for byte (SHA-256 verified identical) and only `cutoff2..4` are fetched.
- Why not a plain refetch: re-pinning "head at end of 2026-10-26" two days later gives a
  newer commit than the 16:15 UTC ingest saw (Vulnrichment `46b2fff` vs `9b12f55`),
  which would silently change Phase 5/6 inputs.
- Uploaded to S3 the same day (25 new objects, 38 MB; remote manifest SHA-256 = local).
- Design and positives: [[risk-scoring-design]]; pinning: [[point-in-time-pinning]].
