---
tags: [dashboard, export, facts]
---

# Dashboard Export Facts (2026-10-26)

Split from [[dashboard]] (note length). Counts and sizes from `cti export` on the snapshot.

## Export facts (2026-10-26 snapshot)

- ≈9 s. 167,844 scored (`ranked_cves`); tiers 167 / 1,512 / 6,713 / 159,452 (ties). `risk.json` 8.4 MB (11c: +vendor/product)
  (8,392 rows, compact JSON), `iocs.json` 0.5 MB (3,592 indicators), `graphs.json`
  0.5 MB. Two runs are byte-identical.
- Age dominates the newest month: 550 of 1,512 high-tier CVEs were published in
  2026-10 (log-age weight; the cap is 365 d). Every critical CVE has a Nuclei template.
- Shared-host graph drops non-global IP literals (127.0.0.1 linked 24 CVEs); top 30
  hosts, 30 CVEs each (`truncated: true`).
- Stale threats (11d, schema 3): if tiers changed since `cti threats` read `risk.json`,
  the export writes every file with threats `available:false, stale:true` (Threats tab says
  "out of date"; KEV sort drops the threat key) and exits 1 with the recovery commands.
  Before, it refused before writing, so `cti threats` re-read the old `risk.json`: a loop.
  The hand-label check on the priority top 20 is still a hard error (only labelling fixes it).
- Python 3.12+ `http.server` collapses a leading `//` in the path before lookup.
- Audit (2026-10-28): requests rejected while parsing (414/505/bad request line) used to
  get no reply (`log_message` hit an unset `self.path`) or an HTTP/0.9 bare body; fixed
  with class defaults and `default_request_version = "HTTP/1.0"`. Dot-directories
  (`.vite/`) excluded; duplicate Host → 400; route collisions refused.
- Defang check: domains/IPs must equal the canonical defanged form of their refanged
  value (IPs must parse); full-width dots refused. Descriptions defang only what the
  extractor recognises (+ emails): render as plain text, never linkify.
- 25 exported values also appear in ThreatFox: all from 6 CVEs' reference pages
  (independent sightings, not copied feed data).
- PR 2 risk: `require-trusted-types-for 'script'` and `style-src 'self'` break libraries
  that set `innerHTML` or inject `<style>`; check the built app in Chrome for violations.
