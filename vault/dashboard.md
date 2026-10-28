---
tags: [dashboard, design, security, phase-8]
---

# Dashboard (Phase 8, planned)

Status 2026-10-28: design canvas made (private artifact "CTI Dashboard Design"); PR 1
(`cti export`, `cti serve`) built; PR 2 (`web/`) next. Plan of record: `tasks/todo.md` § 8.

## Stack decision (owner approved 2026-10-28)

- **Vite + React + TypeScript**, not a Next.js static export. Next's App Router puts
  inline `self.__next_f.push` scripts in every page: a strict CSP would need
  `'unsafe-inline'` or a post-build hashing step. Vite emits only external module
  scripts, so `script-src 'self'` works as is; about half the npm packages.
- Pins ≥14 days old: vite 8.3.4, react 19.3.1, typescript 7.0.2, plugin-react 6.1.2.
  `.npmrc`: `save-exact`, `ignore-scripts`, `min-release-age=14`.
- No UI kit, chart, table or graph library: plain CSS + hand-rolled SVG.

## Serving (`cti serve`)

- Stdlib `BaseHTTPRequestHandler`, bound to 127.0.0.1 only; exact-match allowlist
  of files built at startup (no traversal, symlinks or listings).
- Host header must be `127.0.0.1:<port>`/`localhost:<port>` (DNS rebinding).
- CSP and security headers sent as HTTP headers (a `<meta>` CSP can't carry
  `frame-ancestors`), also on error responses; error bodies never echo the path.

## Data (`cti export`)

- Writes `data/export/<date>/` (gitignored): `meta`, `risk`, `iocs`, `graphs`, `eval`
  JSON, validated by pydantic models. CI builds against a synthetic fixture in
  `web/fixtures/` (documentation IP/domain ranges only).
- Snapshot ranking = the pre-registered logistic model refit on all four labelled
  windows ([[risk-eval]]); `risk_config.py` unchanged and SHA-checked.
- Rank and tier only, no probability. Tier hit rates come from the evaluation folds
  and are labelled as historical; snapshot EPSS version shift disclosed.
- IOCs defanged in Python, shown as text only ([[ioc-extraction]]); abuse.ch feeds
  as aggregates only ([[data-sources]]).

## Export facts (2026-10-26 snapshot)

- ≈9 s. 167,844 ranked; tiers 167 / 1,512 / 6,713 / 159,452 (ties). `risk.json` 7.3 MB
  (8,392 rows, compact JSON), `iocs.json` 0.5 MB (3,592 indicators), `graphs.json`
  0.5 MB. Two runs are byte-identical.
- Recency dominates the newest month: 550 of 1,512 high-tier CVEs were published in
  2026-10 (log-age weight; the cap is 365 d). Every critical CVE has a Nuclei template.
- Shared-host graph drops non-global IP literals (127.0.0.1 linked 24 CVEs); top 30
  hosts, 30 CVEs each (`truncated: true`).
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

## Views (dark theme)

1. Overview · 2. Risk queue · 3. Risk landscape (charts) · 4. Weakness graph
(pillar → CWE → CVE, [[cwe-classification]]) · 5. ATT&CK graph (KEV CVE →
technique → tactic, CTID, [[attack-mapping]]) · 6. Indicators (shared-host graph)
· 7. Evaluation.

Colour: neutral black surfaces; tiers on one ordinal pink → cherry-red ramp (more red = higher risk); model blue, EPSS aqua, KEV CVEs in the ATT&CK graph orange #f59a23 (CVD-validated). Brand: "CTI Console".

## Gotchas

- `python -m http.server` binds all interfaces by default.
- Local runs show the real export. The synthetic fixture exists only for CI (no
  `data/` there). Phase 9 screenshots use real data with the abuse.ch panel cropped
  (licence forbids redistribution); NVD/KEV/EPSS/CWE/ATT&CK content is fine to show.
