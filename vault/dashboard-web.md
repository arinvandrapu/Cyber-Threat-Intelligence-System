---
tags: [dashboard, web, testing, security, phase-8]
---

# Dashboard UI (`web/`)

Vite + React + TypeScript over the `cti export` JSON. Decisions: [[dashboard]].

## Layout

- `src/types.ts` mirrors `dashboard/schema.py`; `tests/unit/test_web_contract.py` fails
  on a schema field missing from the TS interface of the same name.
- `src/data.ts` fetches `/data/*.json` (no-store, no credentials), checks content type
  and `schema_version`. `src/App.tsx`: hash routes `#/<view>[/<CVE>]`, no router.
- `src/views/*`: 7 views. Charts and graphs are hand-rolled SVG with deterministic
  layouts (`hash01` jitter): weakness = layered pillar → CWE → CVE; ATT&CK = radial, one
  angular sector per tactic sized by its techniques; shared hosts = ring + inner CVEs.
- Colours are CSS variables in `src/theme.css` (tiers pink → cherry, KEV orange).

## Fixture

- `tests/web_fixture.py` runs the real export code on made-up records → `web/fixtures/`.
  CVE IDs `CVE-2099-*`, documentation IP/domain ranges only, first disclosure
  "SYNTHETIC FIXTURE"; the header shows a SYNTHETIC DATA chip (`git.commit == "fixture"`).
- A test rebuilds it and requires byte equality: after a schema change run
  `python -m tests.web_fixture web/fixtures`.
- `cti serve --export-dir web/fixtures` serves it; `CTI_EXPORT_DIR=… npm run dev` too.

## Checks

- `npm run check` (`scripts/check.mjs`, `node:test`): no inline script/style/handlers in
  `index.html`, only allowlisted URLs in the bundle (W3C namespaces, react.dev error
  text), no `innerHTML`/`dangerouslySetInnerHTML`/`eval` in `src/`.
- `web/scripts/smoke.py`: `cti serve` + headless Chrome `--dump-dom` per view; fails if a
  view doesn't render or Chrome logs any console line. Chrome reports CSP and Trusted
  Types violations as console messages: verified with a page that has an inline script
  and an `innerHTML` write (both blocked and logged).
- CI job `web`: `npm ci`, `npm audit signatures`, `npm audit --audit-level=high`,
  build, check, smoke on the fixture (Ubuntu runners ship Chrome).

## Audit outcomes (2026-10-28)

- Ratios and tier CIs are computed from counts (`wilson()` in `format.ts`), not from the
  export's 4-decimal rounded rates (baseline CI 0.012–0.023%, critical ≈159× baseline).
- ATT&CK v20 tactics `stealth` and `defense-impairment` must be in `TACTICS` (they were
  silently dropped: 29 → 33 exploitation techniques); unknown tactics get a sector.
- Lists that are cut (top-N CVEs) are sorted by rank first, and say "top N of M".
- Graph selection works by keyboard (`tabIndex`, `role="button"`, Enter/Space).
- IOC precision is AI-labelled, weighted and dominated by CVE IDs; NER gold is
  rule-generated (precision is a lower bound): both labelled that way.

## Gotchas

- `min-release-age=14` also delays security fixes. If `npm audit` fails with no old
  enough fix, override once and say why in the PR: `npm i --min-release-age=0 pkg@x.y.z`.

- TS 7: no global `JSX` namespace with React 19 types; use `ReactElement`.
- `vite.config.ts` stays out of `tsconfig` `include` (it needs node types; Vite
  transpiles it itself), so no `@types/node` dependency.
- Vite `build.modulePreload.polyfill: false` and `assetsInlineLimit: 0`: nothing inline,
  no `data:` assets. `<link rel="icon" href="data:,">` stops a favicon request.
- EPSS percentiles are floored for display (0.99981 → 99.98th, never "100th").
## Clarity passes (2026-10-29, owner feedback)

- PR #35: CVE names (derived for queue CVEs, `export.derived_name`, 8,359 / 8,392; CISA's
  for KEV), a tab guide, plain labels. A fact-check fixed overstatements (most families
  have no category or links; not every test was fixed in advance; "98.5%" is mostly CVE
  IDs; labels by Claude for the owner; +4 vs EPSS is from back-tests).
- Plain-language pass: answers up front, method on request. One-sentence ledes and
  cards; tab guide is one line per tab with "How it works" folded; disclosures moved
  from Overview to Evaluation ("Data versions & limitations"); Threats tiles are
  analyst facts (QA numbers in a folded "How this list is built"); link rows are one
  line (source badge + ✓/✗, details on ▸); bar caption one line, full text in a tooltip.
