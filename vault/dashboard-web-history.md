---
tags: [dashboard, web, history]
---

# Dashboard UI: Audit and Clarity History

Split from [[dashboard-web]] (note length). Dated audit outcomes and owner-feedback passes; later decisions: [[dashboard-display-decisions]].

## Audit outcomes (2026-10-28)

- Ratios and tier CIs are computed from counts (`wilson()` in `format.ts`), not from the
  export's 4-decimal rounded rates (baseline CI 0.012–0.023%, critical ≈89× the overall rate).
- ATT&CK v20 tactics `stealth` and `defense-impairment` must be in `TACTICS` (they were
  silently dropped: 29 → 33 exploitation techniques); unknown tactics get a sector.
- Lists that are cut (top-N CVEs) are sorted by rank first, and say "top N of M".
- Graph selection works by keyboard (`tabIndex`, `role="button"`, Enter/Space).
- IOC precision is AI-labelled, weighted and dominated by CVE IDs; NER gold is
  rule-generated (precision is a lower bound): both labelled that way.

## Clarity passes (2026-10-29, owner feedback)

- PR #35: CVE names (derived for queue CVEs, `export.derived_name`, 8,359 / 8,392; CISA's
  for KEV), a tab guide, plain labels. A fact-check fixed overstatements (most families
  have no category or links; not every test was fixed in advance; "98.5%" is mostly CVE
  IDs; labels by Claude for the owner; +4 vs EPSS is from back-tests).
- Plain-language pass: answers up front, method on request. One-sentence ledes and
  cards; tab guide is one line per tab with "How it works" folded; disclosures moved
  from Overview to Evaluation ("Data versions & disclosures", renamed 11c); Threats tiles are
  analyst facts (QA numbers in a folded "How this list is built"); link rows are one
  line (source badge + ✓/✗, details on ▸); bar caption one line, full text in a tooltip.
- Any CVE anywhere opens a detail: `kev.json` holds CISA's entry for all 1,756 KEV CVEs
  (`export.build_kev`); `#/queue/<CVE>` shows the ranked detail, else a KEV or NVD card.
  ATT&CK panel CVEs expand inline; Indicators' KEV nodes click through.
- Overview top (2026-11-05): the three intro cards and four stat tiles became one
  `.brief` panel, a column per question (KEV to patch | CVEs next | threats; KEV added in
  12.3), each holding its own numbers (`<dl class="stats">`, label above value) and
  button; "how they connect" footer uses export counts ([[threat-queue-overlap]]).
  One column under 1100px. `.tile` stays for Threats/Indicators.
- Overview queue card (2026-11-05): `.row.match` stretches it to the Risk tiers card's
  height; the top-5 list sits in `.queue-viewport` (relative, min-height 260px) with an
  absolutely positioned `.queue-scroll`, so the list never sets the row height and scrolls
  instead. Focusable region for keyboard scrolling.
- 11c UI fixes and why (signs, SSVC wording, layout): [[dashboard-display-decisions]].
