---
tags: [dashboard, web, risk-model, decision, phase-11c]
---

# Dashboard display decisions (11c UI, PR #45)

2026-11-06. Display only: no stored number, model weight or pre-registered output
changed. Context: [[dashboard]], [[dashboard-web]], [[risk-eval]],
[[risk-scoring-design]].

## Signs and small values (plan audit overturned the first plan)

- **No sign flip for age.** Planned: rename to "Newness" and negate `log_age_days`.
  Rejected: the export disclosure would print "+0.57" next to "log-age weight" while
  the model's weight is −0.5725 (and `test_dashboard_export.py` checks "-0.57").
  Instead the label is "Age (older ranks lower)", true for the −0.57 weight and for
  a new CVE's positive contribution (+1.59 at rank 1).
- **No "≈ 0" for small weights.** Planned: show |w| < 0.02 as "≈ 0". Rejected:
  contribution = weight × standardized value, and rare signals have large standardized
  values, so ExploitDB's −0.010 weight still contributes −0.19 on 90 queue rows; bars
  add up, so hiding one misstates the rest; and 0.02 was picked after seeing weights.
  Instead a queue note appears when ExploitDB or "SSVC: PoC / exploited" pulls down.
- **"SSVC: PoC / exploited", not "SSVC: exploited".** The feature is ordinal
  (none 0, poc 1, active 2; `risk_config.py`); the snapshot has no `active`
  (none 6,432, poc 1,538, null 422), so every negative row is a PoC. Caught by the
  implementation audit.
- **Landscape caption:** bar = refit on all windows (262,612 rows, 88 additions),
  bracket = last tested fold; weights move between fits "likely because correlated
  signals share credit" (an explanation, not a finding).

## Plain words and layout

- SSVC column: values none→no, poc→PoC, active→yes, total→full control; header
  "SSVC" with a small legend line (the long header pushed columns off at 1280px).
- Queue hides SSVC and context columns under 900px (`.queue-table`).
- Header: one line from 1280px (tighter tabs, one chip "<date> · read-only" with the
  full text in `title`); wraps below.
- Threats category chart: div bars (the SVG stretched to ~80px); caption says it counts
  all families; categories no shown family has are greyed (inline colour: the
  `.bar-row > span:first-child` rule beats `.faint`).
- Weakness graph: CWE names to 30 chars, full name in `<title>`.
- Evaluation: tier CI on one line; second panel "Data versions & disclosures".
- Evaluation (owner, 2026-11-06): the four middle panels sit in a 2×2 `.eval-grid`
  of equal 400px cells; content that doesn't fit scrolls inside its panel. One column
  under 1000px.

## Links

- Family names link to `#/threats/<name>` (`threatHref`; routing in [[dashboard-web]]).
- KEV CVE under `#/queue/` → `#/kev/` via `location.replace` ([[known-exploited-view]]).
- Known nit: selecting a family inside Threats doesn't update the URL.

## PR 2 (data/export, `feat/11c-data`)

- Terms: "scored" = 167,844 given a tier (`ranked_cves`), "in the queue" = 8,392
  critical/high/elevated, "below the queue" = baseline, "not scored" = outside the window.
- `cves.json`: `export.referenced_cves` walks the export for every clickable CVE
  (`cve`/`cves` keys, `kind: "cve"` nodes; not description text); 154 had no detail, all
  now carded with status from the scored set (`below_queue`/`not_scored`/`no_record`).
  CVE-2025-66478 appears only in text, so needs no card.
- Queue rows: `context.vendor`/`product` (first affected entry, defanged); search +
  vendor `<datalist>` on Risk queue and Known exploited.
- UUID assigners: "CNA (ID xxxxxxxx…)" (owner: no outside name map).
- Schema version 2 (new required `cves.json` + context fields): an old export fails
  with "re-run `cti export`". Export asserts every carded scored CVE is baseline.
- MimiKatz: the labels CSV note isn't in the export; view says "none of the categories
  fits" rather than hard-coding the family.
