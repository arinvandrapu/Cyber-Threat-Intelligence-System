---
tags: [dashboard, web, docs, decision]
---

# Dashboard Guide tab

2026-11-07, `feat/guide-tab`. Last tab: in-depth "how to read" for every view. Context:
[[dashboard]], [[dashboard-web]], [[dashboard-display-decisions]].

## Layout

- `src/views/Guide.tsx`: sticky sidebar. The 12 section links never move; the active
  section's parts are listed in a separate "In <section>" block below them (owner,
  2026-11-07: expanding parts inline made the links below jump while scrolling).
  Native `<select>` "Jump to" under 900px. Content in `src/guide/sections/*.tsx`, one file
  per tab plus `start` and `reference` (Concepts glossary, Data & freshness).
- Each tab section: what it answers, one part per panel (encodings, interactions), how
  it's computed (methods link to Evaluation, not repeated), common misreadings, and an
  "In this snapshot" example built from export numbers. No real number is hard-coded;
  claims that depend on results (e.g. "EPSS has the higher AP") are conditional.
- `PageHead` takes a required `guide: View | null`, so every view shows "How to read this
  tab →" and a new view can't forget it. Overview's tab cards link to their section.

## Routing (plan audit overturned the first design)

- Keys: `#/guide/<section>` or `#/guide/<section>-<part>`; DOM ids `guide-<key>`.
- Links are plain anchors. The Guide listens for `hashchange` itself and scrolls; App
  skips its scroll-to-top for `guide`. Rejected: `pushState` on click, which leaves App's
  `route.name` stale, so Back or a later link to the same key did nothing.
- A click on the address already showing fires no `hashchange`: handled in `onClick`.
- Scroll-spy: on scroll (rAF), the last heading above 120px. At the bottom of the page,
  the linked heading if it is on screen, else the last section. Address follows by
  `replaceState` (debounced, section only, keeps a part key while inside its section,
  skipped if the address changed meanwhile); it fires no `hashchange`.
- Unknown key → top of page (address then becomes `#/guide/start`).

## Gotchas

- `npm run check` fails on any `http(s)://` string in the bundle: name sources in words
  or as bare hosts (`nvd.nist.gov`), never URLs. Don't widen `ALLOWED_URLS`.
- A 10th tab made the header wrap at 1280px; `.tab` padding 7px → 6px fixed it.
- `.guide` is Overview's card class; Guide styles use `gd-*`.
- Headless `--screenshot` renders scrolled pages blank; check deep links with CDP
  (`Page.captureScreenshot`) instead. Restart `cti serve` after a rebuild (new asset
  names 404 otherwise) and load `about:blank` first: hash-only navigations keep the old
  bundle.
