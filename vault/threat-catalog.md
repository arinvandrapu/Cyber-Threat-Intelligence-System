---
tags: [threats, implementation, phase-10]
---

# Threat Catalog (`cti threats`, Phase 10a)

Code: `src/cti/threats/` (`config.py` pre-declared, `review.py` sheets, `catalog.py`).
Output: `data/threats/<date>/threats.json` (gitignored; deterministic, two runs identical).
Decisions and licence: [[threat-layer]].

## Inputs

- Parsed ThreatFox (family = `malware_printable`, IDs = `fk_malware`), MISP clusters via
  `cti.reference.read_pinned`, ATT&CK docs + raw-bundle `uses` (`attack_catalog.uses`),
  `cti extract` alias rows, KEV, risk tiers from `data/export/<date>/risk.json`.
- Owner sheets in `data/reference/`: `threat-categories-<date>.csv` (blind categories),
  `threat-links-<date>.csv` (every CVE link: yes/no). Both written with `open("x")`.
  A half-filled category sheet is refused, not mixed with MISP labels. A link sheet
  whose rows differ from the current links is reported `stale` and not scored.
- `category_rows` overlap (multi-label families count in each category; sum 126,953 vs
  126,917 rows): never show them as shares of 100%.

## Rules found on the first run (2026-10-29, before any owner label)

- **ATT&CK join by the family's own name only.** The Phase 5a alias index falls back to
  ThreatFox aliases: Bashlite lists "Qbot" (QakBot's ATT&CK alias), so 5a merges Bashlite
  into S0650. Catalog: 82 families with software (96 with the fallback). The 5a index
  itself is unchanged (follow-up in `tasks/todo.md`).
- **Mentions link only from reference pages** (`MENTION_ORIGINS`). A family named in an
  NVD description is the vulnerable product (CVE-2024-41111 is a Sliver bug), not the
  exploiter.
- A surface name links only if exactly one family claims it (name, ATT&CK software
  aliases, ThreatFox aliases).

## First run (2026-10-26 snapshot)

- 467 named families (now: 51 reviewed by Claude for the owner, 75 MISP, 341 none). 36 CVE links on 18
  families (26 reference-page mentions, 10 ThreatFox tags); 32 are KEV CVEs, which the
  queue excludes by design, so owner added `linked_kev_cves` as the first priority key
  (own commit, before any label). KEV ransomware-use CVEs: 361 (category link only).

## Reviews (2026-10-29, labelled by Claude: owner delegated; see `REVIEW_LABELLER`)

- Categories: MISP labels 13 of the 34 top families; the other 21 (AMOS, Stealc, XWorm,
  ClearFake, …) have none, so manual labels carry the top of the list. On the 13: no
  contradictions; differences are MISP being single-label (Mirai etc. lack `ddos`,
  Formbook lacks `keylogger`) plus Cobalt Strike (MISP `rat`, review `c2-framework`).
  n is too small for informative CIs.
- Links: 22 / 36 correct (61%, Wilson 45–75%). Reference-page mentions 12 / 26 (46%,
  29–65%): name collisions (Hermes AI agent, MEDUSA rootkit, Plexor), "Mirai" as a
  generic example, product-bug lists, PoC demos. ThreatFox tags 10 / 10 (accepted as
  reporter attributions, not verified).
- Owner decision after the review (`TRUSTED_LINKS`, own commit): only links reviewed
  correct, or unreviewed ThreatFox tags, count toward priority; all stay in the output
  with `review` + `counts_for_priority`. Not chosen: weighting by per-source precision
  (n = 26; reviewed links are known, not averaged). 22 of 36 links now rank.
- New top 5: Mirai, RedTail, XMRIG, Meterpreter, MimiKatz (NetSupportManager RAT and
  Hermes dropped out).
- MISP name collisions hit categories too: Havoc (C2 framework) got `ransomware` from an
  unrelated MISP entry. Owner decision (`PRIORITY_REVIEW_TOP_N` = 20, own commit): every
  family in the priority top 20 is labelled by hand (`cti threats-sheet --priority`,
  repeated until no new family enters: 15 + 2 added). 51 families labelled; top 20 all
  manual. On 24 families both sides label, MISP's extra `ransomware` hit 3 (Havoc,
  Hermes, …); otherwise differences are MISP being single-label.
- Labels change the ranking (ransomware is a key), so the top 20 must be re-checked
  after any label change. Ranks 13–20 are ransomware families with no CVE link.

## Dashboard (10c, 2026-10-29)

- `cti export` reads `data/threats/<date>/threats.json` as an **optional** input (order:
  export → threats → export); missing → `available: false`; stale tiers → export fails.
- Ships the priority top `PRIORITY_REVIEW_TOP_N` (export refuses if any is unreviewed)
  + families with a link not reviewed as wrong (none today: 20 shown); no IOC
  values, URLs or evidence doc IDs. Threats view + "Linked threats" in the CVE detail;
  unchecked MISP labels are dashed. No predicted techniques ([[attack-mapping-v2-results]]).

Related: [[threat-layer]], [[dashboard]], [[ioc-extraction]], [[data-sources]].
