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

- **ATT&CK join by the family's own name only.** The Phase 5a index's alias fallback
  merged Bashlite into QakBot (via "Qbot"); catalog: 82 families with software. The 5a
  index was fixed on 2026-10-29 ([[ioc-extraction]]); the catalog's own-name rule stays.
- **Mentions link only from reference pages** (`MENTION_ORIGINS`). A family named in an
  NVD description is the vulnerable product (CVE-2024-41111 is a Sliver bug), not the
  exploiter.
- A surface name links only if exactly one family claims it (name, ATT&CK software
  aliases, ThreatFox aliases).

## First run (2026-10-26 snapshot)

- 467 named families (now: 56 reviewed by Claude for the owner, 75 MISP, 336 none). 36 CVE links on 18
  families (26 reference-page mentions, 10 ThreatFox tags); 32 are KEV CVEs, which the
  queue excludes by design, so owner added `linked_kev_cves` as the first priority key
  (own commit, before any label). KEV ransomware-use CVEs: 361 (category link only).

## Reviews and link sources

Moved to [[threat-links]] (review results, owner decisions on links, ATT&CK links).

## Dashboard (10c, 2026-10-29)

- `cti export` reads `data/threats/<date>/threats.json` as an **optional** input (order:
  export → threats → export); missing → `available: false`; stale tiers → export fails.
- Ships the priority top `PRIORITY_REVIEW_TOP_N` (export refuses if any is unreviewed)
  + families with a link not reviewed as wrong (none today: 20 shown); no IOC
  values, URLs or evidence doc IDs. Threats view + "Linked threats" in the CVE detail;
  unchecked MISP labels are dashed. No predicted techniques ([[attack-mapping-v2-results]]).

Related: [[threat-layer]], [[dashboard]], [[ioc-extraction]], [[data-sources]].
