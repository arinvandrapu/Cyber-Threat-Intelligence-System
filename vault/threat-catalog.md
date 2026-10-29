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

- 467 named families; categories: MISP 99, none 368 (owner review pending).
- 36 CVE links on 18 families: 26 reference-page mentions, 10 ThreatFox tags. 32 of 36
  are KEV CVEs, which the risk queue excludes, so only 4 families meet the
  "linked high-tier queue CVE" rule. KEV ransomware-use CVEs: 361 (category link only).
- Name collisions remain (ThreatFox "Medusa" vs ATT&CK MEDUSA rootkit vs Medusa
  ransomware): the link review measures this.

Related: [[threat-layer]], [[ioc-extraction]], [[data-sources]].
