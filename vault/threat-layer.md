---
tags: [threats, design, licensing, phase-10]
---

# Threat Layer (Phase 10a)

Status 2026-10-29: `cti threats` built ([[threat-catalog]]); owner reviews pending.
Plan of record `tasks/todo.md` § 10.
Why: the system classified bugs ([[cwe-classification]]), not threats.

## Decisions

- Threats are **categorised, linked and prioritised**, and explain CVEs. They do **not**
  feed the CVE risk score ([[risk-eval]]): alias links come from snapshot-time, KEV-first
  reference pages, so as features they would leak and be selection-biased.
- Vocabulary: STIX 2.1 `malware-type-ov` plus infostealer, loader, c2-framework,
  web-skimmer, fake-update. Multi-label: families change role (Emotet: banker → loader
  → botnet).
- Category source: MISP galaxies (CC0/BSD; licence checked per file), category = the
  galaxy file. Malpedia has no category field and is CC BY-NC-SA: not used for labels.
- Owner labels the top 34 families **blind** (`cti threats-sheet` →
  `data/reference/threat-categories-2026-10-26.csv`), then compares with the auto labels.
- Threat priority is a pre-declared heuristic, not ML: linked KEV CVEs (added 2026-10-29,
  see [[threat-catalog]]), linked high-tier queue CVEs, ransomware,
  30-day IOC growth, then volume; every row says why. Raw IOC volume mostly reflects who
  submits to ThreatFox (ClearFake, Mirai), not priority.

## Licence: abuse.ch terms §7.3

- abuse.ch terms (updated 2026-10-21) forbid using ThreatFox/URLhaus data to train or
  improve AI models without Spamhaus consent. Only Feodo/SSLBL/YARAify are CC0.
- Allowed here: counting, aggregates, lookup lists (the alias index, [[ioc-extraction]]).
- Found and fixed 2026-10-28: `cwe_eval.gold_check()` fitted TF-IDF + LR on the gold set,
  incl. 50 ThreatFox rows ([[gold-set-provenance]]). Now filtered by `gold.trainable()`;
  `tests/unit/test_licence_guard.py` blocks new feed readers and unfiltered gold fits.
- Dropped: a classifier over ThreatFox report URLs (it would train on their data).

## ThreatFox facts (2026-10-26 snapshot)

- 126,917 IOCs, 472 names / 481 IDs (one family can span platform IDs: `elf.mirai` +
  `win.mirai`, so family = printable name). Names containing "unknown": 18,201 rows,
  incl. role IDs `unknown_loader` 2,342, `_stealer` 1,246, `_rat` 719, `_webinject` 51.
- 467 named families, 108,716 rows: top 22 / 46 / 79 / 197 cover 80 / 90 / 95 / 99%.
  The planning figures (32,044 unknown; top 34 = 99%) were a miscount; top 34 = 86.6%.
- Parse keeps `malware_printable`; Malpedia `fk_malware` only as fallback (10a keeps both).
- CVE tags: 166 rows, 16 CVEs. KEV `knownRansomwareCampaignUse` names no family, so it
  links a CVE to the ransomware category only.

## MISP coverage (checked 2026-10-29)

- By normalised name/synonym, the 9 committed cluster files name 18 of the top 34 known
  ThreatFox families: 52,064 of 94,162 rows (55%). Missing incl. ClearFake, VShell,
  IClickFix, AMOS, DCRat, XWorm, Stealc, AdaptixC2. Malpedia URLs in `refs` are rare
  (≤ 13 per file), so the join is by name; owner labels carry the top 34.

## Links available

- `alias_index()` (`nlp/extract.py:83`) joins ~110 families to ATT&CK software (S####).
- ATT&CK v20 `uses`: 10,739 malware → technique, 869 tool → technique, 4,815 group →
  technique. Not parsed by `sources/attack.py`; read from the raw bundle.

Related: [[data-sources]], [[attack-mapping-v2]], [[dashboard]].
