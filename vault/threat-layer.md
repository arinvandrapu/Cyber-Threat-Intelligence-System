---
tags: [threats, design, licensing, phase-10]
---

# Threat Layer (Phase 10a, planned)

Status 2026-10-28: planned, owner-approved; plan of record `tasks/todo.md` § 10.
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
- Owner labels the top 34 families **blind**, then compares with the auto labels.
- Threat priority is a pre-declared heuristic, not ML: linked high-tier CVEs, ransomware,
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

- 126,917 IOCs, 481 families. Names containing "unknown": 32,044 rows. Of the rest, the
  top 11 / 20 / 26 / 34 families cover 80 / 90 / 95 / 99%.
- Parse keeps `malware_printable`; Malpedia `fk_malware` only as fallback (10a keeps both).
- CVE tags: 166 rows, 16 CVEs. KEV `knownRansomwareCampaignUse` names no family, so it
  links a CVE to the ransomware category only.

## Links available

- `alias_index()` (`nlp/extract.py:83`) joins ~110 families to ATT&CK software (S####).
- ATT&CK v20 `uses`: 10,739 malware → technique, 869 tool → technique, 4,815 group →
  technique. Not parsed by `sources/attack.py`; read from the raw bundle.

Related: [[data-sources]], [[attack-mapping-v2]], [[dashboard]].
