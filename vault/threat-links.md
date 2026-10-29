---
tags: [threats, evaluation, links, phase-10]
---

# Threat ↔ CVE Links: Sources and Review

How `cti threats` links malware families to CVEs, how the links were reviewed, and the
owner decisions that followed. Catalog overview: [[threat-catalog]].

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
  (n = 26; reviewed links are known, not averaged). 22 of 36 links ranked then.
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

## ATT&CK software links (2026-10-29)

- Third source `attack:software` (trusted): CVEs ATT&CK's own prose says a software
  exploits (`attack_catalog.software_cves_from_bundle`; citation names and reference
  titles ignored: they name campaign CVEs). 54 pairs / 30 software; 17 links on 7 families
  (Cobalt Strike, Agent Tesla, Formbook/XLoader/Xloader, Ramsay, PoshC2), all reviewed
  correct. Links now 39 / 53 correct (74%, 60–84%). 5 families entered the top 20 and
  were labelled; top 1 is now Cobalt Strike (4 KEV CVEs, old Java bugs).
- Rejected: campaigns (cross product), MISP descriptions, KEV text, Metasploit names.
- The link sheet is append-only: new links arrive blank (unreviewed, not an error).

Related: [[threat-catalog]], [[threat-layer]], [[attack-mapping]].
