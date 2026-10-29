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
  exploits (`attack_catalog.software_cves_from_bundle`; prose cleaned first, so citation
  names, link targets and reference titles are never read). 54 pairs / 30 software;
  17 links on 7 families.
- Review per source: ThreatFox tags 10/10, ATT&CK 13/17, reference pages 12/26; all
  35/53 (66%). The 4 rejected ATT&CK links are a **platform name collision**: ThreatFox
  "XLoader" is `apk.xloader` (Android, MoqHao) and "Xloader" `osx.xloader` (macOS build),
  but ATT&CK's sentence is the Windows XLoader's Office exploits. Lesson: the own-name join
  ignores platform; check `malware_ids` when a family links.
- Cobalt Strike is now rank 1 on a **capability** statement ("can exploit" four 2011–2013
  Java CVEs via modules), not observed use; recorded in the sheet notes.
- Rejected sources: campaigns (cross product), MISP descriptions, KEV text, Metasploit names.
- The link sheet is append-only (new links blank = unreviewed, only when none removed);
  `review.links.unreviewed` counts them. Quoted MITRE text carries MITRE's attribution.

Related: [[threat-catalog]], [[threat-layer]], [[attack-mapping]].
