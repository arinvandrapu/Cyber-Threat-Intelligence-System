---
tags: [report, intelligence, phase-9]
---

# Intel Brief (`cti report`, Phase 9.1)

Code: `src/cti/dashboard/brief.py`. Sample: `docs/sample-intel-brief.md` (real export,
stamped clean at `f1b25d8`, the last 9.1 code commit). Golden: `tests/golden/brief_fixture.md` (synthetic fixture). Reads only the
export ([[dashboard]]); no NumPy, no network, no clock.

## Design

- `facts(export_dir)` validates each file with `schema.FILES` and computes every number;
  `render(facts)` only words them. Owner 2026-11-07: Markdown in `docs/`, no tab, no PDF.
- Conventions (external due diligence): `TLP:CLEAR` first and last line (public data
  only); BLUF; observed vs judged labels; ICD 203: a confidence label never shares a
  sentence with a likelihood word; sources with versions and a reliability note.
- Confidence key (rule, not taste), on the positive events a judgement rests on: low < 10;
  moderate < 50 or when another measure disagrees (EPSS higher mean AP, top-1% CI
  includes 0); else high. Today both are **low**: model vs EPSS rests on 6 top-100 hits
  (impl. audit: keying it on all 68 positives overstated it), critical tier on 6 positives.
- Judgements are stated as judgements ("adds value over EPSS only at the very top of the
  list"), then the measurement, then confidence in its own sentence.

## Wording rules (plan audit, 2026-11-07)

- Forward test stated as the pre-registered verdict ("logistic better", +4, CI +1 to +8)
  **and** the counter-evidence (EPSS mean AP 0.0151 vs 0.0112; top-1% +1, CI −6 to +9).
  "1%" there is the top-1% cutoff, not a significance level.
- Section 1 is "Known exploited: threat-linked first", a fixed sort, not "Patch now";
  explains `knownRansomwareCampaignUse` ("Unknown" ≠ none) and that due dates bind US
  federal civilian agencies (1,751/1,756 passed); no per-row due dates. BOD number not
  cited (a replacement was reported but unverified).
- Watch list: "ranking, not a prediction"; newness drives it (7 of top 10 ≤ 30 days old)
  and the EPSS version gap, both in the section header, not only in Limitations. EPSS
  shown as probability + "top x%" (no "99.98th").
- Threat links worded per source via `KEV_LINK_SOURCES` (moved to `threats/config.py`
  so the brief and dashboard share it); never "exploits"; rejected links dropped.
- Limitations are `meta.disclosures` verbatim: one source of truth, not retyped.
- No indicators, no CVE descriptions, no URLs (abuse.ch terms; test enforces).
- Implementation audit: "public exploit" = ExploitDB or Metasploit (Nuclei templates are
  mostly detection); NVD is a model input via publication date (age), EPSS via percentile;
  tier CIs recomputed from counts (export rounds to 4 places: baseline is 0.012–0.023%,
  not 0.010–0.020%); IOC column = ThreatFox rows, change = last 30 d minus prior 30 d.

## Reproducibility

The brief states the export's commit, clean/dirty, and a SHA-256 over the 8 export files.
`cti report --check docs/sample-intel-brief.md` exits 1 unless the file equals the brief
the current generator makes from the current export (whole text: catches another export,
a hand edit, or an older generator):
CI has no real data, so the golden fixture test guards the generator and `--check` guards
the committed sample. Regenerate both after any export change ([[dashboard-export-facts]]).

**Gotcha:** any re-stamp of the export (even from an uncommitted tree) changes `meta.json`
and so the hash: the sample then fails `--check`. Order: commit code, `cti export` (clean),
`cti report --out docs/sample-intel-brief.md`, commit docs (`_git_state` watches `src/`
and `data/reference/` only, so a docs commit keeps the stamp clean). Re-stamping after every merge now also
means regenerating the sample in the same PR.
