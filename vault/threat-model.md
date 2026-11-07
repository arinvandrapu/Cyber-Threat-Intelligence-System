---
tags: [security, threat-model, stride, phase-9]
---

# Threat Model (Phase 9.2)

Deliverable: `docs/threat-model.md` (STRIDE, public doc). Plan: `tasks/todo.md` → 9.2.
Builds on [[ssrf-safe-fetching]], [[aws-cost-and-security]], [[dashboard-web]].

## Decisions so far (2026-11-07)

- Structure = Shostack's four questions; STRIDE **per boundary-crossing flow** (not every
  element); qualitative likelihood × impact with a stated key. No DREAD (dropped by
  Microsoft for inconsistent scoring), no CVSS for design threats.
- **Cite controls as `file` + symbol name or test name, not line numbers**: line numbers
  rot with every edit; a committed test can check that every cited path, symbol and test
  still exists, so the doc fails CI instead of silently going stale.
- Framework IDs only if verified on MITRE's own site. Verified: ATLAS AML.T0010 = "AI
  Supply Chain Compromise" (renamed from "ML …"), AML.T0010.003 = Model; D3FEND D3-OTF =
  Outbound Traffic Filtering. A D3FEND file-hashing ID appears only on mirrors → left out.
  T1190 is a misfit for a loopback-only server (say so rather than claim it).
- Verified in code, not assumed: httpx strips `Authorization` on cross-origin redirects
  (`httpx/_client.py` `_redirect_headers`), so the GitHub token can't follow a redirect
  to another host; botocore DEBUG logs the canonical request (access-key ID, not the
  secret) — relevant because `cti -v` sets the root logger to DEBUG.

## Plan audit changes (2026-11-07)

- Attacker profiles A1–A6 before the table (A6 = LLM-assisted labelling as an integrity
  risk, not an adversary); assets carry a class (secret / hazardous / licence-restricted /
  integrity-critical / public).
- Main table: ID, flow, attacker, STRIDE, threat, weakness/technique, inherent → residual,
  decision; controls and evidence in a list below (12 columns was unreadable on GitHub).
- Rating key: L/M/H likelihood by how attacker input reaches the element; impact H =
  credentials, code execution, silent integrity loss in published numbers, AWS loss.
- IDs: CWE-346 (not CWE-350) for DNS rebinding; CWE-611/776/502 shown as mitigated;
  CWE-770 for uncapped reads; CWE-1333 (ReDoS) listed as unverified (no timing test).
  ATT&CK checked against v20 (snapshot bundle v20.0; current v20.1, 2026-10-13); all six
  technique names confirmed in the bundle. CTID mappings are ATT&CK 16.1 (separate).
- Two gaps fixed in the PR, no output change: `cli.NOISY_LOGGERS` keeps botocore, boto3,
  s3transfer, urllib3 at WARNING under `-v` (R6); `_git_state` also watches
  `data/reference/` so an uncommitted label-sheet edit marks exports dirty (R4). Hashing
  the sheets into threats output stays deferred (changes export → sample brief).
- `docs/architecture.md` "Security boundaries" shrunk to a summary linking the model.
- Citation check: `tests/unit/test_threat_model_refs.py` (89 citations: files, 24
  symbols, 31 tests); a chained bare symbol inherits the preceding `file::` path.

## Implementation audit (2026-11-07)

- Logging test asserted effective levels, which pass under pytest without the fix; now
  asserts each logger's own level (mutation-checked: fails without `NOISY_LOGGERS`).
- Headline link precision is the judged 25/43 (decisions §14), not 35/53; links reorder
  families but never a CVE's risk rank. T3 deadline = body read only (+15 s per op);
  lxml parses page HTML only (feed XML is defusedxml).
- Rating: 3×3 grid + residual-only **R** (needs defeating a CI-tested control) → every
  residual is mechanically checkable; the four residual M (T5, T8, T9, T12) are exactly
  the ones resting on config or disclosure. Added T15 (licence/hazardous-data leak),
  R13 (2,000 attacker-chosen URLs), R3 now includes the Vulnrichment total size; DFD got
  a `cti upload` process (no store-to-store flows). Checker: chains across line breaks;
  ignores keyword args and nested attributes.

## Inputs

- Internal inventory: ~40 built controls with evidence; 14 gaps (manifest overwritable +
  noncurrent versions expire after 30 d; review CSVs unpinned; uncapped in-memory feed
  downloads; tar total size; HTML parser CPU; `-v` DEBUG; long-lived IAM key; no
  CloudTrail data events; `cti serve` unauthenticated on loopback; defang of unknown
  names relies on text-only rendering; no PyPI min-age; Claude-labelled CSVs; 2,000
  attacker-chosen scrape URLs).
- Coupling to remember: any change that alters `cti threats` or export output also
  changes the committed sample brief's hash ([[intel-brief]]).
