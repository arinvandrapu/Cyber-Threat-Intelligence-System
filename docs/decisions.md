# Design Decisions

Each entry records a decision, why it was made, the alternatives considered, and what it
costs. The system itself is described in [architecture.md](architecture.md).

Several decisions respond to lessons from an earlier team prototype of a similar
pipeline (a university capstone), referred to below as *the prototype*.

## Index

1. [Ingest once into an immutable raw snapshot](#1-ingest-once-into-an-immutable-raw-snapshot)
2. [S3 as a write-once archive, not a live working store](#2-s3-as-a-write-once-archive-not-a-live-working-store)
3. [All compute runs locally](#3-all-compute-runs-locally)
4. [Forward-looking risk evaluation with point-in-time data](#4-forward-looking-risk-evaluation-with-point-in-time-data)
5. [Pin git-hosted feeds by first-parent history](#5-pin-git-hosted-feeds-by-first-parent-history)
6. [A custom, minimal SSRF-safe fetcher](#6-a-custom-minimal-ssrf-safe-fetcher)
7. [SecureBERT 2.0 for text, scikit-learn for tabular risk](#7-securebert-20-for-text-scikit-learn-for-tabular-risk)
8. [Report the gold set as a sanity check, not accuracy](#8-report-the-gold-set-as-a-sanity-check-not-accuracy)
9. [Drop sources that are stale, closed, or ethically problematic](#9-drop-sources-that-are-stale-closed-or-ethically-problematic)
10. [Evaluate classification on CWE labels, with choices fixed before scoring](#10-evaluate-classification-on-cwe-labels-with-choices-fixed-before-scoring)
11. [A local dashboard: Vite + React, served by Python with a strict CSP](#11-a-local-dashboard-vite--react-served-by-python-with-a-strict-csp)
12. [Never train a model on abuse.ch data](#12-never-train-a-model-on-abusech-data)
13. [Threat priority is a declared rule, kept out of the risk score](#13-threat-priority-is-a-declared-rule-kept-out-of-the-risk-score)
14. [Claude labelled the threat reviews for the owner, and the export says so](#14-claude-labelled-the-threat-reviews-for-the-owner-and-the-export-says-so)
15. [Known exploited order: a fixed rule signed off before any output](#15-known-exploited-order-a-fixed-rule-signed-off-before-any-output)
16. [The dashboard shows the model's numbers as they are](#16-the-dashboard-shows-the-models-numbers-as-they-are)

---

## 1. Ingest once into an immutable raw snapshot

**Decision.** `cti ingest` runs once and stores raw source responses unmodified (gzip'd)
with a manifest of SHA-256, fetch time, and source version. Parsing is a separate offline
step. A second ingest is refused; the only exception is a logged
`--refetch <source> --reason …`, which keeps the old copy.

**Why.**
- A parser bug costs a re-parse, not a re-download. Sources rate-limit, and some (EPSS,
  KEV, live IOC feeds) change daily, so a re-download gives *different* data.
- The dataset behind every reported number is fixed and auditable.
- Minimal API load on public sources.

**Alternatives.** Fetch-and-parse in one pass (the prototype's model); scheduled
incremental ingests. Both make results depend on when the pipeline last ran.

**Cost.** Everything a later phase needs must be in the data contract
(`tasks/todo.md`) before the real run, including scraped reference pages.

## 2. S3 as a write-once archive, not a live working store

**Decision.** The ingest writes to local disk. After `cti parse` validates the snapshot,
`cti upload` copies it to S3 once. Uploads cannot overwrite (`If-None-Match: *`, also
enforced in IAM), the storage layer has no delete, and reads verify SHA-256. No pipeline
stage reads from S3, and processed output is not stored there.

**How the prototype differed.** It used S3 as its live store: every stage wrote to the
bucket with `put_object` as it ran (raw CVEs under `nist/cve/YYYY/MM/DD/`, enrichment
under `enriched/…`, then corpus and NLP output), and later stages read their input back
with `get_object`. Nothing prevented re-fetching, so each run added new dated folders
and there was no record of exactly which data a result came from.

**Why not do the same here.**
1. **Compute is local** ([decision 3](#3-all-compute-runs-locally)). With one machine,
   routing every parse, re-parse, and NLP run through S3 adds latency, request charges,
   and a network dependency, with no benefit. In the prototype a shared bucket made
   sense because several people and machines worked on the same data.
2. **Cost.** At ~250 MB, storage is cents. What grows with iteration is requests and
   egress. A live store is hit on every run; an archive gets one upload (~2–3k PUTs,
   ≈ $0.015) and is almost never read.
3. **Reproducibility.** The forward-looking evaluation
   ([decision 4](#4-forward-looking-risk-evaluation-with-point-in-time-data)) is only
   valid if the data is frozen at a point in time. A live store that gains new data and
   overwritten objects on every run is what made the prototype's metrics untraceable.
   A write-once, checksummed snapshot is evidence.
4. **Blast radius.** A live store needs credentials that can write and overwrite all the
   time. Here S3 credentials are used only during `cti upload`, and even then cannot
   overwrite or delete.

**When a live store would be right.** A scheduled cloud ingest (Lambda/ECS), several
collaborators or machines sharing data, or data too large for a laptop. None apply. If a
scheduled ingest is added later, the snapshot layout (`<id>/raw/<source>/<attempt>/…`)
carries over unchanged; only where the code runs would change.

## 3. All compute runs locally

**Decision.** S3 is the only AWS service. Parsing, SecureBERT 2.0 inference (~150M
params, CPU, one-time batch), and modeling run on the owner's laptop. No EC2, Lambda,
SageMaker, KMS, or CloudTrail data events.

**Why.** Near-zero spend (expected well under $1/month; Budgets alert at $5), a smaller
cloud attack surface, and the workload fits on one machine.

**Cost.** Not suitable for continuous collection; this is a reproducible batch study.

## 4. Forward-looking risk evaluation with point-in-time data

**Decision.** Score CVEs using only data as of a cutoff (snapshot − 180 days), then
measure which were added to CISA KEV after the cutoff. Report precision@50/100 and
PR-AUC against CVSS-only and EPSS-only baselines. Tier thresholds come from these
results.

**Why.** The prototype tiered ~94% of items "high" using hand-tuned weights that were
never validated, so the tiers ranked nothing. Predicting future KEV additions is an
honest test that the score finds what attackers actually exploit.

**Cost.** The ingest must capture cutoff copies of EPSS, ExploitDB, Metasploit, Nuclei,
and Vulnrichment, and fields that leak KEV status (NVD `cisa*`, Vulnrichment ADP `kev`,
Nuclei `kev`/`epss` tags) are dropped at parse time. KEV additions are rare, so counts
and intervals are reported with the metrics.

**Update (Phase 7a).** One cutoff gave only 17 positives and no clean training set. Four
cutoffs 180 days apart (2024-11-05 → 2026-04-29) give a rolling-origin evaluation: train
on earlier windows, test on the next. That's 68 test positives. The extra dates were added
by a logged refetch that copied the existing files byte for byte and fetched only the new
dates, so earlier results are unchanged.

**Result (Phase 7b).** Pre-registered before scoring. A logistic model on cutoff-time
signals beats EPSS at a 100-CVE budget (+4 of 68, paired CI +1 to +8), but not at 1%, and
EPSS keeps the higher average precision. Rank tiers fall monotonically.

## 5. Pin git-hosted feeds by first-parent history

**Decision.** For Vulnrichment, Metasploit, and Nuclei, the cutoff state is the branch
head found with `git rev-list -1 --first-parent --before=<cutoff>` on a treeless,
shallow clone. ExploitDB uses GitLab's `first_parent=true&until=…`.

**Why.** GitHub's commits API `until=` filters by committer date over every reachable
commit. A PR commit dated before the cutoff but merged after it would be returned, and
its tree contains files that were not on the branch at the cutoff: leakage.

## 6. A custom, minimal SSRF-safe fetcher

**Decision.** Reference URLs from public CVE records are untrusted, so they are fetched
through a ~150-line fetcher on httpx (`http/safe_fetch.py`): http/https on ports 80/443
only, every resolved address must be globally routable, connections go to the validated
IP (Host header and SNI carry the real name), and redirects are followed manually and
re-validated (max 3).

**Why.** Each control is visible and tested. Advocate is archived (2023); `httpx-secure`
hides the controls inside a dependency.

**Cost.** Extra review found subtle issues that had to be fixed (pooled TLS connections
skipping cert checks, proxy env vars, slow-drip responses), now covered by tests.

## 7. SecureBERT 2.0 for text, scikit-learn for tabular risk

**Decision.** SecureBERT 2.0 handles language: NER (malware, products, orgs) and ATT&CK
technique mapping by embedding similarity. scikit-learn handles the tabular risk model
(LR/GBM), the TF-IDF baseline, and metrics.

**Why.** CVSS, EPSS, KEV, and exploit availability are tabular features; a transformer
is the wrong tool for them. Text features are added to the risk model and their value is
measured by an ablation, not assumed.

## 8. Report the gold set as a sanity check, not accuracy

**Decision.** The 299-document classification gold set (inherited from the prototype)
is frozen and checksummed, and results on it are reported next to source-only and
majority baselines as a sanity check.

**Why.** Its labels are rule-generated, not hand-labeled, and most equal the label
implied by the document's source feed, so a source-only predictor scores very high. Presenting that as real-world
accuracy would be misleading. The stronger evaluation is
[decision 4](#4-forward-looking-risk-evaluation-with-point-in-time-data).

## 9. Drop sources that are stale, closed, or ethically problematic

**Decision.** Not used: PhishTank (registrations closed), Ransomwatch (archived; its
replacements publish victim names), Feodo Tracker (no updates since 2026-03, no CVE
link), AlienVault OTX (overlaps abuse.ch; cut for scope).

**Why.** Fewer, maintained sources with clear terms beat a long list of stale ones, and
publishing ransomware victim names is not something this project does.

## 10. Evaluate classification on CWE labels, with choices fixed before scoring

**Decision.** Phase 6 classifies NVD CVE descriptions into CWE classes (human-assigned
labels, with their assigner kept) rather than relying on the gold set. Every choice (split
dates, label chain, class threshold, masking, method settings, the headline metric) is
in `src/cti/nlp/cwe_config.py`, committed before any test score existed.

**Why.** The gold set's primary label equals its source feed for 298 of 299 documents
(decision 8), so it can't show much. CWE labels are real, plentiful, and MITRE's own.
26–30% of descriptions contain their CWE's name, so the headline is computed on the rest. The Phase 5 ATT&CK result taught that a method designed after seeing test
numbers is fragile, so this evaluation was pre-registered.

**Deviation (2026-10-29).** The TF-IDF logistic regression uses the stochastic `saga`
solver and was not seeded, so re-runs differed by up to 0.002 at four decimals. It is now
seeded with the config's seed; this is recorded in the config header and the vault. The
seeded run kept the headline score and the chosen setting; one secondary figure (TF-IDF on
descriptions that name the CWE) moved from 0.91 to 0.92.

## 11. A local dashboard: Vite + React, served by Python with a strict CSP

**Decision.** The dashboard is a Vite + React + TypeScript app that reads JSON written by
`cti export` and is served by `cti serve`, a small standard-library server bound to
127.0.0.1. The original plan was a Next.js static export.

**Why.** Next.js puts inline scripts in every exported page, so a strict
Content-Security-Policy would need `'unsafe-inline'` or a hashing step after each build.
Vite emits only external scripts, so `script-src 'self'` works as is, and it pulls in
about half the npm packages. Serving from Python sends the CSP as a real HTTP header (a
`<meta>` tag can't carry `frame-ancestors`), checks the Host header against DNS
rebinding, and serves only a fixed allowlist of files built at startup, so path tricks
and directory listings can't happen. The dashboard shows rank and tier, never a
probability, and labels tier hit rates as historical results from the evaluation folds.

## 12. Never train a model on abuse.ch data

**Decision.** No model is fitted on ThreatFox or URLhaus data. abuse.ch data is used only
for counting, published aggregates, and the family-name lookup list behind alias
matching. `cti.gold.NO_TRAINING_SOURCES` names the two feeds, and
`tests/unit/test_licence_guard.py` fails CI if a new module names them or loads the gold
set for fitting without `gold.trainable()`.

**Why.** The abuse.ch terms of use (updated 2026-10-21, §7.3) forbid using their data to
train or improve AI models without Spamhaus's consent. An audit on 2026-10-28 found one
breach: the gold-set sanity check in `cti cwe-eval` fitted TF-IDF + logistic regression
on all 299 gold documents, 50 of them ThreatFox records. That check now drops them first
and reports the exclusion. No headline result used abuse.ch data.

**Cost.** A planned classifier over the threat reports that ThreatFox links to was
dropped. Threat categories come from MISP galaxies (CC0) instead.

## 13. Threat priority is a declared rule, kept out of the risk score

**Decision.** `cti threats` ranks malware families by a fixed key order in
`src/cti/threats/config.py`: linked CISA KEV CVEs, linked critical- or high-tier queue CVEs,
ransomware category, 30-day IOC growth, then IOC volume. Every row says why it ranks where
it does, and the dashboard calls it a fixed rule, not a trained model. Threat links explain
CVEs; they are never inputs to the CVE risk score.

**Why.** No labels exist to train or evaluate a threat ranking, and fitting a model on
ThreatFox data is not allowed ([decision 12](#12-never-train-a-model-on-abusech-data)). As
risk features, the links would leak: they come from snapshot-time reference pages, which
were chosen KEV-first, so they encode the label the risk model is tested on.

**Cost.** The priority is not validated. Some rules were added after the first run, each
in its own commit and listed in the config header (the KEV-link key, which links count, the
manual-label top 20). 47 of 53 links point at KEV CVEs, which the risk queue excludes, so
threats mostly explain KEV CVEs ([decision 15](#15-known-exploited-order-a-fixed-rule-signed-off-before-any-output)).

## 14. Claude labelled the threat reviews for the owner, and the export says so

**Decision.** The plan was for the owner to label the top families' categories blind and to
review every threat ↔ CVE link. On 2026-10-29 the owner delegated both reviews to Claude.
This is recorded in `REVIEW_LABELLER` (`src/cti/threats/config.py`) and shipped in
`threats.json` (`review.labeller`): not fully blind, because MISP name matches for some top
families had appeared in earlier tool output; links judged from the evidence page text;
ThreatFox tags accepted as reporter attributions.

**Why.** The labels change the ranking, so who made them, and how independent they were,
belongs next to the results. Judged link precision, 25 of 43 (58%, Wilson 95% CI 43–72%),
is reported apart from the 10 accepted tags; counting them (35/53) would overstate what was
checked.

**Cost.** Category agreement measures Claude against MISP, not an analyst against MISP.
The 56 hand-labelled families and the link reviews are committed in `data/reference/`, so a
human review can replace them.

## 15. Known exploited order: a fixed rule signed off before any output

**Decision.** The Known exploited view lists all 1,756 KEV CVEs in a fixed order: linked to
a shown threat family by a link that counts for priority (26 CVEs), then CISA known
ransomware use (361), then newest CISA listing date, then CVE ID. The owner signed off the
rule on 2026-11-06 before any output was seen. `cti export` writes each entry's
`priority_rank` and a `why` line naming its source.

**Why.** The risk queue excludes KEV CVEs by design, but confirmed-exploited CVEs still
need an order to patch in. Nothing labels which KEV CVE matters more, so the order cannot be
evaluated; it is presented as a sort order, not a prediction.

**Alternatives.** Ransomware before threat links; newest listing only; CISA's due date
(1,751 of 1,756 are past due at the snapshot, and it is a US federal deadline, so it
separates nothing).

**Cost.** Unevaluated. The listing date says when CISA added a CVE, not how active it is;
287 entries share CISA's first batch date (2021-11-03) and sort last within their group.

## 16. The dashboard shows the model's numbers as they are

**Decision.** Display wording follows the exported numbers, even when they read oddly:
- **No sign flip for age.** The label is "Age (older ranks lower)" next to the model's
  negative weight (−0.57 in the refit), not a renamed "Newness" with the sign reversed.
- **No "≈ 0" for small weights.** A contribution is weight × standardized value, so a
  rare signal with a small weight can still move a row: ExploitDB's −0.010 weight
  contributes −0.19 on 90 queue rows. A queue note explains when a public exploit or SSVC
  pulls a row down.
- **"Scored" vs "in the queue".** 167,844 CVEs are scored (given a tier); 8,392 are in the
  queue (critical, high, elevated).
- **"SSVC: PoC / exploited".** The feature is ordinal (none, PoC, active); no queued CVE
  has "active", so every negative contribution comes from a PoC.

**Why.** The sign flip and "≈ 0" were in the first dashboard-fix plan and were rejected by
its audit; the SSVC wording was caught by the implementation audit. A flipped sign or a rounded-away contribution would make the dashboard disagree with
`risk.json` and the tests, and the 0.02 rounding threshold had been picked after seeing the
weights.

**Cost.** Some rows read counter-intuitively (a public exploit lowering rank) and need an
explanatory note rather than a cleaner number.
