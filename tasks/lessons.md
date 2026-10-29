# Lessons

Patterns captured after corrections, so the same mistakes aren't repeated.
Reviewed at the start of each session.

## Format

### <short title>
- **Mistake:** what went wrong
- **Trigger:** the situation that surfaces it
- **Rule:** what to do instead

## Lessons

### Every change lands through a PR the owner merges
- **Mistake:** Pushed directly to `main` while setting up a repo.
- **Trigger:** Seeding a repo, replacing a starter commit, any push targeting `main`.
- **Rule:** Feature branch → push branch → open PR → stop. The owner merges manually.

### Check PR state before pushing more commits to its branch
- **Mistake:** Pushed three commits to a PR branch after the PR had already been merged, so they never reached `main`.
- **Trigger:** Adding follow-up changes to an open PR, especially after time has passed.
- **Rule:** Run `gh pr view <n> --json state` first. If it's merged, branch from the updated `main` and open a new PR.

### Finish the audit before opening the PR
- **Mistake:** Opened the Phase 1 PR while the code audit was still running. The owner merged it, so the fixes needed a second PR.
- **Trigger:** Any non-trivial PR. The owner reviews and merges quickly.
- **Rule:** Run the implementation audit and apply its fixes first, then open the PR.

### Batch follow-up pushes to an open PR
- **Mistake:** Pushed four small commits (two of them docs-only) to an open PR within six minutes, so CI ran four times and the owner asked why.
- **Trigger:** Fixing audit findings or adding vault notes after a PR is open.
- **Rule:** Batch follow-ups into one push. CI now cancels superseded PR runs (#20), but still don't push docs-only commits one by one.

### Fix the question before choosing the method
- **Mistake:** In Phase 5 the ATT&CK hybrid was designed after seeing the zero-shot test results, and turned out β-fragile. Phase 6's planned gold-set evaluation would have been circular (labels = source feed for 298/299).
- **Trigger:** Any evaluation whose result goes in the README.
- **Rule:** Check that the labels can answer the question first, then commit a config fixing every choice before any test score (Phase 6 `cwe_config.py` is the pattern).


### Read third-party data before committing it
- **Mistake:** Phase 10-0 committed MISP's `ransomware.json` as an unmodified copy. It held ransom notes, one with a victim's portal login, plus leak-site .onion links; CI gitleaks failed the PR.
- **Trigger:** Committing any upstream data file, however reputable the source.
- **Rule:** Run `gitleaks dir <path>` locally and scan for fields you don't need (victims, notes, live URLs) before the first push; commit only the fields used, via a tested, idempotent trim.

### Check identity, not just names, before marking a link correct
- **Mistake:** Reviewing ATT&CK software links, I marked ThreatFox "XLoader" and "Xloader" correct because the names matched ATT&CK S1207; their IDs were `apk.xloader` (Android, a different malware) and `osx.xloader` (macOS build), so the Windows Office-exploit sentence didn't apply. An audit caught it.
- **Trigger:** Any review or join that connects records by name across sources (ThreatFox, ATT&CK, MISP, reference pages).
- **Rule:** Before marking a name-based link correct, check the source's own ID (platform prefix, Malpedia ID) and that the evidence describes the same variant; note any mismatch.
